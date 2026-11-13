use std::collections::BTreeMap;

use riggs_types::phishing::{Evidence, Level, MailObservation, PageObservation, Provider, Reason};
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::cues::{evaluate, link_target, sender_address, Cue, LookalikeHit};
use crate::domain::{name, Name};
use crate::lookalike::lookalike;
use crate::policy::Policy;

/// How long a checked mail's link hosts, and a flagged page, are remembered.
pub const RECENT_MS: u64 = 30 * 60 * 1000;
/// Entries per in-memory map; past it the oldest go first.
pub const RECENT_CAP: usize = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRow {
    /// Registrable domain.
    pub domain: String,
    pub first_ms: u64,
    pub last_ms: u64,
    /// Sightings since the login became known; 0 while it is pending (seen on weak evidence only).
    pub count: u32,
}

/// How strongly a login was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginEvidence {
    /// The password field merely held a value (the sensor's `filled`). A page can arrange that by
    /// itself, so such a login stays pending until it is seen again later.
    Weak,
    /// The person typed or pasted the password, or the browser's own password manager filled it.
    Strong,
    /// The admin's `trust`: known at once, past the lookalike and flagged refusals.
    Trusted,
}

impl From<Evidence> for LoginEvidence {
    fn from(evidence: Evidence) -> Self {
        match evidence {
            Evidence::Filled => LoginEvidence::Weak,
            Evidence::Typed | Evidence::Autofill => LoginEvidence::Strong,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderRow {
    /// Registrable domain, or a hex SHA-256 of the lowercased address at a free-mail domain.
    pub key: String,
    pub first_ms: u64,
    /// [`message_fingerprint`] of the first message seen from this sender.
    pub first_msg: u64,
}

/// A persistent mutation for the caller to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Insert or replace the row for its domain.
    Login(LoginRow),
    /// Delete the login row for this registrable domain.
    LoginRemoved(String),
    /// Insert a new sender row.
    Sender(SenderRow),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub level: Level,
    /// Every fired cue, in `Cue` order, including cues whose weight is 0.
    pub cues: Vec<Cue>,
    /// Summed weight of the fired soft cues; 0 for a page.
    pub score: f32,
    /// Registrable domain to log: the sender's for a mail, the page's for a page. Empty when the
    /// host has none (an IP literal, a single label).
    pub domain: String,
    /// Banner reasons, in `cues` order, for what can raise the level only: hard cues, page rules
    /// and soft cues whose weight is above 0. A lookalike reason names both domains of its hit.
    pub reasons: Vec<Reason>,
    /// One hit per fired lookalike cue, in `cues` order, whatever its weight.
    pub lookalikes: Vec<LookalikeHit>,
}

/// One local user's history. Pure state: time comes in as `now_ms`, and every persistent change is
/// returned for the caller to store.
#[derive(Debug, Clone, Default)]
pub struct User {
    logins: BTreeMap<String, (LoginRow, Name)>,
    senders: BTreeMap<String, SenderRow>,
    /// Host of a link in a checked mail -> highest level of the mails carrying it, and when.
    mail_links: BTreeMap<String, (Level, u64)>,
    /// Registrable domain of a page check that was not `none` -> its level, and when.
    flagged: BTreeMap<String, (Level, u64)>,
}

impl User {
    /// Rebuilds a user from stored rows. A login row whose domain is not its own registrable
    /// domain is an error.
    pub fn new(
        logins: impl IntoIterator<Item = LoginRow>,
        senders: impl IntoIterator<Item = SenderRow>,
    ) -> Result<User, String> {
        let mut user = User::default();
        for row in logins {
            let name = name(&row.domain)
                .filter(|n| n.registrable == row.domain)
                .ok_or_else(|| {
                    format!("stored login {} is not a registrable domain", row.domain)
                })?;
            user.logins.insert(row.domain.clone(), (row, name));
        }
        user.senders = senders
            .into_iter()
            .map(|row| (row.key.clone(), row))
            .collect();
        Ok(user)
    }

    /// Every login row, pending ones (count 0) included, in domain order.
    pub fn logins(&self) -> impl Iterator<Item = &LoginRow> {
        self.logins.values().map(|(row, _)| row)
    }

    /// The known logins: what the rules compare against and exempt. A pending login is not one.
    fn known(&self) -> Vec<&Name> {
        self.logins
            .values()
            .filter(|(row, _)| row.count > 0)
            .map(|(_, n)| n)
            .collect()
    }

    /// Checks an opened mail. Re-opening the first mail seen from a sender gives the verdict it
    /// got the first time.
    pub fn check_mail(
        &mut self,
        policy: &Policy,
        mail: &MailObservation,
        now_ms: u64,
    ) -> (Assessment, Option<Change>) {
        let from = sender_address(&mail.from_addr);
        let key = sender_key(policy, &from);
        let msg = message_fingerprint(mail.provider, &mail.message_id);
        let never_seen = self
            .senders
            .get(&key)
            .is_none_or(|row| row.first_msg == msg);
        let (fired, lookalikes) = evaluate(mail, &from, policy, &self.known(), never_seen);
        let score: f32 = fired
            .keys()
            .filter(|cue| cue.is_soft())
            .map(|cue| policy.weights[cue])
            .sum();
        let level = if fired.keys().any(|cue| cue.is_hard()) {
            Level::Danger
        } else if score >= policy.caution_threshold {
            Level::Caution
        } else {
            Level::None
        };
        let domain = from
            .rsplit_once('@')
            .and_then(|(_, d)| name(d))
            .map_or_else(String::new, |n| n.registrable);

        // A click enters the browser at the href's host and, through a redirector, ends at the
        // destination's host: both count as reached from this mail.
        let hosts = mail
            .links
            .iter()
            .flat_map(|l| {
                [
                    Url::parse(l.href.trim()).ok(),
                    link_target(&l.href, policy).0,
                ]
            })
            .flatten()
            .filter_map(|url| host_key(url.host_str()?));
        for host in hosts {
            remember(&mut self.mail_links, host, level, now_ms);
        }
        prune(&mut self.mail_links, now_ms);

        let mut change = None;
        if !self.senders.contains_key(&key) && self.senders.len() < policy.max_senders {
            let row = SenderRow {
                key: key.clone(),
                first_ms: now_ms,
                first_msg: msg,
            };
            self.senders.insert(key, row.clone());
            change = Some(Change::Sender(row));
        }
        (
            assessment(policy, level, fired, lookalikes, score, domain),
            change,
        )
    }

    /// Checks a page that holds a password field.
    pub fn check_page(
        &mut self,
        policy: &Policy,
        page: &PageObservation,
        now_ms: u64,
    ) -> Assessment {
        let name = name(&page.host);
        let domain = name
            .as_ref()
            .map_or_else(String::new, |n| n.registrable.clone());
        let known = self.known();
        if known.iter().any(|k| k.registrable == domain) {
            return assessment(policy, Level::None, BTreeMap::new(), vec![], 0.0, domain);
        }
        let mut fired = BTreeMap::new();
        let mut lookalikes = vec![];
        let hard = name
            .as_ref()
            .and_then(|n| lookalike(n, known.iter().copied(), &policy.guards))
            .filter(|(_, rule)| rule.is_hard());
        let level = if let Some((k, rule)) = hard {
            let cue = Cue::from(rule);
            fired.insert(cue, Some(k.registrable.clone()));
            lookalikes.push(LookalikeHit {
                cue,
                candidate: domain.clone(),
                known: k.registrable.clone(),
            });
            Level::Danger
        } else {
            let linked = [Some(page.host.as_str()), page.entry_host.as_deref()]
                .into_iter()
                .flatten()
                .filter_map(host_key)
                .filter_map(|host| recent(&self.mail_links, &host, now_ms))
                .reduce(higher);
            let from_mail = page.opened_from_mail || linked.is_some();
            let mail_level = higher(
                page.mail_level.unwrap_or(Level::None),
                linked.unwrap_or(Level::None),
            );
            if !from_mail || known.len() < policy.warmup_logins {
                Level::None
            } else if mail_level == Level::None {
                fired.insert(Cue::PageFromMailUnknownLogin, None);
                Level::Caution
            } else {
                fired.insert(Cue::PageFromMailUnknownLogin, None);
                fired.insert(Cue::PageFromFlaggedMail, None);
                Level::Danger
            }
        };
        if level != Level::None && !domain.is_empty() {
            remember(&mut self.flagged, domain.clone(), level, now_ms);
            prune(&mut self.flagged, now_ms);
        }
        assessment(policy, level, fired, lookalikes, 0.0, domain)
    }

    /// Records a login and returns the changes to store, in this order: a pending login dropped to
    /// make room, then the login's own row.
    ///
    /// A known login is refreshed. A new domain is known at once on strong evidence or a trust,
    /// and pending (count 0) on weak evidence. A pending login becomes known on strong evidence,
    /// a trust, or weak evidence again at least `weak_login_confirm_hours` after its first
    /// sighting; weak evidence sooner only refreshes it. Creating or confirming a login is
    /// refused, recording nothing, for a hard lookalike of a known login or a domain a page check
    /// flagged in the last 30 minutes (neither applies to a trust), and for a new domain at the
    /// login cap when there is no pending login to drop.
    pub fn login_seen(
        &mut self,
        policy: &Policy,
        host: &str,
        now_ms: u64,
        evidence: LoginEvidence,
    ) -> Result<Vec<Change>, String> {
        let name = name(host).ok_or("not a registrable domain")?;
        let domain = name.registrable.clone();
        if let Some((row, _)) = self.logins.get_mut(&domain) {
            let known = row.count > 0;
            let early = evidence == LoginEvidence::Weak
                && now_ms < row.first_ms.saturating_add(policy.weak_login_confirm_ms);
            if known || early {
                row.last_ms = now_ms;
                if known {
                    row.count = row.count.saturating_add(1);
                }
                return Ok(vec![Change::Login(row.clone())]);
            }
        }
        if evidence != LoginEvidence::Trusted {
            let hard = lookalike(&name, self.known(), &policy.guards).filter(|(_, r)| r.is_hard());
            if let Some((k, _)) = hard {
                return Err(format!("looks like {}, a login domain", k.registrable));
            }
            if recent(&self.flagged, &domain, now_ms).is_some() {
                return Err("a page check flagged it in the last 30 minutes".into());
            }
        }
        if let Some((row, _)) = self.logins.get_mut(&domain) {
            row.last_ms = now_ms;
            row.count = 1;
            return Ok(vec![Change::Login(row.clone())]);
        }
        let mut changes = Vec::new();
        if self.logins.len() >= policy.max_logins {
            // A flood of pending logins must not lock real ones out: the oldest pending one goes.
            let oldest = self
                .logins
                .values()
                .filter(|(row, _)| row.count == 0)
                .min_by_key(|(row, _)| row.first_ms)
                .map(|(row, _)| row.domain.clone())
                .ok_or("the login cap is reached")?;
            self.logins.remove(&oldest);
            changes.push(Change::LoginRemoved(oldest));
        }
        let row = LoginRow {
            domain: domain.clone(),
            first_ms: now_ms,
            last_ms: now_ms,
            count: u32::from(evidence != LoginEvidence::Weak),
        };
        self.logins.insert(domain, (row.clone(), name));
        changes.push(Change::Login(row));
        Ok(changes)
    }

    /// Drops a login, for the admin's `forget`.
    pub fn forget(&mut self, host: &str) -> Option<Change> {
        let registrable = name(host)?.registrable;
        self.logins
            .remove(&registrable)
            .map(|_| Change::LoginRemoved(registrable))
    }
}

/// First 8 bytes, big-endian, of SHA-256 over the provider's wire tag, a NUL byte and the
/// message id.
pub fn message_fingerprint(provider: Provider, message_id: &str) -> u64 {
    let tag = match provider {
        Provider::Gmail => "gmail",
        Provider::OutlookWeb => "outlook_web",
        Provider::OutlookAddin => "outlook_addin",
    };
    let digest = Sha256::new()
        .chain_update(tag)
        .chain_update([0u8])
        .chain_update(message_id)
        .finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first)
}

/// The registrable domain of `from` (a [`sender_address`]), or a hex SHA-256 of it when its domain
/// is free mail or has no registrable domain.
fn sender_key(policy: &Policy, from: &str) -> String {
    from.rsplit_once('@')
        .map(|(_, d)| d)
        .filter(|d| !policy.is_freemail(d))
        .and_then(name)
        .map_or_else(
            || {
                Sha256::digest(from.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            },
            |n| n.registrable,
        )
}

fn assessment(
    policy: &Policy,
    level: Level,
    fired: BTreeMap<Cue, Option<String>>,
    lookalikes: Vec<LookalikeHit>,
    score: f32,
    domain: String,
) -> Assessment {
    let reasons = fired
        .iter()
        .filter(|(cue, _)| !cue.is_soft() || policy.weights[cue] > 0.0)
        .map(|(cue, known)| Reason {
            cue: cue.id().into(),
            text: match lookalikes.iter().find(|hit| hit.cue == *cue) {
                Some(hit) => cue.lookalike_reason(&hit.candidate, &hit.known),
                None => cue.reason(known.as_deref()),
            },
        })
        .collect();
    Assessment {
        level,
        cues: fired.into_keys().collect(),
        score,
        domain,
        reasons,
        lookalikes,
    }
}

/// The same host string for a link's host and for a page's host.
fn host_key(host: &str) -> Option<String> {
    Host::parse(host.strip_suffix('.').unwrap_or(host))
        .ok()
        .map(|h| h.to_string())
}

fn higher(a: Level, b: Level) -> Level {
    let rank = |level| match level {
        Level::None => 0,
        Level::Caution => 1,
        Level::Danger => 2,
    };
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

fn recent(map: &BTreeMap<String, (Level, u64)>, key: &str, now_ms: u64) -> Option<Level> {
    map.get(key)
        .filter(|(_, at)| now_ms < at.saturating_add(RECENT_MS))
        .map(|(level, _)| *level)
}

fn remember(map: &mut BTreeMap<String, (Level, u64)>, key: String, level: Level, now_ms: u64) {
    let level = recent(map, &key, now_ms).map_or(level, |previous| higher(previous, level));
    map.insert(key, (level, now_ms));
}

fn prune(map: &mut BTreeMap<String, (Level, u64)>, now_ms: u64) {
    map.retain(|_, (_, at)| now_ms < at.saturating_add(RECENT_MS));
    let excess = map.len().saturating_sub(RECENT_CAP);
    if excess > 0 {
        let mut by_age: Vec<(u64, String)> =
            map.iter().map(|(k, (_, at))| (*at, k.clone())).collect();
        by_age.sort();
        for (_, key) in by_age.into_iter().take(excess) {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cues::tests::{link, mail, shipped, wrapping};
    use riggs_types::phishing::Level::{Caution, Danger, None as Clear};
    use LoginEvidence::{Strong, Trusted, Weak};

    const MINUTE: u64 = 60 * 1000;

    fn page(host: &str) -> PageObservation {
        PageObservation {
            host: host.into(),
            entry_host: None,
            opened_from_mail: false,
            mail_level: None,
        }
    }

    fn from_mail(host: &str, mail_level: Option<Level>) -> PageObservation {
        PageObservation {
            opened_from_mail: true,
            mail_level,
            ..page(host)
        }
    }

    /// A user with `n` logins at constructed domains, far from every test host, plus `extra`.
    fn user_with(n: usize, extra: &[&str]) -> User {
        let mut domains: Vec<String> = (0..n).map(|i| format!("warmup{i}.org")).collect();
        domains.extend(extra.iter().map(|d| d.to_string()));
        let rows = domains.into_iter().map(|d| LoginRow {
            domain: name(&d).unwrap().registrable,
            first_ms: 1,
            last_ms: 1,
            count: 1,
        });
        User::new(rows, []).unwrap()
    }

    fn cues(a: &Assessment) -> Vec<&str> {
        a.cues.iter().map(|c| c.id()).collect()
    }

    // Mail.

    #[test]
    fn the_same_mail_from_the_same_state_gives_the_same_result() {
        let p = shipped();
        let mut m = mail();
        m.subject = "Re: URGENT".into();
        m.links = vec![link("Sign in", "https://amazongproducts.ru/")];
        m.attachments = vec!["file.zip".into()];
        let start = user_with(0, &["amazon.com"]);
        let (mut a, mut b) = (start.clone(), start);
        assert_eq!(a.check_mail(&p, &m, 1_000), b.check_mail(&p, &m, 1_000));
    }

    #[test]
    fn reopening_the_first_mail_from_a_sender_gives_its_first_verdict() {
        let p = shipped();
        let mut user = User::default();
        let first = mail();
        let (opened, change) = user.check_mail(&p, &first, 1_000);
        assert!(opened.cues.contains(&Cue::SenderNeverSeen));
        let Some(Change::Sender(row)) = change else {
            panic!("expected a sender row, got {change:?}");
        };
        assert_eq!(row.key, "example.com");
        assert_eq!(
            row.first_msg,
            message_fingerprint(first.provider, &first.message_id)
        );

        let (reopened, change) = user.check_mail(&p, &first, 2_000);
        assert_eq!(reopened, opened);
        assert_eq!(change, None);

        let mut second = mail();
        second.message_id = "m2".into();
        let (later, _) = user.check_mail(&p, &second, 3_000);
        assert!(!later.cues.contains(&Cue::SenderNeverSeen));
    }

    #[test]
    fn a_hard_cue_is_danger_even_with_every_weight_at_zero() {
        let mut m = mail();
        m.from_addr = "orders@amazan.com".into();
        let (a, _) = user_with(0, &["amazon.com"]).check_mail(&shipped(), &m, 1);
        assert_eq!(a.level, Danger);
        assert_eq!(a.domain, "amazan.com");
        assert_eq!(cues(&a)[0], "domain_lookalike_misspelling");
        assert!(a.cues.contains(&Cue::SenderNeverSeen));
        // Zero-weight soft cues are logged in `cues` but give no banner line.
        assert_eq!(
            a.reasons,
            [Reason {
                cue: "domain_lookalike_misspelling".into(),
                text:
                    "amazan.com looks like amazon.com, where you log in, but is a different site."
                        .into(),
            }]
        );
        assert_eq!(
            a.lookalikes,
            [LookalikeHit {
                cue: Cue::DomainLookalikeMisspelling,
                candidate: "amazan.com".into(),
                known: "amazon.com".into(),
            }]
        );
    }

    #[test]
    fn lookalike_hits_name_both_domains_one_per_cue_in_cue_order() {
        let mut m = mail();
        m.from_addr = "news@www.nist.com".into();
        m.links = vec![
            link("Shop", "https://amazongproducts.ru/"),
            link("Sign in", "https://amazan.com/"),
            link("Sign in", "https://amazan.org/"),
        ];
        let (a, _) = user_with(0, &["amazon.com", "nist.gov"]).check_mail(&shipped(), &m, 1);
        let hits: Vec<(&str, &str, &str)> = a
            .lookalikes
            .iter()
            .map(|h| (h.cue.id(), h.candidate.as_str(), h.known.as_str()))
            .collect();
        assert_eq!(
            hits,
            [
                ("domain_lookalike_misspelling", "amazan.com", "amazon.com"),
                (
                    "domain_lookalike_brand_token",
                    "amazongproducts.ru",
                    "amazon.com"
                ),
                ("domain_lookalike_suffix_swap", "nist.com", "nist.gov"),
            ]
        );
    }

    #[test]
    fn reasons_hold_only_the_soft_cues_with_a_weight_above_zero() {
        let mut p = shipped();
        p.weights.insert(Cue::Urgency, 0.5);
        p.weights.insert(Cue::AttachmentPresent, -0.5);
        let mut m = mail();
        m.subject = "URGENT".into();
        m.attachments = vec!["file.pdf".into()];
        let (a, _) = User::default().check_mail(&p, &m, 1);
        assert!(a.cues.contains(&Cue::AttachmentPresent));
        assert!(a.cues.contains(&Cue::SenderNeverSeen));
        let shown: Vec<&str> = a.reasons.iter().map(|r| r.cue.as_str()).collect();
        assert_eq!(shown, ["urgency"]);
    }

    #[test]
    fn soft_cues_reach_caution_at_the_threshold_and_never_danger() {
        let mut p = shipped();
        let mut m = mail();
        m.subject = "URGENT".into();
        m.attachments = vec!["file.pdf".into()];

        let (a, _) = User::default().check_mail(&p, &m, 1);
        assert_eq!((a.level, a.score), (Clear, 0.0));

        p.weights.insert(Cue::Urgency, 0.5);
        p.weights.insert(Cue::AttachmentPresent, 0.4);
        let (a, _) = User::default().check_mail(&p, &m, 1);
        assert_eq!(a.level, Clear);
        p.weights.insert(Cue::AttachmentPresent, 0.5);
        let (a, _) = User::default().check_mail(&p, &m, 1);
        assert_eq!((a.level, a.score), (Caution, 1.0));
        p.weights.insert(Cue::Urgency, 1000.0);
        let (a, _) = User::default().check_mail(&p, &m, 1);
        assert_eq!(a.level, Caution);
    }

    #[test]
    fn a_free_mail_sender_is_keyed_by_a_hash_of_the_address() {
        let p = shipped();
        let mut m = mail();
        m.from_addr = "Someone@Gmail.com".into();
        let (a, change) = User::default().check_mail(&p, &m, 1);
        assert_eq!(a.domain, "gmail.com");
        let Some(Change::Sender(row)) = change else {
            panic!("expected a sender row");
        };
        assert_eq!(row.key.len(), 64);
        assert!(row.key.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(row.key, sender_key(&p, "someone@gmail.com"));
        assert_ne!(row.key, sender_key(&p, "other@gmail.com"));
    }

    #[test]
    fn the_sender_address_is_normalised_once_for_every_check() {
        let p = shipped();
        let user = user_with(0, &["amazon.com"]);
        for from in [
            "orders@amazan.com\n",
            " ORDERS@Amazan.COM",
            "orders@amazan.com.",
        ] {
            let mut m = mail();
            m.from_addr = from.into();
            let (a, change) = user.clone().check_mail(&p, &m, 1);
            assert_eq!(a.level, Danger, "{from:?}");
            assert_eq!(a.domain, "amazan.com", "{from:?}");
            let Some(Change::Sender(row)) = change else {
                panic!("expected a sender row for {from:?}");
            };
            assert_eq!(row.key, "amazan.com", "{from:?}");
        }
        // A free-mail sender keeps one hashed key, whatever its case, whitespace or trailing dot.
        for from in [
            "someone@gmail.com",
            "Someone@GMAIL.com ",
            "someone@gmail.com.",
        ] {
            let mut m = mail();
            m.from_addr = from.into();
            let (_, change) = User::default().check_mail(&p, &m, 1);
            let Some(Change::Sender(row)) = change else {
                panic!("expected a sender row for {from:?}");
            };
            assert_eq!(row.key, sender_key(&p, "someone@gmail.com"), "{from:?}");
        }
    }

    #[test]
    fn at_the_sender_cap_senders_are_not_recorded_and_still_answered() {
        let mut p = shipped();
        p.max_senders = 1;
        let mut user = User::default();
        assert!(user.check_mail(&p, &mail(), 1).1.is_some());
        let mut other = mail();
        other.from_addr = "someone@example.org".into();
        let (a, change) = user.check_mail(&p, &other, 2);
        assert_eq!(change, None);
        assert!(a.cues.contains(&Cue::SenderNeverSeen));
    }

    #[test]
    fn a_user_rebuilt_from_rows_remembers_logins_and_senders() {
        let p = shipped();
        let sender = SenderRow {
            key: "example.com".into(),
            first_ms: 1,
            first_msg: 7,
        };
        let login = LoginRow {
            domain: "amazon.com".into(),
            first_ms: 1,
            last_ms: 2,
            count: 3,
        };
        let mut user = User::new([login.clone()], [sender]).unwrap();
        assert_eq!(user.logins().collect::<Vec<_>>(), [&login]);
        let (a, change) = user.check_mail(&p, &mail(), 5);
        assert!(!a.cues.contains(&Cue::SenderNeverSeen));
        assert_eq!(change, None);

        let bad = LoginRow {
            domain: "www.amazon.com".into(),
            ..login
        };
        assert!(User::new([bad], []).is_err());
    }

    // Pages.

    #[test]
    fn a_page_at_a_hard_lookalike_is_danger() {
        let mut user = user_with(0, &["bankofamerica.com"]);
        let a = user.check_page(&shipped(), &page("www.bankofarnerica.com"), 1);
        assert_eq!(a.level, Danger);
        assert_eq!(a.domain, "bankofarnerica.com");
        assert_eq!(cues(&a), ["domain_lookalike_misspelling"]);
        assert_eq!(
            a.reasons[0].text,
            "bankofarnerica.com looks like bankofamerica.com, where you log in, but is a different \
             site."
        );
        assert_eq!(
            a.lookalikes,
            [LookalikeHit {
                cue: Cue::DomainLookalikeMisspelling,
                candidate: "bankofarnerica.com".into(),
                known: "bankofamerica.com".into(),
            }]
        );
    }

    #[test]
    fn a_soft_lookalike_page_falls_through_to_the_context_rule() {
        let mut user = user_with(0, &["amazon.com"]);
        let a = user.check_page(&shipped(), &page("amazongproducts.ru"), 1);
        assert_eq!(a.level, Clear);
    }

    #[test]
    fn the_context_rule_waits_for_the_warm_up_count() {
        let p = shipped();
        let below = p.warmup_logins - 1;
        let a = user_with(below, &[]).check_page(&p, &from_mail("signup.example.net", None), 1);
        assert_eq!((a.level, a.cues.len()), (Clear, 0));
        let a = user_with(p.warmup_logins, &[]).check_page(
            &p,
            &from_mail("signup.example.net", None),
            1,
        );
        assert_eq!(a.level, Caution);
        assert_eq!(cues(&a), ["page_from_mail_unknown_login"]);
        let a = user_with(p.warmup_logins, &[]).check_page(&p, &page("signup.example.net"), 1);
        assert_eq!(a.level, Clear);
    }

    #[test]
    fn context_with_a_flagged_mail_is_danger() {
        let p = shipped();
        let mut user = user_with(p.warmup_logins, &[]);
        let a = user.check_page(&p, &from_mail("signup.example.net", Some(Caution)), 1);
        assert_eq!(a.level, Danger);
        assert_eq!(
            cues(&a),
            ["page_from_mail_unknown_login", "page_from_flagged_mail"]
        );
        let shown: Vec<&str> = a.reasons.iter().map(|r| r.cue.as_str()).collect();
        assert_eq!(shown, cues(&a));
    }

    #[test]
    fn a_login_set_host_is_always_clear() {
        let p = shipped();
        let mut user = user_with(p.warmup_logins, &["example.net"]);
        let a = user.check_page(&p, &from_mail("login.example.net", Some(Danger)), 1);
        assert_eq!(
            (a.level, a.domain.as_str(), a.cues.len()),
            (Clear, "example.net", 0)
        );
    }

    #[test]
    fn a_lookalike_behind_a_wrapper_is_danger_and_both_hosts_count_as_from_mail() {
        let p = wrapping();
        let wrapped = |destination: &str| {
            let mut m = mail();
            m.links = vec![link(
                "Sign in",
                &format!("https://eu1.linkcheck.example/?url=https%3A%2F%2F{destination}%2F"),
            )];
            m
        };
        let (a, _) = user_with(0, &["amazon.com"]).check_mail(&p, &wrapped("amazan.com"), 0);
        assert_eq!(a.level, Danger);

        let mut user = user_with(p.warmup_logins, &[]);
        user.check_mail(&p, &wrapped("signin.example.org"), 0);
        for host in ["eu1.linkcheck.example", "signin.example.org"] {
            assert_eq!(user.check_page(&p, &page(host), 1).level, Caution, "{host}");
        }
    }

    #[test]
    fn links_in_a_checked_mail_mark_their_hosts_as_from_mail_for_30_minutes() {
        let mut p = shipped();
        let mut user = user_with(p.warmup_logins, &[]);
        let mut m = mail();
        m.links = vec![link("Sign in", "https://Click.Example.net./track?x=1")];
        user.check_mail(&p, &m, 0);

        let a = user.check_page(&p, &page("click.example.net"), 30 * MINUTE - 1);
        assert_eq!(a.level, Caution);
        let a = user.check_page(&p, &page("click.example.net"), 30 * MINUTE);
        assert_eq!(a.level, Clear);

        // The entry host routes too, and the map carries the mail's level.
        p.weights.insert(Cue::LinkTextHidesUrl, 1.0);
        user.check_mail(&p, &m, 40 * MINUTE);
        let mut landed = page("signin.example.org");
        landed.entry_host = Some("click.example.net".into());
        let a = user.check_page(&p, &landed, 41 * MINUTE);
        assert_eq!(a.level, Danger);
        assert_eq!(a.domain, "example.org");
    }

    // Logins.

    const HOUR: u64 = 60 * MINUTE;

    fn row(domain: &str, first_ms: u64, last_ms: u64, count: u32) -> LoginRow {
        LoginRow {
            domain: domain.into(),
            first_ms,
            last_ms,
            count,
        }
    }

    fn count_of(user: &User, domain: &str) -> Option<u32> {
        user.logins().find(|r| r.domain == domain).map(|r| r.count)
    }

    #[test]
    fn login_seen_records_then_refreshes() {
        let p = shipped();
        let mut user = User::default();
        let first = user.login_seen(&p, "www.example.com", 10, Strong).unwrap();
        assert_eq!(first, [Change::Login(row("example.com", 10, 10, 1))]);
        // Any evidence refreshes a known login.
        let again = user.login_seen(&p, "login.example.com", 20, Weak).unwrap();
        assert_eq!(again, [Change::Login(row("example.com", 10, 20, 2))]);
        assert_eq!(
            user.logins().collect::<Vec<_>>(),
            [&row("example.com", 10, 20, 2)]
        );
        assert!(user.login_seen(&p, "192.168.1.1", 30, Strong).is_err());
    }

    #[test]
    fn a_new_domain_is_known_on_strong_evidence_or_a_trust_and_pending_on_weak() {
        let p = shipped();
        for (evidence, count) in [(Weak, 0), (Strong, 1), (Trusted, 1)] {
            let mut user = User::default();
            let changes = user.login_seen(&p, "example.com", 10, evidence).unwrap();
            let expected = [Change::Login(row("example.com", 10, 10, count))];
            assert_eq!(changes, expected, "{evidence:?}");
        }
        assert_eq!(LoginEvidence::from(Evidence::Filled), Weak);
        assert_eq!(LoginEvidence::from(Evidence::Typed), Strong);
        assert_eq!(LoginEvidence::from(Evidence::Autofill), Strong);
    }

    #[test]
    fn weak_evidence_confirms_a_pending_login_only_after_the_confirmation_time() {
        let p = shipped();
        let confirm = p.weak_login_confirm_ms;
        assert_eq!(confirm, 12 * HOUR);
        let mut user = User::default();
        user.login_seen(&p, "example.com", 0, Weak).unwrap();
        let early = user
            .login_seen(&p, "example.com", confirm - 1, Weak)
            .unwrap();
        assert_eq!(
            early,
            [Change::Login(row("example.com", 0, confirm - 1, 0))]
        );
        let late = user.login_seen(&p, "example.com", confirm, Weak).unwrap();
        assert_eq!(late, [Change::Login(row("example.com", 0, confirm, 1))]);
    }

    #[test]
    fn strong_evidence_or_a_trust_confirms_a_pending_login_at_once() {
        let p = shipped();
        for evidence in [Strong, Trusted] {
            let mut user = User::default();
            user.login_seen(&p, "example.com", 0, Weak).unwrap();
            let changes = user
                .login_seen(&p, "example.com", MINUTE, evidence)
                .unwrap();
            let expected = [Change::Login(row("example.com", 0, MINUTE, 1))];
            assert_eq!(changes, expected, "{evidence:?}");
        }
    }

    #[test]
    fn a_pending_login_is_still_judged_and_is_no_lookalike_target() {
        let p = shipped();
        // Not exempt from the page rule.
        let mut user = user_with(p.warmup_logins, &[]);
        user.login_seen(&p, "example.net", 0, Weak).unwrap();
        let a = user.check_page(&p, &from_mail("example.net", None), 1);
        assert_eq!(a.level, Caution);
        // Not counted towards the warm-up.
        let mut user = user_with(p.warmup_logins - 1, &[]);
        user.login_seen(&p, "example.org", 0, Weak).unwrap();
        let a = user.check_page(&p, &from_mail("signup.example.net", None), 1);
        assert_eq!(a.level, Clear);
        // Still a candidate: a pending amazan.com is a lookalike of amazon.com once that is known.
        let mut user = User::default();
        user.login_seen(&p, "amazan.com", 0, Weak).unwrap();
        user.login_seen(&p, "amazon.com", 1, Strong).unwrap();
        assert_eq!(user.check_page(&p, &page("amazan.com"), 2).level, Danger);
        // No target: with amazon.com only pending, amazan.com resembles no known login.
        let mut user = User::default();
        user.login_seen(&p, "amazon.com", 0, Weak).unwrap();
        assert_eq!(user.check_page(&p, &page("amazan.com"), 1).level, Clear);
        let mut m = mail();
        m.from_addr = "orders@amazan.com".into();
        assert_eq!(user.check_mail(&p, &m, 2).0.level, Clear);
        assert!(user.login_seen(&p, "amazan.com", 3, Strong).is_ok());
    }

    #[test]
    fn creating_or_confirming_a_pending_login_meets_the_refusals_of_a_new_one() {
        let p = shipped();
        // A hard lookalike of a known login: refused at creation...
        let mut user = user_with(0, &["amazon.com"]);
        assert!(user.login_seen(&p, "amazan.com", 0, Weak).is_err());
        assert_eq!(count_of(&user, "amazan.com"), None);
        // ...and at confirmation, when the known login arrived after the pending one.
        let mut user = User::default();
        user.login_seen(&p, "amazan.com", 0, Weak).unwrap();
        user.login_seen(&p, "amazon.com", 1, Strong).unwrap();
        assert!(user.login_seen(&p, "amazan.com", 2, Strong).is_err());
        assert!(user.login_seen(&p, "amazan.com", 12 * HOUR, Weak).is_err());
        assert_eq!(count_of(&user, "amazan.com"), Some(0));
        assert!(user
            .login_seen(&p, "amazan.com", 13 * HOUR, Trusted)
            .is_ok());

        // A domain a page check just flagged: refused at creation...
        let mut user = user_with(p.warmup_logins, &[]);
        user.check_page(&p, &from_mail("signup.example.org", None), 0);
        assert!(user.login_seen(&p, "example.org", MINUTE, Weak).is_err());
        assert_eq!(count_of(&user, "example.org"), None);
        // ...and at confirmation.
        user.login_seen(&p, "example.net", 0, Weak).unwrap();
        user.check_page(&p, &from_mail("signup.example.net", None), MINUTE);
        assert!(user
            .login_seen(&p, "example.net", 2 * MINUTE, Strong)
            .is_err());
        assert_eq!(count_of(&user, "example.net"), Some(0));
        assert!(user
            .login_seen(&p, "example.net", 3 * MINUTE, Trusted)
            .is_ok());
        assert!(user
            .login_seen(&p, "example.org", 4 * MINUTE, Trusted)
            .is_ok());
    }

    #[test]
    fn pending_logins_survive_a_rebuild_as_pending() {
        let p = shipped();
        let warm = user_with(p.warmup_logins, &[]);
        let pending = row("example.net", 5, 6, 0);
        let rows = warm.logins().cloned().chain([pending.clone()]);
        let mut user = User::new(rows, []).unwrap();
        assert!(user.logins().any(|r| *r == pending));
        let a = user.check_page(&p, &from_mail("example.net", None), 7);
        assert_eq!(a.level, Caution);
    }

    #[test]
    fn at_the_cap_the_oldest_pending_login_makes_room_and_a_known_one_never_does() {
        let mut p = shipped();
        p.max_logins = 3;
        let mut user = user_with(0, &["example.com"]);
        user.login_seen(&p, "example.net", 10, Weak).unwrap();
        user.login_seen(&p, "example.org", 20, Weak).unwrap();
        let changes = user.login_seen(&p, "example.de", 30, Strong).unwrap();
        let expected = [
            Change::LoginRemoved("example.net".into()),
            Change::Login(row("example.de", 30, 30, 1)),
        ];
        assert_eq!(changes, expected);
        let changes = user.login_seen(&p, "example.fr", 40, Weak).unwrap();
        let expected = [
            Change::LoginRemoved("example.org".into()),
            Change::Login(row("example.fr", 40, 40, 0)),
        ];
        assert_eq!(changes, expected);
        let changes = user.login_seen(&p, "example.it", 50, Trusted).unwrap();
        assert_eq!(changes[0], Change::LoginRemoved("example.fr".into()));
        // No pending login is left: a new one is refused, and the known ones stay.
        assert!(user.login_seen(&p, "example.es", 60, Strong).is_err());
        assert!(user.login_seen(&p, "example.es", 60, Trusted).is_err());
        let domains: Vec<&str> = user.logins().map(|r| r.domain.as_str()).collect();
        assert_eq!(domains, ["example.com", "example.de", "example.it"]);
        // A known login is still refreshed at the cap.
        assert!(user.login_seen(&p, "example.com", 70, Weak).is_ok());
    }

    #[test]
    fn login_seen_refuses_a_lookalike_unless_trusted() {
        let p = shipped();
        let mut user = user_with(0, &["amazon.com"]);
        assert!(user.login_seen(&p, "amazan.com", 1, Strong).is_err());
        assert_eq!(user.logins().count(), 1);
        assert!(user.login_seen(&p, "amazan.com", 2, Trusted).is_ok());
        assert_eq!(user.logins().count(), 2);
    }

    #[test]
    fn login_seen_refuses_a_recently_flagged_host_unless_trusted() {
        let p = shipped();
        let mut user = user_with(p.warmup_logins, &[]);
        let flagged = user.check_page(&p, &from_mail("signup.example.net", None), 0);
        assert_eq!(flagged.level, Caution);
        assert!(user
            .login_seen(&p, "signup.example.net", MINUTE, Strong)
            .is_err());
        assert!(user
            .login_seen(&p, "example.net", 30 * MINUTE, Strong)
            .is_ok());

        let mut user = user_with(p.warmup_logins, &[]);
        user.check_page(&p, &from_mail("signup.example.net", None), 0);
        assert!(user
            .login_seen(&p, "signup.example.net", MINUTE, Trusted)
            .is_ok());
    }

    #[test]
    fn forget_drops_a_login() {
        let mut user = user_with(0, &["example.com"]);
        assert_eq!(
            user.forget("www.example.com"),
            Some(Change::LoginRemoved("example.com".into()))
        );
        assert_eq!(user.forget("example.com"), None);
        assert_eq!(user.logins().count(), 0);
    }

    #[test]
    fn message_fingerprints_differ_by_provider_and_id() {
        let a = message_fingerprint(Provider::Gmail, "m1");
        assert_eq!(a, message_fingerprint(Provider::Gmail, "m1"));
        assert_ne!(a, message_fingerprint(Provider::OutlookWeb, "m1"));
        assert_ne!(a, message_fingerprint(Provider::Gmail, "m2"));
    }

    #[test]
    fn the_recent_maps_drop_the_oldest_past_the_cap() {
        let mut map = BTreeMap::new();
        for i in 0..=RECENT_CAP as u64 {
            remember(&mut map, format!("h{i}.example.com"), Clear, i);
        }
        prune(&mut map, RECENT_CAP as u64);
        assert_eq!(map.len(), RECENT_CAP);
        assert!(!map.contains_key("h0.example.com"));
    }

    /// The heaviest mail `MailObservation::check_limits` admits, against a full login set. Run with
    /// `cargo test --release -p riggs-phishing worst_case -- --ignored --nocapture`; it prints
    /// timings and asserts none.
    #[test]
    #[ignore]
    fn worst_case_check_mail_timing() {
        use crate::domain::{MAX_HOST_BYTES, MAX_LABEL_BYTES};
        let p = shipped();
        // `first` followed by `n` written in base-26 letters, `len` characters in all.
        let word = |first: u8, mut n: usize, len: usize| {
            let mut s = String::from(first as char);
            for _ in 1..len {
                s.push((b'a' + (n % 26) as u8) as char);
                n /= 26;
            }
            s
        };
        let users = |label: &dyn Fn(usize) -> String| {
            let logins = (0..p.max_logins).map(|i| LoginRow {
                domain: format!("{}.com", label(i)),
                first_ms: 1,
                last_ms: 1,
                count: 1,
            });
            User::new(logins, []).unwrap()
        };
        // Dense: every login label is `len` characters starting with "a", like every candidate part,
        // the shortest length at which both typo guards let a part be compared, so every
        // comparison passes its cheap filters and runs the edit distance. Spread: first letters
        // a-z and lengths 4-12, so about one login in 26 * 9 / 3 is that close.
        let len = p.guards.typo_min_label.max(p.guards.typo_part_min_label);
        let dense = users(&|i| word(b'a', i, len));
        let spread = users(&|i| word(b'a' + (i % 26) as u8, i, 4 + (i / 26) % 9));
        // The longest hosts `name()` accepts, made of `len`-character parts: the registrable label
        // takes as many parts as a label holds, then subdomain labels go in front while the host
        // fits. Logins below 2,000 have "a" in the last two places; the offset puts other letters
        // there in every part, so no part is within one edit of a login and nothing fires to cut
        // a comparison short.
        let label_max = MAX_LABEL_BYTES;
        let offset = 26usize.pow(len as u32 - 3) + 26usize.pow(len as u32 - 2);
        let label = |from: usize, count: usize| {
            (from..from + count)
                .map(|n| word(b'a', n + offset, len))
                .collect::<Vec<_>>()
                .join("-")
        };
        let fits = |room: usize| ((room + 1) / (len + 1)).min((label_max + 1) / (len + 1));
        let host = |first: usize| {
            let count = fits(MAX_HOST_BYTES - ".com".len());
            let mut host = format!("{}.com", label(first, count));
            let mut next = first + count;
            loop {
                let count = fits(MAX_HOST_BYTES.saturating_sub(host.len() + 1));
                if count == 0 {
                    break host;
                }
                host = format!("{}.{host}", label(next, count));
                next += count;
            }
        };
        let mut m = mail();
        m.subject = "x".repeat(4096);
        m.body_text = "a.co ".repeat(65536 / 5);
        m.attachments = (0..100).map(|i| format!("file{i}.zip")).collect();
        m.links = (0..500)
            .map(|i| {
                let text = format!("https://{}/{}", host(i * 64), "x".repeat(3800));
                let href = format!("https://{}/?q={}", host(i * 64 + 32), "x".repeat(7900));
                link(&text, &href)
            })
            .collect();
        assert_eq!(m.check_limits(), Ok(()));
        let first = host(0);
        let longest_label = first.split('.').map(str::len).max().unwrap();
        println!(
            "hosts of {} bytes, longest label {longest_label}",
            first.len()
        );

        let start = std::time::Instant::now();
        crate::cues::link_only_body(&m);
        println!("link_only_body: {:?}", start.elapsed());
        for (shape, user) in [("dense", dense), ("spread", spread)] {
            let mut times = Vec::new();
            for _ in 0..5 {
                let mut fresh = user.clone();
                let start = std::time::Instant::now();
                let (a, _) = fresh.check_mail(&p, &m, 1);
                times.push(start.elapsed());
                assert_eq!(a.level, Clear);
                assert!(a.cues.contains(&Cue::ObservationTruncated));
            }
            times.sort();
            let known = user.known();
            let start = std::time::Instant::now();
            let candidates = crate::cues::lookalike_hosts(&m, &p);
            let checked = &candidates[..candidates.len().min(p.max_hosts)];
            let lookalikes = checked
                .iter()
                .filter(|c| lookalike(c, known.iter().copied(), &p.guards).is_some())
                .count();
            println!(
                "{shape} login set: check_mail min {:?}, median {:?}, max {:?}; lookalike pass \
                 {:?} over {} of {} candidates ({} fired)",
                times[0],
                times[2],
                times[4],
                start.elapsed(),
                checked.len(),
                candidates.len(),
                lookalikes,
            );
        }
    }
}
