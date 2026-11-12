use std::collections::BTreeMap;

use riggs_types::phishing::{Level, MailObservation, PageObservation, Provider, Reason};
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::cues::{mail_cues, Cue};
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
    pub count: u32,
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
    /// One banner reason per fired cue, in the same order as `cues`.
    pub reasons: Vec<Reason>,
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

    /// In domain order.
    pub fn logins(&self) -> impl Iterator<Item = &LoginRow> {
        self.logins.values().map(|(row, _)| row)
    }

    fn known(&self) -> Vec<&Name> {
        self.logins.values().map(|(_, n)| n).collect()
    }

    /// Checks an opened mail. Re-opening the first mail seen from a sender gives the verdict it
    /// got the first time.
    pub fn check_mail(
        &mut self,
        policy: &Policy,
        mail: &MailObservation,
        now_ms: u64,
    ) -> (Assessment, Option<Change>) {
        let key = sender_key(policy, &mail.from_addr);
        let msg = message_fingerprint(mail.provider, &mail.message_id);
        let never_seen = self
            .senders
            .get(&key)
            .is_none_or(|row| row.first_msg == msg);
        let fired = mail_cues(mail, policy, &self.known(), never_seen);
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
        let domain = mail
            .from_addr
            .rsplit_once('@')
            .and_then(|(_, d)| name(d))
            .map_or_else(String::new, |n| n.registrable);

        let hosts = mail.links.iter().filter_map(|l| {
            let url = Url::parse(l.href.trim()).ok()?;
            host_key(url.host_str()?)
        });
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
        (assessment(level, fired, score, domain), change)
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
        if self.logins.contains_key(&domain) {
            return assessment(Level::None, BTreeMap::new(), 0.0, domain);
        }
        let mut fired = BTreeMap::new();
        let hard = name
            .as_ref()
            .and_then(|n| lookalike(n, self.known(), &policy.guards))
            .filter(|(_, rule)| rule.is_hard());
        let level = if let Some((k, rule)) = hard {
            fired.insert(Cue::from(rule), Some(k.registrable.clone()));
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
            if !from_mail || self.logins.len() < policy.warmup_logins {
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
        assessment(level, fired, 0.0, domain)
    }

    /// Records or refreshes a login. Refuses, recording nothing, a hard lookalike of a login-set
    /// domain or a domain a page check flagged in the last 30 minutes (both skipped when
    /// `trusted`), and a new domain once the login cap is reached.
    pub fn login_seen(
        &mut self,
        policy: &Policy,
        host: &str,
        now_ms: u64,
        trusted: bool,
    ) -> Result<Change, String> {
        let name = name(host).ok_or("not a registrable domain")?;
        if let Some((row, _)) = self.logins.get_mut(&name.registrable) {
            row.last_ms = now_ms;
            row.count = row.count.saturating_add(1);
            return Ok(Change::Login(row.clone()));
        }
        if !trusted {
            let hard = lookalike(&name, self.known(), &policy.guards).filter(|(_, r)| r.is_hard());
            if let Some((k, _)) = hard {
                return Err(format!("looks like {}, a login domain", k.registrable));
            }
            if recent(&self.flagged, &name.registrable, now_ms).is_some() {
                return Err("a page check flagged it in the last 30 minutes".into());
            }
        }
        if self.logins.len() >= policy.max_logins {
            return Err("the login cap is reached".into());
        }
        let row = LoginRow {
            domain: name.registrable.clone(),
            first_ms: now_ms,
            last_ms: now_ms,
            count: 1,
        };
        self.logins
            .insert(name.registrable.clone(), (row.clone(), name));
        Ok(Change::Login(row))
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

/// The registrable domain of the address, or a hex SHA-256 of the lowercased address when the
/// domain is free mail or has no registrable domain.
fn sender_key(policy: &Policy, from_addr: &str) -> String {
    let addr = from_addr.trim().to_lowercase();
    addr.rsplit_once('@')
        .map(|(_, d)| d)
        .filter(|d| !policy.is_freemail(d))
        .and_then(name)
        .map_or_else(
            || {
                Sha256::digest(addr.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            },
            |n| n.registrable,
        )
}

fn assessment(
    level: Level,
    fired: BTreeMap<Cue, Option<String>>,
    score: f32,
    domain: String,
) -> Assessment {
    let reasons = fired
        .iter()
        .map(|(cue, known)| Reason {
            cue: cue.id().into(),
            text: cue.reason(known.as_deref()),
        })
        .collect();
    Assessment {
        level,
        cues: fired.into_keys().collect(),
        score,
        domain,
        reasons,
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
    use crate::cues::tests::{link, mail, shipped};
    use riggs_types::phishing::Level::{Caution, Danger, None as Clear};

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
        assert_eq!(
            a.reasons[0].text,
            "Looks like amazon.com, where you log in, but is a different site."
        );
        assert_eq!(a.reasons.len(), a.cues.len());
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
        assert!(a.reasons[0].text.contains("bankofamerica.com"));
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

    #[test]
    fn login_seen_records_then_refreshes() {
        let p = shipped();
        let mut user = User::default();
        let first = user.login_seen(&p, "www.example.com", 10, false).unwrap();
        let expected = LoginRow {
            domain: "example.com".into(),
            first_ms: 10,
            last_ms: 10,
            count: 1,
        };
        assert_eq!(first, Change::Login(expected.clone()));
        let again = user.login_seen(&p, "login.example.com", 20, false).unwrap();
        let refreshed = LoginRow {
            last_ms: 20,
            count: 2,
            ..expected
        };
        assert_eq!(again, Change::Login(refreshed.clone()));
        assert_eq!(user.logins().collect::<Vec<_>>(), [&refreshed]);
        assert!(user.login_seen(&p, "192.168.1.1", 30, false).is_err());
    }

    #[test]
    fn login_seen_refuses_a_lookalike_unless_trusted() {
        let p = shipped();
        let mut user = user_with(0, &["amazon.com"]);
        assert!(user.login_seen(&p, "amazan.com", 1, false).is_err());
        assert_eq!(user.logins().count(), 1);
        assert!(user.login_seen(&p, "amazan.com", 2, true).is_ok());
        assert_eq!(user.logins().count(), 2);
    }

    #[test]
    fn login_seen_refuses_a_recently_flagged_host_unless_trusted() {
        let p = shipped();
        let mut user = user_with(p.warmup_logins, &[]);
        let flagged = user.check_page(&p, &from_mail("signup.example.net", None), 0);
        assert_eq!(flagged.level, Caution);
        assert!(user
            .login_seen(&p, "signup.example.net", MINUTE, false)
            .is_err());
        assert!(user
            .login_seen(&p, "example.net", 30 * MINUTE, false)
            .is_ok());

        let mut user = user_with(p.warmup_logins, &[]);
        user.check_page(&p, &from_mail("signup.example.net", None), 0);
        assert!(user
            .login_seen(&p, "signup.example.net", MINUTE, true)
            .is_ok());
    }

    #[test]
    fn login_seen_refuses_a_new_domain_at_the_cap() {
        let mut p = shipped();
        p.max_logins = 1;
        let mut user = user_with(0, &["example.com"]);
        assert!(user.login_seen(&p, "example.org", 1, true).is_err());
        assert!(user.login_seen(&p, "example.com", 1, false).is_ok());
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
}
