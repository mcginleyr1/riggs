use std::collections::{BTreeMap, BTreeSet};

use riggs_types::phishing::MailObservation;
use url::{Host, Url};

use crate::domain::{name, Name};
use crate::lookalike::{lookalike, Lookalike};
use crate::policy::Policy;

/// Cue ids are those of `docs/PHISHING_CUES.md`. The declaration order is the order cues are
/// reported in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cue {
    // Hard: any one makes a mail or a page `danger`.
    DomainLookalikeMisspelling,
    DomainLookalikeEmbedded,
    // Page context rule; not weighted.
    PageFromMailUnknownLogin,
    PageFromFlaggedMail,
    // Soft, need history.
    DomainLookalikeBrandToken,
    DomainLookalikeSuffixSwap,
    BrandNameInFreemailSender,
    SenderNeverSeen,
    ReplyToUnsentMessage,
    AttachmentFromUnseenSender,
    // Soft, sender and structure.
    DisplayNameAddressMismatch,
    AuthorityRoleSenderName,
    LinkTextTargetMismatch,
    LinkTextHidesUrl,
    LinkOnlyBody,
    LinkTargetHighRiskFile,
    LinkWrapperUnreadable,
    AttachmentPresent,
    AttachmentHighRiskType,
    AttachmentTypeDiffersFromBodyMention,
    // Soft, phrase lists.
    Urgency,
    ThreatOfConsequence,
    RequestSensitiveInformation,
    RequestPayment,
    AccountProblemClaim,
    ClickOrOpenRequest,
    GenericGreeting,
    LegalBoilerplate,
    SecurityIndicatorText,
    TooGoodToBeTrueOffer,
    ExclusiveOfferForYou,
    LimitedTimeOffer,
    HumanitarianAppeal,
    MimicsBusinessProcess,
    CompromisingPictureLure,
    // Soft, engineering.
    ObservationTruncated,
}

const KNOWN: &str = "{known}";
const ANY_KNOWN: &str = "a site where you log in";
const MAX_REASON_CHARS: usize = 120;

impl Cue {
    pub const ALL: [Cue; 36] = [
        Cue::DomainLookalikeMisspelling,
        Cue::DomainLookalikeEmbedded,
        Cue::PageFromMailUnknownLogin,
        Cue::PageFromFlaggedMail,
        Cue::DomainLookalikeBrandToken,
        Cue::DomainLookalikeSuffixSwap,
        Cue::BrandNameInFreemailSender,
        Cue::SenderNeverSeen,
        Cue::ReplyToUnsentMessage,
        Cue::AttachmentFromUnseenSender,
        Cue::DisplayNameAddressMismatch,
        Cue::AuthorityRoleSenderName,
        Cue::LinkTextTargetMismatch,
        Cue::LinkTextHidesUrl,
        Cue::LinkOnlyBody,
        Cue::LinkTargetHighRiskFile,
        Cue::LinkWrapperUnreadable,
        Cue::AttachmentPresent,
        Cue::AttachmentHighRiskType,
        Cue::AttachmentTypeDiffersFromBodyMention,
        Cue::Urgency,
        Cue::ThreatOfConsequence,
        Cue::RequestSensitiveInformation,
        Cue::RequestPayment,
        Cue::AccountProblemClaim,
        Cue::ClickOrOpenRequest,
        Cue::GenericGreeting,
        Cue::LegalBoilerplate,
        Cue::SecurityIndicatorText,
        Cue::TooGoodToBeTrueOffer,
        Cue::ExclusiveOfferForYou,
        Cue::LimitedTimeOffer,
        Cue::HumanitarianAppeal,
        Cue::MimicsBusinessProcess,
        Cue::CompromisingPictureLure,
        Cue::ObservationTruncated,
    ];

    /// The one table of cue ids and banner reasons. `{known}` stands for the imitated known domain.
    fn row(self) -> (&'static str, &'static str) {
        match self {
            Cue::DomainLookalikeMisspelling => (
                "domain_lookalike_misspelling",
                "Looks like {known} but is a different site.",
            ),
            Cue::DomainLookalikeEmbedded => (
                "domain_lookalike_embedded",
                "Carries the address of {known} inside a different site's address.",
            ),
            Cue::PageFromMailUnknownLogin => (
                "page_from_mail_unknown_login",
                "You opened this page from mail and have not logged in here before.",
            ),
            Cue::PageFromFlaggedMail => (
                "page_from_flagged_mail",
                "The mail you opened this page from was flagged.",
            ),
            Cue::DomainLookalikeBrandToken => (
                "domain_lookalike_brand_token",
                "Uses the name of {known} in a different site's address.",
            ),
            Cue::DomainLookalikeSuffixSwap => (
                "domain_lookalike_suffix_swap",
                "Has the name of {known} under a different ending.",
            ),
            Cue::BrandNameInFreemailSender => (
                "brand_name_in_freemail_sender",
                "A free mail account named after {known} sent this.",
            ),
            Cue::SenderNeverSeen => (
                "sender_never_seen",
                "You have not had mail from this sender before.",
            ),
            Cue::ReplyToUnsentMessage => (
                "reply_to_unsent_message",
                "Looks like a reply, but you have not had mail from this sender before.",
            ),
            Cue::AttachmentFromUnseenSender => (
                "attachment_from_unseen_sender",
                "Has an attachment from a sender you have not had mail from before.",
            ),
            Cue::DisplayNameAddressMismatch => (
                "display_name_address_mismatch",
                "The sender's name does not match their address.",
            ),
            Cue::AuthorityRoleSenderName => (
                "authority_role_sender_name",
                "The sender presents as a role, such as HR or IT, not as a person.",
            ),
            Cue::LinkTextTargetMismatch => (
                "link_text_target_mismatch",
                "A link shows one site but goes to another.",
            ),
            Cue::LinkTextHidesUrl => (
                "link_text_hides_url",
                "A link's text does not show where it goes.",
            ),
            Cue::LinkOnlyBody => ("link_only_body", "The mail is nothing but links."),
            Cue::LinkTargetHighRiskFile => (
                "link_target_high_risk_file",
                "A link downloads a file that runs code when opened.",
            ),
            Cue::LinkWrapperUnreadable => (
                "link_wrapper_unreadable",
                "A link passes through a link checker, and where it leads could not be read.",
            ),
            Cue::AttachmentPresent => ("attachment_present", "Has an attachment."),
            Cue::AttachmentHighRiskType => (
                "attachment_high_risk_type",
                "Has an attachment that runs code when opened.",
            ),
            Cue::AttachmentTypeDiffersFromBodyMention => (
                "attachment_type_differs_from_body_mention",
                "The mail names one file type but attaches another.",
            ),
            Cue::Urgency => ("urgency", "Pushes you to act at once."),
            Cue::ThreatOfConsequence => (
                "threat_of_consequence",
                "Threatens consequences if you do not act.",
            ),
            Cue::RequestSensitiveInformation => (
                "request_sensitive_information",
                "Asks for passwords or personal or financial details.",
            ),
            Cue::RequestPayment => (
                "request_payment",
                "Asks for a payment or a change of payment details.",
            ),
            Cue::AccountProblemClaim => (
                "account_problem_claim",
                "Claims a problem with your account, order or payment.",
            ),
            Cue::ClickOrOpenRequest => (
                "click_or_open_request",
                "Asks you to click a link or open a file.",
            ),
            Cue::GenericGreeting => ("generic_greeting", "Greets you without your name."),
            Cue::LegalBoilerplate => ("legal_boilerplate", "Carries legal or disclaimer wording."),
            Cue::SecurityIndicatorText => (
                "security_indicator_text",
                "Claims to be signed, verified or secure.",
            ),
            Cue::TooGoodToBeTrueOffer => (
                "too_good_to_be_true_offer",
                "Offers a prize, refund or something free.",
            ),
            Cue::ExclusiveOfferForYou => (
                "exclusive_offer_for_you",
                "Offers something special just for you.",
            ),
            Cue::LimitedTimeOffer => ("limited_time_offer", "Puts a deadline on an offer."),
            Cue::HumanitarianAppeal => (
                "humanitarian_appeal",
                "Appeals to your wish to help someone.",
            ),
            Cue::MimicsBusinessProcess => (
                "mimics_business_process",
                "Looks like a routine notice, such as an invoice, order or delivery.",
            ),
            Cue::CompromisingPictureLure => (
                "compromising_picture_lure",
                "Invites you to look at a compromising picture.",
            ),
            Cue::ObservationTruncated => (
                "observation_truncated",
                "The mail was too large to check in full.",
            ),
        }
    }

    pub fn id(self) -> &'static str {
        self.row().0
    }

    pub fn from_id(id: &str) -> Option<Cue> {
        Cue::ALL.into_iter().find(|cue| cue.id() == id)
    }

    pub fn is_hard(self) -> bool {
        matches!(
            self,
            Cue::DomainLookalikeMisspelling | Cue::DomainLookalikeEmbedded
        )
    }

    pub fn is_page(self) -> bool {
        matches!(
            self,
            Cue::PageFromMailUnknownLogin | Cue::PageFromFlaggedMail
        )
    }

    /// Weighted mail cues: every cue that is neither hard nor a page rule.
    pub fn is_soft(self) -> bool {
        !self.is_hard() && !self.is_page()
    }

    /// Cues decided by a phrase list in the policy.
    pub fn is_phrase(self) -> bool {
        matches!(
            self,
            Cue::AuthorityRoleSenderName
                | Cue::Urgency
                | Cue::ThreatOfConsequence
                | Cue::RequestSensitiveInformation
                | Cue::RequestPayment
                | Cue::AccountProblemClaim
                | Cue::ClickOrOpenRequest
                | Cue::GenericGreeting
                | Cue::LegalBoilerplate
                | Cue::SecurityIndicatorText
                | Cue::TooGoodToBeTrueOffer
                | Cue::ExclusiveOfferForYou
                | Cue::LimitedTimeOffer
                | Cue::HumanitarianAppeal
                | Cue::MimicsBusinessProcess
                | Cue::CompromisingPictureLure
        )
    }

    /// Banner text, at most 120 characters. Names `known` when it fits.
    pub fn reason(self, known: Option<&str>) -> String {
        let template = self.row().1;
        known
            .map(|k| template.replace(KNOWN, &format!("{k}, where you log in,")))
            .filter(|text| text.chars().count() <= MAX_REASON_CHARS)
            .unwrap_or_else(|| template.replace(KNOWN, ANY_KNOWN))
    }

    /// Banner text for a lookalike cue that names the candidate too, at most 120 characters;
    /// [`Cue::reason`] with the known domain alone when it does not fit. The lookalike templates
    /// open with a capitalized verb, which follows the candidate in lower case.
    pub fn lookalike_reason(self, candidate: &str, known: &str) -> String {
        let template = self.row().1;
        let text = format!(
            "{candidate} {}{}",
            template[..1].to_lowercase(),
            &template[1..]
        )
        .replace(KNOWN, &format!("{known}, where you log in,"));
        if text.chars().count() <= MAX_REASON_CHARS {
            text
        } else {
            self.reason(Some(known))
        }
    }
}

impl From<Lookalike> for Cue {
    fn from(rule: Lookalike) -> Cue {
        match rule {
            Lookalike::Misspelling => Cue::DomainLookalikeMisspelling,
            Lookalike::Embedded => Cue::DomainLookalikeEmbedded,
            Lookalike::SuffixSwap => Cue::DomainLookalikeSuffixSwap,
            Lookalike::BrandToken => Cue::DomainLookalikeBrandToken,
        }
    }
}

/// A fired lookalike cue and the two registrable domains behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookalikeHit {
    pub cue: Cue,
    /// The host that fired it: the sender's domain, a link's target, a link's text, or a page.
    pub candidate: String,
    /// The login-set domain it resembles.
    pub known: String,
}

/// Every mail cue the mail fires, in cue order, each with the known domain it names when it names
/// one. `known` is the user's login set; `never_seen` says whether the sender counts as never seen.
pub fn mail_cues(
    mail: &MailObservation,
    policy: &Policy,
    known: &[&Name],
    never_seen: bool,
) -> BTreeMap<Cue, Option<String>> {
    mail_cues_and_lookalikes(mail, policy, known, never_seen).0
}

/// [`mail_cues`], plus one [`LookalikeHit`] per fired lookalike cue, in cue order: the first
/// candidate host that fired it.
pub fn mail_cues_and_lookalikes(
    mail: &MailObservation,
    policy: &Policy,
    known: &[&Name],
    never_seen: bool,
) -> (BTreeMap<Cue, Option<String>>, Vec<LookalikeHit>) {
    let from = sender_address(&mail.from_addr);
    evaluate(mail, &from, policy, known, never_seen)
}

/// The sender's address as every check reads it: trimmed, lowercased, without a trailing dot.
pub(crate) fn sender_address(from_addr: &str) -> String {
    let addr = from_addr.trim().to_lowercase();
    match addr.strip_suffix('.') {
        Some(addr) => addr.to_string(),
        None => addr,
    }
}

/// [`mail_cues_and_lookalikes`] with the sender's address already through [`sender_address`].
pub(crate) fn evaluate(
    mail: &MailObservation,
    from: &str,
    policy: &Policy,
    known: &[&Name],
    never_seen: bool,
) -> (BTreeMap<Cue, Option<String>>, Vec<LookalikeHit>) {
    let targets: Vec<(Option<Url>, bool)> = mail
        .links
        .iter()
        .map(|l| link_target(&l.href, policy))
        .collect();
    let candidates = mail_names(from, mail, &targets);
    let capped = candidates.len() > policy.max_hosts;
    let mut hits = BTreeMap::new();
    for candidate in candidates.iter().take(policy.max_hosts) {
        if let Some((k, rule)) = lookalike(candidate, known.iter().copied(), &policy.guards) {
            let cue = Cue::from(rule);
            hits.entry(cue).or_insert_with(|| LookalikeHit {
                cue,
                candidate: candidate.registrable.clone(),
                known: k.registrable.clone(),
            });
        }
    }
    let mut fired: BTreeMap<Cue, Option<String>> = hits
        .values()
        .map(|hit| (hit.cue, Some(hit.known.clone())))
        .collect();
    if let Some(k) = brand_name_in_freemail_sender(from, policy, known) {
        fired.insert(Cue::BrandNameInFreemailSender, Some(k));
    }

    let lines: Vec<&str> = mail
        .body_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let subject = normalize(&mail.subject);
    let body = normalize(&mail.body_text);
    let opening = normalize(&lines[..lines.len().min(3)].join("\n"));
    let closing = normalize(&lines[lines.len().saturating_sub(5)..].join("\n"));
    let from_name = normalize(&mail.from_name);
    for cue in Cue::ALL.into_iter().filter(|c| c.is_phrase()) {
        let fields = match cue {
            Cue::GenericGreeting => vec![&opening],
            Cue::AuthorityRoleSenderName => vec![&from_name, &closing],
            Cue::SecurityIndicatorText => vec![&body],
            _ => vec![&subject, &body],
        };
        let hit = policy.phrases[&cue]
            .iter()
            .any(|phrase| fields.iter().any(|field| contains_phrase(field, phrase)));
        if hit {
            fired.insert(cue, None);
        }
    }

    let attached = !mail.attachments.is_empty();
    let structural = [
        (Cue::SenderNeverSeen, never_seen),
        (
            Cue::ReplyToUnsentMessage,
            never_seen && is_reply(&mail.subject),
        ),
        (Cue::AttachmentFromUnseenSender, never_seen && attached),
        (
            Cue::DisplayNameAddressMismatch,
            display_name_address_mismatch(mail, from),
        ),
        (
            Cue::LinkTextTargetMismatch,
            link_text_target_mismatch(mail, &targets),
        ),
        (
            Cue::LinkTextHidesUrl,
            mail.links.iter().any(|l| text_host(&l.text).is_none()),
        ),
        (Cue::LinkOnlyBody, link_only_body(mail)),
        (
            Cue::LinkTargetHighRiskFile,
            link_target_high_risk_file(&targets, policy),
        ),
        (
            Cue::LinkWrapperUnreadable,
            targets.iter().any(|(_, unreadable)| *unreadable),
        ),
        (Cue::AttachmentPresent, attached),
        (
            Cue::AttachmentHighRiskType,
            mail.attachments
                .iter()
                .map(String::as_str)
                .filter_map(extension)
                .any(|e| policy.high_risk.contains(&e)),
        ),
        (
            Cue::AttachmentTypeDiffersFromBodyMention,
            attachment_type_differs_from_body_mention(mail, policy),
        ),
        (Cue::ObservationTruncated, mail.truncated || capped),
    ];
    for (cue, on) in structural {
        if on {
            fired.insert(cue, None);
        }
    }
    (fired, hits.into_values().collect())
}

/// Where a link leads. For a redirector's link it is the `http` or `https` URL, with a host, in the
/// redirector's query parameter (form-decoded); otherwise the href itself. The flag marks a
/// redirector's link whose destination cannot be read, which is then judged by its href. One
/// level is unwrapped: a destination that is itself a redirector's link stays as it is.
pub(crate) fn link_target(href: &str, policy: &Policy) -> (Option<Url>, bool) {
    let Ok(url) = Url::parse(href.trim()) else {
        return (None, false);
    };
    let Some(param) = policy.redirector_param(&url) else {
        return (Some(url), false);
    };
    let destination = url
        .query_pairs()
        .find(|(key, _)| key == param)
        .and_then(|(_, value)| Url::parse(&value).ok())
        .filter(|d| matches!(d.scheme(), "http" | "https") && d.host().is_some());
    match destination {
        Some(destination) => (Some(destination), false),
        None => (Some(url), true),
    }
}

/// The hosts this mail's lookalike rules would check, in order, before the `max_hosts` cap.
pub fn lookalike_hosts(mail: &MailObservation, policy: &Policy) -> Vec<Name> {
    let targets: Vec<(Option<Url>, bool)> = mail
        .links
        .iter()
        .map(|l| link_target(&l.href, policy))
        .collect();
    mail_names(&sender_address(&mail.from_addr), mail, &targets)
}

/// Every host name a lookalike rule checks, once each: the sender's domain, then each link's
/// target and the domain its text names, in link order. `targets` are the links' [`link_target`]s.
fn mail_names(from: &str, mail: &MailObservation, targets: &[(Option<Url>, bool)]) -> Vec<Name> {
    let sender = from.rsplit_once('@').map(|(_, d)| d.to_owned());
    let links = mail
        .links
        .iter()
        .zip(targets)
        .flat_map(|(l, (target, _))| {
            let target = target.as_ref().and_then(Url::host).map(|h| h.to_owned());
            [target, text_host(&l.text)]
        })
        .filter_map(|host| match host {
            Some(Host::Domain(d)) => Some(d),
            _ => None,
        });
    let mut seen = BTreeSet::new();
    sender
        .into_iter()
        .chain(links)
        .filter_map(|host| name(&host))
        .filter(|n| seen.insert(n.host.clone()))
        .collect()
}

fn href_host(href: &str) -> Option<Host> {
    Url::parse(href.trim()).ok()?.host().map(|h| h.to_owned())
}

/// The host a link's visible text names, when the text is a URL or a bare host name. Bare text
/// counts as a domain only under a known public suffix, so "Click.This" stays words.
fn text_host(text: &str) -> Option<Host> {
    let text = text.trim();
    if text.is_empty() || text.contains(char::is_whitespace) {
        return None;
    }
    if text.contains("://") {
        return href_host(text);
    }
    let host = href_host(&format!("http://{text}"))?;
    match &host {
        Host::Domain(d) => psl::domain(d.as_bytes())
            .is_some_and(|d| d.suffix().is_known())
            .then_some(host),
        _ => Some(host),
    }
}

/// What two hosts are compared by: the registrable domain, or the host itself when it has none.
fn site(host: &Host) -> String {
    match host {
        Host::Domain(d) => name(d).map_or_else(|| d.clone(), |n| n.registrable),
        ip => ip.to_string(),
    }
}

fn link_text_target_mismatch(mail: &MailObservation, targets: &[(Option<Url>, bool)]) -> bool {
    mail.links.iter().zip(targets).any(|(l, (target, _))| {
        let target = target.as_ref().and_then(Url::host).map(|h| h.to_owned());
        matches!(
            (text_host(&l.text), target),
            (Some(text), Some(target)) if site(&text) != site(&target)
        )
    })
}

/// Nothing is left of the body once link texts, link targets and URL or domain words are removed.
pub(crate) fn link_only_body(mail: &MailObservation) -> bool {
    let mut rest = mail.body_text.clone();
    for link in &mail.links {
        for s in [link.text.trim(), link.href.trim()] {
            if !s.is_empty() && rest.contains(s) {
                rest = rest.replace(s, " ");
            }
        }
    }
    !mail.links.is_empty()
        && rest
            .split_whitespace()
            .all(|w| text_host(w).is_some() || !w.chars().any(char::is_alphanumeric))
}

fn link_target_high_risk_file(targets: &[(Option<Url>, bool)], policy: &Policy) -> bool {
    targets
        .iter()
        .filter_map(|(target, _)| target.as_ref())
        .filter_map(|url| url.path_segments()?.next_back().and_then(extension))
        .any(|e| policy.high_risk.contains(&e))
}

/// The last extension of a file name, lowercased, with its dot.
fn extension(file: &str) -> Option<String> {
    file.rsplit_once('.')
        .map(|(_, e)| format!(".{}", e.to_lowercase()))
}

fn attachment_type_differs_from_body_mention(mail: &MailObservation, policy: &Policy) -> bool {
    let attached: Vec<String> = mail
        .attachments
        .iter()
        .map(String::as_str)
        .filter_map(extension)
        .collect();
    let body = mail.body_text.to_lowercase();
    // An extension is named when it is followed by a non-alphanumeric or the end.
    let names = |e: &str| {
        body.match_indices(e)
            .any(|(i, _)| !body[i + e.len()..].starts_with(char::is_alphanumeric))
    };
    !mail.attachments.is_empty()
        && policy
            .body_mention
            .iter()
            .any(|e| !attached.contains(e) && names(e))
}

fn display_name_address_mismatch(mail: &MailObservation, from: &str) -> bool {
    let name_words = words(&mail.from_name);
    let from_domain = from
        .rsplit_once('@')
        .and_then(|(_, d)| name(d))
        .map(|n| n.registrable);
    let names_other_domain = mail
        .from_name
        .split_whitespace()
        .filter_map(|t| text_host(t.trim_matches(|c: char| !c.is_alphanumeric())))
        .filter_map(|host| match host {
            Host::Domain(d) => name(&d),
            _ => None,
        })
        .any(|n| Some(n.registrable) != from_domain);
    // Related when a display-name word of 3 or more characters occurs anywhere in the address, or
    // an address word of 3 or more characters occurs anywhere in the display name, ignoring case:
    // "John Smith" and jsmith@ are related through "smith". The address's public suffix is left
    // out, or "com" would relate "Commerce Dept" to every .com address; a domain without a
    // registrable name keeps all its words.
    let display = mail.from_name.to_lowercase();
    let long = |w: &&String| w.chars().count() >= 3;
    let related = |addr: &str| {
        let addr = sender_address(addr);
        let addr = match addr.rsplit_once('@').map(|(local, d)| (local, name(d))) {
            Some((local, Some(n))) => {
                let rest = n.host.strip_suffix(&n.suffix).unwrap_or(&n.host);
                format!("{local}@{}", rest.trim_end_matches('.'))
            }
            _ => addr,
        };
        name_words
            .iter()
            .filter(long)
            .any(|w| addr.contains(w.as_str()))
            || words(&addr)
                .iter()
                .filter(long)
                .any(|w| display.contains(w.as_str()))
    };
    let reply_to = mail.reply_to.as_deref().filter(|r| !r.trim().is_empty());
    !name_words.is_empty()
        && (names_other_domain || !related(from) || reply_to.is_some_and(|r| !related(r)))
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn brand_name_in_freemail_sender(from: &str, policy: &Policy, known: &[&Name]) -> Option<String> {
    let (local, domain) = from.rsplit_once('@')?;
    if !policy.is_freemail(domain) {
        return None;
    }
    known
        .iter()
        .find(|k| {
            k.unicode.chars().count() >= policy.guards.brand_token_min_label
                && local.contains(k.label.as_str())
        })
        .map(|k| k.registrable.clone())
}

/// RFC 5322 section 3.6.5: a reply's subject starts with "Re: ". Case is not significant here.
fn is_reply(subject: &str) -> bool {
    subject
        .trim_start()
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("re: "))
}

/// Lowercased, typographic quotes made ASCII, and every run of whitespace made one space.
pub(crate) fn normalize(text: &str) -> String {
    text.to_lowercase()
        // U+2018..U+201B single and U+201C..U+201F double quotation marks.
        .replace(['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'], "'")
        .replace(['\u{201C}', '\u{201D}', '\u{201E}', '\u{201F}'], "\"")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `phrase` occurs in `text` (both normalized) without a letter or digit glued to either end.
fn contains_phrase(text: &str, phrase: &str) -> bool {
    let glued = |outside: Option<char>, edge: Option<char>| {
        outside.is_some_and(char::is_alphanumeric) && edge.is_some_and(char::is_alphanumeric)
    };
    let mut from = 0;
    while let Some(i) = text[from..].find(phrase).map(|i| from + i) {
        let end = i + phrase.len();
        if !glued(text[..i].chars().next_back(), phrase.chars().next())
            && !glued(text[end..].chars().next(), phrase.chars().next_back())
        {
            return true;
        }
        from = i + text[i..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use riggs_types::phishing::{Link, Provider};

    pub(crate) fn shipped() -> Policy {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/phishing-policy.toml");
        Policy::from_toml(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    pub(crate) fn mail() -> MailObservation {
        MailObservation {
            provider: Provider::Gmail,
            message_id: "m1".into(),
            from_name: String::new(),
            from_addr: "sender@example.com".into(),
            reply_to: None,
            to: vec![],
            subject: String::new(),
            body_text: String::new(),
            links: vec![],
            attachments: vec![],
            truncated: false,
        }
    }

    pub(crate) fn link(text: &str, href: &str) -> Link {
        Link {
            text: text.into(),
            href: href.into(),
        }
    }

    /// The shipped policy plus a constructed redirector under the reserved `.example` name.
    pub(crate) fn wrapping() -> Policy {
        let mut p = shipped();
        p.redirectors = vec![crate::policy::Redirector {
            suffix: "linkcheck.example".into(),
            param: "url".into(),
        }];
        p
    }

    fn fires(cue: Cue, mail: &MailObservation, known: &[&str], never_seen: bool) -> bool {
        fires_with(&shipped(), cue, mail, known, never_seen)
    }

    fn fires_with(
        policy: &Policy,
        cue: Cue,
        mail: &MailObservation,
        known: &[&str],
        never_seen: bool,
    ) -> bool {
        let names: Vec<Name> = known.iter().map(|k| name(k).unwrap()).collect();
        let known: Vec<&Name> = names.iter().collect();
        mail_cues(mail, policy, &known, never_seen).contains_key(&cue)
    }

    fn with(edit: impl FnOnce(&mut MailObservation)) -> MailObservation {
        let mut m = mail();
        edit(&mut m);
        m
    }

    #[test]
    fn the_table_covers_every_cue_once_and_matches_the_lookalike_strength() {
        let ids: BTreeSet<&str> = Cue::ALL.iter().map(|c| c.id()).collect();
        assert_eq!(ids.len(), Cue::ALL.len());
        assert!(Cue::ALL.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(Cue::ALL.iter().filter(|c| c.is_soft()).count(), 32);
        assert_eq!(Cue::ALL.iter().filter(|c| c.is_phrase()).count(), 16);
        for rule in [
            Lookalike::Misspelling,
            Lookalike::Embedded,
            Lookalike::SuffixSwap,
            Lookalike::BrandToken,
        ] {
            assert_eq!(Cue::from(rule).is_hard(), rule.is_hard());
        }
    }

    #[test]
    fn reasons_fit_120_characters_and_name_a_short_known_domain() {
        let long = format!("{}.com", "a".repeat(240));
        for cue in Cue::ALL {
            for known in [None, Some("paypal.com"), Some(long.as_str())] {
                let text = cue.reason(known);
                assert!(text.chars().count() <= 120, "{}: {text}", cue.id());
                assert!(!text.contains('{'), "{}: {text}", cue.id());
            }
        }
        assert_eq!(
            Cue::DomainLookalikeMisspelling.reason(Some("paypal.com")),
            "Looks like paypal.com, where you log in, but is a different site."
        );
        assert_eq!(
            Cue::DomainLookalikeMisspelling.reason(None),
            "Looks like a site where you log in but is a different site."
        );
    }

    #[test]
    fn lookalike_reasons_name_the_candidate_when_it_fits() {
        assert_eq!(
            Cue::DomainLookalikeMisspelling.lookalike_reason("micorsoft-support.com", "microsoft.com"),
            "micorsoft-support.com looks like microsoft.com, where you log in, but is a different site."
        );
        let long = format!("{}.com", "a".repeat(60));
        for cue in Cue::ALL
            .into_iter()
            .filter(|c| c.id().starts_with("domain_lookalike_"))
        {
            for (candidate, known) in [
                ("nist.com", "nist.gov"),
                (long.as_str(), "nist.gov"),
                (long.as_str(), long.as_str()),
            ] {
                let text = cue.lookalike_reason(candidate, known);
                assert!(text.chars().count() <= 120, "{}: {text}", cue.id());
                assert!(!text.contains('{'), "{}: {text}", cue.id());
            }
            // Too long with the candidate: the known domain alone, as `reason` gives it.
            assert_eq!(
                cue.lookalike_reason(&long, "nist.gov"),
                cue.reason(Some("nist.gov"))
            );
        }
    }

    #[test]
    fn phrases_match_case_insensitively_on_collapsed_whitespace_at_word_boundaries() {
        assert!(contains_phrase(
            &normalize("Please\n  CLICK   here"),
            "please click here"
        ));
        assert!(contains_phrase("get it free!", "free"));
        assert!(!contains_phrase("freedom", "free"));
        assert!(!contains_phrase("carefree", "free"));
        assert!(contains_phrase("carefree free", "free"));
        assert!(contains_phrase("dear user,x", "dear user,"));
        assert!(contains_phrase("x-a-a", "a-a"));
    }

    #[test]
    fn typographic_quotes_fold_to_ascii() {
        assert_eq!(
            normalize("\u{2018}a\u{2019} \u{201A}b\u{201B} \u{201C}c\u{201D} \u{201E}d\u{201F}"),
            "'a' 'b' \"c\" \"d\""
        );
        // CISA-ASE indicator 2's seed "Sir/Ma'am", written with a typographic apostrophe.
        let m = with(|m| m.body_text = "Dear Sir/Ma\u{2019}am,".into());
        assert!(fires(Cue::GenericGreeting, &m, &[], false));
    }

    // Hard lookalikes on each mail field. Examples from PHISHING_CUES.md section 4.

    #[test]
    fn a_misspelled_sender_domain_is_a_hard_cue() {
        let m = with(|m| m.from_addr = "orders@amazan.com".into());
        assert!(fires(
            Cue::DomainLookalikeMisspelling,
            &m,
            &["amazon.com"],
            false
        ));
        let m = with(|m| m.from_addr = "orders@amazon.com".into());
        assert!(!fires(
            Cue::DomainLookalikeMisspelling,
            &m,
            &["amazon.com"],
            false
        ));
    }

    #[test]
    fn an_embedding_link_target_is_a_hard_cue() {
        let m = with(|m| m.links = vec![link("Sign in", "https://google.com.rogueserver.biz/")]);
        assert!(fires(
            Cue::DomainLookalikeEmbedded,
            &m,
            &["google.com"],
            false
        ));
        assert!(!fires(Cue::DomainLookalikeEmbedded, &m, &[], false));
    }

    #[test]
    fn a_misspelled_domain_in_link_text_is_a_hard_cue() {
        let m = with(|m| m.links = vec![link("www.bankofarnerica.com", "https://example.com/")]);
        assert!(fires(
            Cue::DomainLookalikeMisspelling,
            &m,
            &["bankofamerica.com"],
            false
        ));
        let m = with(|m| m.links = vec![link("www.bankofamerica.com", "https://example.com/")]);
        assert!(!fires(
            Cue::DomainLookalikeMisspelling,
            &m,
            &["bankofamerica.com"],
            false
        ));
    }

    #[test]
    fn soft_lookalikes_name_the_known_domain() {
        let m = with(|m| m.links = vec![link("Shop", "https://amazongproducts.ru/")]);
        let known = name("amazon.com").unwrap();
        let fired = mail_cues(&m, &shipped(), &[&known], false);
        assert_eq!(
            fired.get(&Cue::DomainLookalikeBrandToken),
            Some(&Some("amazon.com".to_string()))
        );
        let m = with(|m| m.from_addr = "news@www.nist.com".into());
        assert!(fires(
            Cue::DomainLookalikeSuffixSwap,
            &m,
            &["nist.gov"],
            false
        ));
        assert!(!fires(
            Cue::DomainLookalikeSuffixSwap,
            &m,
            &["nist.com"],
            false
        ));
    }

    // History cues.

    #[test]
    fn brand_name_in_freemail_sender() {
        // KB4-blog, "Number One Most Suspicious Sign".
        let m = with(|m| m.from_addr = "microsoftustechsupport@outlook.com".into());
        assert!(fires(
            Cue::BrandNameInFreemailSender,
            &m,
            &["microsoft.com"],
            false
        ));
        let m = with(|m| m.from_addr = "microsoftustechsupport@example.com".into());
        assert!(!fires(
            Cue::BrandNameInFreemailSender,
            &m,
            &["microsoft.com"],
            false
        ));
        let m = with(|m| m.from_addr = "someone@outlook.com".into());
        assert!(!fires(
            Cue::BrandNameInFreemailSender,
            &m,
            &["microsoft.com"],
            false
        ));
    }

    #[test]
    fn never_seen_cues() {
        let m = mail();
        assert!(fires(Cue::SenderNeverSeen, &m, &[], true));
        assert!(!fires(Cue::SenderNeverSeen, &m, &[], false));

        let reply = with(|m| m.subject = "Re: invoice".into());
        assert!(fires(Cue::ReplyToUnsentMessage, &reply, &[], true));
        assert!(!fires(Cue::ReplyToUnsentMessage, &reply, &[], false));
        let regarding = with(|m| m.subject = "Regarding invoice".into());
        assert!(!fires(Cue::ReplyToUnsentMessage, &regarding, &[], true));

        let attached = with(|m| m.attachments = vec!["file.pdf".into()]);
        assert!(fires(Cue::AttachmentFromUnseenSender, &attached, &[], true));
        assert!(!fires(
            Cue::AttachmentFromUnseenSender,
            &attached,
            &[],
            false
        ));
        assert!(!fires(Cue::AttachmentFromUnseenSender, &m, &[], true));
    }

    // Sender and structure.

    #[test]
    fn display_name_address_mismatch() {
        // NIST B.2.2: display name "IT Helpdesk", reply-to accounts-payable@gmail.com.
        let m = with(|m| {
            m.from_name = "IT Helpdesk".into();
            m.from_addr = "helpdesk@example.com".into();
            m.reply_to = Some("accounts-payable@gmail.com".into());
        });
        assert!(fires(Cue::DisplayNameAddressMismatch, &m, &[], false));
        let m = with(|m| {
            m.from_name = "service@example.org".into();
            m.from_addr = "service@example.com".into();
        });
        assert!(fires(Cue::DisplayNameAddressMismatch, &m, &[], false));
        let m = with(|m| {
            m.from_name = "Example Support".into();
            m.from_addr = "support@example.com".into();
        });
        assert!(!fires(Cue::DisplayNameAddressMismatch, &m, &[], false));
        assert!(!fires(Cue::DisplayNameAddressMismatch, &mail(), &[], false));

        // Containment, not whole words: the abbreviation misfire measurement 2H found.
        let john = |addr: &str| {
            with(|m| {
                m.from_name = "John Smith".into();
                m.from_addr = addr.into();
            })
        };
        assert!(!fires(
            Cue::DisplayNameAddressMismatch,
            &john("jsmith@example.com"),
            &[],
            false
        ));
        assert!(!fires(
            Cue::DisplayNameAddressMismatch,
            &john("smith.j@example.com"),
            &[],
            false
        ));
        assert!(fires(
            Cue::DisplayNameAddressMismatch,
            &john("accounts-payable@example.com"),
            &[],
            false
        ));
        // Address words reach into the display name too, and words under 3 characters do not count.
        let m = with(|m| {
            m.from_name = "Contoso Billing Team".into();
            m.from_addr = "billing@example.net".into();
        });
        assert!(!fires(Cue::DisplayNameAddressMismatch, &m, &[], false));
        let m = with(|m| {
            m.from_name = "Al Bo".into();
            m.from_addr = "albo.x@example.org".into();
        });
        assert!(fires(Cue::DisplayNameAddressMismatch, &m, &[], false));

        // The public suffix is no word, in either direction.
        let unrelated = |from_name: &str, from_addr: &str| {
            let m = with(|m| {
                m.from_name = from_name.into();
                m.from_addr = from_addr.into();
            });
            fires(Cue::DisplayNameAddressMismatch, &m, &[], false)
        };
        assert!(unrelated("Commerce Dept", "billing@example.com"));
        assert!(unrelated("Net Solutions", "billing@example.net"));
        assert!(unrelated("Org Admin", "billing@example.org"));
        assert!(!unrelated("Example Commerce", "billing@example.com"));
        // A domain without a registrable name keeps all its words.
        assert!(!unrelated("Localhost Admin", "root@localhost"));
    }

    #[test]
    fn authority_role_sender_name_reads_the_display_name_and_the_last_five_lines() {
        let m = with(|m| m.from_name = "Human Resources".into());
        assert!(fires(Cue::AuthorityRoleSenderName, &m, &[], false));
        let m = with(|m| m.body_text = "Hello\n\nPlease reply.\n\nThanks,\nYour CEO".into());
        assert!(fires(Cue::AuthorityRoleSenderName, &m, &[], false));
        let m = with(|m| m.body_text = "IT Helpdesk\n1\n2\n3\n4\n5".into());
        assert!(!fires(Cue::AuthorityRoleSenderName, &m, &[], false));
        let m = with(|m| m.subject = "System Administrator".into());
        assert!(!fires(Cue::AuthorityRoleSenderName, &m, &[], false));
    }

    #[test]
    fn link_text_target_mismatch() {
        // NIST section 2.1.3: text www.niist.gov, target commerce.gov.
        let m = with(|m| m.links = vec![link("www.niist.gov", "http://commerce.gov/")]);
        assert!(fires(Cue::LinkTextTargetMismatch, &m, &[], false));
        let m = with(|m| m.links = vec![link("www.nist.gov", "https://www.nist.gov/x")]);
        assert!(!fires(Cue::LinkTextTargetMismatch, &m, &[], false));
    }

    #[test]
    fn link_text_hides_url() {
        // NIST B.2.3: text "Department of Defense", target www.nist.gov.
        let m = with(|m| m.links = vec![link("Department of Defense", "https://www.nist.gov/")]);
        assert!(fires(Cue::LinkTextHidesUrl, &m, &[], false));
        // ".this" is not on the public suffix list (".here" is, so "Click.Here" reads as a domain).
        let m = with(|m| m.links = vec![link("Click.This", "https://www.nist.gov/")]);
        assert!(fires(Cue::LinkTextHidesUrl, &m, &[], false));
        let m = with(|m| m.links = vec![link("www.nist.gov", "https://www.nist.gov/")]);
        assert!(!fires(Cue::LinkTextHidesUrl, &m, &[], false));
    }

    #[test]
    fn link_only_body() {
        let url = "https://example.com/a";
        let m = with(|m| {
            m.body_text = format!("{url}\n\n");
            m.links = vec![link(url, url)];
        });
        assert!(fires(Cue::LinkOnlyBody, &m, &[], false));
        let m = with(|m| {
            m.body_text = format!("See {url}");
            m.links = vec![link(url, url)];
        });
        assert!(!fires(Cue::LinkOnlyBody, &m, &[], false));
        let m = with(|m| m.body_text = url.into());
        assert!(!fires(Cue::LinkOnlyBody, &m, &[], false));
    }

    #[test]
    fn link_target_high_risk_file() {
        let m = with(|m| m.links = vec![link("Get it", "https://example.com/setup.EXE")]);
        assert!(fires(Cue::LinkTargetHighRiskFile, &m, &[], false));
        for href in [
            "https://example.com/setup.exe.html",
            "https://example.com/a?file=setup.exe",
        ] {
            let m = with(|m| m.links = vec![link("Get it", href)]);
            assert!(
                !fires(Cue::LinkTargetHighRiskFile, &m, &[], false),
                "{href}"
            );
        }
    }

    #[test]
    fn attachment_cues() {
        let m = with(|m| m.attachments = vec!["notes.txt".into()]);
        assert!(fires(Cue::AttachmentPresent, &m, &[], false));
        assert!(!fires(Cue::AttachmentPresent, &mail(), &[], false));

        // CISA-GUIDE p. 7.
        let m = with(|m| m.attachments = vec!["photo.SCR".into()]);
        assert!(fires(Cue::AttachmentHighRiskType, &m, &[], false));
        let m = with(|m| m.attachments = vec!["photo.zip".into()]);
        assert!(!fires(Cue::AttachmentHighRiskType, &m, &[], false));
    }

    #[test]
    fn attachment_type_differs_from_body_mention() {
        // NIST Appendix B Figure 1: the body says .doc, the attached file is .zip.
        let differs = with(|m| {
            m.body_text = "Open file.doc today".into();
            m.attachments = vec!["file.zip".into()];
        });
        assert!(fires(
            Cue::AttachmentTypeDiffersFromBodyMention,
            &differs,
            &[],
            false
        ));
        let same = with(|m| {
            m.body_text = "Open file.doc today".into();
            m.attachments = vec!["file.doc".into()];
        });
        assert!(!fires(
            Cue::AttachmentTypeDiffersFromBodyMention,
            &same,
            &[],
            false
        ));
        let longer = with(|m| {
            m.body_text = "Open file.docx today".into();
            m.attachments = vec!["file.zip".into()];
        });
        assert!(!fires(
            Cue::AttachmentTypeDiffersFromBodyMention,
            &longer,
            &[],
            false
        ));
        let none = with(|m| m.body_text = "Open file.doc today".into());
        assert!(!fires(
            Cue::AttachmentTypeDiffersFromBodyMention,
            &none,
            &[],
            false
        ));
    }

    #[test]
    fn observation_truncated() {
        let m = with(|m| m.truncated = true);
        assert!(fires(Cue::ObservationTruncated, &m, &[], false));
        assert!(!fires(Cue::ObservationTruncated, &mail(), &[], false));
    }

    // Phrase cues: each seed below is from PHISHING_CUES.md section 4; the misses are the same
    // words glued to a letter, or the phrase in a field the cue does not read.

    #[test]
    fn phrase_cues_in_subject_or_body() {
        let cases = [
            (Cue::Urgency, "URGENT", "insurgent"),
            (
                Cue::ThreatOfConsequence,
                "It will be permanently locked.",
                "permanently lockedout",
            ),
            (
                Cue::RequestSensitiveInformation,
                "Send your Social Security Number",
                "social security numbers",
            ),
            (
                Cue::RequestPayment,
                "please make a payment",
                "make a payments",
            ),
            (
                Cue::AccountProblemClaim,
                "There is a problem with your recent order.",
                "a problem with your recent order",
            ),
            (
                Cue::ClickOrOpenRequest,
                "Please click here",
                "please click hereafter",
            ),
            (
                Cue::LegalBoilerplate,
                "Do not reply to this email.",
                "do not reply to this email",
            ),
            (Cue::TooGoodToBeTrueOffer, "Enter the lottery", "lottery2"),
            (
                Cue::ExclusiveOfferForYou,
                "a special birthday coupon",
                "a special birthday coupons",
            ),
            (
                Cue::LimitedTimeOffer,
                "Offer expires in 14 days",
                "offer expires in 14 daysx",
            ),
            (
                Cue::HumanitarianAppeal,
                "donate your gift certificate to a family in need",
                "a family in needs",
            ),
            (
                Cue::MimicsBusinessProcess,
                "Unpaid invoice",
                "unpaid invoices",
            ),
        ];
        for (cue, hit, miss) in cases {
            let in_subject = with(|m| m.subject = hit.into());
            let in_body = with(|m| m.body_text = hit.into());
            let missed = with(|m| m.body_text = miss.into());
            assert!(fires(cue, &in_subject, &[], false), "{}", cue.id());
            assert!(fires(cue, &in_body, &[], false), "{}", cue.id());
            assert!(!fires(cue, &missed, &[], false), "{}", cue.id());
        }
    }

    #[test]
    fn security_indicator_text_reads_the_body_only() {
        let m = with(|m| m.body_text = "This message was digitally signed.".into());
        assert!(fires(Cue::SecurityIndicatorText, &m, &[], false));
        let m = with(|m| m.subject = "digitally signed".into());
        assert!(!fires(Cue::SecurityIndicatorText, &m, &[], false));
    }

    #[test]
    fn generic_greeting_reads_the_first_three_non_empty_lines() {
        let m = with(|m| m.body_text = "\n\nDear Valued Customer,\nYour order.".into());
        assert!(fires(Cue::GenericGreeting, &m, &[], false));
        let m = with(|m| m.body_text = "1\n2\n3\nDear user,".into());
        assert!(!fires(Cue::GenericGreeting, &m, &[], false));
        let m = with(|m| m.subject = "Dear user,".into());
        assert!(!fires(Cue::GenericGreeting, &m, &[], false));
    }

    #[test]
    fn lookalike_hosts_lists_the_sender_then_each_link_target_and_text_once() {
        let m = with(|m| {
            m.links = vec![
                link("www.example.net", "https://a.example.org/"),
                link(
                    "Open",
                    "https://eu1.linkcheck.example/?url=https%3A%2F%2Fb.example.org%2F",
                ),
                link("Open", "https://A.example.org/again"),
                link("Open", "not a url"),
            ]
        });
        let hosts = |p: &Policy| -> Vec<String> {
            lookalike_hosts(&m, p).into_iter().map(|n| n.host).collect()
        };
        assert_eq!(
            hosts(&wrapping()),
            [
                "example.com",
                "a.example.org",
                "www.example.net",
                "b.example.org"
            ]
        );
        assert_eq!(
            hosts(&shipped()),
            [
                "example.com",
                "a.example.org",
                "www.example.net",
                "eu1.linkcheck.example"
            ]
        );
    }

    #[test]
    fn the_host_cap_checks_the_sender_then_the_first_links() {
        let mut p = shipped();
        p.max_hosts = 3;
        let known = &["amazon.com"];
        let links = |hosts: &[&str]| {
            with(|m| {
                m.links = hosts
                    .iter()
                    .map(|h| link("Open", &format!("https://{h}/")))
                    .collect()
            })
        };
        let lookalike =
            |m: &MailObservation| fires_with(&p, Cue::DomainLookalikeMisspelling, m, known, false);
        let truncated =
            |m: &MailObservation| fires_with(&p, Cue::ObservationTruncated, m, &[], false);

        // The sender's example.com is candidate 1, which leaves room for two link hosts.
        let inside = links(&["a.example.org", "amazan.com", "c.example.org"]);
        assert!(lookalike(&inside));
        assert!(truncated(&inside));
        let beyond = links(&["a.example.org", "b.example.org", "amazan.com"]);
        assert!(!lookalike(&beyond));
        assert!(truncated(&beyond));

        let mut sender = links(&["a.example.org", "b.example.org", "c.example.org"]);
        sender.from_addr = "orders@amazan.com".into();
        assert!(lookalike(&sender), "the sender is never dropped");
        assert!(truncated(&sender));

        let at_cap = links(&["a.example.org", "amazan.com"]);
        assert!(lookalike(&at_cap));
        assert!(!truncated(&at_cap));

        let repeated = links(&[
            "a.example.org",
            "A.Example.org",
            "a.example.org.",
            "amazan.com",
        ]);
        assert!(lookalike(&repeated));
        assert!(!truncated(&repeated));
    }

    // Link unwrapping. Every URL here is constructed; `linkcheck.example` is a made-up redirector.

    #[test]
    fn a_wrapped_link_is_judged_by_its_destination() {
        let p = wrapping();
        let lookalike = with(|m| {
            m.links = vec![link(
                "Sign in",
                "https://eu1.linkcheck.example/?url=https%3A%2F%2Famazan.com%2Flogin&data=x",
            )]
        });
        assert!(fires_with(
            &p,
            Cue::DomainLookalikeMisspelling,
            &lookalike,
            &["amazon.com"],
            false
        ));
        assert!(!fires(
            Cue::DomainLookalikeMisspelling,
            &lookalike,
            &["amazon.com"],
            false
        ));

        let honest = with(|m| {
            m.links = vec![link(
                "www.example.com",
                "https://eu1.linkcheck.example/?data=x&url=https%3A%2F%2Fwww.example.com%2Fa",
            )]
        });
        assert!(!fires_with(
            &p,
            Cue::LinkTextTargetMismatch,
            &honest,
            &[],
            false
        ));
        assert!(fires(Cue::LinkTextTargetMismatch, &honest, &[], false));
        assert!(!fires_with(
            &p,
            Cue::LinkWrapperUnreadable,
            &honest,
            &[],
            false
        ));

        let download = with(|m| {
            m.links = vec![link(
                "Get it",
                "https://eu1.linkcheck.example/?url=https%3A%2F%2Fexample.com%2Fsetup.exe",
            )]
        });
        assert!(fires_with(
            &p,
            Cue::LinkTargetHighRiskFile,
            &download,
            &[],
            false
        ));
    }

    #[test]
    fn an_unreadable_wrapper_fires_its_cue_and_is_judged_as_it_stands() {
        let p = wrapping();
        for href in [
            "https://eu1.linkcheck.example/?data=x",
            "https://eu1.linkcheck.example/?url=not%20a%20url",
            "https://eu1.linkcheck.example/?url=ftp%3A%2F%2Fexample.com%2Ff",
            "https://eu1.linkcheck.example/?url=",
        ] {
            let m = with(|m| m.links = vec![link("www.example.com", href)]);
            assert!(
                fires_with(&p, Cue::LinkWrapperUnreadable, &m, &[], false),
                "{href}"
            );
            assert!(
                fires_with(&p, Cue::LinkTextTargetMismatch, &m, &[], false),
                "{href}"
            );
            assert!(!fires(Cue::LinkWrapperUnreadable, &m, &[], false), "{href}");
        }
    }

    #[test]
    fn only_the_suffix_and_its_subdomains_are_wrappers() {
        let p = wrapping();
        let destination = "?url=https%3A%2F%2Fexample.org%2F";
        for host in [
            "linkcheck.example",
            "a.b.linkcheck.example",
            "eu1.linkcheck.example.",
        ] {
            let (target, unreadable) = link_target(&format!("https://{host}/{destination}"), &p);
            assert_eq!(target.unwrap().host_str(), Some("example.org"), "{host}");
            assert!(!unreadable);
        }
        let (target, unreadable) =
            link_target(&format!("https://evillinkcheck.example/{destination}"), &p);
        assert_eq!(target.unwrap().host_str(), Some("evillinkcheck.example"));
        assert!(!unreadable);
    }

    #[test]
    fn nested_wrapping_is_unwrapped_once() {
        let p = wrapping();
        let href = "https://eu1.linkcheck.example/?url=https%3A%2F%2Feu2.linkcheck.example%2F%3Furl%3Dhttps%253A%252F%252Famazan.com%252F";
        let (target, unreadable) = link_target(href, &p);
        let target = target.unwrap();
        assert_eq!(target.host_str(), Some("eu2.linkcheck.example"));
        assert_eq!(target.query(), Some("url=https%3A%2F%2Famazan.com%2F"));
        assert!(!unreadable);
        let m = with(|m| m.links = vec![link("Sign in", href)]);
        assert!(!fires_with(
            &p,
            Cue::DomainLookalikeMisspelling,
            &m,
            &["amazon.com"],
            false
        ));
    }

    #[test]
    fn compromising_picture_lure_ships_empty_and_fires_once_a_phrase_is_added() {
        let m = with(|m| m.body_text = "constructed test phrase".into());
        assert!(!fires(Cue::CompromisingPictureLure, &m, &[], false));
        let mut policy = shipped();
        policy.phrases.insert(
            Cue::CompromisingPictureLure,
            vec!["constructed test phrase".into()],
        );
        assert!(fires_with(
            &policy,
            Cue::CompromisingPictureLure,
            &m,
            &[],
            false
        ));
    }
}
