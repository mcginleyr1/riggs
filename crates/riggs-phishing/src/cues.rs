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
    pub const ALL: [Cue; 35] = [
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

/// Every mail cue the mail fires, in cue order, each with the known domain it names when it names
/// one. `known` is the user's login set; `never_seen` says whether the sender counts as never seen.
pub fn mail_cues(
    mail: &MailObservation,
    policy: &Policy,
    known: &[&Name],
    never_seen: bool,
) -> BTreeMap<Cue, Option<String>> {
    let mut fired = BTreeMap::new();
    for candidate in mail_names(mail) {
        if let Some((k, rule)) = lookalike(&candidate, known.iter().copied(), &policy.guards) {
            fired
                .entry(Cue::from(rule))
                .or_insert_with(|| Some(k.registrable.clone()));
        }
    }
    if let Some(k) = brand_name_in_freemail_sender(mail, policy, known) {
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
            display_name_address_mismatch(mail),
        ),
        (Cue::LinkTextTargetMismatch, link_text_target_mismatch(mail)),
        (
            Cue::LinkTextHidesUrl,
            mail.links.iter().any(|l| text_host(&l.text).is_none()),
        ),
        (Cue::LinkOnlyBody, link_only_body(mail)),
        (
            Cue::LinkTargetHighRiskFile,
            link_target_high_risk_file(mail, policy),
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
        (Cue::ObservationTruncated, mail.truncated),
    ];
    for (cue, on) in structural {
        if on {
            fired.insert(cue, None);
        }
    }
    fired
}

/// Every host name a lookalike rule checks, once each: the sender's domain, then each link's
/// target and the domain its text names, in link order.
fn mail_names(mail: &MailObservation) -> Vec<Name> {
    let sender = mail.from_addr.rsplit_once('@').map(|(_, d)| d.to_owned());
    let links = mail
        .links
        .iter()
        .flat_map(|l| [href_host(&l.href), text_host(&l.text)])
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

fn link_text_target_mismatch(mail: &MailObservation) -> bool {
    mail.links.iter().any(|l| {
        matches!(
            (text_host(&l.text), href_host(&l.href)),
            (Some(text), Some(target)) if site(&text) != site(&target)
        )
    })
}

/// Nothing is left of the body once link texts, link targets and URL or domain words are removed.
fn link_only_body(mail: &MailObservation) -> bool {
    let mut rest = mail.body_text.clone();
    for link in &mail.links {
        for s in [link.text.trim(), link.href.trim()] {
            if !s.is_empty() {
                rest = rest.replace(s, " ");
            }
        }
    }
    !mail.links.is_empty()
        && rest
            .split_whitespace()
            .all(|w| text_host(w).is_some() || !w.chars().any(char::is_alphanumeric))
}

fn link_target_high_risk_file(mail: &MailObservation, policy: &Policy) -> bool {
    mail.links
        .iter()
        .filter_map(|l| Url::parse(l.href.trim()).ok())
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

fn display_name_address_mismatch(mail: &MailObservation) -> bool {
    let name_words = words(&mail.from_name);
    let from_domain = mail
        .from_addr
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
    let shares_word = |addr: &str| {
        let addr_words = words(addr);
        name_words.iter().any(|w| addr_words.contains(w))
    };
    let reply_to = mail.reply_to.as_deref().filter(|r| !r.trim().is_empty());
    !name_words.is_empty()
        && (names_other_domain
            || !shares_word(&mail.from_addr)
            || reply_to.is_some_and(|r| !shares_word(r)))
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn brand_name_in_freemail_sender(
    mail: &MailObservation,
    policy: &Policy,
    known: &[&Name],
) -> Option<String> {
    let addr = mail.from_addr.trim().to_lowercase();
    let (local, domain) = addr.rsplit_once('@')?;
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

/// Lowercased, with every run of whitespace made one space.
pub(crate) fn normalize(text: &str) -> String {
    text.to_lowercase()
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
        assert_eq!(Cue::ALL.iter().filter(|c| c.is_soft()).count(), 31);
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
            (Cue::TooGoodToBeTrueOffer, "FREE", "freedom"),
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
