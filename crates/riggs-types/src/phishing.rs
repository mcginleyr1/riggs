//! Wire types between phishing sensors (browser extension, mail add-in) and the daemon.
//!
//! Observation structs accept unknown fields: sensors and daemon are updated independently.

use serde::{Deserialize, Serialize};

const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HREF_BYTES: usize = 8 * 1024;
const MAX_STRING_BYTES: usize = 4 * 1024;
const MAX_LINKS: usize = 500;
const MAX_ATTACHMENTS: usize = 100;
const MAX_RECIPIENTS: usize = 500;
const MAX_HOST_BYTES: usize = 255;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PhishingRequest {
    // Sensors. Any local user may send these; the daemon keys them by the socket peer's uid.
    CheckMail(Box<MailObservation>),
    CheckPage(PageObservation),
    LoginSeen(LoginObservation),
    Status,
    // Admin. Daemon owner only; `uid` names the user whose state is meant.
    SetMode { mode: Mode },
    Trust { uid: u32, domain: String },
    Forget { uid: u32, domain: String },
    Logins { uid: u32 },
    Recent { uid: u32, limit: u32 },
    Stats { uid: u32 },
}

impl PhishingRequest {
    pub fn is_admin(&self) -> bool {
        match self {
            Self::CheckMail(_) | Self::CheckPage(_) | Self::LoginSeen(_) | Self::Status => false,
            Self::SetMode { .. }
            | Self::Trust { .. }
            | Self::Forget { .. }
            | Self::Logins { .. }
            | Self::Recent { .. }
            | Self::Stats { .. } => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Gmail,
    OutlookWeb,
    OutlookAddin,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    None,
    Caution,
    Danger,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Off,
    Monitor,
    Warn,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    Typed,
    Autofill,
    Filled,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Mail,
    Page,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MailObservation {
    pub provider: Provider,
    /// The provider's id for the message; used only to dedupe.
    pub message_id: String,
    pub from_name: String,
    pub from_addr: String,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    pub subject: String,
    pub body_text: String,
    #[serde(default)]
    pub links: Vec<Link>,
    /// File names.
    #[serde(default)]
    pub attachments: Vec<String>,
    /// Set by the sensor when it cut a string, cut a list or dropped entries to fit its size budget.
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub text: String,
    pub href: String,
}

impl MailObservation {
    /// The daemon's own cap on what a sensor may send; it does not trust the sender's.
    /// Lengths are UTF-8 bytes. The error names the field, never its content.
    pub fn check_limits(&self) -> Result<(), String> {
        let counts = [
            ("to", self.to.len(), MAX_RECIPIENTS),
            ("links", self.links.len(), MAX_LINKS),
            ("attachments", self.attachments.len(), MAX_ATTACHMENTS),
        ];
        let fields = [
            ("message_id", self.message_id.len(), MAX_STRING_BYTES),
            ("from_name", self.from_name.len(), MAX_STRING_BYTES),
            ("from_addr", self.from_addr.len(), MAX_STRING_BYTES),
            (
                "reply_to",
                self.reply_to.as_ref().map_or(0, String::len),
                MAX_STRING_BYTES,
            ),
            ("subject", self.subject.len(), MAX_STRING_BYTES),
            ("body_text", self.body_text.len(), MAX_BODY_BYTES),
        ];
        let recipients = self
            .to
            .iter()
            .map(|to| ("to[]", to.len(), MAX_STRING_BYTES));
        let links = self.links.iter().flat_map(|link| {
            [
                ("links[].text", link.text.len(), MAX_STRING_BYTES),
                ("links[].href", link.href.len(), MAX_HREF_BYTES),
            ]
        });
        let attachments = self
            .attachments
            .iter()
            .map(|name| ("attachments[]", name.len(), MAX_STRING_BYTES));
        first_over_limit(
            counts
                .into_iter()
                .chain(fields)
                .chain(recipients)
                .chain(links)
                .chain(attachments),
        )
    }
}

/// Each check is `(field, length, limit)`. The error names the field, never its content.
fn first_over_limit(
    checks: impl IntoIterator<Item = (&'static str, usize, usize)>,
) -> Result<(), String> {
    match checks.into_iter().find(|(_, len, max)| len > max) {
        Some((field, len, max)) => Err(format!("{field} exceeds its limit ({len} > {max})")),
        None => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PageObservation {
    /// Set by the extension's worker from the browser's record of the tab, never by the page.
    pub host: String,
    /// First host this tab navigated to.
    #[serde(default)]
    pub entry_host: Option<String>,
    #[serde(default)]
    pub opened_from_mail: bool,
    /// Verdict level of the mail this tab was opened from.
    #[serde(default)]
    pub mail_level: Option<Level>,
}

impl PageObservation {
    /// The daemon's own cap: a host longer than a DNS name can be is refused.
    pub fn check_limits(&self) -> Result<(), String> {
        first_over_limit([
            ("host", self.host.len(), MAX_HOST_BYTES),
            (
                "entry_host",
                self.entry_host.as_ref().map_or(0, String::len),
                MAX_HOST_BYTES,
            ),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginObservation {
    pub host: String,
    pub evidence: Evidence,
}

impl LoginObservation {
    /// The daemon's own cap: a host longer than a DNS name can be is refused.
    pub fn check_limits(&self) -> Result<(), String> {
        first_over_limit([("host", self.host.len(), MAX_HOST_BYTES)])
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PhishingResponse {
    Verdict(PhishingVerdict),
    Status(PhishingStatus),
    Logins(Vec<LoginEntry>),
    Recent(Vec<VerdictEntry>),
    Stats(PhishingStats),
    Ok,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhishingVerdict {
    pub level: Level,
    pub reasons: Vec<Reason>,
    pub show: bool,
}

/// `cue` is a cue id; ids are plain strings so the cue list can change without a wire change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub cue: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhishingStatus {
    pub mode: Mode,
    pub logins: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginEntry {
    pub domain: String,
    pub first_ms: u64,
    pub last_ms: u64,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictEntry {
    pub time_ms: u64,
    pub kind: ObservationKind,
    pub domain: String,
    pub cues: Vec<String>,
    pub score: f32,
    pub level: Level,
    pub shown: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhishingStats {
    pub total: u32,
    pub caution: u32,
    pub danger: u32,
    pub cues: Vec<CueCount>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CueCount {
    pub cue: String,
    pub hits: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tags_are_snake_case() {
        let tags = [
            (json!(Provider::Gmail), "gmail"),
            (json!(Provider::OutlookWeb), "outlook_web"),
            (json!(Provider::OutlookAddin), "outlook_addin"),
            (json!(Level::None), "none"),
            (json!(Level::Caution), "caution"),
            (json!(Level::Danger), "danger"),
            (json!(Mode::Off), "off"),
            (json!(Mode::Monitor), "monitor"),
            (json!(Mode::Warn), "warn"),
            (json!(Evidence::Typed), "typed"),
            (json!(Evidence::Autofill), "autofill"),
            (json!(Evidence::Filled), "filled"),
            (json!(ObservationKind::Mail), "mail"),
            (json!(ObservationKind::Page), "page"),
        ];
        for (value, tag) in tags {
            assert_eq!(value, json!(tag));
        }
    }

    #[test]
    fn check_mail_with_only_required_fields_defaults_the_rest_and_ignores_unknown_ones() {
        let request: PhishingRequest = serde_json::from_value(json!({"CheckMail": {
            "provider": "gmail",
            "message_id": "m1",
            "from_name": "",
            "from_addr": "sender@example.com",
            "subject": "",
            "body_text": "",
            "field_from_a_newer_sensor": 1,
        }}))
        .unwrap();
        let expected = MailObservation {
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
        };
        assert_eq!(request, PhishingRequest::CheckMail(Box::new(expected)));
    }

    #[test]
    fn check_mail_carries_the_truncated_flag() {
        let request: PhishingRequest = serde_json::from_value(json!({"CheckMail": {
            "provider": "gmail",
            "message_id": "m1",
            "from_name": "",
            "from_addr": "sender@example.com",
            "subject": "",
            "body_text": "",
            "truncated": true,
        }}))
        .unwrap();
        assert!(matches!(request, PhishingRequest::CheckMail(mail) if mail.truncated));
    }

    #[test]
    fn check_page_with_only_host_defaults_the_rest() {
        let request: PhishingRequest =
            serde_json::from_value(json!({"CheckPage": {"host": "example.com"}})).unwrap();
        let expected = PageObservation {
            host: "example.com".into(),
            entry_host: None,
            opened_from_mail: false,
            mail_level: None,
        };
        assert_eq!(request, PhishingRequest::CheckPage(expected));
    }

    #[test]
    fn check_limits_accepts_each_limit_and_rejects_one_over_each() {
        let fill = |len| "a".repeat(len);
        let at_limits = MailObservation {
            provider: Provider::Gmail,
            message_id: fill(MAX_STRING_BYTES),
            from_name: fill(MAX_STRING_BYTES),
            from_addr: fill(MAX_STRING_BYTES),
            reply_to: Some(fill(MAX_STRING_BYTES)),
            to: vec![fill(MAX_STRING_BYTES); MAX_RECIPIENTS],
            subject: fill(MAX_STRING_BYTES),
            body_text: fill(MAX_BODY_BYTES),
            links: vec![
                Link {
                    text: fill(MAX_STRING_BYTES),
                    href: fill(MAX_HREF_BYTES),
                };
                MAX_LINKS
            ],
            attachments: vec![fill(MAX_STRING_BYTES); MAX_ATTACHMENTS],
            truncated: false,
        };
        assert_eq!(at_limits.check_limits(), Ok(()));

        let error_after = |grow: fn(&mut MailObservation)| {
            let mut mail = at_limits.clone();
            grow(&mut mail);
            mail.check_limits().unwrap_err()
        };
        let errors = [
            ("message_id", error_after(|m| m.message_id.push('a'))),
            ("from_name", error_after(|m| m.from_name.push('a'))),
            ("from_addr", error_after(|m| m.from_addr.push('a'))),
            (
                "reply_to",
                error_after(|m| m.reply_to.as_mut().unwrap().push('a')),
            ),
            ("subject", error_after(|m| m.subject.push('a'))),
            ("body_text", error_after(|m| m.body_text.push('a'))),
            ("to", error_after(|m| m.to.push(String::new()))),
            ("to[]", error_after(|m| m.to[MAX_RECIPIENTS - 1].push('a'))),
            ("links", error_after(|m| m.links.push(m.links[0].clone()))),
            (
                "links[].text",
                error_after(|m| m.links[MAX_LINKS - 1].text.push('a')),
            ),
            (
                "links[].href",
                error_after(|m| m.links[MAX_LINKS - 1].href.push('a')),
            ),
            (
                "attachments",
                error_after(|m| m.attachments.push(String::new())),
            ),
            (
                "attachments[]",
                error_after(|m| m.attachments[MAX_ATTACHMENTS - 1].push('a')),
            ),
        ];
        for (field, error) in errors {
            assert_eq!(error.split(' ').next(), Some(field), "{error}");
            assert!(
                !error.contains("aa"),
                "error must not echo content: {error}"
            );
        }
    }

    #[test]
    fn host_limits_accept_255_bytes_and_reject_256() {
        let page = PageObservation {
            host: "a".repeat(MAX_HOST_BYTES),
            entry_host: Some("a".repeat(MAX_HOST_BYTES)),
            opened_from_mail: true,
            mail_level: None,
        };
        let login = LoginObservation {
            host: "a".repeat(MAX_HOST_BYTES),
            evidence: Evidence::Typed,
        };
        assert_eq!(page.check_limits(), Ok(()));
        assert_eq!(login.check_limits(), Ok(()));

        let mut long_host = page.clone();
        long_host.host.push('a');
        let mut long_entry_host = page.clone();
        long_entry_host.entry_host.as_mut().unwrap().push('a');
        let mut long_login_host = login.clone();
        long_login_host.host.push('a');
        let errors = [
            ("host", long_host.check_limits()),
            ("entry_host", long_entry_host.check_limits()),
            ("host", long_login_host.check_limits()),
        ];
        for (field, result) in errors {
            let error = result.unwrap_err();
            assert_eq!(error, format!("{field} exceeds its limit (256 > 255)"));
        }
    }
}
