use std::collections::BTreeMap;

use riggs_types::phishing::Mode;
use serde::Deserialize;

use crate::cues::{normalize, Cue};
use crate::domain::name;
use crate::lookalike::Guards;

/// The policy file as written. Every key is required: there are no compiled-in defaults.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    mode: Mode,
    caution_threshold: f32,
    warmup_logins: usize,
    max_logins: usize,
    max_senders: usize,
    lookalike: Guards,
    weights: BTreeMap<String, f32>,
    phrases: BTreeMap<String, Vec<String>>,
    extensions: Extensions,
    freemail: Freemail,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Extensions {
    high_risk: Vec<String>,
    body_mention: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Freemail {
    domains: Vec<String>,
}

/// A validated policy. Built only by [`Policy::from_toml`].
#[derive(Debug, Clone)]
pub struct Policy {
    pub(crate) mode: Mode,
    pub(crate) caution_threshold: f32,
    pub(crate) warmup_logins: usize,
    pub(crate) max_logins: usize,
    pub(crate) max_senders: usize,
    pub(crate) guards: Guards,
    /// One weight per soft cue.
    pub(crate) weights: BTreeMap<Cue, f32>,
    /// One normalized phrase list per phrase cue.
    pub(crate) phrases: BTreeMap<Cue, Vec<String>>,
    pub(crate) high_risk: Vec<String>,
    pub(crate) body_mention: Vec<String>,
    /// SpamAssassin `freemail_domains` patterns: `*` matches any run of characters except `.`.
    pub(crate) freemail: Vec<String>,
}

impl Policy {
    /// Parses and validates a policy file. An error names the line or the key, and never quotes a
    /// snippet of the file.
    pub fn from_toml(text: &str) -> Result<Policy, String> {
        let file: File = toml::from_str(text).map_err(|e| {
            let line = e.span().map_or(0, |span| {
                text.as_bytes()[..span.start]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count()
                    + 1
            });
            format!("line {line}: {}", e.message())
        })?;
        if !(file.caution_threshold.is_finite() && file.caution_threshold > 0.0) {
            return Err("caution_threshold must be a finite number above 0".into());
        }
        let weights = by_cue("weights", "soft", file.weights, Cue::is_soft)?;
        if let Some((cue, _)) = weights.iter().find(|(_, w)| !w.is_finite()) {
            return Err(format!("weights.{} must be a finite number", cue.id()));
        }
        let phrases = by_cue("phrases", "phrase", file.phrases, Cue::is_phrase)?
            .into_iter()
            .map(|(cue, list)| {
                let list: Vec<String> = list.iter().map(String::as_str).map(normalize).collect();
                if list.iter().any(String::is_empty) {
                    return Err(format!("phrases.{} holds an empty phrase", cue.id()));
                }
                Ok((cue, list))
            })
            .collect::<Result<_, _>>()?;
        let is_extension = |e: &str| {
            e.len() > 1
                && e.starts_with('.')
                && e[1..]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        };
        let is_pattern = |d: &str| {
            !d.is_empty()
                && d.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.*".contains(&b))
        };
        let is_registrable = |d: &str| name(d).is_some_and(|n| n.registrable == d);
        check(
            "extensions.high_risk",
            &file.extensions.high_risk,
            is_extension,
        )?;
        check(
            "extensions.body_mention",
            &file.extensions.body_mention,
            is_extension,
        )?;
        check("freemail.domains", &file.freemail.domains, is_pattern)?;
        check(
            "lookalike.embedding_ignore",
            &file.lookalike.embedding_ignore,
            is_registrable,
        )?;
        Ok(Policy {
            mode: file.mode,
            caution_threshold: file.caution_threshold,
            warmup_logins: file.warmup_logins,
            max_logins: file.max_logins,
            max_senders: file.max_senders,
            guards: file.lookalike,
            weights,
            phrases,
            high_risk: file.extensions.high_risk,
            body_mention: file.extensions.body_mention,
            freemail: file.freemail.domains,
        })
    }

    /// Whether verdicts are shown is the caller's decision, from this mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn guards(&self) -> &Guards {
        &self.guards
    }

    /// `domain` is the lowercased domain of an address, matched whole as SpamAssassin does.
    pub(crate) fn is_freemail(&self, domain: &str) -> bool {
        self.freemail
            .iter()
            .any(|pattern| glob(pattern.as_bytes(), domain.as_bytes()))
    }
}

/// Keys a table by cue, refusing a missing key and a key that is not a `kind` cue id.
fn by_cue<T>(
    table: &str,
    kind: &str,
    entries: BTreeMap<String, T>,
    wanted: fn(Cue) -> bool,
) -> Result<BTreeMap<Cue, T>, String> {
    let missing: Vec<&str> = Cue::ALL
        .into_iter()
        .filter(|cue| wanted(*cue) && !entries.contains_key(cue.id()))
        .map(Cue::id)
        .collect();
    if !missing.is_empty() {
        return Err(format!("{table}: missing {}", missing.join(", ")));
    }
    entries
        .into_iter()
        .map(
            |(id, value)| match Cue::from_id(&id).filter(|cue| wanted(*cue)) {
                Some(cue) => Ok((cue, value)),
                None => Err(format!("{table}: {id} is not a {kind} cue id")),
            },
        )
        .collect()
}

fn check(key: &str, items: &[String], valid: impl Fn(&str) -> bool) -> Result<(), String> {
    match items.iter().position(|item| !valid(item)) {
        Some(i) => Err(format!("{key}: entry {} is malformed", i + 1)),
        None => Ok(()),
    }
}

fn glob(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => {
            glob(rest, text)
                || (text.first().is_some_and(|c| *c != b'.') && glob(pattern, &text[1..]))
        }
        Some((p, rest)) => text.first() == Some(p) && glob(rest, &text[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cues::tests::shipped;

    fn shipped_text() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/phishing-policy.toml");
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn the_shipped_policy_loads_in_monitor_mode_with_every_weight_at_zero() {
        let p = shipped();
        assert_eq!(p.mode(), Mode::Monitor);
        assert_eq!(p.weights.len(), 31);
        assert!(p.weights.values().all(|w| *w == 0.0));
        assert_eq!(p.phrases.len(), 16);
        assert!(p.phrases[&Cue::CompromisingPictureLure].is_empty());
        assert_eq!(p.high_risk, [".scr", ".exe", ".pif", ".cpl"]);
        assert_eq!(p.body_mention.len(), 9);
        assert!(p.guards().embedding_ignore.is_empty());
    }

    #[test]
    fn shipped_phrases_are_stored_normalized() {
        let p = shipped();
        assert!(p.phrases[&Cue::Urgency].contains(&"urgent".to_string()));
        assert!(p.phrases[&Cue::GenericGreeting].contains(&"sir/ma'am".to_string()));
    }

    #[test]
    fn freemail_patterns_match_whole_domains_with_star_stopping_at_dots() {
        let p = shipped();
        for domain in [
            "gmail.com",
            "outlook.com",
            "hotmail.co.uk",
            "yahoo.com.br",
            "x.rr.com",
        ] {
            assert!(p.is_freemail(domain), "{domain}");
        }
        for domain in [
            "example.com",
            "mail.gmail.com",
            "x.outlook.com",
            "a.b.rr.com",
        ] {
            assert!(!p.is_freemail(domain), "{domain}");
        }
    }

    #[test]
    fn edits_that_break_the_contract_are_refused() {
        let text = shipped_text();
        let cases = [
            ("unknown key", format!("colour = 1\n{text}")),
            ("missing weight", text.replacen("urgency = 0.0\n", "", 1)),
            (
                "extra weight",
                text.replacen("[weights]\n", "[weights]\nmade_up = 0.0\n", 1),
            ),
            (
                "hard cue weight",
                text.replacen(
                    "[weights]\n",
                    "[weights]\ndomain_lookalike_embedded = 0.0\n",
                    1,
                ),
            ),
            (
                "unknown mode",
                text.replacen("mode = \"monitor\"", "mode = \"loud\"", 1),
            ),
            (
                "unknown phrase key",
                text.replacen("[phrases]\n", "[phrases]\nmade_up = []\n", 1),
            ),
            (
                "missing guard",
                text.replacen("typo_min_label = 6", "# typo_min_label = 6", 1),
            ),
            (
                "zero threshold",
                text.replacen("caution_threshold = 1.0", "caution_threshold = 0.0", 1),
            ),
            ("bad extension", text.replacen("\".scr\"", "\"scr\"", 1)),
        ];
        for (what, edited) in cases {
            assert!(edited != text, "{what}: the edit did not apply");
            let error = Policy::from_toml(&edited).unwrap_err();
            assert!(!error.contains('\n'), "{what}: {error}");
        }
        let unknown = Policy::from_toml(&format!("colour = 1\n{text}")).unwrap_err();
        assert!(
            unknown.starts_with("line 1: unknown field `colour`"),
            "{unknown}"
        );
        let mode = Policy::from_toml(&text.replacen("\"monitor\"", "\"loud\"", 1)).unwrap_err();
        assert!(
            mode.starts_with("line 11: unknown variant `loud`"),
            "{mode}"
        );
        let missing = Policy::from_toml(&text.replacen("urgency = 0.0\n", "", 1)).unwrap_err();
        assert_eq!(missing, "weights: missing urgency");
        let extra = text.replacen("[weights]\n", "[weights]\nmade_up = 0.0\n", 1);
        assert_eq!(
            Policy::from_toml(&extra).unwrap_err(),
            "weights: made_up is not a soft cue id"
        );
    }
}
