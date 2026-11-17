use serde::Deserialize;

use crate::domain::{fold, Name};

/// Ordered strongest first: when several rules fire, the first one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lookalike {
    /// Homoglyph or one-edit typo of the known label, on the whole label or on a hyphen part.
    Misspelling,
    /// The known registrable domain appears as whole labels in the candidate host.
    Embedded,
    /// Same label, different public suffix.
    SuffixSwap,
    /// The known label is a token of the candidate host, or a proper prefix of its label.
    BrandToken,
}

impl Lookalike {
    pub fn is_hard(self) -> bool {
        matches!(self, Self::Misspelling | Self::Embedded)
    }
}

/// Starting guesses, to be measured on a top-sites list. Lengths count the characters of the
/// known domain's Unicode label, except `embedded_min_domain`, which counts its ASCII registrable domain.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guards {
    pub homoglyph_min_label: usize,
    /// The typo rule on the candidate's whole label.
    pub typo_min_label: usize,
    /// The typo rule on one of the candidate's hyphen parts, which are often ordinary words.
    pub typo_part_min_label: usize,
    pub typo_same_first_char: bool,
    pub typo_trailing_s_exempt: bool,
    pub embedded_min_domain: usize,
    /// Registrable domains of candidate hosts under which an embedded known domain is not flagged.
    pub embedding_ignore: Vec<String>,
    pub brand_token_min_label: usize,
    pub brand_prefix_min_label: usize,
}

/// The known domain `candidate` imitates, with the strongest rule that fires; ties go to the first
/// known domain. A candidate whose registrable domain is itself known is never a lookalike. A
/// candidate whose label is itself a known label is never a misspelling of another known domain:
/// it is that domain's name under another suffix. The embedded rule, which reads the rest of the
/// host, still applies to it.
pub fn lookalike<'a>(
    candidate: &Name,
    known: impl IntoIterator<Item = &'a Name>,
    guards: &Guards,
) -> Option<(&'a Name, Lookalike)> {
    let known: Vec<&'a Name> = known.into_iter().collect();
    if known.iter().any(|k| k.registrable == candidate.registrable) {
        return None;
    }
    // What the misspelling rules compare, with the typo rule's guard for each: the whole label,
    // then its hyphen parts.
    let mut forms = Vec::new();
    if !known.iter().any(|k| k.label == candidate.label) {
        forms.push((
            candidate.unicode.clone(),
            candidate.fold.clone(),
            guards.typo_min_label,
        ));
        let parts: Vec<&str> = candidate
            .unicode
            .split('-')
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() > 1 {
            forms.extend(
                parts
                    .iter()
                    .map(|p| (p.to_string(), fold(p), guards.typo_part_min_label)),
            );
        }
    }
    let rest = candidate
        .host
        .strip_suffix(&candidate.suffix)
        .and_then(|h| h.strip_suffix('.'))
        .unwrap_or(&candidate.host);
    let tokens: Vec<&str> = rest.split(['.', '-']).collect();

    let mut best: Option<(&'a Name, Lookalike)> = None;
    for k in known {
        let Some(rule) = rule(candidate, &forms, &tokens, k, guards) else {
            continue;
        };
        if best.is_none_or(|(_, b)| rule < b) {
            best = Some((k, rule));
        }
    }
    best
}

fn rule(
    candidate: &Name,
    forms: &[(String, String, usize)],
    tokens: &[&str],
    k: &Name,
    g: &Guards,
) -> Option<Lookalike> {
    let k_len = k.unicode.chars().count();
    let misspelled = forms.iter().any(|(raw, folded, typo_min)| {
        (k_len >= g.homoglyph_min_label && *folded == k.fold && *raw != k.unicode)
            || (k_len >= *typo_min && typo(folded, &k.fold, g))
    });
    if misspelled {
        return Some(Lookalike::Misspelling);
    }
    if k.registrable.len() >= g.embedded_min_domain
        && !g.embedding_ignore.contains(&candidate.registrable)
        && appears(tokens, &k.registrable)
    {
        return Some(Lookalike::Embedded);
    }
    if candidate.label == k.label {
        return Some(Lookalike::SuffixSwap);
    }
    let token = k_len >= g.brand_token_min_label && appears(tokens, &k.label);
    let prefix = k_len >= g.brand_prefix_min_label
        && candidate.label.len() > k.label.len()
        && candidate.label.starts_with(&k.label);
    (token || prefix).then_some(Lookalike::BrandToken)
}

/// `known`, split on `.` and `-` as the candidate's `tokens` are, occurs among them as consecutive
/// tokens. Splitting both sides alike is what lets `t-mobile.com`, and every IDN domain (its ASCII
/// form holds `--`), be found.
fn appears(tokens: &[&str], known: &str) -> bool {
    let pieces = || known.split(['.', '-']);
    tokens
        .windows(pieces().count())
        .any(|w| w.iter().copied().eq(pieces()))
}

/// One insertion, deletion, substitution or adjacent transposition between two folds.
fn typo(a: &str, b: &str, g: &Guards) -> bool {
    let trailing_s = a.strip_suffix('s') == Some(b) || b.strip_suffix('s') == Some(a);
    a.chars().count().abs_diff(b.chars().count()) <= 1
        && (!g.typo_same_first_char || a.chars().next() == b.chars().next())
        && !(g.typo_trailing_s_exempt && trailing_s)
        && strsim::osa_distance(a, b) == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::name;

    fn guards() -> Guards {
        Guards {
            homoglyph_min_label: 4,
            typo_min_label: 6,
            typo_part_min_label: 8,
            typo_same_first_char: true,
            typo_trailing_s_exempt: true,
            embedded_min_domain: 6,
            embedding_ignore: vec![],
            brand_token_min_label: 5,
            brand_prefix_min_label: 6,
        }
    }

    fn check(candidate: &str, known: &str, g: &Guards) -> Option<Lookalike> {
        let known = [name(known).unwrap()];
        lookalike(&name(candidate).unwrap(), &known, g).map(|(_, rule)| rule)
    }

    // Sourced examples, PHISHING_CUES.md section 4, "Sourced examples that are not phrases".

    #[test]
    fn micorsoft_support_is_a_misspelling_of_microsoft_by_its_first_hyphen_part() {
        // KB4 FROM 4. The part "micorsoft" is one transposition from "microsoft".
        let rule = check("micorsoft-support.com", "microsoft.com", &guards());
        assert_eq!(rule, Some(Lookalike::Misspelling));
    }

    #[test]
    fn bankofarnerica_is_a_homoglyph_misspelling_of_bankofamerica() {
        // KB4 HYPERLINKS 3: "rn" for "m".
        let rule = check("www.bankofarnerica.com", "bankofamerica.com", &guards());
        assert_eq!(rule, Some(Lookalike::Misspelling));
    }

    #[test]
    fn amazan_is_a_typo_misspelling_of_amazon() {
        // CISA-RRP "Recognize" item 4; CISA-TIP p. 2. "amazon" is exactly the typo guard's 6.
        let rule = check("amazan.com", "amazon.com", &guards());
        assert_eq!(rule, Some(Lookalike::Misspelling));
    }

    #[test]
    fn niist_and_ni_st_are_below_the_typo_guard_for_nist_and_fire_once_it_is_lowered() {
        // NIST section 2.1.3 and B.2.4. "nist" has 4 characters, under the shipped typo guard of 6,
        // and folds differently from both candidates, so no rule fires at the shipped values.
        assert_eq!(check("www.niist.gov", "nist.gov", &guards()), None);
        assert_eq!(check("www.ni-st.gov", "nist.gov", &guards()), None);
        let lowered = Guards {
            typo_min_label: 4,
            ..guards()
        };
        let rule = check("www.niist.gov", "nist.gov", &lowered);
        assert_eq!(rule, Some(Lookalike::Misspelling));
        let rule = check("www.ni-st.gov", "nist.gov", &lowered);
        assert_eq!(rule, Some(Lookalike::Misspelling));
    }

    #[test]
    fn nist_com_is_a_suffix_swap_of_nist_gov() {
        // NIST B.2.4, third example.
        let rule = check("www.nist.com", "nist.gov", &guards());
        assert_eq!(rule, Some(Lookalike::SuffixSwap));
    }

    #[test]
    fn google_com_rogueserver_biz_embeds_google_com() {
        // KB4-blog, "Number One Most Suspicious Sign".
        let rule = check("google.com.rogueserver.biz", "google.com", &guards());
        assert_eq!(rule, Some(Lookalike::Embedded));
    }

    #[test]
    fn amazongproducts_carries_amazon_as_a_prefix() {
        // KB4-blog, "Number One Most Suspicious Sign". Filed there as embedded; the brief makes the
        // prefix form the soft brand-token rule.
        let rule = check("amazongproducts.ru", "amazon.com", &guards());
        assert_eq!(rule, Some(Lookalike::BrandToken));
    }

    #[test]
    fn an_idn_homoglyph_is_a_misspelling() {
        let rule = check("p\u{430}ypal.com", "paypal.com", &guards());
        assert_eq!(rule, Some(Lookalike::Misspelling));
    }

    #[test]
    fn a_known_registrable_domain_is_never_a_lookalike() {
        let known = [name("paypal.com").unwrap(), name("paypa1.com").unwrap()];
        let candidate = name("www.paypa1.com").unwrap();
        assert_eq!(lookalike(&candidate, &known, &guards()), None);
    }

    #[test]
    fn a_label_that_is_itself_known_is_a_suffix_swap_not_a_misspelling() {
        // The shape measurement 2H found on Tranco: "mercadolibre" is one edit from "mercadolivre",
        // but it is the label of a known domain under another suffix.
        let known = [
            name("mercadolivre.com.br").unwrap(),
            name("mercadolibre.com.ar").unwrap(),
        ];
        let candidate = name("mercadolibre.com.mx").unwrap();
        let (k, rule) = lookalike(&candidate, &known, &guards()).unwrap();
        assert_eq!(
            (k.registrable.as_str(), rule),
            ("mercadolibre.com.ar", Lookalike::SuffixSwap)
        );
        // Without the exact label, the same candidate is a misspelling.
        let (k, rule) = lookalike(&candidate, &known[..1], &guards()).unwrap();
        assert_eq!(
            (k.registrable.as_str(), rule),
            ("mercadolivre.com.br", Lookalike::Misspelling)
        );
    }

    #[test]
    fn a_hyphenated_known_domain_is_found_embedded_and_as_a_token() {
        let g = guards();
        // Dotted and hyphenated forms of the embedded rule.
        assert_eq!(
            check("t-mobile.com.evil.biz", "t-mobile.com", &g),
            Some(Lookalike::Embedded)
        );
        assert_eq!(
            check("t-mobile-com.evil.biz", "t-mobile.com", &g),
            Some(Lookalike::Embedded)
        );
        // The known label as a host label, and inside a hyphenated label.
        assert_eq!(
            check("t-mobile.evil.biz", "t-mobile.com", &g),
            Some(Lookalike::BrandToken)
        );
        assert_eq!(
            check("secure-t-mobile.biz", "t-mobile.com", &g),
            Some(Lookalike::BrandToken)
        );
        // Pieces of the known label that are not consecutive are no match.
        assert_eq!(check("t-shop-mobile.biz", "t-mobile.com", &g), None);
    }

    #[test]
    fn an_idn_known_domain_is_found_embedded_and_as_a_token() {
        // bücher.de is xn--bcher-kva.de in ASCII; the "--" used to defeat both rules.
        let g = guards();
        assert_eq!(
            check("bücher.de.example.com", "bücher.de", &g),
            Some(Lookalike::Embedded)
        );
        assert_eq!(
            check("bücher.example.com", "bücher.de", &g),
            Some(Lookalike::BrandToken)
        );
    }

    #[test]
    fn a_known_label_does_not_hide_an_embedded_domain() {
        let known = [name("abcdef.com").unwrap(), name("secure.net").unwrap()];
        let candidate = name("abcdef.com.secure.org").unwrap();
        let (k, rule) = lookalike(&candidate, &known, &guards()).unwrap();
        assert_eq!(
            (k.registrable.as_str(), rule),
            ("abcdef.com", Lookalike::Embedded)
        );
    }

    #[test]
    fn typo_part_guard() {
        let g = guards();
        // A hyphen part one edit from an 8-character label fires; from a 7-character one it does not.
        assert_eq!(
            check("abcdefgx-shop.com", "abcdefgh.com", &g),
            Some(Lookalike::Misspelling)
        );
        assert_eq!(check("abcdefx-shop.com", "abcdefg.com", &g), None);
        // The whole label keeps typo_min_label, and the homoglyph rule on parts keeps its own guard.
        assert_eq!(
            check("abcdefx.com", "abcdefg.com", &g),
            Some(Lookalike::Misspelling)
        );
        assert_eq!(
            check("abcrn-shop.com", "abcm.com", &g),
            Some(Lookalike::Misspelling)
        );
    }

    #[test]
    fn the_sourced_examples_at_the_shipped_guards() {
        let shipped = crate::cues::tests::shipped();
        let g = shipped.guards();
        let cases = [
            (
                "micorsoft-support.com",
                "microsoft.com",
                Some(Lookalike::Misspelling),
            ),
            (
                "www.bankofarnerica.com",
                "bankofamerica.com",
                Some(Lookalike::Misspelling),
            ),
            ("amazan.com", "amazon.com", Some(Lookalike::Misspelling)),
            ("www.niist.gov", "nist.gov", None),
            ("www.ni-st.gov", "nist.gov", None),
            ("www.nist.com", "nist.gov", Some(Lookalike::SuffixSwap)),
            (
                "google.com.rogueserver.biz",
                "google.com",
                Some(Lookalike::Embedded),
            ),
            (
                "amazongproducts.ru",
                "amazon.com",
                Some(Lookalike::BrandToken),
            ),
        ];
        for (candidate, known, rule) in cases {
            assert_eq!(
                check(candidate, known, g),
                rule,
                "{candidate} against {known}"
            );
        }
    }

    #[test]
    fn the_strongest_rule_wins_and_ties_go_to_the_first_known() {
        // A brand-token prefix, then two one-edit typos of the candidate's label.
        let known = [
            name("abcdef.net").unwrap(),
            name("abcdefgx.com").unwrap(),
            name("abcdefxh.com").unwrap(),
        ];
        let candidate = name("abcdefgh.com").unwrap();
        let (k, rule) = lookalike(&candidate, &known, &guards()).unwrap();
        assert_eq!(
            (k.registrable.as_str(), rule),
            ("abcdefgx.com", Lookalike::Misspelling)
        );
        let (k, rule) = lookalike(&candidate, &known[..1], &guards()).unwrap();
        assert_eq!(
            (k.registrable.as_str(), rule),
            ("abcdef.net", Lookalike::BrandToken)
        );
    }

    // Each guard, just inside and just outside. Labels are constructed to exercise one rule.

    #[test]
    fn homoglyph_guard() {
        // "abcm" and "abm" fold to "abcrn" and "abrn".
        let g = guards();
        assert_eq!(
            check("abcrn.com", "abcm.com", &g),
            Some(Lookalike::Misspelling)
        );
        assert_eq!(check("abrn.com", "abm.com", &g), None);
    }

    #[test]
    fn typo_length_guard() {
        let g = guards();
        assert_eq!(
            check("abcdeg.com", "abcdef.com", &g),
            Some(Lookalike::Misspelling)
        );
        assert_eq!(check("abcdf.com", "abcde.com", &g), None);
    }

    #[test]
    fn typo_first_character_guard() {
        let g = guards();
        assert_eq!(
            check("abcdeg.com", "abcdef.com", &g),
            Some(Lookalike::Misspelling)
        );
        assert_eq!(check("xbcdef.com", "abcdef.com", &g), None);
        let off = Guards {
            typo_same_first_char: false,
            ..guards()
        };
        assert_eq!(
            check("xbcdef.com", "abcdef.com", &off),
            Some(Lookalike::Misspelling)
        );
    }

    #[test]
    fn typo_trailing_s_guard() {
        let g = guards();
        assert_eq!(
            check("abcdefx.com", "abcdef.com", &g),
            Some(Lookalike::Misspelling)
        );
        // Not a misspelling; the label prefix still makes it a brand token.
        assert_eq!(
            check("abcdefs.com", "abcdef.com", &g),
            Some(Lookalike::BrandToken)
        );
        let off = Guards {
            typo_trailing_s_exempt: false,
            ..guards()
        };
        assert_eq!(
            check("abcdefs.com", "abcdef.com", &off),
            Some(Lookalike::Misspelling)
        );
    }

    #[test]
    fn embedded_length_guard() {
        let g = guards();
        assert_eq!(
            check("abc.de.example.com", "abc.de", &g),
            Some(Lookalike::Embedded)
        );
        assert_eq!(check("ab.de.example.com", "ab.de", &g), None);
    }

    #[test]
    fn embedded_hyphen_form() {
        let rule = check("secure-abcdef-com.example.org", "abcdef.com", &guards());
        assert_eq!(rule, Some(Lookalike::Embedded));
    }

    #[test]
    fn embedding_ignore_guard() {
        let ignoring = Guards {
            embedding_ignore: vec!["example.net".into()],
            ..guards()
        };
        assert_eq!(
            check("abcdef.com.example.org", "abcdef.com", &ignoring),
            Some(Lookalike::Embedded)
        );
        // Ignored for embedding; the token rule still sees the label.
        assert_eq!(
            check("abcdef.com.example.net", "abcdef.com", &ignoring),
            Some(Lookalike::BrandToken)
        );
    }

    #[test]
    fn brand_token_guard() {
        let g = guards();
        assert_eq!(
            check("abcde.example.com", "abcde.com", &g),
            Some(Lookalike::BrandToken)
        );
        assert_eq!(
            check("login-abcde.example", "abcde.com", &g),
            Some(Lookalike::BrandToken)
        );
        assert_eq!(check("abcd.example.com", "abcd.com", &g), None);
    }

    #[test]
    fn brand_prefix_guard() {
        let g = guards();
        assert_eq!(
            check("abcdefxyz.com", "abcdef.com", &g),
            Some(Lookalike::BrandToken)
        );
        assert_eq!(check("abcdexyz.com", "abcde.com", &g), None);
    }

    #[test]
    fn the_public_suffix_is_not_a_token() {
        // ".example" is not on the public suffix list, so it is the suffix and "example" is no token.
        assert_eq!(check("abcdef.example", "example.com", &guards()), None);
    }
}
