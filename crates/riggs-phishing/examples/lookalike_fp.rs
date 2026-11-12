//! Counts lookalike-rule hits among popular sites, where every hit is a false positive: the top N
//! domains of a top-sites list are the login set, and each of the top M is checked against it
//! with the engine's own rule. Domains print only for hard-rule hits; they are public list entries.
//!
//! ```text
//! cargo run --release --locked --example lookalike_fp -- LIST [options]
//!   LIST                 `rank,domain` rows, such as a Tranco list
//!   --known N            default 1000
//!   --candidates M       default 100000
//!   --policy FILE        the guards' source; default: the repository's config/phishing-policy.toml
//!   --set GUARD=VALUE    overrides one guard, repeatable; embedding_ignore takes a comma list
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::exit;

use riggs_phishing::cues::Cue;
use riggs_phishing::domain::{name, Name};
use riggs_phishing::lookalike::{lookalike, Guards, Lookalike};
use riggs_phishing::reload::load_policy_file;

const SHIPPED_POLICY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/phishing-policy.toml"
);
const RULES: [Lookalike; 4] = [
    Lookalike::Misspelling,
    Lookalike::Embedded,
    Lookalike::SuffixSwap,
    Lookalike::BrandToken,
];

fn main() {
    if let Err(e) = run(std::env::args().skip(1)) {
        eprintln!("lookalike_fp: {e}\nusage: see the header of crates/riggs-phishing/examples/lookalike_fp.rs");
        exit(1);
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let (mut list, mut known_n, mut candidates_m) = (None, 1_000u32, 100_000u32);
    let (mut policy, mut sets) = (PathBuf::from(SHIPPED_POLICY), Vec::new());
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--known" => known_n = value()?.parse().map_err(|e| format!("--known: {e}"))?,
            "--candidates" => {
                candidates_m = value()?.parse().map_err(|e| format!("--candidates: {e}"))?;
            }
            "--policy" => policy = value()?.into(),
            "--set" => sets.push(value()?),
            _ if list.is_none() && !arg.starts_with("--") => list = Some(PathBuf::from(&arg)),
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    let list = list.ok_or("no list given")?;
    let mut guards = load_policy_file(&policy)
        .map_err(|e| e.to_string())?
        .guards()
        .clone();
    for assignment in &sets {
        set_guard(&mut guards, assignment)?;
    }
    let text = std::fs::read_to_string(&list).map_err(|e| format!("{}: {e}", list.display()))?;
    let (rows, skipped) = parse_list(&text);

    let (mut known, mut known_unusable): (Vec<(u32, Name)>, Vec<&str>) = (Vec::new(), Vec::new());
    for (rank, domain) in rows.iter().filter(|(rank, _)| *rank <= known_n) {
        match name(domain) {
            Some(n) => known.push((*rank, n)),
            None => known_unusable.push(domain),
        }
    }
    // Reversed, so a registrable domain listed twice keeps its better rank.
    let known_rank: BTreeMap<&str, u32> = known
        .iter()
        .rev()
        .map(|(rank, n)| (n.registrable.as_str(), *rank))
        .collect();

    let bands: Vec<u32> = [1_000, 10_000, 100_000]
        .into_iter()
        .filter(|band| *band < candidates_m)
        .chain([candidates_m])
        .collect();
    let mut checked = vec![0usize; bands.len()];
    let mut hits: BTreeMap<Lookalike, Vec<usize>> = RULES
        .into_iter()
        .map(|rule| (rule, vec![0; bands.len()]))
        .collect();
    let mut hard = Vec::new();
    let mut unusable = 0;
    for (rank, domain) in rows.iter().filter(|(rank, _)| *rank <= candidates_m) {
        let Some(candidate) = name(domain) else {
            unusable += 1;
            continue;
        };
        let found = lookalike(&candidate, known.iter().map(|(_, n)| n), &guards);
        for (i, _) in bands.iter().enumerate().filter(|&(_, &band)| *rank <= band) {
            checked[i] += 1;
            if let Some((_, rule)) = found {
                hits.get_mut(&rule).expect("every rule has a row")[i] += 1;
            }
        }
        if let Some((k, rule)) = found.filter(|(_, rule)| rule.is_hard()) {
            hard.push((*rank, candidate.registrable, rule, k.registrable.clone()));
        }
    }

    println!(
        "list {}: {} rows, {skipped} skipped (not a domain name)",
        list.display(),
        rows.len()
    );
    println!(
        "known: ranks 1 to {known_n}, {} usable, {} with no registrable domain: {}",
        known.len(),
        known_unusable.len(),
        known_unusable.join(" ")
    );
    println!(
        "candidates: ranks 1 to {candidates_m}, {unusable} with no registrable domain; a candidate that is itself known is never flagged"
    );
    println!("{guards:?}");
    let row = |head: &str, kind: &str, cells: Vec<String>| {
        println!(
            "{head:<30} {kind:<5} {}",
            cells.iter().map(|c| format!("{c:>18}")).collect::<String>()
        );
    };
    let cell = |k: usize, n: usize| format!("{k} ({:.3}%)", 100.0 * k as f64 / n.max(1) as f64);
    println!();
    row(
        "rule, hits (% of candidates)",
        "kind",
        bands.iter().map(|b| format!("top {b}")).collect(),
    );
    for rule in RULES {
        let kind = if rule.is_hard() { "hard" } else { "soft" };
        let counts = &hits[&rule];
        row(
            Cue::from(rule).id(),
            kind,
            (0..bands.len())
                .map(|i| cell(counts[i], checked[i]))
                .collect(),
        );
    }
    row(
        "any hard rule",
        "hard",
        (0..bands.len())
            .map(|i| {
                let k = hits[&Lookalike::Misspelling][i] + hits[&Lookalike::Embedded][i];
                cell(k, checked[i])
            })
            .collect(),
    );
    row(
        "candidates checked",
        "",
        checked.iter().map(usize::to_string).collect(),
    );

    println!("\nhard-rule hits: candidate rank, candidate, rule, known, known rank");
    for (rank, candidate, rule, known) in &hard {
        println!(
            "{rank:>7}  {candidate:<40} {:<30} {known:<30} {:>5}",
            Cue::from(*rule).id(),
            known_rank[known.as_str()]
        );
    }
    Ok(())
}

/// `rank,domain` rows. A row whose domain is not lowercase letters, digits, dots and hyphens is
/// skipped and counted: the Tranco list carries a few `_wildcard_` rows.
fn parse_list(text: &str) -> (Vec<(u32, String)>, usize) {
    let mut skipped = 0;
    let rows = text
        .lines()
        .filter_map(|line| {
            let row = line
                .split_once(',')
                .and_then(|(rank, domain)| Some((rank.parse().ok()?, domain.to_string())))
                .filter(|(_, domain): &(u32, String)| {
                    !domain.is_empty()
                        && domain.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                        })
                });
            skipped += usize::from(row.is_none());
            row
        })
        .collect();
    (rows, skipped)
}

fn set_guard(guards: &mut Guards, assignment: &str) -> Result<(), String> {
    let (key, value) = assignment
        .split_once('=')
        .ok_or_else(|| format!("--set {assignment}: expected GUARD=VALUE"))?;
    let number = || value.parse().map_err(|e| format!("{key}: {e}"));
    let flag = || value.parse().map_err(|e| format!("{key}: {e}"));
    match key {
        "homoglyph_min_label" => guards.homoglyph_min_label = number()?,
        "typo_min_label" => guards.typo_min_label = number()?,
        "typo_part_min_label" => guards.typo_part_min_label = number()?,
        "typo_same_first_char" => guards.typo_same_first_char = flag()?,
        "typo_trailing_s_exempt" => guards.typo_trailing_s_exempt = flag()?,
        "embedded_min_domain" => guards.embedded_min_domain = number()?,
        "embedding_ignore" => {
            guards.embedding_ignore = value
                .split(',')
                .filter(|d| !d.is_empty())
                .map(String::from)
                .collect();
        }
        "brand_token_min_label" => guards.brand_token_min_label = number()?,
        "brand_prefix_min_label" => guards.brand_prefix_min_label = number()?,
        _ => return Err(format!("{key} is not a lookalike guard")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_drops_carriage_returns_and_skips_rows_that_are_not_domains() {
        let (rows, skipped) = parse_list(
            "1,example.com\r\n2,_wildcard_.example\r\nrank,domain\r\n3,xn--bcher-kva.de\r\n",
        );
        assert_eq!(
            rows,
            [
                (1, "example.com".to_string()),
                (3, "xn--bcher-kva.de".to_string())
            ]
        );
        assert_eq!(skipped, 2);
    }

    #[test]
    fn guards_are_overridden_by_name_and_unknown_ones_refused() {
        let path = std::path::Path::new(SHIPPED_POLICY);
        let mut guards = load_policy_file(path).unwrap().guards().clone();
        set_guard(&mut guards, "typo_min_label=5").unwrap();
        set_guard(&mut guards, "typo_part_min_label=9").unwrap();
        set_guard(&mut guards, "typo_same_first_char=false").unwrap();
        set_guard(&mut guards, "embedding_ignore=example.com,example.org").unwrap();
        assert_eq!(guards.typo_min_label, 5);
        assert_eq!(guards.typo_part_min_label, 9);
        assert!(!guards.typo_same_first_char);
        assert_eq!(guards.embedding_ignore, ["example.com", "example.org"]);
        assert!(set_guard(&mut guards, "typo_min_label=five").is_err());
        assert!(set_guard(&mut guards, "warmup_logins=3").is_err());
        assert!(set_guard(&mut guards, "typo_min_label").is_err());
    }
}
