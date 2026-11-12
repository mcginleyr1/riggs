//! Replays mail through the phishing engine the daemon runs and prints cue rates per input and,
//! for a phishing input against a legitimate one, side by side.
//!
//! Each message becomes the observation the browser extension would send for it, capped as the
//! extension's worker caps it. Output is aggregates only: cue ids, counts, rates and years.
//! Nothing of a message (subject, body, address, display name, URL) reaches stdout or stderr,
//! errors and panics included.
//!
//! ```text
//! cargo run --release --locked --example eval -- [options]
//!
//! inputs, each repeatable; inputs that share a label are pooled:
//!   --eml LABEL DIR GLOB   files in DIR whose name matches GLOB (`*` matches any run)
//!   --mbox LABEL FILE      an mbox file
//!   --sa-dir LABEL DIR     SpamAssassin corpus layout: only files named <number>.<md5>
//! options:
//!   --phish LABEL --legit LABEL  also print the two-sided table for these two inputs
//!   --policy FILE          default: the repository's config/phishing-policy.toml
//!   --chronological        one user per input, messages in date order
//!                          (default: independent, a fresh user per message)
//!   --logins FILE          login domains to seed every user with, one per line
//!   --keep-label LABEL     keep only messages whose X-Gmail-Labels holds one of these (untested)
//!   --drop-label LABEL     drop messages whose X-Gmail-Labels holds one of these (untested)
//!   --padding              also measure long base64-alphabet runs in the walked text and what
//!                          stripping them before the cut would change; the engine's own input
//!                          and every other table stay as they are
//!   --no-padding-rule      cap without the padding rule, as the sensors did before it
//! ```

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::exit;

use mail_parser::{MessageParser, PartKind, DOW, MONTH};
use riggs_phishing::cues::{lookalike_hosts, Cue, LookalikeHit};
use riggs_phishing::domain::name;
use riggs_phishing::engine::{LoginRow, User};
use riggs_phishing::policy::Policy;
use riggs_phishing::reload::load_policy_file;
use riggs_types::phishing::{Level, Link, MailObservation, Provider};
use scraper::{ElementRef, Html, Node, Selector};
use sha2::{Digest, Sha256};

const SHIPPED_POLICY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/phishing-policy.toml"
);
const USAGE: &str = "usage: see the header of crates/riggs-phishing/examples/eval.rs";

// The worker's caps: docs/PHISHING.md, "Limits" and "Capping". `check_limits` holds the same
// numbers privately, and every capped observation is checked against it.
const MAX_BODY: usize = 64 * 1024;
const MAX_HREF: usize = 8 * 1024;
const MAX_STRING: usize = 4 * 1024;
const MAX_LINKS: usize = 500;
const MAX_RECIPIENTS: usize = 500;
const MAX_ATTACHMENTS: usize = 100;
const MAX_REQUEST: usize = 6 * 1024 * 1024;
/// The padding rule (`riggs-phish-padding.md`, binding for every capper): before any limit, each
/// run of more than this many base64-alphabet characters in `body_text` becomes one space.
const PADDING_RUN: usize = 256;

/// The subject of the mail-store entry that heads some mbox files (data README).
const PLACEHOLDER: &str = "FOLDER INTERNAL DATA";

/// The sensors' body-text block list.
const BLOCKS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
];

/// Jeffreys smoothing: half a count added to each outcome, so a cue that never fires on one side
/// still has a finite ratio, with less pull towards 50% than add-one.
const SMOOTHING: f64 = 0.5;
/// Distinct bodies a cue must fire on, on each side, before its ratio is read: the standard error
/// of ln(rate) is about 1/sqrt(k), so 10 keeps each side's share of the ratio's error near 0.3.
const MIN_SUPPORT: usize = 10;

/// `--padding`: the what-if strips runs of base64-alphabet characters longer than each of these.
const RUN_LIMITS: [usize; 4] = [64, 128, 256, 1024];
/// A prose word is a whitespace-separated token of at most this many characters holding a letter.
const MAX_WORD_CHARS: usize = 30;
/// Prose words a cut body needs before its visible text counts as having reached the engine.
const MIN_PROSE_WORDS: usize = 10;

enum Source {
    Eml(PathBuf, String),
    Mbox(PathBuf),
    SaDir(PathBuf),
}

struct Options {
    inputs: Vec<(String, Vec<Source>)>,
    policy: PathBuf,
    chronological: bool,
    logins: Option<PathBuf>,
    keep: Vec<String>,
    drop: Vec<String>,
    phish: Option<String>,
    legit: Option<String>,
    padding: bool,
    padding_rule: bool,
}

struct Mail {
    obs: MailObservation,
    year: Option<u16>,
    /// 0 when the message has no usable date.
    when_ms: u64,
    labels: Vec<String>,
    padding: Option<Padding>,
}

/// One message's padding measurement (`--padding`), taken on the walked text before the cap.
struct Padding {
    over_cap: bool,
    walked: usize,
    longest_run: usize,
    /// Bytes in runs longer than each of `RUN_LIMITS`.
    in_long_runs: [usize; 4],
    prose_in_cut: bool,
    /// Over-cap HTML only: body text nodes holding a run longer than the smallest limit, and how
    /// many of them an inline style hides.
    nodes: (usize, usize),
    /// Phrase cues of the observation as the worker caps it; empty when no limit strips a run.
    before: Vec<Cue>,
    /// Per limit, when stripping removed at least one run.
    stripped: [Option<Stripped>; 4],
}

struct Stripped {
    fits: bool,
    prose_in_cut: bool,
    after: Vec<Cue>,
    /// Every removed run repeats one character, as a line of `-` or `=` does.
    one_character: bool,
}

#[derive(Default)]
struct Tally {
    read: usize,
    unparsed: usize,
    placeholders: usize,
    filtered: usize,
}

struct Outcome {
    year: Option<u16>,
    body: [u8; 32],
    cues: Vec<Cue>,
    level: Level,
    truncated: bool,
    /// The engine's lookalike candidate hosts for this mail, the sender's domain included, before
    /// the `max_hosts` cap.
    lookalike_hosts: usize,
    lookalikes: Vec<LookalikeHit>,
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map_or_else(String::new, |l| format!(" at {}:{}", l.file(), l.line()));
        eprintln!("eval: panic{at}; its message is withheld because it may quote mail");
    }));
    let options = parse_args(std::env::args().skip(1)).unwrap_or_else(|e| {
        eprintln!("eval: {e}\n{USAGE}");
        exit(2)
    });
    if let Err(e) = run(&options) {
        eprintln!("eval: {e}");
        exit(1);
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        inputs: Vec::new(),
        policy: PathBuf::from(SHIPPED_POLICY),
        chronological: false,
        logins: None,
        keep: Vec::new(),
        drop: Vec::new(),
        phish: None,
        legit: None,
        padding: false,
        padding_rule: true,
    };
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        let input = match flag.as_str() {
            "--eml" => Some((value()?, Source::Eml(value()?.into(), value()?))),
            "--mbox" => Some((value()?, Source::Mbox(value()?.into()))),
            "--sa-dir" => Some((value()?, Source::SaDir(value()?.into()))),
            "--phish" => {
                o.phish = Some(value()?);
                None
            }
            "--legit" => {
                o.legit = Some(value()?);
                None
            }
            "--policy" => {
                o.policy = value()?.into();
                None
            }
            "--logins" => {
                o.logins = Some(value()?.into());
                None
            }
            "--keep-label" => {
                o.keep.push(value()?);
                None
            }
            "--drop-label" => {
                o.drop.push(value()?);
                None
            }
            "--chronological" => {
                o.chronological = true;
                None
            }
            "--padding" => {
                o.padding = true;
                None
            }
            "--no-padding-rule" => {
                o.padding_rule = false;
                None
            }
            _ => return Err(format!("unknown argument {flag}")),
        };
        if let Some((label, source)) = input {
            match o.inputs.iter_mut().find(|(l, _)| *l == label) {
                Some((_, sources)) => sources.push(source),
                None => o.inputs.push((label, vec![source])),
            }
        }
    }
    if o.inputs.is_empty() {
        return Err("no input".into());
    }
    if o.phish.is_some() != o.legit.is_some() {
        return Err("--phish and --legit go together".into());
    }
    for label in o.phish.iter().chain(&o.legit) {
        if !o.inputs.iter().any(|(l, _)| l == label) {
            return Err(format!("{label} is not an input label"));
        }
    }
    Ok(o)
}

fn run(o: &Options) -> Result<(), String> {
    let policy = load_policy_file(&o.policy).map_err(|e| e.to_string())?;
    let seed = seed_user(o.logins.as_deref())?;
    let logins = seed.logins().count();
    let mode = if o.chronological {
        "chronological (one user per input, messages in date order)"
    } else {
        "independent (a fresh user per message)"
    };
    let rule = if o.padding_rule { "on" } else { "off" };
    println!("policy {}", o.policy.display());
    println!(
        "replay {mode}; {logins} login domains seeded; padding rule (runs over {PADDING_RUN} characters removed before the cap) {rule}"
    );
    let note = |cue: Cue| match cue {
        Cue::SenderNeverSeen if !o.chronological => "true by construction: independent replay",
        Cue::ReplyToUnsentMessage | Cue::AttachmentFromUnseenSender if !o.chronological => {
            "history half true by construction"
        }
        Cue::DomainLookalikeMisspelling
        | Cue::DomainLookalikeEmbedded
        | Cue::DomainLookalikeBrandToken
        | Cue::DomainLookalikeSuffixSwap
        | Cue::BrandNameInFreemailSender
            if logins == 0 =>
        {
            "cannot fire: no login domains"
        }
        _ => "",
    };

    let mut results = BTreeMap::new();
    for (label, sources) in &o.inputs {
        let padding = o.padding.then_some(&policy);
        let (tally, mut mails) = read_input(sources, &o.keep, &o.drop, padding, o.padding_rule)
            .map_err(|e| format!("{label}: {e}"))?;
        let paddings: Vec<Padding> = mails.iter_mut().filter_map(|m| m.padding.take()).collect();
        let outcomes = replay(&policy, &seed, mails, o.chronological);
        print_input(label, &tally, &outcomes, &note);
        if o.padding {
            print_padding(&paddings);
        }
        results.insert(label.as_str(), outcomes);
    }
    if let (Some(phish), Some(legit)) = (&o.phish, &o.legit) {
        let p = distinct(&results[phish.as_str()]);
        let l = distinct(&results[legit.as_str()]);
        print_two_sided((phish, &p), (legit, &l), &note);
    }
    Ok(())
}

fn seed_user(path: Option<&Path>) -> Result<User, String> {
    let Some(path) = path else {
        return Ok(User::default());
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let rows = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let domain = name(line)
                .ok_or_else(|| format!("{}: {line} is not a domain name", path.display()))?
                .registrable;
            Ok(LoginRow {
                domain,
                first_ms: 0,
                last_ms: 0,
                count: 1,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    User::new(rows, [])
}

fn read_input(
    sources: &[Source],
    keep: &[String],
    drop: &[String],
    padding: Option<&Policy>,
    padding_rule: bool,
) -> Result<(Tally, Vec<Mail>), String> {
    let mut tally = Tally::default();
    let mut mails = Vec::new();
    let mut take = |raw: &[u8], position: String| {
        tally.read += 1;
        match observe(raw, &position, padding, padding_rule) {
            Err(_) => tally.unparsed += 1,
            Ok(mail) if mail.obs.subject.contains(PLACEHOLDER) => tally.placeholders += 1,
            Ok(mail) if !wanted(&mail.labels, keep, drop) => tally.filtered += 1,
            Ok(mail) => mails.push(mail),
        }
    };
    let read = |path: &Path| std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
    for source in sources {
        match source {
            Source::Eml(dir, glob) => {
                for path in files(dir, |file| matches_glob(glob, file))? {
                    take(&read(&path)?, path.display().to_string());
                }
            }
            Source::SaDir(dir) => {
                for path in files(dir, is_sa_name)? {
                    take(&read(&path)?, path.display().to_string());
                }
            }
            Source::Mbox(path) => {
                let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
                let mut index = 0;
                split_mbox(BufReader::new(file), |raw| {
                    index += 1;
                    take(&raw, format!("{}#{index}", path.display()));
                })
                .map_err(|e| format!("{}: {e}", path.display()))?;
            }
        }
    }
    Ok((tally, mails))
}

/// Regular files in `dir` whose name `keep` accepts, in name order.
fn files(dir: &Path, keep: impl Fn(&str) -> bool) -> Result<Vec<PathBuf>, String> {
    let error = |e: io::Error| format!("{}: {e}", dir.display());
    let mut files = std::fs::read_dir(dir)
        .map_err(error)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    files.retain(|p| p.is_file() && p.file_name().and_then(|n| n.to_str()).is_some_and(&keep));
    files.sort();
    Ok(files)
}

fn matches_glob(glob: &str, name: &str) -> bool {
    match glob.split_once('*') {
        None => glob == name,
        Some((head, rest)) => name.strip_prefix(head).is_some_and(|tail| {
            (0..=tail.len())
                .filter(|i| tail.is_char_boundary(*i))
                .any(|i| matches_glob(rest, &tail[i..]))
        }),
    }
}

/// `<number>.<md5>`: a SpamAssassin corpus message, not its `cmds` file.
fn is_sa_name(file: &str) -> bool {
    file.split_once('.').is_some_and(|(number, md5)| {
        !number.is_empty()
            && number.bytes().all(|b| b.is_ascii_digit())
            && md5.len() == 32
            && md5.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

fn wanted(labels: &[String], keep: &[String], drop: &[String]) -> bool {
    (keep.is_empty() || labels.iter().any(|l| keep.contains(l)))
        && !labels.iter().any(|l| drop.contains(l))
}

/// Splits an mbox by the data README's rule: a message starts at an envelope line that opens the
/// file or follows a blank line. Body lines may start with `From ` too.
fn split_mbox(mut reader: impl BufRead, mut each: impl FnMut(Vec<u8>)) -> io::Result<()> {
    let mut message: Option<Vec<u8>> = None;
    let mut line = Vec::new();
    let mut after_blank = true;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if after_blank && is_envelope(&line) {
            if let Some(done) = message.replace(Vec::new()) {
                each(done);
            }
        } else if let Some(m) = &mut message {
            m.extend_from_slice(&line);
        }
        after_blank = matches!(line.as_slice(), b"\n" | b"\r\n");
    }
    message.into_iter().for_each(each);
    Ok(())
}

/// `From <sender> <weekday> <month> <day> <hh:mm:ss> <year>`, with or without a zone, which may
/// also stand before the year.
fn is_envelope(line: &[u8]) -> bool {
    let line = String::from_utf8_lossy(line);
    let w: Vec<&str> = line.split_whitespace().collect();
    let digits = |s: &str, lengths: &[usize]| {
        lengths.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
    };
    line.starts_with("From ")
        && matches!(w.len(), 7 | 8)
        && DOW.contains(&w[2])
        && MONTH.contains(&w[3])
        && digits(w[4], &[1, 2])
        && w[5].split(':').count() == 3
        && w[5].split(':').all(|part| digits(part, &[2]))
        && w[6..].iter().any(|s| digits(s, &[4]))
}

fn strip_envelope(raw: &[u8]) -> &[u8] {
    let first = raw
        .split_inclusive(|b| *b == b'\n')
        .next()
        .unwrap_or_default();
    if is_envelope(first) {
        &raw[first.len()..]
    } else {
        raw
    }
}

/// The observation a sensor would send for `raw`, capped as the worker caps it (with or without
/// the padding rule), and with a policy the padding measurement of the uncapped one. The error is
/// fixed text, so nothing of the message can reach it.
fn observe(
    raw: &[u8],
    position: &str,
    padding: Option<&Policy>,
    padding_rule: bool,
) -> Result<Mail, &'static str> {
    let message = MessageParser::new()
        .parse(strip_envelope(raw))
        .ok_or("no header block")?;
    let from = message.from().and_then(|list| list.first());
    let to = [message.to(), message.cc()]
        .into_iter()
        .flatten()
        .flat_map(|list| list.mailboxes())
        .filter_map(|m| m.address())
        .map(String::from)
        .collect();

    let html: Vec<_> = message
        .html_body()
        .filter(|part| matches!(part.kind(), PartKind::Html))
        .filter_map(|part| part.text())
        .collect();
    let mut links = Vec::new();
    let body_text = if html.is_empty() {
        let text = message
            .text_body()
            .filter(|part| matches!(part.kind(), PartKind::Text))
            .filter_map(|part| part.text())
            .collect::<Vec<_>>()
            .join("\n");
        links = text_links(&text);
        text
    } else {
        html.iter()
            .map(|part| {
                let (text, part_links) = html_view(part);
                links.extend(part_links);
                text
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let attachments = message
        .attachments()
        .filter(|part| !part.is_inline())
        .filter_map(|part| part.attachment_name())
        .filter(|file| !file.is_empty())
        .map(String::from)
        .collect();

    let date = message
        .all_received()
        .next()
        .and_then(|received| received.date())
        .or_else(|| message.date())
        .filter(|d| d.is_valid());
    let labels = message
        .headers()
        .get("X-Gmail-Labels")
        .map(|h| {
            String::from_utf8_lossy(h.raw_value())
                .split(',')
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let message_id = message.message_id().map_or_else(
        || {
            Sha256::digest(position.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        },
        String::from,
    );

    let mut obs = MailObservation {
        provider: Provider::Gmail,
        message_id,
        from_name: from.and_then(|m| m.name()).unwrap_or_default().to_string(),
        from_addr: from
            .and_then(|m| m.address())
            .unwrap_or_default()
            .to_string(),
        reply_to: message
            .reply_to()
            .and_then(|list| list.first())
            .and_then(|m| m.address())
            .map(String::from),
        to,
        subject: message.subject().unwrap_or_default().to_string(),
        body_text,
        links,
        attachments,
        truncated: false,
    };
    let padding = padding.map(|policy| measure_padding(&obs, &html, policy));
    cap(&mut obs, padding_rule);
    Ok(Mail {
        obs,
        year: date.map(|d| d.year),
        when_ms: date.map_or(0, |d| {
            u64::try_from(d.to_timestamp())
                .unwrap_or(0)
                .saturating_mul(1000)
        }),
        labels,
        padding,
    })
}

/// Runs of base64-alphabet characters, URL-safe ones included, measured on `obs` before the cap,
/// and what removing the runs longer than each limit would change against capping without the
/// padding rule. The engine runs with a fresh user, so only phrase cues are compared.
fn measure_padding(obs: &MailObservation, html: &[Cow<str>], policy: &Policy) -> Padding {
    let body = &obs.body_text;
    let over_cap = body.len() > MAX_BODY;
    let lengths: Vec<usize> = runs(body).collect();
    let in_long_runs =
        RUN_LIMITS.map(|limit| lengths.iter().filter(|n| **n > limit).sum::<usize>());
    let prose_in_cut =
        |text: &str| prose_words(&text[..text.floor_char_boundary(MAX_BODY)]) >= MIN_PROSE_WORDS;
    let phrase_cues = |body: &str| {
        let mut capped = obs.clone();
        capped.body_text = body.to_string();
        cap(&mut capped, false);
        let (assessment, _) = User::default().check_mail(policy, &capped, 0);
        assessment
            .cues
            .into_iter()
            .filter(|cue| cue.is_phrase())
            .collect::<Vec<_>>()
    };
    let affected = in_long_runs.iter().any(|n| *n > 0);
    let stripped = RUN_LIMITS.map(|limit| {
        lengths.iter().any(|n| *n > limit).then(|| {
            let text = strip_runs(body, limit);
            Stripped {
                fits: text.len() <= MAX_BODY,
                prose_in_cut: prose_in_cut(&text),
                after: phrase_cues(&text),
                one_character: body
                    .split(|c: char| !is_run_char(c))
                    .filter(|run| run.len() > limit)
                    .all(|run| run.bytes().all(|b| b == run.as_bytes()[0])),
            }
        })
    });
    let nodes = if over_cap {
        html.iter()
            .map(|part| padding_nodes(part))
            .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1))
    } else {
        (0, 0)
    };
    Padding {
        over_cap,
        walked: body.len(),
        longest_run: lengths.iter().copied().max().unwrap_or(0),
        in_long_runs,
        prose_in_cut: prose_in_cut(body),
        nodes,
        before: if affected {
            phrase_cues(body)
        } else {
            Vec::new()
        },
        stripped,
    }
}

fn is_run_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "+/=_-".contains(c)
}

/// Lengths of the maximal runs of base64-alphabet characters in `text`.
fn runs(text: &str) -> impl Iterator<Item = usize> + '_ {
    text.split(|c: char| !is_run_char(c))
        .map(str::len)
        .filter(|n| *n > 0)
}

/// `text` with each run longer than `limit` replaced by one space; everything else stays in place.
fn strip_runs(text: &str, limit: usize) -> String {
    let mut out = String::with_capacity(text.len());
    let mut start = 0;
    for (i, c) in text.char_indices().chain([(text.len(), ' ')]) {
        if !is_run_char(c) {
            if i - start <= limit {
                out.push_str(&text[start..i]);
            } else {
                out.push(' ');
            }
            if i < text.len() {
                out.push(c);
            }
            start = i + c.len_utf8();
        }
    }
    out
}

fn prose_words(text: &str) -> usize {
    text.split_whitespace()
        .filter(|w| w.chars().count() <= MAX_WORD_CHARS && w.chars().any(char::is_alphabetic))
        .count()
}

/// Text nodes the body-text walk reads (under `body`, outside `script` and `style`) that hold a run
/// longer than the smallest limit, and how many of them sit under an element an inline style hides.
fn padding_nodes(html: &str) -> (usize, usize) {
    let document = Html::parse_document(html);
    let body = Selector::parse("body").expect("constant selector");
    let Some(body) = document.select(&body).next() else {
        return (0, 0);
    };
    let mut nodes = (0, 0);
    for node in body.descendants() {
        let Node::Text(text) = node.value() else {
            continue;
        };
        let around: Vec<ElementRef<'_>> = node.ancestors().filter_map(ElementRef::wrap).collect();
        let read = !around
            .iter()
            .any(|e| matches!(e.value().name(), "script" | "style"));
        if read && runs(text).any(|n| n > RUN_LIMITS[0]) {
            nodes.0 += 1;
            if around.iter().any(|e| e.attr("style").is_some_and(hides)) {
                nodes.1 += 1;
            }
        }
    }
    nodes
}

/// An inline style that hides what it applies to: `display:none`, `visibility:hidden`, or a zero
/// `font-size`, `max-height` or `opacity` (`0`, `0px`, but not `0.5em`).
fn hides(style: &str) -> bool {
    let style = style.to_ascii_lowercase().replace(char::is_whitespace, "");
    let zero = |property: &str| {
        style.match_indices(property).any(|(i, _)| {
            !style[i + property.len()..].starts_with(|c: char| c.is_ascii_digit() || c == '.')
        })
    };
    style.contains("display:none")
        || style.contains("visibility:hidden")
        || ["font-size:0", "max-height:0", "opacity:0"]
            .into_iter()
            .any(zero)
}

/// Body text and links of an HTML part, read from the parsed document as the sensors read it. A
/// link is an `a` or an image map's `area` with an `href`, in document order.
fn html_view(html: &str) -> (String, Vec<Link>) {
    let document = Html::parse_document(html);
    let body = Selector::parse("body").expect("constant selector");
    let anchors = Selector::parse("a[href], area[href]").expect("constant selector");
    let body = document
        .select(&body)
        .next()
        .unwrap_or_else(|| document.root_element());
    let links = body
        .select(&anchors)
        .map(|a| Link {
            text: walk(a)
                .split(is_js_space)
                .filter(|word| !word.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
            href: a.attr("href").unwrap_or_default().to_string(),
        })
        .collect();
    (walk(body), links)
}

/// Whitespace as JavaScript's `\s` matches it, which the sensors use to collapse a link's text:
/// Unicode's White_Space without U+0085, plus U+FEFF.
fn is_js_space(c: char) -> bool {
    c == '\u{feff}' || (c != '\u{85}' && c.is_whitespace())
}

/// The sensors' body-text walk: text nodes as they are, nothing from `script` or `style`, a newline
/// before and after a block element, one for `br` and `hr`. A stack, not recursion, so a deeply
/// nested document cannot overflow it.
fn walk(root: ElementRef) -> String {
    let mut text = String::new();
    let mut stack = vec![(*root, false)];
    while let Some((node, closing)) = stack.pop() {
        if closing {
            text.push('\n');
            continue;
        }
        match node.value() {
            Node::Text(t) => text.push_str(t),
            Node::Element(e) => match e.name() {
                "script" | "style" => {}
                "br" | "hr" => text.push('\n'),
                tag => {
                    if BLOCKS.contains(&tag) {
                        text.push('\n');
                        stack.push((node, true));
                    }
                    stack.extend(node.children().rev().map(|child| (child, false)));
                }
            },
            _ => {}
        }
    }
    text
}

/// The URLs of a plain-text body as links whose text is the URL. An approximation of a mail
/// client's linkifier: only `http://` and `https://`.
fn text_links(text: &str) -> Vec<Link> {
    text.split_whitespace()
        .filter_map(|word| {
            let lower = word.to_ascii_lowercase();
            let start = ["http://", "https://"]
                .into_iter()
                .filter_map(|scheme| lower.find(scheme))
                .min()?;
            let url = word[start..].trim_end_matches(|c: char| ".,;:!?'\")]}>".contains(c));
            Some(Link {
                text: url.to_string(),
                href: url.to_string(),
            })
        })
        .collect()
}

/// The worker's capping (docs/PHISHING.md, "Capping"), `truncated` included, preceded by the padding
/// rule unless `padding_rule` is off.
fn cap(mail: &mut MailObservation, padding_rule: bool) {
    let before = mail.body_text.len();
    if padding_rule {
        mail.body_text = strip_runs(&mail.body_text, PADDING_RUN);
    }
    // A removed run always shortens the body: it held more than 256 characters and left one space.
    let mut cut = mail.body_text.len() < before
        || mail.to.len() > MAX_RECIPIENTS
        || mail.links.len() > MAX_LINKS
        || mail.attachments.len() > MAX_ATTACHMENTS;
    mail.to.truncate(MAX_RECIPIENTS);
    mail.links.truncate(MAX_LINKS);
    mail.attachments.truncate(MAX_ATTACHMENTS);
    let mut fit = |text: &mut String, max: usize| {
        if text.len() > max {
            text.truncate(text.floor_char_boundary(max));
            cut = true;
        }
    };
    for text in [
        &mut mail.message_id,
        &mut mail.from_name,
        &mut mail.from_addr,
        &mut mail.subject,
    ] {
        fit(text, MAX_STRING);
    }
    if let Some(reply_to) = &mut mail.reply_to {
        fit(reply_to, MAX_STRING);
    }
    fit(&mut mail.body_text, MAX_BODY);
    for text in mail.to.iter_mut().chain(&mut mail.attachments) {
        fit(text, MAX_STRING);
    }
    for link in &mut mail.links {
        fit(&mut link.text, MAX_STRING);
        fit(&mut link.href, MAX_HREF);
    }
    mail.truncated = cut;
    // Measured once, then reduced by what each dropped entry took: its text, and a comma unless
    // it was the list's last entry, plus one when `false` becomes `true`.
    let mut size = request_len(mail);
    while size > MAX_REQUEST {
        let (entry, left) = if let Some(link) = mail.links.pop() {
            (link_len(&link), mail.links.len())
        } else if let Some(to) = mail.to.pop() {
            (string_len(&to), mail.to.len())
        } else {
            break;
        };
        size -= entry + usize::from(left > 0) + usize::from(!mail.truncated);
        mail.truncated = true;
    }
    debug_assert_eq!(size, request_len(mail));
    assert!(mail.check_limits().is_ok());
}

/// UTF-8 length of a string as `JSON.stringify` writes it.
fn string_len(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if c < ' ' => 6,
            c => c.len_utf8(),
        })
        .sum::<usize>()
}

fn link_len(link: &Link) -> usize {
    r#"{"text":,"href":}"#.len() + string_len(&link.text) + string_len(&link.href)
}

/// UTF-8 length of `JSON.stringify({CheckMail: mail})`, the size the worker budgets.
fn request_len(mail: &MailObservation) -> usize {
    let list = |items: Vec<usize>| 2 + items.iter().sum::<usize>() + items.len().saturating_sub(1);
    let strings = |items: &[String]| list(items.iter().map(|s| string_len(s)).collect());
    let provider = match mail.provider {
        Provider::Gmail => "gmail",
        Provider::OutlookWeb => "outlook_web",
        Provider::OutlookAddin => "outlook_addin",
    };
    let fields = [
        ("provider", string_len(provider)),
        ("message_id", string_len(&mail.message_id)),
        ("from_name", string_len(&mail.from_name)),
        ("from_addr", string_len(&mail.from_addr)),
        ("reply_to", mail.reply_to.as_deref().map_or(4, string_len)),
        ("to", strings(&mail.to)),
        ("subject", string_len(&mail.subject)),
        ("body_text", string_len(&mail.body_text)),
        ("links", list(mail.links.iter().map(link_len).collect())),
        ("attachments", strings(&mail.attachments)),
        ("truncated", if mail.truncated { 4 } else { 5 }),
    ];
    r#"{"CheckMail":{}}"#.len()
        + fields
            .iter()
            .map(|(key, value)| key.len() + r#""":"#.len() + value)
            .sum::<usize>()
        + fields.len()
        - 1
}

fn replay(policy: &Policy, seed: &User, mut mails: Vec<Mail>, chronological: bool) -> Vec<Outcome> {
    if chronological {
        mails.sort_by_key(|m| m.when_ms);
    }
    let mut user = seed.clone();
    mails
        .iter()
        .map(|m| {
            if !chronological {
                user = seed.clone();
            }
            let (assessment, _) = user.check_mail(policy, &m.obs, m.when_ms);
            Outcome {
                year: m.year,
                body: Sha256::digest(m.obs.body_text.as_bytes()).into(),
                cues: assessment.cues,
                level: assessment.level,
                truncated: m.obs.truncated,
                lookalike_hosts: lookalike_hosts(&m.obs, policy).len(),
                lookalikes: assessment.lookalikes,
            }
        })
        .collect()
}

/// Nearest-rank percentile of sorted values, `permille` thousandths: the smallest value at or
/// below which that share of the values lies.
fn percentile(sorted: &[usize], permille: usize) -> usize {
    let rank = (permille * sorted.len()).div_ceil(1000).max(1);
    sorted.get(rank - 1).copied().unwrap_or(0)
}

/// Messages per lookalike hit, keyed by cue, candidate and known domain (registrable domains, from
/// the engine's own hit list), most frequent first within a cue.
fn lookalike_hits(outcomes: &[Outcome]) -> Vec<(&LookalikeHit, usize)> {
    let mut counts: BTreeMap<(Cue, &str, &str), (&LookalikeHit, usize)> = BTreeMap::new();
    for hit in outcomes.iter().flat_map(|o| &o.lookalikes) {
        let key = (hit.cue, hit.candidate.as_str(), hit.known.as_str());
        counts.entry(key).or_insert((hit, 0)).1 += 1;
    }
    let mut hits: Vec<_> = counts.into_values().collect();
    hits.sort_by_key(|(hit, n)| (hit.cue, std::cmp::Reverse(*n)));
    hits
}

/// The first outcome of each distinct body text, in input order.
fn distinct(outcomes: &[Outcome]) -> Vec<&Outcome> {
    let mut seen = BTreeSet::new();
    outcomes.iter().filter(|o| seen.insert(o.body)).collect()
}

fn fired<'a>(outcomes: impl IntoIterator<Item = &'a Outcome>, cue: Cue) -> usize {
    outcomes
        .into_iter()
        .filter(|o| o.cues.contains(&cue))
        .count()
}

fn mail_cues() -> impl Iterator<Item = Cue> {
    Cue::ALL.into_iter().filter(|cue| !cue.is_page())
}

fn pct(k: usize, n: usize) -> String {
    if n == 0 {
        "-".into()
    } else {
        format!("{:.1}", 100.0 * k as f64 / n as f64)
    }
}

/// ln of the phishing rate over the legitimate rate, each smoothed as (k + 0.5) / (n + 1).
fn log_ratio(k_phish: usize, n_phish: usize, k_legit: usize, n_legit: usize) -> f64 {
    let rate = |k: usize, n: usize| (k as f64 + SMOOTHING) / (n as f64 + 2.0 * SMOOTHING);
    (rate(k_phish, n_phish) / rate(k_legit, n_legit)).ln()
}

fn supported(k_phish: usize, k_legit: usize) -> bool {
    k_phish >= MIN_SUPPORT && k_legit >= MIN_SUPPORT
}

fn print_input(
    label: &str,
    tally: &Tally,
    outcomes: &[Outcome],
    note: &dyn Fn(Cue) -> &'static str,
) {
    let set = distinct(outcomes);
    let levels = |all: Vec<Level>| {
        let count = |level| all.iter().filter(|l| **l == level).count();
        format!(
            "none {}, caution {}, danger {}",
            count(Level::None),
            count(Level::Caution),
            count(Level::Danger)
        )
    };
    println!("\n== {label} ==");
    println!(
        "messages read {}; not parseable {}; mail-store placeholders {}; dropped by label filter {}; checked {}",
        tally.read, tally.unparsed, tally.placeholders, tally.filtered, outcomes.len()
    );
    println!(
        "distinct bodies {}; truncated observations {}",
        set.len(),
        outcomes.iter().filter(|o| o.truncated).count()
    );
    println!(
        "levels over messages: {}",
        levels(outcomes.iter().map(|o| o.level).collect())
    );
    println!(
        "levels over distinct bodies: {}",
        levels(set.iter().map(|o| o.level).collect())
    );
    let mut hosts: Vec<usize> = outcomes.iter().map(|o| o.lookalike_hosts).collect();
    hosts.sort_unstable();
    let over = |n: usize| hosts.iter().filter(|h| **h > n).count();
    println!(
        "lookalike candidate hosts per message, sender's domain included (nearest rank): median {}, p90 {}, p99 {}, p99.9 {}, max {}; messages over 50: {}, over 100: {}, over 200: {}",
        percentile(&hosts, 500),
        percentile(&hosts, 900),
        percentile(&hosts, 990),
        percentile(&hosts, 999),
        hosts.last().copied().unwrap_or(0),
        over(50),
        over(100),
        over(200)
    );

    println!(
        "\n{:<42} {:>9} {:>6} {:>9} {:>6}  note",
        "cue", "distinct", "%", "messages", "%"
    );
    for cue in mail_cues() {
        let (k, m) = (fired(set.iter().copied(), cue), fired(outcomes, cue));
        println!(
            "{:<42} {:>9} {:>6} {:>9} {:>6}  {}",
            cue.id(),
            k,
            pct(k, set.len()),
            m,
            pct(m, outcomes.len()),
            note(cue)
        );
    }

    let hits = lookalike_hits(outcomes);
    if !hits.is_empty() {
        println!("\nlookalike hits (registrable domains): cue, candidate, known, messages");
        for (hit, n) in hits {
            println!(
                "{:<30} {:<40} {:<30} {n:>6}",
                hit.cue.id(),
                hit.candidate,
                hit.known
            );
        }
    }

    let mut years: BTreeMap<Option<u16>, (usize, Vec<&Outcome>)> = BTreeMap::new();
    for o in outcomes {
        years.entry(o.year).or_default().0 += 1;
    }
    for &o in &set {
        years.entry(o.year).or_default().1.push(o);
    }
    if years.keys().all(Option::is_none) {
        println!("\nno dated messages");
        return;
    }
    let row = |head: &str, cells: Vec<String>| {
        println!(
            "{head:<42} {}",
            cells.iter().map(|c| format!("{c:>8}")).collect::<String>()
        );
    };
    println!("\nper year, % of distinct bodies (year of the topmost Received header, else Date)");
    row(
        "year",
        years
            .keys()
            .map(|y| y.map_or_else(|| "undated".into(), |y| y.to_string()))
            .collect(),
    );
    row(
        "messages",
        years.values().map(|(m, _)| m.to_string()).collect(),
    );
    row(
        "distinct bodies",
        years.values().map(|(_, d)| d.len().to_string()).collect(),
    );
    for cue in mail_cues() {
        row(
            cue.id(),
            years
                .values()
                .map(|(_, d)| pct(fired(d.iter().copied(), cue), d.len()))
                .collect(),
        );
    }
}

fn print_padding(paddings: &[Padding]) {
    let over: Vec<&Padding> = paddings.iter().filter(|p| p.over_cap).collect();
    let count =
        |set: &[&Padding], test: &dyn Fn(&Padding) -> bool| set.iter().filter(|p| test(p)).count();
    println!(
        "\npadding, per message: walked text over the {MAX_BODY}-byte body cap in {} of {}; a run is a maximal run of A-Z a-z 0-9 + / = _ -",
        over.len(),
        paddings.len()
    );
    if !over.is_empty() {
        let mut longest: Vec<usize> = over.iter().map(|p| p.longest_run).collect();
        longest.sort_unstable();
        let walked: usize = over.iter().map(|p| p.walked).sum();
        let shares: Vec<String> = RUN_LIMITS
            .iter()
            .enumerate()
            .map(|(i, limit)| {
                let bytes = over.iter().map(|p| p.in_long_runs[i]).sum();
                format!("> {limit}: {}%", pct(bytes, walked))
            })
            .collect();
        println!(
            "over the cap: longest run p10 {}, median {}, p90 {}; share of their walked text in runs {}",
            percentile(&longest, 100),
            percentile(&longest, 500),
            percentile(&longest, 900),
            shares.join(", ")
        );
        println!(
            "over the cap: text nodes holding a run > {}: none {}, 1 {}, 2-10 {}, 11-100 {}, over 100 {}; where there are any, an inline style hides all {}, some {}, none {}",
            RUN_LIMITS[0],
            count(&over, &|p| p.nodes.0 == 0),
            count(&over, &|p| p.nodes.0 == 1),
            count(&over, &|p| (2..=10).contains(&p.nodes.0)),
            count(&over, &|p| (11..=100).contains(&p.nodes.0)),
            count(&over, &|p| p.nodes.0 > 100),
            count(&over, &|p| p.nodes.0 > 0 && p.nodes.1 == p.nodes.0),
            count(&over, &|p| p.nodes.1 > 0 && p.nodes.1 < p.nodes.0),
            count(&over, &|p| p.nodes.0 > 0 && p.nodes.1 == 0),
        );
        println!(
            "over the cap: at least {MIN_PROSE_WORDS} prose words (tokens of at most {MAX_WORD_CHARS} characters with a letter) inside the cut as is: {}",
            count(&over, &|p| p.prose_in_cut)
        );
    }

    let all: Vec<&Padding> = paddings.iter().collect();
    let row = |head: &str, cell: &dyn Fn(usize, &Padding) -> bool, set: &[&Padding]| {
        let cells: String = (0..RUN_LIMITS.len())
            .map(|i| format!("{:>14}", count(set, &|p| cell(i, p))))
            .collect();
        println!("{head:<50}{cells}");
    };
    println!(
        "\nwhat-if: remove runs longer than N before the cut (the engine's input stays as it is)"
    );
    println!(
        "{:<50}{}",
        "N",
        RUN_LIMITS.map(|n| format!("{n:>14}")).concat()
    );
    let lost = |i: usize, p: &Padding| p.stripped[i].is_some();
    row("messages that lose a run", &lost, &all);
    row(
        "  of them under the cap (collateral)",
        &|i, p| !p.over_cap && lost(i, p),
        &all,
    );
    row(
        "    removing only runs of one repeated character",
        &|i, p| !p.over_cap && p.stripped[i].as_ref().is_some_and(|s| s.one_character),
        &all,
    );
    row(
        "over the cap: fit under it after",
        &|i, p| p.stripped[i].as_ref().is_some_and(|s| s.fits),
        &over,
    );
    row(
        "over the cap: enough prose words inside the cut after",
        &|i, p| {
            p.stripped[i]
                .as_ref()
                .map_or(p.prose_in_cut, |s| s.prose_in_cut)
        },
        &over,
    );
    println!("phrase cues on the messages that lose a run, before -> after");
    let changes = |head: &str, fired: &dyn Fn(&[Cue]) -> bool| {
        let cells: String = (0..RUN_LIMITS.len())
            .map(|i| {
                let lost = paddings
                    .iter()
                    .filter_map(|p| p.stripped[i].as_ref().map(|s| (p, s)));
                let before = lost.clone().filter(|(p, _)| fired(&p.before)).count();
                let after = lost.filter(|(_, s)| fired(&s.after)).count();
                format!("{:>14}", format!("{before} -> {after}"))
            })
            .collect();
        println!("  {head:<48}{cells}");
    };
    for cue in Cue::ALL.into_iter().filter(|cue| cue.is_phrase()) {
        changes(cue.id(), &|cues| cues.contains(&cue));
    }
    changes("any phrase cue", &|cues| !cues.is_empty());
}

fn print_two_sided(
    (phish, p): (&str, &[&Outcome]),
    (legit, l): (&str, &[&Outcome]),
    note: &dyn Fn(Cue) -> &'static str,
) {
    println!("\n== two-sided: {phish} as phishing against {legit} as legitimate, over distinct bodies ==");
    println!(
        "rate = (k + {SMOOTHING}) / (n + {}) on each side; ln ratio = ln(phishing rate / legitimate rate); support = at least {MIN_SUPPORT} on each side",
        2.0 * SMOOTHING
    );
    println!("n: {phish} {}, {legit} {}", p.len(), l.len());
    println!(
        "\n{:<42} {:>8} {:>6} {:>8} {:>6} {:>9} {:>8}  note",
        "cue", "k phish", "%", "k legit", "%", "ln ratio", "support"
    );
    for cue in mail_cues() {
        let (kp, kl) = (fired(p.iter().copied(), cue), fired(l.iter().copied(), cue));
        // With nothing on either side the smoothed ratio only reflects the two sample sizes.
        let ratio = if note(cue).is_empty() && kp + kl > 0 {
            format!("{:.2}", log_ratio(kp, p.len(), kl, l.len()))
        } else {
            "-".into()
        };
        println!(
            "{:<42} {:>8} {:>6} {:>8} {:>6} {:>9} {:>8}  {}",
            cue.id(),
            kp,
            pct(kp, p.len()),
            kl,
            pct(kl, l.len()),
            ratio,
            if supported(kp, kl) { "yes" } else { "no" },
            note(cue)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail(raw: &str) -> MailObservation {
        observe(raw.as_bytes(), "test", None, true).unwrap().obs
    }

    fn lines(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    }

    #[test]
    fn two_adjacent_blocks_give_two_lines() {
        let (text, _) = html_view("<p>Thanks</p><p>Human Resources</p>");
        assert_eq!(lines(&text), ["Thanks", "Human Resources"]);
    }

    #[test]
    fn br_breaks_a_line() {
        let (text, _) = html_view("Hello<br>world");
        assert_eq!(lines(&text), ["Hello", "world"]);
    }

    #[test]
    fn adjacent_table_cells_do_not_glue() {
        let (text, _) = html_view("<table><tr><td>left</td><td>right</td></tr></table>");
        assert_eq!(lines(&text), ["left", "right"]);
    }

    #[test]
    fn script_and_style_content_is_absent() {
        let (text, _) =
            html_view("<style>p { color: red }</style><p>shown</p><script>var hidden;</script>");
        assert_eq!(lines(&text), ["shown"]);
    }

    #[test]
    fn inline_elements_inside_a_sentence_add_nothing() {
        let (text, _) = html_view("<p>Hello <b>dear</b> <span>user</span>, <a href=x>here</a></p>");
        assert_eq!(lines(&text), ["Hello dear user, here"]);
    }

    #[test]
    fn a_link_over_inline_and_block_children_is_one_line_with_single_spaces() {
        let (_, links) = html_view("<a href=\"x\"><span>Sign</span>\n<div>in   now</div></a>");
        assert_eq!(links[0].text, "Sign in now");
    }

    #[test]
    fn link_text_collapses_what_javascript_calls_whitespace() {
        // U+FEFF is whitespace to JavaScript's `\s` and U+0085 is not; U+00A0 is to both.
        let (_, links) =
            html_view("<a href=\"x\">\u{a0}Sign\u{feff}\u{feff}in\u{85}now\u{feff}</a>");
        assert_eq!(links[0].text, "Sign in\u{85}now");
        assert!(is_js_space('\u{3000}') && is_js_space('\t') && !is_js_space('\u{85}'));
    }

    #[test]
    fn links_keep_the_raw_href_and_anchors_without_href_are_not_links() {
        let (_, links) =
            html_view("<a href=\" HTTPS://Example.COM/a?b=1&amp;c=2 \">Go</a><a name=top>Top</a>");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].href, " HTTPS://Example.COM/a?b=1&c=2 ");
    }

    #[test]
    fn image_map_areas_with_an_href_are_links_with_empty_text_in_document_order() {
        let (_, links) = html_view(
            "<a href=\"https://one.example/\">one</a>\
             <map name=m><area shape=rect href=\"https://two.example/\"><area shape=rect></map>\
             <a href=\"https://three.example/\">three</a>",
        );
        let found: Vec<(&str, &str)> = links
            .iter()
            .map(|l| (l.text.as_str(), l.href.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                ("one", "https://one.example/"),
                ("", "https://two.example/"),
                ("three", "https://three.example/")
            ]
        );
    }

    #[test]
    fn the_html_part_is_read_instead_of_a_decoy_text_part() {
        let m = mail(concat!(
            "From: Sender <sender@example.com>\n",
            "Subject: s\n",
            "Content-Type: multipart/alternative; boundary=b\n\n",
            "--b\nContent-Type: text/plain\n\nDecoy words\n",
            "--b\nContent-Type: text/html\n\n<p>Real words <a href=\"https://example.org/x\">here</a></p>\n",
            "--b--\n",
        ));
        assert_eq!(lines(&m.body_text), ["Real words here"]);
        assert_eq!(m.links[0].href, "https://example.org/x");
        assert_eq!(
            (m.from_name.as_str(), m.from_addr.as_str()),
            ("Sender", "sender@example.com")
        );
    }

    #[test]
    fn a_message_without_html_uses_its_text_as_is_and_its_urls_as_links() {
        let m = mail(concat!(
            "From: sender@example.com\n",
            "Content-Type: text/plain\n\n",
            "Line one\n  see <https://example.org/a>, then http://example.net.\n",
        ));
        assert_eq!(
            m.body_text,
            "Line one\n  see <https://example.org/a>, then http://example.net.\n"
        );
        let hrefs: Vec<&str> = m.links.iter().map(|l| l.href.as_str()).collect();
        assert_eq!(hrefs, ["https://example.org/a", "http://example.net"]);
        assert!(m.links.iter().all(|l| l.text == l.href));
    }

    #[test]
    fn inline_images_are_not_attachments() {
        let m = mail(concat!(
            "From: sender@example.com\n",
            "Content-Type: multipart/mixed; boundary=outer\n\n",
            "--outer\nContent-Type: multipart/related; boundary=inner\n\n",
            "--inner\nContent-Type: text/html\n\n<p>hi <img src=\"cid:logo\"></p>\n",
            "--inner\nContent-Type: image/png; name=logo.png\n",
            "Content-Disposition: inline; filename=logo.png\nContent-ID: <logo>\n",
            "Content-Transfer-Encoding: base64\n\niVBORw0KGgo=\n",
            "--inner--\n",
            "--outer\nContent-Type: application/pdf; name=invoice.pdf\n",
            "Content-Disposition: attachment; filename=invoice.pdf\n",
            "Content-Transfer-Encoding: base64\n\nJVBERi0xLjQK\n",
            "--outer--\n",
        ));
        assert_eq!(m.attachments, ["invoice.pdf"]);
    }

    #[test]
    fn non_utf8_charsets_are_decoded() {
        let latin1 = mail(concat!(
            "From: sender@example.com\n",
            "Content-Type: text/html; charset=iso-8859-1\n",
            "Content-Transfer-Encoding: quoted-printable\n\n",
            "<p>caf=E9</p>\n",
        ));
        assert_eq!(lines(&latin1.body_text), ["café"]);

        let mut raw =
            b"From: sender@example.com\nContent-Type: text/plain; charset=shift_jis\n\n".to_vec();
        raw.extend_from_slice(b"\x93\xfa\x96\x7b\n");
        let sjis = observe(&raw, "test", None, true).unwrap().obs;
        assert_eq!(sjis.body_text.trim(), "日本");
    }

    #[test]
    fn a_leading_envelope_line_is_not_a_header() {
        let m = mail("From sender@example.com Fri Jan  2 03:04:05 2015\nSubject: kept\n\nbody\n");
        assert_eq!(m.subject, "kept");
    }

    #[test]
    fn the_mbox_splits_only_at_envelope_lines_after_a_blank_line() {
        let mbox = concat!(
            "From MAILER-DAEMON Fri Jan  2 03:04:05 2015\n",
            "Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\n\nstore\n\n",
            "From a@example.com Sat Jan  3 01:05:34 2015\n",
            "Subject: one\n\n",
            "From the start of the week, nothing changed.\n",
            "From b@example.com Sun Jan  4 01:05:34 2015 +0000\n",
            "\n",
            "From c@example.com Mon Jan  5 01:05:34 +0000 2015\n",
            "Subject: two\n\nbody\n",
        );
        let mut messages = Vec::new();
        split_mbox(mbox.as_bytes(), |m| messages.push(m)).unwrap();
        assert_eq!(messages.len(), 3);
        let one = String::from_utf8(messages[1].clone()).unwrap();
        assert!(one.contains("From the start of the week"));
        assert!(one.contains("From b@example.com Sun Jan  4"));
        assert!(String::from_utf8_lossy(&messages[2]).starts_with("Subject: two"));
    }

    #[test]
    fn placeholders_and_files_that_are_not_messages_are_skipped() {
        let dir = std::env::temp_dir().join(format!("riggs-eval-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let message = "From: sender@example.com\nSubject: s\n\nbody\n";
        let md5 = "0123456789abcdef0123456789abcdef";
        for (file, content) in [
            (format!("00001.{md5}"), message),
            ("cmds".to_string(), "mv 00001 00002\n"),
            ("sample-1.eml".to_string(), message),
            ("sample-2.eml".to_string(), ""),
            ("listing.csv".to_string(), "a,b\n"),
        ] {
            std::fs::write(dir.join(file), content).unwrap();
        }
        let mbox = dir.join("mbox");
        std::fs::write(
            &mbox,
            concat!(
                "From MAILER-DAEMON Fri Jan  2 03:04:05 2015\n",
                "Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\n\nstore\n\n",
                "From a@example.com Sat Jan  3 01:05:34 2015\n",
                "Date: Sat, 3 Jan 2015 01:05:34 +0000\nSubject: one\n\nbody\n",
            ),
        )
        .unwrap();

        let read = |source: Source| read_input(&[source], &[], &[], None, true).unwrap();
        let (sa, mails) = read(Source::SaDir(dir.clone()));
        assert_eq!((sa.read, mails.len()), (1, 1));
        let (eml, mails) = read(Source::Eml(dir.clone(), "sample-*.eml".into()));
        assert_eq!((eml.read, eml.unparsed, mails.len()), (2, 1, 1));
        let (mbox, mails) = read(Source::Mbox(mbox));
        assert_eq!((mbox.read, mbox.placeholders, mails.len()), (2, 1, 1));
        assert_eq!(mails[0].obs.subject, "one");
        assert_eq!(mails[0].year, Some(2015));
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(!is_sa_name("cmds"));
        assert!(!matches_glob("sample-*.eml", "oroginal3989.csv"));
    }

    #[test]
    fn gmail_labels_keep_and_drop() {
        let labels = vec!["Inbox".to_string(), "Spam".to_string()];
        let (inbox, spam) = (vec!["Inbox".to_string()], vec!["Spam".to_string()]);
        assert!(wanted(&labels, &[], &[]));
        assert!(wanted(&labels, &inbox, &[]));
        assert!(!wanted(&labels, &inbox, &spam));
        assert!(!wanted(&[], &inbox, &[]));
    }

    #[test]
    fn a_parse_failure_names_nothing_from_the_input() {
        let raw = b"secret-marker-without-any-header-or-blank-line";
        let Err(error) = observe(raw, "p", None, true) else {
            panic!("expected a parse failure");
        };
        assert!(!error.contains("secret") && !error.contains("marker"));
        assert!(observe(b"", "p", None, true).is_err());
    }

    #[test]
    fn a_missing_message_id_is_a_hash_of_the_position() {
        let raw = b"From: sender@example.com\n\nbody\n";
        let (a, b) = (
            observe(raw, "a#1", None, true).unwrap(),
            observe(raw, "a#2", None, true).unwrap(),
        );
        assert_eq!(a.obs.message_id.len(), 64);
        assert_ne!(a.obs.message_id, b.obs.message_id);
    }

    #[test]
    fn chronological_replay_fills_the_sender_history_in_date_order() {
        let policy = load_policy_file(Path::new(SHIPPED_POLICY)).unwrap();
        let raw = |id: &str, date: &str| {
            format!("From: a@example.com\nMessage-ID: <{id}@example.com>\nDate: {date}\n\n{id}\n")
        };
        let mails = || {
            vec![
                observe(
                    raw("late", "Tue, 3 Feb 2015 00:00:00 +0000").as_bytes(),
                    "1",
                    None,
                    true,
                )
                .unwrap(),
                observe(
                    raw("early", "Fri, 3 Jan 2014 00:00:00 +0000").as_bytes(),
                    "2",
                    None,
                    true,
                )
                .unwrap(),
            ]
        };
        let summary = |outcomes: Vec<Outcome>| -> Vec<(Option<u16>, bool)> {
            outcomes
                .iter()
                .map(|o| (o.year, o.cues.contains(&Cue::SenderNeverSeen)))
                .collect()
        };
        let chronological = replay(&policy, &User::default(), mails(), true);
        assert_eq!(
            summary(chronological),
            [(Some(2014), true), (Some(2015), false)]
        );
        let independent = replay(&policy, &User::default(), mails(), false);
        assert_eq!(
            summary(independent),
            [(Some(2015), true), (Some(2014), true)]
        );
    }

    #[test]
    fn runs_are_base64_alphabet_and_only_the_long_ones_are_removed() {
        let text = format!(
            "Hi {} there,{}\nok_-+/= done",
            "A".repeat(70),
            "b".repeat(130)
        );
        assert_eq!(runs(&text).collect::<Vec<_>>(), [2, 70, 5, 130, 7, 4]);
        assert_eq!(strip_runs(&text, 64), "Hi   there, \nok_-+/= done");
        assert_eq!(
            strip_runs(&text, 128),
            format!("Hi {} there, \nok_-+/= done", "A".repeat(70))
        );
        assert_eq!(strip_runs(&text, 1024), text);
        let long_token = "a".repeat(MAX_WORD_CHARS + 1);
        assert_eq!(
            prose_words(&format!("one two 3 four, five-six é {long_token}")),
            5
        );
    }

    #[test]
    fn inline_styles_that_hide_are_told_from_those_that_do_not() {
        for style in [
            "DISPLAY: none",
            "color:red; font-size: 0px",
            "opacity:0",
            "max-height:0;overflow:hidden",
            "visibility:hidden",
        ] {
            assert!(hides(style), "{style}");
        }
        for style in ["font-size:0.9em", "opacity:0.5", "display:block", ""] {
            assert!(!hides(style), "{style}");
        }
    }

    #[test]
    fn padding_nodes_are_the_walked_text_nodes_with_a_long_run() {
        let run = "Zm9v".repeat(20);
        let html = format!(
            "<div style=\"display:none\">{run}</div><p style=\"font-size:0.9em\">{run}</p>\
             <style>.x {{ background: url({run}) }}</style><p>short words</p>"
        );
        assert_eq!(padding_nodes(&html), (2, 1));
    }

    #[test]
    fn padding_before_the_visible_text_is_measured_and_the_what_if_recovers_the_text() {
        let policy = load_policy_file(Path::new(SHIPPED_POLICY)).unwrap();
        let padding = "Zm9v".repeat(20_000);
        let prose = "Your mailbox is almost full so please confirm your details at once today";
        let raw = format!(
            "From: sender@example.com\nContent-Type: text/html\n\n\
             <div style=\"font-size:0px\">{padding}</div><p>{prose}</p>\n"
        );
        let mail = observe(raw.as_bytes(), "p", Some(&policy), true).unwrap();
        assert!(mail.obs.truncated);
        let p = mail.padding.unwrap();
        assert!(p.over_cap && !p.prose_in_cut);
        assert_eq!(p.longest_run, padding.len());
        assert_eq!(p.in_long_runs, [padding.len(); 4]);
        assert_eq!(p.nodes, (1, 1));
        assert!(p.before.iter().all(|cue| cue.is_phrase()));
        for stripped in &p.stripped {
            let s = stripped.as_ref().unwrap();
            assert!(s.fits && s.prose_in_cut && !s.one_character);
            assert!(s.after.iter().all(|cue| cue.is_phrase()));
        }

        let short = format!(
            "From: sender@example.com\n\nreference {} here\n",
            "x".repeat(100)
        );
        let p = observe(short.as_bytes(), "p", Some(&policy), true)
            .unwrap()
            .padding
            .unwrap();
        assert!(!p.over_cap);
        assert_eq!(
            p.stripped.each_ref().map(Option::is_some),
            [true, false, false, false]
        );
        assert!(p.stripped[0].as_ref().unwrap().one_character);
    }

    /// The cases `riggs-phish-padding.md` lists.
    #[test]
    fn the_padding_rule_replaces_long_runs_before_the_cut() {
        let capped = |body: String| {
            let mut m = mail("From: sender@example.com\n\nbody\n");
            m.body_text = body;
            cap(&mut m, true);
            (m.body_text, m.truncated)
        };
        let sentence = "Please confirm your account details today.";

        let after_run = capped(format!("{}\n{sentence}", "Q".repeat(300)));
        assert_eq!(after_run, (format!(" \n{sentence}"), true));

        let at_limit = "Q".repeat(PADDING_RUN);
        assert_eq!(capped(at_limit.clone()), (at_limit, false));

        for interruption in [" ", ".", "é"] {
            let body = format!("{}{interruption}{}", "Q".repeat(255), "Q".repeat(256));
            assert_eq!(capped(body.clone()), (body, false), "{interruption}");
        }

        let (body, truncated) = capped(format!("{}\n{sentence}", "Zm9v".repeat(20_000)));
        assert!(truncated && body.len() <= MAX_BODY && body.contains(sentence));

        let run = "Q".repeat(300);
        let around = capped(format!("{run} middle words {run}"));
        assert_eq!(around, ("  middle words  ".to_string(), true));

        let no_spaces = "日本語の文章".repeat(2_000);
        assert_eq!(capped(no_spaces.clone()), (no_spaces, false));
    }

    #[test]
    fn lookalike_hits_come_from_the_engine_with_both_registrable_domains() {
        let policy = load_policy_file(Path::new(SHIPPED_POLICY)).unwrap();
        let login = LoginRow {
            domain: "amazon.com".into(),
            first_ms: 0,
            last_ms: 0,
            count: 1,
        };
        let seed = User::new([login], []).unwrap();
        let mails: Vec<Mail> = [
            "orders@mail.amazan.com",
            "orders@amazan.com",
            "news@example.org",
        ]
        .map(|from| {
            let raw = format!("From: {from}\n\nhello\n");
            observe(raw.as_bytes(), from, None, true).unwrap()
        })
        .into();
        let outcomes = replay(&policy, &seed, mails, false);
        let hits: Vec<(Cue, &str, &str, usize)> = lookalike_hits(&outcomes)
            .into_iter()
            .map(|(hit, n)| (hit.cue, hit.candidate.as_str(), hit.known.as_str(), n))
            .collect();
        assert_eq!(
            hits,
            [(
                Cue::DomainLookalikeMisspelling,
                "amazan.com",
                "amazon.com",
                2
            )]
        );
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        let ten: Vec<usize> = (1..=10).collect();
        assert_eq!(
            [500, 900, 990, 999].map(|p| percentile(&ten, p)),
            [5, 9, 10, 10]
        );
        let thousand: Vec<usize> = (1..=1000).collect();
        assert_eq!(percentile(&thousand, 999), 999);
        assert_eq!(percentile(&[], 500), 0);
    }

    #[test]
    fn distinct_bodies_count_once_in_input_order() {
        let outcome = |body: u8, year| Outcome {
            year: Some(year),
            body: [body; 32],
            cues: vec![],
            level: Level::None,
            truncated: false,
            lookalike_hosts: 0,
            lookalikes: vec![],
        };
        let outcomes = [outcome(1, 2020), outcome(2, 2021), outcome(1, 2022)];
        let set = distinct(&outcomes);
        assert_eq!(set.len(), 2);
        assert_eq!(set[0].year, Some(2020));
    }

    #[test]
    fn the_log_ratio_is_smoothed_and_support_needs_ten_on_each_side() {
        assert_eq!(log_ratio(0, 0, 0, 0), 0.0);
        assert!((log_ratio(9, 9, 0, 9) - 19f64.ln()).abs() < 1e-12);
        assert!((log_ratio(1, 3, 3, 3) - (1.5f64 / 3.5).ln()).abs() < 1e-12);
        assert!(log_ratio(0, 100, 50, 100).is_finite());
        assert!(supported(10, 10));
        assert!(!supported(9, 1000));
        assert!(!supported(1000, 9));
    }

    #[test]
    fn strings_are_cut_on_a_character_boundary_and_set_truncated() {
        let mut m = mail("From: sender@example.com\n\nbody\n");
        assert!(!m.truncated);
        m.body_text = format!("{}é", "a".repeat(MAX_BODY - 1));
        m.attachments = vec!["file.pdf".into(); MAX_ATTACHMENTS + 1];
        // The body is one long run, so the padding rule stays off to test the field limit alone.
        cap(&mut m, false);
        assert_eq!(m.body_text.len(), MAX_BODY - 1);
        assert_eq!(m.attachments.len(), MAX_ATTACHMENTS);
        assert!(m.truncated);
    }

    #[test]
    fn the_request_budget_drops_links_from_the_end_first() {
        let mut m = mail("From: sender@example.com\n\nbody\n");
        let link = Link {
            text: "t".repeat(MAX_STRING),
            href: "h".repeat(MAX_HREF),
        };
        m.links = vec![link; MAX_LINKS];
        m.to = vec!["r".repeat(MAX_STRING); MAX_RECIPIENTS];
        cap(&mut m, true);
        assert!(request_len(&m) <= MAX_REQUEST);
        assert!(m.links.len() < MAX_LINKS);
        assert_eq!(m.to.len(), MAX_RECIPIENTS);
        assert!(m.truncated);
    }

    #[test]
    fn the_request_length_is_that_of_the_serialized_request() {
        let m = MailObservation {
            provider: Provider::Gmail,
            message_id: "m1".into(),
            from_name: "A \"B\"".into(),
            from_addr: "a@example.com".into(),
            reply_to: None,
            to: vec!["x@example.com".into(), "y@example.com".into()],
            subject: "é\u{1}".into(),
            body_text: "line\nline\\".into(),
            links: vec![Link {
                text: "go".into(),
                href: "https://example.com/".into(),
            }],
            attachments: vec![],
            truncated: false,
        };
        let json = concat!(
            r#"{"CheckMail":{"provider":"gmail","message_id":"m1","from_name":"A \"B\"","#,
            r#""from_addr":"a@example.com","reply_to":null,"to":["x@example.com","y@example.com"],"#,
            r#""subject":"é\u0001","body_text":"line\nline\\","#,
            r#""links":[{"text":"go","href":"https://example.com/"}],"attachments":[],"truncated":false}}"#,
        );
        assert_eq!(request_len(&m), json.len());
    }
}
