# Riggs: Phishing Protection

Phishing happens inside the mail view and the browser, where Riggs has no
other sensor. This feature watches two things in a Chromium browser: the mail
you open in Gmail, and the pages that ask for a password. It judges them
against the sites where you have logged in before, and either records what it
would warn about (monitor mode, the default) or warns you (warn mode).

Nothing here has been run in a real browser. Every test of the extension runs
in Node against stand-ins for the browser's interfaces. The daemon side has
been run on macOS as an ordinary user, without a browser. Read
[Limits and known gaps](#limits-and-known-gaps) and
[Not confirmed in a real browser](#not-confirmed-in-a-real-browser) before you
rely on it.

Contents: [What it is](#what-it-is) · [Enabling it](#enabling-it) ·
[Modes](#modes) · [The `riggs phishing` commands](#the-riggs-phishing-commands) ·
[How a verdict is reached](#how-a-verdict-is-reached) ·
[Known and pending logins](#known-and-pending-logins) ·
[The policy file](#the-policy-file) · [What is recorded](#what-is-recorded) ·
[What the popup says](#what-the-popup-says) · [Measuring](#measuring) ·
[Limits and known gaps](#limits-and-known-gaps) ·
[Not confirmed in a real browser](#not-confirmed-in-a-real-browser) ·
[Linux](#linux) · [Outlook for Mac](#outlook-for-mac) ·
[Browser extension contract](#browser-extension-contract)

## What it is

Three parts:

1. **Sensors.** A Chromium extension (`extensions/riggs-browser`, Manifest V3,
   plain JavaScript). One content script reads the message you open in Gmail
   (sender, recipients, subject, body text, links, attachment names). Another
   runs in every `http` and `https` page and notices when a password field
   appears and when a login is submitted. The extension holds no scoring logic.
2. **The daemon's decision.** The extension's service worker passes each
   observation to the native-messaging host `riggs-browser-host`, a small
   program the browser starts for each request. The host forwards it over the
   daemon's local Unix socket and returns the answer. The daemon
   (`crates/riggs-phishing`, wired in `crates/riggs-daemon/src/phishing.rs`)
   decides and keeps the per-user state. Nothing sends it to a console: the
   crate that talks to the console never mentions phishing data
   (`rg -i phishing crates/riggs-cloud` finds nothing).
3. **The policy.** `phishing-policy.toml` holds the mode, the thresholds, the
   weight of every soft cue and the phrase lists. It is the only switch: with
   no policy file at daemon start, the feature is off.

What a person sees: in warn mode, a banner above a mail or page that looks
wrong, and for a password page judged `danger`, a warning page that replaces
it. In monitor mode, nothing at all; the daemon only records what it would have
shown.

The rest of this file is the guide. The last section, "Browser extension
contract", is the interface between the extension's files and the host; it
matters to someone changing that code, not to someone using the feature.

## Enabling it

### macOS

```
sudo install/install.sh
```

The installer builds the release binaries, then, for this feature, installs:

| What | Where |
|---|---|
| the native-messaging host | `/usr/local/bin/riggs-browser-host`, mode 755 |
| its manifest, `com.riggs.browser.json`, root-owned, mode 644 | `/Library/Google/Chrome/NativeMessagingHosts/`, `/Library/Application Support/Chromium/NativeMessagingHosts/`, `/Library/Microsoft/Edge/NativeMessagingHosts/` |
| the same manifest, owned by you, only if `~/Library/Application Support/BraveSoftware/Brave-Browser` exists | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/` |
| the policy file, never overwriting one that exists | `/etc/riggs/phishing-policy.toml` |
| the extension, root-owned so that a process running as you cannot change what the browser loads | `/usr/local/share/riggs/browser-extension` |

The browser directories are the ones Chrome's and Edge's documentation give
for a system-wide host on macOS (Chromium's is in Chrome's documentation too).
Brave documents no system-wide directory, so its manifest goes into your own
Brave directory, and only when Brave has been run by you before the installer
runs. If you start Brave for the first time afterwards, run the installer
again. That the Brave directory is the one Brave reads is unverified.

The policy file has to be in place before the daemon starts: the daemon looks
for it once, at startup (`/etc/riggs/phishing-policy.toml`, then
`config/phishing-policy.toml` relative to its working directory). Without it
the daemon logs `no phishing policy file; phishing protection is off` and
answers every sensor request with the error `phishing protection not running`,
which the extension's popup shows as an answer it does not understand. Once
the daemon runs, edits to the file are picked up without a restart.

**The one step that cannot be automated.** A browser takes an unpacked
extension only by hand. Branded Chrome 137 and later ignores the
`--load-extension` command-line switch, and macOS's external-extension files
must point at the Chrome Web Store; there is no store listing. So, once in each
browser profile:

1. Open `chrome://extensions` (`edge://extensions` in Edge) and turn on
   "Developer mode".
2. Choose "Load unpacked" and select `/usr/local/share/riggs/browser-extension`.

The installer prints these steps. The extension's ID is fixed by the `key` in
its manifest, and the native-messaging manifest names that ID in
`allowed_origins`, so only this extension may talk to the host. A copy loaded
from a development checkout has the same ID and works; a copy without the `key`
does not (the popup then says it is not the one the installer set up).

Then open the extension's popup (its toolbar icon). A working install says
"Monitor mode". [What the popup says](#what-the-popup-says) lists every state.

The extension is switched off in incognito windows, on purpose: nothing from
them may reach the daemon.

To remove everything: `sudo install/uninstall.sh`. It deletes the host, the
manifests (the Brave one too), the extension directory, and, if you answer yes
to the existing prompt about `/etc/riggs`, the policy file and the rest of the
configuration. The browser keeps its entry for the extension until you remove
it at `chrome://extensions`.

### Linux

There is no installer. See [Linux](#linux).

## Modes

`mode` is the first key of the policy file.

| Mode | What the daemon does | What a person sees |
|---|---|---|
| `off` | no checks; sensor requests get an empty answer; nothing is recorded | nothing; the popup says protection is switched off |
| `monitor` (shipped) | checks everything, records every check in the log with `shown` false | nothing |
| `warn` | as `monitor`, and lets a `caution` or `danger` verdict be shown | banners; a warning page for a `danger` password page |

To change it, on an installed host:

```
sudo riggs phishing mode warn
```

This edits only the `mode` value of `/etc/riggs/phishing-policy.toml`, keeping
its comments, and applies it at once. If the edited text would not load,
nothing is written. You can also edit the file by hand; when the daemon finds
that the file no longer loads, it keeps the policy it had and logs the error
with the file and line, not the content.

Recommended order: leave `monitor` on for a while, read
`sudo riggs phishing recent` and `sudo riggs phishing stats`, then move to
`warn`. That is advice, not a measured procedure; see
[Measuring](#measuring) for why.

## The `riggs phishing` commands

`riggs phishing status` can be run by any local user. Every other subcommand
is for the daemon's owner (root on an installed host, so use `sudo`) and is
refused otherwise with `permission denied: command requires daemon-owner
privilege`. The daemon keeps its state per local user, named by the user id of
whoever connects to its socket. Under `sudo`, the commands that take a user
default to the user who ran `sudo` (`SUDO_UID`); `--user UID` names another.

| Command | What it does |
|---|---|
| `riggs phishing` or `status` | mode and the number of known logins of this user |
| `riggs phishing recent [--limit N] [--user UID]` | the newest checks, one line per mail or page, default 50 |
| `riggs phishing stats [--user UID]` | totals and how often each cue fired |
| `riggs phishing logins [--user UID]` | the sites this user has logged in to |
| `riggs phishing trust DOMAIN [--user UID]` | make a domain a known login |
| `riggs phishing forget DOMAIN [--user UID]` | remove a login |
| `riggs phishing mode off\|monitor\|warn` | set the mode |

`riggs --socket PATH phishing ...` talks to a daemon on another socket (the
option goes before the command).

Output shapes (colour codes omitted; the domains are examples):

```
$ riggs phishing status
Phishing Protection
────────────────────────────────────
  Mode:     monitor
  Logins:   1

$ sudo riggs phishing recent
Recent Phishing Checks
─────────────────────────────────────────────────────────────────────────────
  TIME (UTC)           KIND  DOMAIN                         LEVEL    SHOWN  CUES
  2026-11-12 22:41:05  mail  amazan.com                     danger   no     domain_lookalike_misspelling
  2026-11-12 22:39:12  page  example.com                    none     no

$ sudo riggs phishing stats
Phishing Statistics
────────────────────────────────────
  Total:     2
  Caution:   0
  Danger:    1

  CUE                                      HITS
  domain_lookalike_misspelling             1

$ sudo riggs phishing logins
Known Logins
─────────────────────────────────────────────────────────────────────────────
  DOMAIN                         FIRST (UTC)          LAST (UTC)           COUNT
  amazon.com                     2026-11-12 22:34:33  2026-11-12 22:34:33  1
  example.org                    2026-11-12 22:36:10  2026-11-12 22:36:10  0

$ sudo riggs phishing trust example.com
ok
```

The `status` and `logins` shapes are what a manual run of the daemon printed.
The `recent` and `stats` blocks show the columns of the code in
`crates/riggs-cli/src/commands.rs` with made-up rows, since no browser sent
that run anything. `SHOWN` says whether the daemon allowed the verdict to be
displayed (only in warn mode, and only for `caution` and `danger`), not that a
page displayed it. The last row of the `logins` example, count 0, is a pending
login ([Known and pending logins](#known-and-pending-logins)). `Logins:` in
`status` does not count pending ones.

Errors are printed as `Error: <text>`, for example
`Error: example.com is not a login of uid 501` for `forget`, and
`the phishing store is busy; try again` for `trust` or `forget` when the
daemon's write queue is full (nothing changed in that case).

## How a verdict is reached

The daemon gives every observation one of three levels: `none`, `caution`,
`danger`. The rules are in `crates/riggs-phishing`; `docs/PHISHING_CUES.md` is
the catalogue of every cue, with the document each comes from, and is the place
to read a cue's exact rule. This section only orders them.

**Hard lookalike rules** make a mail or a page `danger` on their own:

- `domain_lookalike_misspelling`: a host that is one typo or one look-alike
  character away from a domain you have logged in to (`amazan.com` against a
  known `amazon.com`).
- `domain_lookalike_embedded`: a known domain written out inside another host's
  name (`google.com.rogueserver.biz` against a known `google.com`).

Both examples are from the catalogue's section 4, which names their sources.
For a mail the rules look at the sender's domain, each link's target host and
the host a link's text names. For a page, at the page's host. Every length
threshold they use is a policy key (`[lookalike]`), because they are
starting values that were measured only against a list of popular sites
([Measuring](#measuring)). A host is judged only if it is a valid DNS name: one
longer than 253 bytes, or with a label longer than 63 bytes, has no name and is
not judged.

**The page context rule** applies to a page that asks for a password. A page
whose domain is a known login is `none`. Otherwise, if the page was opened from
a mail (or its host appears among the links of a mail checked in the last 30
minutes) and you have at least `warmup_logins` known logins (20 as shipped),
the page is `caution` (`page_from_mail_unknown_login`: "You opened this page
from mail and have not logged in here before."), and `danger` when that mail
was itself `caution` or `danger` (`page_from_flagged_mail`: "The mail you
opened this page from was flagged."). With fewer known logins than the
warm-up, this rule never fires: there is too little history to call a site
unusual. The warm-up number is a guess, not a measurement. A page that fires
either rule, or a lookalike, also marks its domain as flagged for 30 minutes,
and during that time that domain cannot become a known login by itself.

**Soft cues** (sender never seen, link text that names another site, an
urgent phrase, a high-risk attachment type, a mail the extension had to cut
short, and so on) each have a weight in the policy. A mail whose weights add
up to `caution_threshold` (1.0 as shipped) or more is `caution`. **Every weight
ships at 0.0.** A weight's size and sign have to come from measurement on real
mail, and the only measurement so far is not good enough to set one
([Measuring](#measuring)). So as shipped, only the two hard rules and the two
page rules can produce a verdict, and the soft cues are computed, listed in
the log and counted by `stats`, but change nothing. Cue ids and where each is
defined: `docs/PHISHING_CUES.md`, section 3 (catalogue) and section 5
(summary); the phrase lists are its section 4.

What a level does in the browser, in warn mode:

| Observation | `none` | `caution` | `danger` |
|---|---|---|---|
| a mail | nothing | banner "Riggs: this looks unusual" above the message body, one line per reason | banner "Riggs: this may be phishing" |
| a password page | nothing | the same two banners above the page | the page is replaced by a warning page ("Riggs stopped this page") with **Close this tab** and **Continue anyway** (disabled for the first two seconds); a `danger` page is not replaced again for a host you chose to continue to, until the browser restarts |

No wording ever says that a mail or page is safe: `none` shows nothing. A
`danger` mail gets a banner only; the warning page is for password pages.
**Continue anyway** opens the blocked page's address again (the page is loaded
anew, so anything typed into it before is gone); Back is not used, because
Chrome may skip a page an extension navigated away from.

### Known and pending logins

The daemon learns where you log in from the sensor's reports. How sure the
sensor is depends on the evidence it reports:

- `typed`: it saw trusted keyboard input into the password field.
- `autofill`: the browser filled the field.
- `filled`: the field held a value, but the sensor saw neither. **This is weak
  evidence**: a page can fill a password field by script and wait for a click.

A login seen on `typed` or `autofill` is **known** at once and exempts that
domain from the page rules. A login seen only on `filled` is **pending**: it
exempts nothing, is not something other domains are compared with, and does not
count towards `warmup_logins`. A pending login becomes known on strong
evidence, on `riggs phishing trust`, or on a second weak sighting at least
`weak_login_confirm_hours` after the first (12 as shipped). A pending login is
stored with a count of 0, which is how `riggs phishing logins` lists it. At
`max_logins`, a new domain replaces the oldest pending login; with none
pending, it is refused. A known login is never dropped to make room.

A login is also refused, recording nothing, when its domain is a hard lookalike
of a known login or was flagged by a page check in the last 30 minutes;
`trust` skips both refusals. The extension itself does not report `filled` from
a frame on another host than its page's, so an advertisement frame cannot make
its own host pending.

Pending logins cost real users something: a password-manager user's logins
become known only on the next typed or autofilled sighting, or 12 hours after
a second filled one. The 12 hours is a chosen value, not a measured one.

## The policy file

`config/phishing-policy.toml` in the repository; `/etc/riggs/phishing-policy.toml`
once installed. Every key is required. A missing, unknown or misspelled key
stops the file from loading; so do values that could never work: a
`caution_threshold` that is not a finite number above 0, `max_logins` of 0,
`warmup_logins` above `max_logins` (the page rule could never fire),
`weak_login_confirm_hours` of 0 (two scripted clicks would make a login), a
`links.max_hosts` of 0, a malformed `links.redirectors` entry, a weight that is
not a finite number, an empty phrase. Errors name the file and the line or key,
never its content.

| Section | Keys |
|---|---|
| top level | `mode`, `caution_threshold`, `warmup_logins`, `max_logins` (per user, pending included), `weak_login_confirm_hours`, `max_senders` |
| `[lookalike]` | `homoglyph_min_label`, `typo_min_label`, `typo_part_min_label`, `typo_same_first_char`, `typo_trailing_s_exempt`, `embedded_min_domain`, `embedding_ignore`, `brand_token_min_label`, `brand_prefix_min_label` |
| `[weights]` | one weight per soft cue |
| `[phrases]` | one phrase list per phrase cue; matching ignores case and runs of whitespace and needs a word boundary at each end |
| `[extensions]` | `high_risk`, `body_mention` |
| `[links]` | `max_hosts` (distinct hosts of one mail that the lookalike rules check, 100 as shipped), `redirectors` (link-checking gateways to look through; the one entry, Microsoft's Safe Links, is commented out because its query parameter name is unverified) |
| `[freemail]` | `domains`: free-mail providers, from Apache SpamAssassin's list; a sender at one of them is recorded by a hash of its whole address, not by its domain |

The file's comments carry each phrase's source and each guard's meaning.

## What is recorded

**By the daemon, on disk**, in its database `riggs.db` (`/var/lib/riggs/` on an
installed host), which only its owner can read (mode 0600; on an installed host
that is root). Table layouts: `docs/DATA_LAYER.md`, "Phishing tables".

| What | Content | How long |
|---|---|---|
| logins | per user: registrable domain, first time seen, last time seen, count (0 = pending) | until you `forget` one; at most `max_logins` per user |
| senders | per user: the sender's registrable domain, or for a free-mail or unnameable address a SHA-256 of the whole address; the time first seen; a fingerprint of that first message | kept; at most `max_senders` per user |
| check log | per mail opened and per password page checked: time, `mail` or `page`, the sender's or page's registrable domain, the ids of the cues that fired, the score, the level, whether it was shown | `[store] retention_days` (90 as shipped), swept every `[engine] retention_sweep_secs`; at most 500 rows per user per UTC day, the rest are answered and not logged |

**By the daemon, in memory only**, lost when it restarts: the hosts linked from
mails checked in the last 30 minutes and the domains flagged in the last 30
minutes (each at most 5,000), used by the page context rule.

**By the browser, in the extension's session storage**, which is in memory,
cleared when the browser restarts or the extension is reloaded, and not
readable by web pages: per tab, the host the tab was first sent to, whether it
was opened from mail and the mail's level, and, for a page the extension
blocked, that page's full address, which "Continue anyway" needs; per browser
session, the hosts you chose to continue to and whether each mail adapter
works. Nothing else is stored by the extension.

**Never recorded anywhere**: a mail's subject, body, recipients, display name,
link targets or text, attachment names, or message id (only an 8-byte
fingerprint of the id, so that opening one mail twice reads back as one entry);
no full address (except in the extension's session memory, for the blocked
page); nothing the daemon logs contains observation content. The host
`riggs-browser-host` writes nothing to stderr.

**What does leave the browser.** Every mail you open in Gmail, and every
password page, is sent in full (the body is cut at 64 KiB) to the daemon over
its local socket, in monitor mode too, so that the daemon can judge it. That
is a local socket on your machine, and the daemon does not send it on. It is
held in memory for the length of the check.

**Who can see it.** Anyone who can read `riggs.db` (root), and anyone who can
run `sudo riggs phishing ...`. The socket itself is open to every local user
for sensor requests; the daemon keys the state by the connecting user's id, so
one user cannot read or change another's. Two limits on that: a local user can
send sensor requests that create logins and senders for their own id only, and
the daemon refuses, per user, more than 16 simultaneous connections in the pool
of non-owner connections (the pool is 32 by default,
`[comms] ipc_max_connections`). The owner has a pool of its own, so a user
cannot lock the owner out.

## What the popup says

The toolbar popup asks the extension's worker for its state.

| Headline | Meaning |
|---|---|
| Protection is on | warn mode, and the daemon answers. A `!` on the icon means Riggs warned you about something in that tab |
| Monitor mode | the daemon answers and records, and shows no warnings |
| Protection is switched off | `mode = "off"` |
| Riggs is not protecting this browser | the host or the daemon is not answering; the lines below the headline say which of five causes it is: no host manifest (`host_not_found`), a copy of the extension the installer did not set up (`host_forbidden`), the host crashed (`host_exited`), the daemon does not answer (`daemon_unreachable`), or an answer the extension does not understand (`error`), or the extension's own worker is not answering |

Below the headline, outside the `off` state: `Sites where Riggs has seen you
sign in: N` (the known logins) and, for Gmail, whether the mail adapter could
read the last message (`working`, `not working`, or `no message opened yet`).
A `?` on the icon means an adapter could not read a message, which then went
unchecked.

## Measuring

The weights ship at 0.0 because nobody has measured them on mail that matters.
The tools are `cargo` examples of `crates/riggs-phishing`; they print
aggregates only (cue ids, counts, rates), never a subject, address or link,
and they build the observation the way the extension does (same body-text walk,
same capping), so a measurement transfers.

```
cargo run --release --locked -p riggs-phishing --example eval -- \
    --mbox mine /path/to/your-mail.mbox \
    --policy /path/to/a-copy-of-phishing-policy.toml
cargo run --release --locked -p riggs-phishing --example lookalike_fp -- \
    /path/to/top-sites.csv --known 1000 --candidates 100000
```

`eval` reads `--eml`, `--mbox` or SpamAssassin-layout directories, replays
them through the engine the daemon runs, prints each cue's rate per input, and
with `--phish LABEL --legit LABEL` a table of both sides. `--logins FILE` seeds
a login set; `--chronological` replays one user's mail in date order. The header
of `crates/riggs-phishing/examples/eval.rs` is its usage. `lookalike_fp` takes
a `rank,domain` list, uses the top N as the login set and counts what the
lookalike rules flag among the top M, where every hit is a false positive.

What has been measured, and what that does and does not support:

- The phishing side is public phishing collections. The only public
  legitimate-mail collection that was measured is from 2002 (plain-text mailing
  lists), which is not what mail looks like now. The two-sided table the
  tool printed is an exercise of the tool, not a basis for weights, and none
  was proposed. The decision needs your own mail (`--keep-label` and
  `--drop-label` filter a Gmail Takeout export by label; that path is
  untested).
- The measurement tables made while building this were not re-run after the
  last engine fixes, so the numbers below are from an engine slightly older
  than the one shipped.
- The guards of the lookalike rules were measured against a top-sites list
  only: with the top 1,000 sites as the login set, 243 of the top 100,000 sites
  were flagged by a hard rule at the guards as measured (0.24%). Every one of
  those is a false positive, and they are the kind to expect.

## Limits and known gaps

Stated plainly, as found in review. None of this is hidden by a default.

**Coverage**

- Gmail is the only webmail source. Outlook on the web has no adapter yet; the
  wire protocol has a place for one (`outlook_web`). Outlook for Mac has its own,
  separate path: [Outlook for Mac](#outlook-for-mac).
- The mail adapter reads the message layout of one capture of Gmail's page.
  Whether Gmail's page looks like that for you (other layouts, other
  languages, replies, drafts, inline images) was not captured. When the adapter
  cannot read a message it reports that, the popup says so, and the message is
  not checked.
- The page sensor runs only in `http` and `https` pages. A page with another
  scheme, `file:` included (an HTML attachment saved and opened from disk, for
  instance), is not checked.
- A password box that is not an `input` of type `password` (a masked text
  field, a canvas, script collecting keys) is not seen at all. A password field
  inside a shadow tree is seen when you first act in it, not when it appears.
  To report a login after a click or Enter, the sensor also looks through the
  shadow trees around the event for password fields nobody focused (what a
  password manager leaves), but at most 500 elements per event; a field beyond
  that is not found.
- Nothing is checked in incognito windows.
- A mail whose text is padded can still push its words past the 64 KiB cap.
  The extension removes any run of more than 256 letters, digits and `+/=_-`
  before capping, which was measured on one padding campaign. Padding that this
  rule does not match (shorter runs, runs of whitespace) is not removed; such
  a mail is recorded with the `observation_truncated` cue.

**What a page can do**

- A page can create a pending login for its own domain with one click: a
  prefilled password field and any trusted click make the sensor report
  `filled`. It stays pending and exempts nothing until a second weak sighting
  12 hours later or strong evidence. A page that does this twice, half a day
  apart, becomes a known login for its own host (never another's).
- The `document.open()` race in the page sensor: after a page calls
  `document.open()`, the sensor's listeners are put back one microtask later,
  and a page that adds its own capturing listeners in the same task is ahead of
  them and can stop every event. Fields in the document itself are still seen;
  fields in shadow trees, a return from the back/forward cache and the
  activation of a prerendered page are not.
- The banner is advisory. The page can remove, cover or restyle it; in Gmail,
  mail content cannot. The `!` badge on the icon is the one warning a page
  cannot remove, and it can go stale: after a flagged mail is read the `!`
  stays on that tab until the tab does a full navigation, which Gmail does not
  do while you read mail.
- A page that keeps you clicking in one spot for more than two seconds can still
  get a click onto "Continue anyway".

**The daemon**

- Two local users acting together can still fill the daemon's connection pool
  (two users of 16 each fill the default 32). The per-user limit only stops one.
  An `ipc_max_connections` of 16 or less leaves the hole open for one user.
- The verdict and the state are per local user, but a daemon run by hand as an
  ordinary user treats that user as the owner.

**Weights and measurement**

- Soft cue weights ship at 0.0, so only the hard rules and the page rules can
  produce a verdict until weights are measured on your own mail.
- The only public legitimate-mail collection measured is from 2002.
- The measurement tables were not re-run after the last engine fixes.
- The dense worst case of one mail check (many distinct hosts and a large login
  set) took 234 ms in the last measurement, on one machine; the IPC timeout is
  5 seconds.

**What was tested with what**

- Nothing has been run in a real browser. Every extension test runs in Node
  (v25.9.0, the only version used, which is itself past its end of life) in jsdom against
  stand-ins for the browser's interfaces.
- The Rust side (engine, store, daemon, CLI, native host) builds, passes
  `clippy -D warnings` and passes its tests on Linux as well as macOS: the
  workspace's format, clippy and test gate was run in a `rust:1.99` Linux
  container. Nothing else was done on Linux: no host was installed, no
  native-messaging manifest placed, no browser talked to the host.

## Not confirmed in a real browser

One list, collected from the reports of the extension, host and worker. Each
item is something the code depends on that its documentation or Chromium's source
suggests but nobody has observed.

**The host and the worker**

- That Chrome accepts the host's reply frame, and what it does when the host
  answers and exits without reading an input over 8 MiB.
- That a rejected `sendNativeMessage` carries the error texts Chrome documents.
  If it does not, the popup shows `error` for the three host failures, with the
  wrong advice.
- That `{"Status": null}` reaches the host with its `null`. Without it the
  popup always shows `error`.
- That `chrome.tabs.update` may send a tab to the extension's own warning page
  although the page is not web-accessible, and to an `http` or `https` address
  without a permission. If the first is false, nothing is ever blocked.
- That `webNavigation.onCreatedNavigationTarget` fires for a link with
  `rel="noopener"`, which is how webmail opens links. If not, tabs opened from
  mail are not marked as opened from mail, and the page context rule loses its
  main input.
- That `onBeforeNavigate` carries the address before redirects, and that a mail
  link opened in the same tab commits as `link` without `forward_back`.
- How `chrome.webNavigation.getFrame` answers for a document by its id (shown,
  replaced, in the back/forward cache) and for a `blob:` page.
- That `sender.documentId` is set for every content-script sender.
- That Edge and Brave behave like Chrome.

**The page sensor and the warning page**

- That real input is trusted and scripted input is not, and that nothing of the
  page runs before a `document_start` content script.
- That the sensor's capturing listeners on `window` receive what they should,
  including `prerenderingchange`, and whether content scripts run in a
  prerendering document at all.
- That `:-webkit-autofill` matches a saved password before and after the first
  gesture, and that Chrome's keyless trusted `keydown` on autofill arrives as
  read from its source.
- After a back/forward cache restore: that the sensor's state is intact,
  `pageshow` has `persisted`, and the sender is already `active`.
- That named elements (`<img name="...">`) shadow `document` and form
  properties in a content script's world, which the sensor and the banner
  guard against.
- Shadow trees: that a trusted event from inside reaches `window` with the
  outermost host as its target, and that `chrome.dom.openOrClosedShadowRoot`
  gives a content script a closed tree.
- That Chrome erases a content script's listeners on `document.open()` and
  keeps its observers.
- The warning page: that `tabs.getCurrent()` returns the tab after
  `tabs.update`, that `tabs.remove` closes it without the `tabs` permission,
  both colour schemes, the wrapped host name, the two-second delay on a real
  clock, and the whole Continue round trip.
- Whether Chrome evaluates `banner.js` twice in Gmail's top frame.

**Gmail**

- That Gmail tolerates a foreign element before `.ii.gt`; if it removes it on
  every render, the banner is redrawn after each quiet period without end.
- The banner's look on Gmail's light and dark themes, and whether a click on
  Dismiss or Enter on it also triggers something in Gmail.
- Whether mail content can paint over the banner.
- Whether Gmail renders a message in steps, so that recipients or attachment
  cards arrive after the observation went out, and whether the page holds
  messages that are not on screen.
- That the selectors work in Chrome; they were run in jsdom only.
- How `role="alert"` is announced.

## Linux

What works: the daemon runs on Linux, the policy file and the CLI are the same,
and `riggs-browser-host` is an ordinary Unix program using the same socket
(`/var/run/riggs.sock` by default). What does not exist: an installer. The Rust
side builds, lints clean and passes its tests on Linux (the format, clippy and
test gate, run in a `rust:1.99` container). What has not been done on Linux:
installing the host, placing a native-messaging manifest, a browser talking to
the host, and the manual steps below. The manual steps are in `docs/STANDALONE.md`,
"Phishing protection (browser)".

## Outlook for Mac

**Nobody has run this in Outlook.** The pane, the bridge and the daemon have
been run together without Outlook: the real bridge and a development daemon,
with the pane loaded from the bridge in macOS's web view and a stand-in for
Office's script. Everything that depends on Outlook itself is listed in
[Not confirmed in a real Outlook](#not-confirmed-in-a-real-outlook), each with
how you would confirm it. Nothing below is a promise that it works there.

An Outlook add-in is a web page that Outlook shows in a side pane. It is
installed by adding a small XML file, the manifest, to your mailbox; the
manifest only names the page's address. Riggs's page is served by a small
program on your own Mac, so that the page can hand the message you are reading
to the Riggs daemon.

### Who it works for

- **Mailboxes that Microsoft hosts:** Microsoft 365 (work or school) and
  Outlook.com. Microsoft's documentation says add-ins are supported for these
  and "not supported" for other accounts.
- **Not a Gmail, iCloud or IMAP account added to Outlook.** Microsoft states
  that POP3 and IMAP accounts in Outlook do not support Office add-ins. On the
  Mac such an account works only if it was added in a way that syncs it to
  Microsoft's cloud ("IMAP CloudCache"), which copies the mail to Microsoft;
  whether a custom add-in can be installed on it was not found. For a Gmail
  account, use the browser extension.
- **Outlook for Mac 16.13 or later** (the pinned pane needs it; Microsoft
  documents the pane as pinnable on Mac from that version), with Microsoft's
  mailbox API 1.5 or later. The manifest asks for 1.5. The new Outlook for Mac
  offers 1.1 to 1.14, the legacy one 1.1 to 1.8 (Microsoft's notes put the end
  of the legacy one's support in October 2026).
- **Exchange on-premises** needs Exchange 2016 or later and is limited to API
  1.5.
- **A tenant administrator can stop it:** an administrator can remove the
  "My Custom Apps" role, turn off add-ins for the mailbox, or turn off
  optional connected experiences, and then you cannot add it, or it stops
  working. The add-in's name, `Riggs`, is stored in the mailbox and an
  administrator of a work account can see it.
- Outlook must be online: Office's script, `office.js`, is loaded from
  Microsoft's content-delivery network every time the pane opens. Without a
  network the pane stays on its first line and checks nothing. If Riggs's
  egress allowlist is enforcing, Outlook has to be allowed to reach
  `*.static.microsoft`, the pattern Microsoft's CDN page asks allow lists to
  carry.

### What it does, and what it cannot do

- **A pinned pane.** Outlook gives an add-in no way to start by itself on the
  Mac. You open the Riggs pane from the ribbon once, pin it (the pin icon on
  the pane), and from then on it checks each message you select. It checks a
  message **only while the pane is open**. A message you open without the pane
  open, or in a mailbox you did not add the add-in to, is not checked.
  Whether the pin survives restarting Outlook is not known (below).
- **One notification.** For a message the daemon flags, in warn mode, the pane
  shows its verdict and also puts one notification bar on the message,
  `Riggs: ` followed by the heading and the first reason, at most 150
  characters. It is of Outlook's informational kind and is not stored (not
  persistent). That is all. **It cannot block or rewrite a link, and a link in
  the message stays clickable.**
- **It checks the same things as the browser extension**, with the same engine,
  the same policy file and the same per-user state: sender, recipients, subject,
  body text, links and attachment names go to the daemon, which decides as
  described in [How a verdict is reached](#how-a-verdict-is-reached). The
  Outlook pane reports mail only. It learns no logins, so the daemon's known
  logins come from the browser extension or from `riggs phishing trust`; without
  known logins the lookalike rules have nothing to compare a sender or link with.
- **Monitor mode shows nothing.** As shipped the mode is `monitor`: the daemon
  records what it would flag and the pane shows no verdict. The mode is the same
  setting as for the browser ([Modes](#modes)). Use `sudo riggs phishing recent`
  to see what was checked.
- **It never says a message is safe.** What the pane says:

| State | The pane's line |
|---|---|
| waiting for Outlook (also if `office.js` cannot load) | Riggs is waiting for Outlook. No message is checked until this line changes. |
| opened outside Outlook | This page is the Riggs pane for Outlook. It does nothing outside Outlook. |
| nothing selected | No message is selected. |
| not a message in read mode | Riggs checks messages you are reading. This item is not one. |
| reading and sending | Checking this message. |
| a field could not be read | Riggs could not read this message, so it was not checked. |
| the bridge or the daemon did not answer (the daemon stopped, or has no policy file, or took over five seconds; also a bridge that is stopped) | Riggs did not check this message. It may be stopped, or phishing protection may be switched off. |
| any other bridge status | Riggs could not check this message (bridge status 403). (with the status it gave) |
| nothing to show (monitor mode, or level `none`) | Riggs has nothing to show for this message. That is not a promise about it. |
| `caution` (warn mode) | Be careful with this message. and one bullet per reason |
| `danger` (warn mode) | This message may be phishing. and one bullet per reason |

Under the state, the pane always says: "Keep this pane pinned. Outlook gives an
add-in no way to start by itself, so Riggs checks a message only while this
pane is open." If Outlook refuses to let the pane follow your selection, that
line says instead that only the message the pane was opened on is checked.

**What the pane sends.** `message_id` is the message's internet message id, `to`
is the To addresses followed by the Cc addresses, `attachments` are the names
of the attachments that are not inline, and `reply_to` is the address of the
first `Reply-To` header, taken from outside any comment or quoted string, so
that an address written inside a display name cannot stand in for the real one.
An unterminated comment or quoted string runs to the end of the header, so
whatever follows it is hidden and no reply address is reported; mail clients
disagree about such headers, and what Outlook does with one is unknown.
`body_text` and each link's text are built by the walk of the contract's
["Body text and link text"](#browser-extension-contract). The pane cuts the body
at 1,000,000 characters after it has removed filler, and the bridge then caps
every field to the daemon's limits ([Limits](#wire-protocol)).

**Padding.** The limit stated for the browser applies here too: padding that the
filler rule does not match (shorter runs, runs of whitespace) can still push a
message's text past the 64 KiB cap, and such a message is recorded with the
`observation_truncated` cue. The pane applies the same filler rule before its
own cut, and the bridge applies it again before capping.

### How it fits together

```
Outlook pane (web page)  --HTTPS-->  riggs-mailbridge  --Unix socket-->  riggs-daemon
   https://localhost:41443/<token>/      127.0.0.1 only, runs as you      /var/run/riggs.sock
```

- **`riggs-mailbridge`** is a LaunchAgent that runs as you, not as root. It
  serves the add-in's seven page files and accepts one kind of request, a mail
  observation, on `POST /<token>/observe`. It forwards the observation to the
  daemon's socket as your user, so the daemon keys the state by your user id,
  never by anything in the request. Its answer is the verdict, or `null` when
  nothing may be shown, or an empty 503 when the daemon gave no verdict.
- **The page is served by the same program**, from `https://localhost:<port>`, so
  the pane's request goes to its own origin and needs no cross-origin
  permission. The bridge never sends a cross-origin (CORS) header.
- **The port** is 41443 unless you pass `--port` to `setup`. It is a machine-wide
  number: on a Mac with several users, the second user's bridge cannot listen
  there and `riggs-mailbridge run` fails with `cannot listen on 127.0.0.1:41443:
  Address already in use`. Give each user their own port with `setup --port N`
  (it is kept after that), and sideload that user's manifest.
- **A random token** is the first segment of every address, 32 hex characters
  made when `setup` first runs. It exists only in the state directory and in the
  manifest, which holds it in the addresses, so the manifest stored in your
  mailbox contains it. A request with a wrong token gets a plain 404.
- **Checks on every request:** the `Host` header must be `localhost:<port>` or
  `127.0.0.1:<port>` (else 403); a POST must carry an `Origin` equal to the
  bridge's own (else 403), a JSON content type (else 415), a body of at most
  8 MiB (else 413) and valid JSON (else 400).

### Installing it

Prerequisites: the base install ([Enabling it](#enabling-it)), so the daemon runs
and has its policy file, and a Microsoft-hosted mailbox that allows custom
add-ins.

1. **Run the installer with the option.** Nothing of the Outlook sensor is
   installed without it.

   ```
   sudo install/install.sh --outlook
   ```

   It builds as for the base install, then installs
   `/usr/local/bin/riggs-mailbridge` and the add-in's eight files (the seven it
   serves and the manifest template) into a root-owned directory, runs
   `riggs-mailbridge setup` **as you, not as root**, installs and loads the
   LaunchAgent for you, and prints what `setup` printed. It does not trust any
   certificate and does not add the add-in to a mailbox. Running it again keeps
   the token and the certificate, so nothing you did in steps 2 and 3 needs
   redoing.

   `setup` prints, for your paths, two steps. These are the shapes:

   ```
   riggs-mailbridge state: /Users/you/Library/Application Support/Riggs/mailbridge
   Certificate: new, valid for 799 more days.

   Two steps only you can take; riggs-mailbridge does not run them.

   1. Trust the bridge's local certificate authority for TLS in your login keychain
      (macOS asks for your password). Run it again after every new certificate:

      security add-trusted-cert -r trustRoot -p ssl -k "$HOME/Library/Keychains/login.keychain-db" '<state directory>/ca.pem'

   2. Add the add-in to your mailbox, again after --renew or a new port: in a browser
      signed in to the mailbox, open https://aka.ms/olksideload, choose My add-ins,
      then under Custom Addins choose Add a custom add-in, Add from File, and pick:

      <state directory>/manifest.xml
   ```

2. **Trust the certificate authority** by running the command of step 1, in a
   Terminal window, as yourself (no `sudo`).

   *The prompt:* macOS shows an authentication dialog and asks for your
   password, because the command changes your own trust settings and adds the
   certificate to your login keychain. Decline, and nothing changes.

   *What you are trusting:* a certificate authority named "Riggs mail bridge
   local CA", made by `setup`, for TLS server certificates only (`-p ssl`) and
   only in your user's trust settings. The authority is **constrained to
   `localhost`**: its certificate carries a critical name constraint that
   permits only `localhost` and `127.0.0.1`. **Its private key is never written
   to disk**: `setup` makes the authority and signs one certificate for
   `localhost` and `127.0.0.1`, then drops the key. Both are ECDSA P-256 and
   valid for 800 days.

   *What that allows:* anything on your Mac that checks TLS against your trust
   settings (Safari, Outlook's web view) accepts the one certificate `setup`
   made, for `localhost` and `127.0.0.1`. *What it does not allow:* a
   certificate from this authority for any other name. The constraint is
   enforced by macOS's evaluator: the bridge's author checked it with
   `security verify-cert` against a test authority with the same constraints,
   which refused a certificate for `example.com` and accepted one for
   `localhost`. The authority cannot sign anything new either, since its key is
   gone. It is not trusted for code signing, mail or other purposes. What stays
   possible: the certificate's own private key, `key.pem`, is a file of yours
   (mode 0600), so a program running as you, or root, can read it and pose as
   `localhost` to your other programs. Same-user malware is not stopped by any
   of this.

   Check it by opening the page in Safari, from the state directory:

   ```
   cd "$HOME/Library/Application Support/Riggs/mailbridge"
   open "https://localhost:$(cat port)/$(cat token)/taskpane.html"
   ```

   You should see a page titled "Riggs" and no certificate warning, with the
   line "This page is the Riggs pane for Outlook. It does nothing outside
   Outlook." A certificate warning means the trust did not take effect.

3. **Add the add-in to your mailbox**, once for each mailbox: in a browser
   signed in to it, open `https://aka.ms/olksideload` (Outlook on the web opens
   "Add-Ins for Outlook"), choose **My add-ins**, then under **Custom Addins**
   **Add a custom add-in**, **Add from File**, and pick the state directory's
   `manifest.xml` (in the file dialog, Cmd+Shift+G lets you paste a path). The
   steps are Microsoft's, from its sideloading page; the dialog was not
   exercised.

   *What this does:* it stores the manifest in your mailbox on Microsoft's
   servers, where it shows up in every Outlook client that opens the mailbox.
   On any other computer the add-in's button appears and fails, because nothing
   listens on that machine's `localhost`. A browser may ask whether the page may
   reach devices on your local network; that has no bearing on the Mac add-in.
   A mailbox that refuses custom add-ins, or an account of a kind that does not
   support them, ends here.

4. **Use it in Outlook for Mac.** Turn the Reading Pane on (View, Reading Pane,
   Right or Below); without it add-ins are unavailable. Select a message in the
   mailbox you added the add-in to. Click the **Riggs** button on the ribbon (under
   the `...` button if it is not shown, where **Customize Toolbar** lets you place
   it; a new add-in may take a while to appear and restarting Outlook may help).
   When the pane opens, its first line should change from "Riggs is waiting for
   Outlook." Click the pin icon on the pane, then select other messages: the
   pane should follow your selection.

5. **Switch to warn mode when you want to see verdicts:**
   `sudo riggs phishing mode warn`. Check what has been checked with
   `sudo riggs phishing recent`.

### What is stored where

| What | Where | Owner, mode |
|---|---|---|
| the bridge | `/usr/local/bin/riggs-mailbridge` | root, 755 |
| the add-in's eight files (seven served, plus `manifest.template.xml`, which is never served) | `/usr/local/share/riggs/outlook-addin/` | root:wheel, readable, writable by root only |
| the state: `token`, `port`, `key.pem` (the leaf certificate's private key), `cert.pem` (leaf, then authority), `ca.pem`, `manifest.xml` | `~/Library/Application Support/Riggs/mailbridge/` | you; directory 0700, every file 0600 |
| the LaunchAgent | `~/Library/LaunchAgents/com.riggs.mailbridge.plist` | you, 644 |
| the bridge's log | `~/Library/Logs/riggs/mailbridge.log` | you |
| the authority's certificate and your trust setting | your login keychain | you; made by your command |
| the manifest, with the token in its addresses, and the add-in's name | your mailbox, at Microsoft | the mailbox |

The files that the bridge serves are root-owned so that a process running as
you cannot change the page Outlook loads. The log holds only fixed phrases and
status numbers (`listening on 127.0.0.1:<port>`, `answered 404`,
`TLS handshake failed, client alert: UnknownCA` and a few more) and nothing from
a request: no mail, no address, no token. `TLS handshake failed, client alert:
UnknownCA` is the line to look for when the pane stays blank: Outlook's web view
does not trust the certificate. Mail goes from the pane to `127.0.0.1` and to
the daemon's socket; the bridge writes none of it to disk. What the daemon
records is what [What is recorded](#what-is-recorded) says for the browser.

**Connections.** The bridge serves at most 64 connections at once, closes an
idle one after 30 seconds, and ends any connection 60 seconds after it was
accepted, after letting a request in flight finish (up to 15 more seconds).
Further connections wait. Another local user cannot pass the token check but
can still hold every one of the 64 places, over and over, and so delay or
starve your checks; the bridge itself stays up and recovers when they stop. A
check that cannot connect in time gets no verdict, and the pane shows nothing
for that message (the line for "did not answer").

### Renewing the certificate

The certificate and its authority are valid for 800 days (under Apple's limit of
825 for TLS server certificates). **Nothing renews them by itself, and nothing
warns you.** When the certificate has expired, `riggs-mailbridge run` refuses to
start, launchd starts it again about every 10 seconds, and each time it logs the
same error, so the pane cannot load. To renew, as yourself:

```
riggs-mailbridge setup --dir "$HOME/Library/Application Support/Riggs/mailbridge" --assets /usr/local/share/riggs/outlook-addin
```

`setup` makes a new certificate and authority when the old certificate is
within 30 days of its end, or is past it, and keeps the token and the port.
Then:

1. Run the trust command it printed again (step 2 above). A new authority is a
   new certificate, and macOS has to be told to trust it. The old authority stays
   trusted until you remove it: list the authorities with
   `security find-certificate -a -c "Riggs mail bridge local CA" -Z "$HOME/Library/Keychains/login.keychain-db"`,
   compare with the hash of the current one
   (`openssl x509 -in ca.pem -noout -fingerprint -sha256`, without the colons), and delete
   each other with `security delete-certificate -t -Z <hash> "$HOME/Library/Keychains/login.keychain-db"`.
2. Restart the bridge so that it reads the new certificate (an expired one
   restarts by itself):
   `launchctl unload "$HOME/Library/LaunchAgents/com.riggs.mailbridge.plist"` and then
   `launchctl load "$HOME/Library/LaunchAgents/com.riggs.mailbridge.plist"`.

The manifest does not change when only the certificate does, so you need not add
the add-in again. `setup --renew` replaces the token, the key and both
certificates; then the manifest changes too, so remove the add-in from the
mailbox and add the new `manifest.xml` (step 3). What Outlook does when a
manifest with the same add-in id is added again is unknown. `--port` also changes
the manifest.

### Removing it completely

```
sudo install/uninstall.sh
```

The uninstaller always removes the Outlook sensor, whether or not it was
installed with `--outlook`: it unloads and deletes the LaunchAgent, the binary,
`/usr/local/share/riggs/outlook-addin` and the state directory. It then prints
two things for you to do, and runs neither:

1. A `security delete-certificate -t -Z <hash> "$HOME/Library/Keychains/login.keychain-db"`
   command that removes the authority's certificate and, with `-t`, your trust
   setting for it, and a `security find-certificate` command that lists any
   authority left (one for each `setup --renew`). The hash is that of the
   authority in the state directory, read just before it was deleted. That
   `-t` removes a trust setting that `add-trusted-cert` made was read from
   `man security`, not tried.
2. The reminder to remove the add-in from the mailbox, which lives there and
   not on this Mac: at `https://aka.ms/olksideload`, My add-ins, Custom Addins,
   the ellipsis on `Riggs`, Remove, in each mailbox you added it to.

### Not confirmed in a real Outlook

Everything inside Outlook is unconfirmed. The pane's behaviour was shown in
macOS's web view against a stand-in for Office's script, and the whole path
(pane, bridge, daemon) was run together; no step below was run in Outlook for
Mac. The real pane shows no counters and no field values, and the bridge logs
none, so each item is confirmed by what you see in Outlook and by
`sudo riggs phishing recent` (one row per message checked: its time, the
sender's domain, the level, whether it was shown, and the cue ids).

| # | Not confirmed | How you would confirm it |
|---|---|---|
| 1 | "Add from File" accepts Riggs's manifest | step 3 ends without an error, and Custom Addins lists `Riggs` |
| 2 | The button appears for a selected message | step 4: `Riggs` on the ribbon, or under `...` |
| 3 | Outlook's web view loads a page from `https://localhost:<port>` once the authority is trusted for SSL in your user trust settings (the trust command uses `-p ssl` and no admin domain; that this is enough is unverified) and accepts an ECDSA P-256 leaf under a name-constrained authority, sent leaf then authority | click the button: the pane's first line changes. If it stays blank, `~/Library/Logs/riggs/mailbridge.log` shows `TLS handshake failed, client alert: UnknownCA`, or no new line at all if Outlook never reached the bridge |
| 4 | `office.js` loads in that page and reports Outlook | the pane leaves "Riggs is waiting for Outlook." |
| 5 | The pane's POST carries `Host: localhost:<port>` and `Origin: https://localhost:<port>`, which the bridge's 403 rules require | the pane never shows `(bridge status 403)`; the log shows `answered 200`, not `answered 403` |
| 6 | The pane can be pinned | the pin icon is on the pane |
| 7 | Pinned, Outlook reports each newly selected message once and the pane then holds that message | select five messages in turn; `recent` has a row for each |
| 8 | The same for different messages inside one conversation | as 7, within a conversation |
| 9 | With nothing selected the pane is told | select an empty folder: "No message is selected." |
| 10 | A message in its own window has a working pane | double-click a message, open the pane there |
| 11 | A message in Junk Email reaches the pane | select one; `recent` has a row |
| 12 | A pinned pane is back after Outlook restarts, without a click | quit and reopen Outlook, select a message; if the pane is gone, it is one click per launch |
| 13 | Sender and subject are the message's own | `recent`'s domain column is the sender's domain |
| 14 | Link targets in the HTML body are the message's own, or wrapped by Safe Links | `sudo riggs phishing trust microsoft.com`, then send yourself a message linking to `micorsoft-support.com` (a lookalike from the cue catalogue) and read the message in warn mode: the pane should say `danger` with a reason |
| 15 | The headers API is there and `Reply-To` is read correctly | send yourself two copies of a message whose display name shares a word with its address, one with a `Reply-To` on an unrelated address: only that copy should show `display_name_address_mismatch` in `recent`'s cues |
| 16 | No Office call fails on real mail | the pane never says "Riggs could not read this message, so it was not checked." |
| 17 | The notification appears as a bar, informational and not stored | in warn mode, select a flagged message: one bar on it, gone when you return after another message |
| 18 | Removing the notification works | after a flagged message, `sudo riggs phishing mode monitor` and reselect: the bar goes |
| 19 | With the bridge stopped the pane says so | `launchctl unload "$HOME/Library/LaunchAgents/com.riggs.mailbridge.plist"`, select a message: "Riggs did not check this message. ..." (load it again afterwards) |
| 20 | What Outlook shows for a pane that cannot load (bridge stopped, pane reopened) | as 19, close and reopen the pane |
| 21 | Without a network the page loads and `office.js` does not | network off, reopen the pane: the line stays "Riggs is waiting for Outlook." |
| 22 | All of this for an Outlook.com mailbox; Microsoft documents pinning as not available for Outlook.com | repeat 4 to 12 there, or whether it pins inside Outlook for Mac at all |
| a | Whether Outlook adds a query string to the pane's address | works either way: the bridge ignores a query |
| b | `cc`, the item type and the inline-attachment filter on real items | no direct view; a failure would show as "Riggs could not read this message, so it was not checked." on a message with a Cc and an attachment |
| c | That Outlook lists Riggs's notification by its key, which the removal in 18 relies on | 18 |
| d | What the body walk gives for real HTML mail, and what the cues make of it | no direct view; compare `recent`'s cues for a mail whose text you know |
| e | That Outlook hands over a body of several hundred kilobytes whole, and that a request of that size leaves its web view | a very long message; `recent` has its row, with `observation_truncated` only if over the cap |
| f | How the bar reads with the `Riggs:` prefix and the 150-character cut, and whether replacing it flickers | look at it |
| g | That the `nosniff` and `Referrer-Policy: same-origin` headers change nothing in Outlook's web view | the pane loads (3 and 4) |
| h | That the pane follows light and dark appearance | switch appearance, reopen the pane |
| i | Whether an item that is not a read-mode message ever reaches the pane | select a meeting request or a draft |
| j | Whether Outlook reuses a cached page or script in spite of `no-store` | matters only after an update: reopen the pane after reinstalling |
| k | What Outlook does when the same add-in id is added again after `setup --renew` | remove, then add the new manifest, and see whether two buttons appear |
| l | That Safe Links is judged correctly: a link it rewrote is judged by its wrapper's address, not its destination, because the policy's Safe Links entry is commented out until its query parameter is checked against a real wrapped link | read a wrapped link's address in Outlook; see the policy file |
| m | That the bridge's cap of 64 connections is enough for Outlook's web view (WebKit's documented default is six per host; Outlook's is unknown) | the pane keeps checking while several are open |
| n | That `launchd`'s default limit of 256 open files is enough at the cap (about 148 are needed by an estimate) | not seen to matter |
| o | That a listener on `0.0.0.0` of the same port does not let the bridge bind and mislead | not tested; only a listener on `127.0.0.1` was |
| p | That the installer and uninstaller work on a real Mac | run them; neither has been executed, and neither the trust nor the delete command has been run |
| q | That the daemon, running as root, and the bridge, running as you, agree on your user id | `sudo riggs phishing logins` lists the logins you expect for your own id; the run so far was one user |

The pane has no Content-Security-Policy, because Office's script loads further
code from Microsoft's network and only Outlook can show whether a policy would
break it. The icons are plain blue squares. The pane does not time out on an
Outlook call that never answers: it stays on "Checking this message." until you
select another message.

## Browser extension contract

This section describes the interface that the worker, the popup, the page
sensor, the warning page, the Gmail adapter, the banner and the native host
are written against, each in its own file and tested on its own. A change
here is a change to all of them.

Chromium family only (Chrome, Edge, Brave, Chromium), Manifest V3, plain
JavaScript, no bundler, no build step. Each browser fact links to the
documentation it was checked against (Chrome's documentation, Chromium's
source, MDN); "unverified" marks what that documentation does not settle. That
Edge and Brave behave like Chrome is unverified.

### File layout

```
extensions/riggs-browser/
  ext/                                the directory Chrome loads: these nine files, nothing else
    manifest.json
    background.js                     service worker (ES module)
    popup.html  popup.js              toolbar popup
    page.js                           page sensor: content script, every frame
    interstitial.html  interstitial.js  warning page
    gmail.js                          Gmail adapter: content script, top frame of mail.google.com
    banner.js                         banner: content script, loaded before gmail.js and page.js
  test/                               node:test files, fixtures
  package.json, package-lock.json, biome.json
                                      package.json must declare "type": "module"
install/native-messaging/
  com.riggs.browser.json              native-messaging host manifest, copied by the installer
```

The host is `crates/riggs-cli/src/bin/riggs-browser-host.rs`; Cargo builds it
as the binary `riggs-browser-host`. An Outlook web adapter (`ext/outlook.js`) is planned for a later stage and is
not in the list yet.

- "Load unpacked" takes the extension directory ([hello world][hello]), so only
  loadable files live in `ext/`; `package.json`, `node_modules` and tests sit
  beside it.
- `background.js` is an ES module (`"type": "module"`). Dynamic `import()` "is
  not supported" in an extension service worker ([service worker basics][sw]).
- `popup.html` and `interstitial.html` load their code with
  `<script src="popup.js">` and `<script src="interstitial.js">`. The default
  policy for extension pages is `script-src 'self'; object-src 'self';`, under
  which "the extension won't run inline Javascript" ([content security
  policy][csp]).
- `banner.js`, `gmail.js` and `page.js` are classic scripts. A `content_scripts`
  entry has no key that would make a file a module ([content_scripts
  reference][csm] lists them all), so `import` and `export` statements are
  syntax errors there. Tests evaluate the file text (for example with
  `node:vm`) instead of importing it.
- `package.json` declares `"type": "module"`, which makes Node load every `.js`
  file below it as an ES module ([Node packages][node]). That is what
  `background.js` and the tests are; under `"type": "commonjs"` their `import`
  statements would fail.

`node --test extensions/riggs-browser/test/manifest.test.js` pins four things:
the extension ID derived from the committed key is the one the native host
allows, the permissions are exactly the three below with no key that could
widen them, the extension cannot be enabled in incognito windows, and every
file the manifest references is in the list above.

### Manifest

| Key | Value | Checked against |
|---|---|---|
| `manifest_version` | `3` | "The only supported value is `3`" ([manifest][manifest]) |
| `version` | `"0.1.0"` | "One to four dot-separated integers" ([version][version]) |
| `description` | one sentence | shown on the extension management page ([manifest][manifest]) |
| `minimum_chrome_version` | `"106"` | `MessageSender.documentLifecycle` and `documentId` are marked "Chrome 106+" ([runtime][rt]); see below |
| `incognito` | `"not_allowed"` | "The extension cannot be enabled in incognito mode" ([incognito][incog]); see below |
| `key` | base64 DER public key | see [Extension ID](#extension-id) |
| `permissions` | `nativeMessaging`, `storage`, `webNavigation` | see below |
| `background` | `service_worker: "background.js"`, `type: "module"` | `service_worker` "specifies a single JavaScript file"; `"type": "module"` allows the `import` statement ([service worker basics][sw]) |
| `action` | `default_popup: "popup.html"` | "An action's popup is shown when the user clicks on the extension's action button in the toolbar" ([action][action]) |
| `content_scripts[0]` | Gmail: `banner.js`, `gmail.js` | defaults apply: top frame only, `document_idle` ([content_scripts reference][csm]) |
| `content_scripts[1]` | every `http` and `https` page: `banner.js`, `page.js` | see below |

**Permissions.** `runtime.sendNativeMessage` "requires the `"nativeMessaging"`
permission" ([runtime][rt]); `chrome.storage` needs `"storage"`
([storage][st]); every `webNavigation` method and event needs
`"webNavigation"` ([webNavigation][wn]). Nothing else is needed:

- `tabs` is not requested. `chrome.tabs.update` (worker),
  `chrome.tabs.getCurrent` and `chrome.tabs.remove` (warning page) and
  `chrome.tabs.onRemoved` work without it: "Most features don't require any
  permissions to use. For example: creating a new tab, reloading a tab,
  navigating to another URL" ([tabs][tabs]). The permission only unlocks a
  `Tab`'s `url`, `pendingUrl`, `title` and `favIconUrl`, so the worker reads
  `sender.tab.id` and nothing else from a `Tab`.
- `chrome.action.setBadgeText`, which the worker uses for the two badges (see
  [Badges](#badges)), needs only the manifest's `action` key ([action][action]).
- No `host_permissions`. The content scripts are injected by their `matches`
  patterns: "Only the `"matches"` key and either `"js"` or `"css"` are
  required" ([content_scripts reference][csm]).

**The page sensor entry** (`content_scripts[1]`):

- `run_at: "document_start"`: "Scripts are injected after any files from css,
  but before any other DOM is constructed or any other script is run"
  ([content scripts][cs]). A page that never finishes parsing is still seen.
- `all_frames: true`: "it will inject into all frames, even if the frame is not
  the topmost frame in the tab" ([content_scripts reference][csm]).
- `match_origin_as_fallback: true`: also frames "created by a matching origin,
  but whose URL or origin may not directly match the pattern", which "include
  frames with different schemes, such as `about:`, `data:`, `blob:`, and
  `filesystem:`" ([content_scripts reference][csm]). Chrome requires such
  patterns to "specify a path of `*`" ([content scripts][cs]); `http://*/*` and
  `https://*/*` do.
- The files of a `js` array are "injected in the order they appear in this
  array" ([content_scripts reference][csm]), so `banner.js` runs before the
  script that uses it.
- These patterns also match `https://mail.google.com/*`, so both entries apply
  to Gmail's top frame and `banner.js` is listed twice for it. Unverified: the
  documentation does not say whether Chrome then evaluates the file twice.
  `banner.js` must be correct either way (see [The banner call](#the-banner-call)).

**`minimum_chrome_version`.** The newest APIs the contract depends on are
`MessageSender.documentLifecycle` and `MessageSender.documentId`, and the
`documentId` argument of `webNavigation.getFrame`, all Chrome 106
([runtime][rt], [webNavigation][wn]). `Document.prerendering`, which the page
sensor reads, is Chrome 108; the sensor reads it as absent where it is missing,
so nothing waits for a prerender there. The others are older: `storage.session` Chrome 102, `match_origin_as_fallback` in a manifest
Chrome 99, promise-returning `sendNativeMessage` Chrome 99, module service
workers Chrome 92 ([what's new][new]). An older browser refuses the manifest:
`MinimumChromeVersionChecker::Parse` fails with a version-too-low error
([Chromium source][minvercc]); the [reference page][minver] only describes the
Web Store case.

**`incognito`.** Protection is off in incognito windows on purpose, and
nothing from them may reach the daemon. Under the default, `"spanning"`, an
extension the person allows in incognito gets "Any events or messages from an
incognito tab" in its one shared process ([incognito][incog]), so mail and
logins from incognito windows would be reported. `"not_allowed"` rules that
out: "Use `"not_allowed"` to prevent this extension from being enabled in
incognito mode" ([incognito][incog]). The warning page could not be shown
there in any case: a spanning extension "will not be able to load pages from
its extension package into the main frame of an incognito tab"
([incognito][incog]).

**Keys that must stay absent.** `host_permissions`, `optional_permissions`,
`optional_host_permissions`, `declarative_net_request`,
`web_accessible_resources`, `externally_connectable`.

- Without `web_accessible_resources`, "By default no resources are web
  accessible" and "A navigation from a web origin to an extension resource is
  blocked unless the resource is listed as web accessible" ([web accessible
  resources][war]). A hostile page can neither open nor frame
  `interstitial.html`.
- Without `externally_connectable`, "all extensions can connect, but no web
  pages can connect" ([externally_connectable][ec]). Messages from other
  extensions arrive on `runtime.onMessageExternal` ([runtime][rt]), so the
  worker registers no `onMessageExternal` and no `onConnectExternal` listener.

### Extension ID

```
lilgnipcebaofalbkdgonmidhpdfomen
```

Chrome derives an extension's ID from its public key: it base64-decodes the
manifest `key` and calls `crx_file::id_util::GenerateId` on the bytes
(`ComputeExtensionID` in [extension.cc][extcc]), which takes the first 16 bytes
of the SHA-256 hash, hex-encodes them and maps each hex digit `0`-`f` to
`a`-`p` (`kIdSize`, `GenerateIdFromHash`, `ConvertHexadecimalToIDAlphabet` in
[id_util.cc][idutil]). Without a `key`, the ID of an unpacked extension is
generated from its path (`GenerateIdForPath`), so it would differ on every
machine and the native host would refuse it. With it, the value "maintains the
unique ID of an extension, or theme when it is loaded during development"
([key][key]).

`key` is the base64 DER encoding (SubjectPublicKeyInfo) of an RSA 2048 public
key. The private key is kept outside the repository and nothing here needs it.
`install/native-messaging/com.riggs.browser.json` names the ID in
`allowed_origins`; the test fails if the two ever disagree.

### Wire protocol

The worker sends one JSON request to the native host with
`chrome.runtime.sendNativeMessage("com.riggs.browser", request)` and gets one
JSON response. Requests and responses are the daemon's `PhishingRequest` and
`PhishingResponse` (serde, externally tagged), defined in
`crates/riggs-types/src/phishing.rs`. As the worker sends and receives them:

```json
{"CheckMail": {"provider": "gmail", "message_id": "...", "from_name": "...", "from_addr": "...",
               "reply_to": null, "to": ["..."], "subject": "...", "body_text": "...",
               "links": [{"text": "...", "href": "..."}], "attachments": ["..."],
               "truncated": false}}
{"CheckPage": {"host": "...", "entry_host": "...", "opened_from_mail": true, "mail_level": "caution"}}
{"LoginSeen": {"host": "...", "evidence": "typed"}}
{"Status": null}

{"Verdict": {"level": "none", "reasons": [{"cue": "...", "text": "..."}], "show": false}}
{"Status": {"mode": "monitor", "logins": 0}}
"Ok"
{"Error": "..."}
```

| Request | Expected response |
|---|---|
| `CheckMail`, `CheckPage` | `Verdict` |
| `LoginSeen` | `"Ok"` |
| `Status` | `Status` |

Any request may be answered with `Error`. The worker treats `Error`, and any
response other than the expected one, as "no answer".

**The worker never sends a bare string to the native host.** Every request is a
JSON object, because `sendNativeMessage` takes `message: object`
([runtime][rt]; an object with arbitrary properties in Chromium's
[runtime.json][rtjson]). That matters for `Status`, the one request without a
payload:

| `Status` request | JSON |
|---|---|
| as the Rust side writes it | `"Status"` |
| as the worker sends it | `{"Status": null}` |

- Both are the same request to the daemon: serde_json reads `{"Status": null}`
  as the unit variant (`unit_variant` in `serde_json` 1.0.151 `src/de.rs`
  deserializes `()` from the value).
- Chrome keeps the `null`: an object argument that allows arbitrary properties
  is passed through as it is ([argument_spec.cc][argspec]) and serialized with
  `JSON.stringify` ([messaging_util.cc][msgutil]).
- Responses are not restricted: the response is typed `any`
  ([runtime.json][rtjson]), so the host may answer with the bare string `"Ok"`.

Values and optional fields:

- `provider` is `gmail`, `outlook_web` or `outlook_addin`; `level` is `none`,
  `caution` or `danger`; `evidence` is `typed`, `autofill` or `filled`; `mode`
  is `off`, `monitor` or `warn`.
- The daemon accepts a request without `reply_to`, `entry_host`, `mail_level`
  or `truncated`. The worker leaves out `entry_host` and `mail_level` when it
  has none and always sends `truncated`; adapters always send `reply_to`, as
  `null` when there is none.
- `show` says whether anything may be displayed. It is `false` in monitor mode.
- A cue id (`reasons[].cue`) is an opaque string to the extension;
  `reasons[].text` is the sentence to display.

**`CheckMail` fields.** A mail adapter always sends the first ten. The
eleventh, `truncated`, is set by the worker and never by an adapter. (The
Outlook for Mac path does not go through the worker: there the pane sets
`truncated` and the mail bridge keeps it and sets it when it cuts; see
[Outlook for Mac](#outlook-for-mac).)

| Field | Type | Meaning |
|---|---|---|
| `provider` | string | which adapter read the message |
| `message_id` | string | the provider's id for the message; used only to dedupe |
| `from_name` | string | sender display name, `""` if none |
| `from_addr` | string | sender address |
| `reply_to` | string or `null` | Reply-To address, `null` if none is shown |
| `to` | string[] | recipient addresses |
| `subject` | string | subject line |
| `body_text` | string | message body as text, built as under "Body text and link text" below |
| `links` | `{text, href}`[] | each `a` and `area` element with an `href` attribute in the body, in document order: its text (built below) and its `href` attribute untouched |
| `attachments` | string[] | attachment file names |
| `truncated` | boolean | `true` when the worker cut or dropped anything to make the observation fit |

**Body text and link text.** The daemon reads `body_text` line by line (the
greeting cue looks at the first three non-empty lines, the role-name cue at the
last five) and matches phrases at word boundaries. An element's `textContent`
drops all structure, so `<p>Thanks</p><p>Human Resources</p>` would become one
glued line and cues would stop firing, and `innerText` depends on layout, which
a parsed but unrendered document does not have. Every builder of a mail
observation therefore uses one explicit walk that needs no layout: the Gmail
adapter, the offline `eval` tool, and any later adapter. Walk the body
element's descendants in document order:

- a text node contributes its data, unchanged;
- a `script` or `style` element contributes nothing and its descendants are not
  visited;
- an element whose tag is in the block list contributes one newline before its
  content and one after it; `br` and `hr`, which have no content, contribute
  one newline;
- every other element contributes only what its descendants contribute.

The block list is `address`, `article`, `aside`, `blockquote`, `br`, `dd`,
`div`, `dl`, `dt`, `fieldset`, `figcaption`, `figure`, `footer`, `form`, `h1`
to `h6`, `header`, `hr`, `li`, `main`, `nav`, `ol`, `p`, `pre`, `section`,
`table`, `td`, `th`, `tr`, `ul`. `body_text` is the concatenation as it is: no
trimming, no collapsing. Text hidden by styling is included on purpose, since
without layout it cannot be told apart and seeing more is the safe side. The
body element and the link element add nothing themselves, only their
descendants do, so a body that is one paragraph begins and ends with a newline.
Only text nodes are text: an image's `alt` is not.

A link's `text` is the same walk over the link element, then every run of
whitespace (newlines included) is replaced by one space and the ends are
trimmed; for an `area`, which has no content, it is the empty string.
"Whitespace" here is exactly what JavaScript's `\s` matches: tab, line feed,
vertical tab, form feed, carriage return, space, U+00A0, U+1680, U+2000 to
U+200A, U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF. It differs from
Unicode's White_Space property in two characters: U+0085 is not in it, U+FEFF
is. A builder in another language uses the same set.

**Limits.** The daemon refuses an observation over any of these and does not
rely on the sender (`check_limits` in `crates/riggs-types/src/phishing.rs` is
authoritative). Lengths are UTF-8 bytes, not JavaScript string lengths.

| What | Limit |
|---|---|
| `body_text` | 65,536 bytes |
| `links[].href` | 8,192 bytes |
| every other string in `CheckMail` | 4,096 bytes |
| `to`, `links` | 500 entries each |
| `attachments` | 100 entries |
| `host`, `entry_host` | 255 bytes |

**Capping.** The worker, not the adapter, makes a mail observation fit before
sending it. Adapters send what they read. In this order:

1. **Filler.** In `body_text` only, before any limit is applied, every maximal
   run of more than 256 consecutive characters from `A-Z`, `a-z`, `0-9`, `+`,
   `/`, `=`, `_` and `-` is replaced by one space. A run of exactly 256 stays,
   and a run interrupted at or before its 256th character by any other
   character (a space, a `.`, a non-ASCII letter) stays. No prose has such a
   run, and text in scripts written without spaces is outside the character
   set. The reason is measured: about 2,500 messages of a public phishing
   collection, nearly all from 2026, carry about 210 KB of base64-like filler
   in one hidden element before their visible text, so a 64 KiB cut kept only
   filler and every cue that reads the body was blind. With this threshold 8 of
   7,605 other messages lose a run, none of them changing a cue, against 443 at
   a threshold of 64. Only `body_text` is treated; subject, link text, link
   targets and every other field keep their limits and nothing else.
2. **Fields.** The request is rebuilt from the ten fields the adapter sends
   (the table above), so a field an adapter adds is dropped. A list over its
   limit keeps its first entries. A string over its limit is cut to the longest
   prefix whose UTF-8 encoding fits, without splitting a code point. Every
   string is also made well-formed, whether or not it was cut: a lone UTF-16
   surrogate, high or low, becomes U+FFFD. `JSON.stringify` would write it as an
   escape (`\ud83d`), which the daemon's JSON parser refuses for a string, and
   the mail would get no verdict.
3. **The whole request.** The field limits do not bound the serialized
   request: `JSON.stringify` writes a quotation mark or a backslash as two
   characters and a control character as up to six ([QuoteJSONString][quote]).
   If `new TextEncoder().encode(JSON.stringify({CheckMail: obs})).length` is
   over 6,291,456 (6 MiB), the worker drops links from the end, then
   recipients from the end, until it is not. Two steps are enough: with both
   lists empty, what remains is at most the body (64 KiB), 100 attachment
   names of 4 KiB and five other strings of 4 KiB. That is 484 KiB raw, and
   under 3 MiB even if every byte were a control character escaped to six.
4. **`truncated`.** The worker sets `obs.truncated` itself, replacing anything
   an adapter put there: `true` if step 1 removed a run, or step 2 or 3 cut a
   string, cut a list or dropped an entry, `false` otherwise. Replacing a lone
   surrogate does not count. The size in step 3 is that of the request as it is
   sent, `truncated` included.

The budget keeps every request under the native host's input limit and the
daemon's frame limit, both 8 MiB (see [The native host](#the-native-host)),
with room for the host's wrapper and for any difference between the browser's
and the daemon's JSON escaping. So a mail cannot escape the check by being too
large to deliver, and `truncated` tells the daemon that it did not see all of
the mail, which it treats as a signal rather than as a clean mail.

**Host to daemon.** The host wraps the request as the daemon's client message,
`{"Phishing": <request>}`, sends it on the daemon's Unix socket
(`/var/run/riggs.sock` unless `RIGGS_SOCKET` names another path, as for the
`riggs` CLI) behind a 4-byte little-endian length, one request per
connection, and unwraps `{"Phishing": <response>}`
(`crates/riggs-comms/src/ipc.rs`). A status request reaches the daemon as
`{"Phishing":{"Status":null}}`, or as the Rust side's own
`{"Phishing":"Status"}` if the host re-serializes it; the daemon reads both
alike. It refuses a frame over `comms.ipc_max_message_bytes`, 8 MiB by
default, and keys sensor requests by the socket peer's uid.

### Messages to the worker

A content script or an extension page calls `chrome.runtime.sendMessage(message)`
and the worker answers. These are one-time requests; there are no ports.

- `runtime.sendMessage` is one of the few extension APIs a content script can
  call directly ([content scripts][cs]); native messaging is not among them.
- Messages and replies are JSON: "the message passing APIs use JSON
  serialization" ([messaging][msg]).
- Every message is an object with a string field `t`.
- `background.js` registers one `chrome.runtime.onMessage` listener and is the
  only file that registers one: with several listeners "only the first listener
  to respond, reject, or throw an error will affect the sender"
  ([messaging][msg]). The worker never starts a conversation
  (`chrome.tabs.sendMessage` is not used).
- The worker answers every message exactly once through `sendResponse`, and its
  listener returns the literal `true` so that it may answer later: "return a
  literal `true` (not just a truthy value)" ([messaging][msg]). Returning a
  promise instead works only "From Chrome 148" ([messaging][msg]) and is not
  used.
- The answer to anything the worker refuses or cannot answer is `null`: an
  unknown `t`, a wrong sender, a malformed field, a host or daemon failure. A
  sender treats a rejected `sendMessage` (the worker is unreachable, for
  example after the extension was reloaded) as `null` too.
- Content scripts are untrusted: "Assume that messages from a content script
  might have been crafted by an attacker" and "Assume any data sent to the
  content script might leak to the web page" ([messaging][msg]). So the worker
  takes the extension, tab, frame, origin and document from `sender`, which the
  browser fills in, never from the payload, and the only thing it sends a content
  script is a verdict that is meant to be displayed.

**Who may send.** `sender.id` must equal `chrome.runtime.id` for every message.
Beyond that the worker knows four kinds of sender:

| Sender | Conditions on `sender` |
|---|---|
| web frame | `tab` is set and `documentLifecycle === "active"` |
| mail frame | a web frame with `frameId === 0` whose `origin` is a mail origin |
| popup | `url === chrome.runtime.getURL("popup.html")` |
| warning page | `url === chrome.runtime.getURL("interstitial.html")`, `tab` is set, `frameId === 0` |

| Mail origin | `provider` |
|---|---|
| `https://mail.google.com` | `gmail` |

- `sender.tab` is present "when the connection was opened from a tab
  (including content scripts)" ([runtime][rt]); the popup has none.
- `sender.origin` is "The origin of the page or frame that opened the
  connection. It can vary from the url property (e.g., about:blank) or can be
  opaque (e.g., sandboxed iframes)" ([runtime][rt]). An `about:blank` frame
  inherits "the origin of the document containing that URL" ([same-origin
  policy][sop]). A sandboxed frame has an opaque origin and a `data:` frame
  gets "a new, empty, security context" ([same-origin policy][sop]); such an
  origin reads as `"null"` ([Window.origin][origin]).
- `sender.frameId` is "0 for top-level frames, positive for child frames"
  ([runtime][rt]). "`frameId == 0` will still continue to represent the
  outermost frame of the active page", while "for prerendered frames the
  `frameId` will be non-zero for the outermost frame" ([instant
  navigation][inst]).
- `sender.documentLifecycle`, available from Chrome 106, is "The lifecycle the
  document that opened the connection is in at the time the port was created"
  ([runtime][rt]). Its values are `prerender`, `active`, `cached` and
  `pending_deletion`; `prerender` means "Not currently presented to the user"
  ([instant navigation][inst]). Only an active document sends `mail`, `page`
  and `login`, and the worker refuses a sender whose `documentLifecycle` is not
  `active`: a block triggered by a prerendering document would replace the page
  the person is actually looking at. Unverified: whether content scripts run in
  a prerendering document at all; the rule holds either way.
- `sender.documentId`, also Chrome 106, is the browser's id of the document that
  sent the message ([runtime][rt]). The worker uses it only to ask the browser
  whether that document is still the one its frame shows (see "A page
  verdict acts only on a document that is still shown", below).

**The host of a web frame.** For `page` and `login` the worker needs a host,
and takes it from the browser's own record, never from the payload:

1. If `sender.origin` is an `http` or `https` origin, the host is
   `new URL(sender.origin).hostname`: the frame's own host.
2. Otherwise the origin is opaque (a sandboxed frame, a `data:` frame). The
   worker reads the tab's top frame with
   `chrome.webNavigation.getFrame({tabId: sender.tab.id, frameId: 0})` and
   uses the host of its `url`. The host is then the page's, not the frame's: a
   password form hidden in a sandboxed frame is judged by the page that shows
   it.
3. If the browser gives no usable URL for the top frame, the worker uses
   `topHost:<tabId>`, the host of the tab's last top-level commit (see
   [Session state](#session-state)). The browser does not hand the worker the
   URL of a `blob:` top frame (Chromium's `frame_navigation_state.cc` lists the
   schemes it reports, and `blob` is not among them), which is what the stored
   host is for. A tab that was open before the extension was loaded has no
   stored host until its next top-level commit.
4. If there is still no host, the worker makes no check and replies `null`.

**What a host is.** The host of a URL is its `hostname` when the URL is `http`
or `https`. A `blob:` URL has the host of the page that made it: the hostname
of the URL's origin, when that origin is `http` or `https` (the URL Standard,
"Origin": for the `blob` scheme the origin is that of the URL inside it if its
scheme is `http`, `https` or `file`, otherwise opaque). A page can build its
form as a blob and navigate to it, so this closes a way around the check. A
`blob:` URL made in an opaque origin, or by a `file:` or an extension page, has
no host, and neither has any other scheme. A hostname over 255 bytes is no host
either: no DNS name is that long, and a page could otherwise open a tab at one
(which fails to load), send the tab on to its real page, and leave
`entry:<tabId>` holding the long name, so that the daemon refuses every
`CheckPage` of that tab; or fill session storage with such names. Writing a
key "from `url`" below means writing that URL's host, and writing nothing when
it has none.

"The frame ID of the main frame is always 0" ([webNavigation][wn]), and the
frame `getFrame` returns has a `url` ([web_navigation.json][wnjson]; the
[reference][wn] gives only the result's type). Because the sender is an active
document, frame 0 is the top frame of the page it is in ([instant
navigation][inst]).

**The messages.**

| `t` | From | Other fields | Reply |
|---|---|---|---|
| `mail` | mail frame | `obs`: object, the `CheckMail` payload without `truncated` | the verdict to display, or `null` |
| `adapter` | mail frame | `provider`: string; `ok`: boolean | `null` |
| `page` | web frame | none | the verdict to display, or `null` |
| `login` | web frame | `evidence`: `"typed"`, `"autofill"` or `"filled"` | `null` |
| `status` | popup | none | a status object |
| `blocked` | warning page | none | `{host, reasons}` or `null` |
| `continue` | warning page | none | `null` |

A verdict in a reply is the daemon's object unchanged:
`{level, reasons: [{cue, text}], show}`. The worker passes it on only when
`show` is `true`; otherwise the reply is `null`. Content scripts therefore never
look at `show`, and in monitor mode nothing about the verdict reaches the page.
The worker accepts a response as a verdict only when its `level` is one of
`none`, `caution`, `danger`; any other is "no answer", since an unknown level
would otherwise be stored, sent back as `mail_level` and make the daemon refuse
every later page check from that mail.

**A page verdict acts only on a document that is still shown.** A page verdict
with `show: true` is passed on, and may set the badge or block the tab, only
while `chrome.webNavigation.getFrame({documentId: sender.documentId})` reports
the sender's document with `documentLifecycle` `"active"`. If the document has
been replaced or removed (the browser answers `null`) or is in the
back/forward cache, the reply is `null` and nothing else happens. Two cases
where the browser cannot say count as shown, so that a verdict is not lost: a
sender whose own URL is a `blob:` URL (`webNavigation` does not see `blob:`
documents at all, and without the exception a page could put its form in one
and shed every verdict), and a call that fails, which includes a sender
without a `documentId`.

**Native calls are queued.** Each native call starts a host process and holds a
connection to the daemon, which accepts a bounded number per user. A page can
create frames faster than hosts can be started. So for `mail`, `page` and
`login`, at most eight native calls run at once; the others wait, and none is
refused. A call that a top frame asked for starts before any waiting call that
only subframes asked for, and top-frame calls go in arrival order (a top frame
that asks for a call already waiting takes it ahead). `page` and `login`
messages from one tab that make the same request (the serialized request is
identical) share one call and get its answer; `mail` requests are never shared,
because each message is sent once. A call that had to wait is not made once
every document that asked for it has gone, and that applies to `mail` too.
`status` is outside the queue: it must not wait behind thirty mails. The queue
lives in the worker and dies with it; a sender treats the rejected
`sendMessage` as `null`. There is no cap on its length: it grows only with the
number of distinct hosts a tab's frames show, and delays subframe checks, never
a top frame's.

`{t: "mail", obs}`

- Sent once per opened message. The adapter does not send the same
  `message_id` twice from one document; it keeps the reply to redraw the banner
  when the mail view re-renders. A message it cannot read completely is not
  sent (see `adapter`).
- `obs.provider` must be the provider of `sender.origin`, or the message is
  refused.
- The worker refuses the message, changes nothing and replies `null` unless
  `obs` has exactly the types of the `CheckMail` table: five strings
  (`message_id`, `from_name`, `from_addr`, `subject`, `body_text`), `reply_to` a
  string or `null` (absent is refused), `to` and `attachments` arrays of
  strings, `links` an array of `{text, href}` strings. A request the daemon
  would refuse is not sent.
- The worker caps `obs` and sets `obs.truncated` (see
  [Wire protocol](#wire-protocol)), sends `{"CheckMail": obs}` through the
  call queue, and records the verdict's level in `mailLevel:<tabId>` whatever
  `show` says. A response that is not a verdict (an `Error`, no answer) records
  no level and does not erase a warning seen earlier (a mail that waited for
  a place and whose document went before its turn counts the same way); see
  [Session state](#session-state) for what is kept and for how long.
- When the reply is not `null` the adapter calls `riggsBanner(anchor, reply)`.
  The adapter sends nothing while `document.prerendering` is `true` and scans
  when `prerenderingchange` fires, since the worker would refuse a sender that
  is not active and the adapter never sends a message twice.

`{t: "adapter", provider, ok}`

- Sent after each attempt to read an opened message: `ok: true` when the
  observation was complete and the `mail` message went out, `ok: false` when a
  required field was missing.
- `provider` must be the provider of `sender.origin`. The worker writes
  `adapter:<provider>`.

`{t: "page"}`

- Sent once per document, when a password field first exists in it, and once
  more each time the document comes back from the back/forward cache
  (`pageshow` fires when a page is "restored from the bfcache" and `persisted`
  tells a cached load apart: [pageshow][pageshow], [persisted][persisted]).
- Only an active document sends it. While `document.prerendering` is `true`
  the sensor waits for `prerenderingchange`, which fires "When the prerendered
  page is activated" ([Document.prerendering][prerender]).
- The worker builds the observation itself: `host` is the host of the web
  frame (above), `entry_host` is `entry:<tabId>`, `opened_from_mail` is
  whether `fromMail:<tabId>` exists and `mail_level` is its `level`. It sends
  `{"CheckPage": {...}}` through the call queue.
- If the verdict has `show: true` and `level: "danger"` and there is no
  `allow:<host>`, then, in one turn of the worker (no navigation event is
  handled in between): it reads the top frame's URL with
  `chrome.webNavigation.getFrame({tabId, frameId: 0})`; it confirms that the
  sender's document is still shown (above), and if not, does nothing and
  replies `null`; it sets the tab's badge; it writes `blocked:<tabId>`; and it
  navigates the tab with
  `chrome.tabs.update(tabId, {url: chrome.runtime.getURL("interstitial.html")})`
  (no query, no fragment) and replies `null`. Reading the URL fails safely: if
  `getFrame` gives nothing, the block is stored without a URL and the tab is
  still sent to the warning page. Unverified: the tabs reference shows an
  extension page opened with `tabs.create` ([tabs][tabs]) but does not spell
  out the same for `tabs.update`; Chromium's `tabs_api.cc` sets the
  navigation's initiator to the extension's own origin, which suggests it works.
  Several frames of one tab with a `danger` verdict each send the tab to the
  same warning page; Chrome keeps the last.
- Otherwise the reply follows the `show` rule (and the document rule above),
  and the page sensor calls `riggsBanner(anchor, reply)` when it is not `null`.

`{t: "login", evidence}`

- Sent on a trusted click or Enter, once per document, when a password field
  that belongs to the event holds a value. Like `page`, only an active document
  sends it. Which fields belong to the event: a click or Enter inside a form
  counts that form's password fields; one outside any form counts only password
  fields that are themselves outside any form. A password manager fills fields
  that nobody focused, and in a shadow tree nothing else finds them, so on such
  a click or Enter the sensor looks through the shadow trees around the event
  for password fields, nearest first. It looks at **at most 500 elements per
  event** (`LIMIT` in the function `lookAround` of `page.js`); a field beyond
  that bound is not found by this look, though a field the person focused,
  typed in or pasted into is already known. `evidence` says how the sensor knows the
  field was filled: `typed` (trusted keyboard input), `autofill` (the browser
  filled it), `filled` (it held a value without either).
- The worker sends `{"LoginSeen": {"host": ..., "evidence": ...}}` with the
  host of the web frame (above), through the call queue. It sends nothing when
  `evidence` is `filled` and the sender is a subframe whose host differs from
  the host of its tab's top frame (from `getFrame`, or `topHost:<tabId>` when
  the browser gives none): a page can fill a password field of its own
  by script and wait for a click, so an embedded advertisement frame could
  otherwise make its own host a "known login" from any site that embeds it.
  `typed` and `autofill` are sent from any frame, and `filled` from the top
  frame or from a frame on the top frame's own host.
- A login that did not have to wait for a place in the queue is sent whatever
  becomes of its page, since a page normally navigates right after a login. One
  that waited is dropped if its document has gone by its turn. Two identical
  reports made at the same moment are counted once.

`{t: "status"}`

- The worker sends `{"Status": null}` and replies with
  `{state, mode, logins, adapters}`:
  - `state`: `"ok"`, or one of the failure states in
    [The native host](#the-native-host).
  - `mode`, `logins`: the daemon's `Status` fields, present only when `state`
    is `"ok"`.
  - `adapters`: an object with one boolean per provider that has reported, for
    example `{"gmail": true}`; `{}` when none has.

`{t: "blocked"}` and `{t: "continue"}`

- The warning page learns what it is showing by asking: `blocked` returns
  `{host, reasons}`, taken from the value of `blocked:<tabId>` for
  `sender.tab.id` (which also holds `url`, never sent), or `null` when that tab
  has nothing blocked. Nothing is passed in the page's URL, so no host or
  reason text lands in the browser history and a hand-typed URL cannot fake a
  warning.
- `continue` means the person chose to go on. If `blocked:<tabId>` exists, the
  worker writes `allow:<host>`, removes `blocked:<tabId>` and, if the block
  holds a `url` that parses as `http` or `https`, calls
  `chrome.tabs.update(tabId, {url})` with it: the tab is sent to the blocked
  page's stored address, and does not go Back. The page is loaded anew (what
  was typed into it is gone, and a page that was the result of a form post comes
  back as a plain load of the same address), the page sensor checks it again,
  and this time, with `allow:<host>` set, the verdict goes to the banner. With
  no usable `url` (see `blocked:<tabId>` below) the allow is written, the block
  removed, and the tab is not navigated: the warning page stays, and opening
  the link again shows the page with its banner. Chrome's error from the
  navigation is not reported, because it quotes the URL.
- Why not Back: `tabs.update` is a renderer-initiated navigation that adds a
  history entry, and Chromium marks the page being left as skippable for Back
  when the person has not clicked or typed in it, which is the normal case
  (the check fires when a password field first exists). `goBack` would then
  pass over the blocked page, or fail when nothing lies before it. This is
  from reading `tabs_api.cc`, `navigation_controller_impl.cc` and `navigator.cc`
  in Chromium; none of it has been run.
- Leaving instead needs no message; the warning page handles it alone. For the
  same reason Back on the warning page usually skips the blocked page, which is
  the safer outcome.

### Session state

Only the worker reads and writes state, and only in `chrome.storage.session`.

- "Session storage holds data in memory while an extension is loaded. The
  storage is cleared if the extension is disabled, reloaded, updated, and when
  the browser restarts" ([storage][st]). Nothing here reaches the disk.
- "By default, it's not exposed to content scripts" ([storage][st]). The worker
  never calls `setAccessLevel`.
- Worker variables are not state: Chrome stops an idle worker "After 30 seconds
  of inactivity" and "Any global variables you set will be lost if the service
  worker shuts down" ([service worker lifecycle][swl]). The worker's only
  variables are its own pending work: the chain that runs steps one at a time
  (below) and the call queue ([Messages to the worker](#messages-to-the-worker)).
  A new worker has none, and nothing needs them to survive.
- No other storage is used anywhere in the extension: no `storage.local`, no
  `storage.sync`, no IndexedDB.
- Steps that read state and then act on it run one at a time, in arrival order:
  the four navigation and tab event handlers, the state read of a `page`
  message, the recording of a mail level, the block, and the body of `continue`.
  A worker that was asleep gets a tab's navigation events and the new page's
  first message in one burst, and the page check must see the provenance those
  events write. The native call itself is not part of the chain.

`<tabId>` is the decimal tab id; "Tab IDs are unique within a browser session"
([tabs][tabs]). The host of a URL is defined under "What a host is" above.
Writing a key "from `url`" below means writing that URL's host, and writing
nothing when it has none.

| Key | Value | Meaning |
|---|---|---|
| `entry:<tabId>` | string | the tab's first host: where it was first sent, before redirects, or where the person last sent it from the address bar |
| `fromMail:<tabId>` | `{level}` or `{}` | the tab was opened from mail; `level` is `none`, `caution` or `danger`, and missing when unknown |
| `mailTab:<tabId>` | `true` | the tab's top frame was on a mail origin at its last top-level commit |
| `mailLevel:<tabId>` | `{none?, caution?, danger?}`: for each level, the time in milliseconds (`Date.now()`) when a mail verdict in that tab last had it | what the tab's mail verdicts have been; the tab's mail level is the highest level whose time is within the last 30 minutes, and unknown when there is none |
| `topHost:<tabId>` | string | the host of the URL of the tab's last top-level commit; missing when that URL has no host or the tab has not committed since the extension loaded |
| `blocked:<tabId>` | `{host, reasons, url?}` | a page replaced by the warning page; `reasons` as in the verdict; `url` is the top frame's URL when the block was made, missing when it could not be read, is not `http` or `https` (a `blob:` page is never reopened from here), or is over 8,192 bytes (the limit of a link target; a megabyte of query string could otherwise make the write of the block fail) |
| `allow:<host>` | `true` | the person chose to continue to this host in this browser session |
| `adapter:<provider>` | boolean | the latest health report of a mail adapter |

How they change:

| Event | Effect |
|---|---|
| `webNavigation.onCreatedNavigationTarget` `{sourceTabId, tabId, url}` | Write `entry:<tabId>` from `url`. If the source tab's top frame is on a mail origin, write `fromMail:<tabId>` with `level` the source tab's mail level from `mailLevel:<sourceTabId>` (`{}` when it is unknown); otherwise, if `fromMail:<sourceTabId>` exists, copy it to `fromMail:<tabId>`. |
| `webNavigation.onBeforeNavigate` with `frameId === 0` | If the tab has no `entry:<tabId>`, write it from `url`. |
| `webNavigation.onCommitted` with `frameId === 0` | In this order. (1) If `transitionQualifiers` contains `"from_address_bar"`: remove `fromMail:<tabId>`; write `entry:<tabId>` from `url`, or remove it when the URL has no host. (2) Otherwise, if `mailTab:<tabId>` exists, `url` is not on a mail origin, `transitionType` is `"link"` and `transitionQualifiers` does not contain `"forward_back"`: write `fromMail:<tabId>` with `level` the tab's mail level from `mailLevel:<tabId>` (`{}` when it is unknown), and write `entry:<tabId>` from `url`. (3) Write `mailTab:<tabId>` if `url` is on a mail origin, remove it if not. (4) Write `topHost:<tabId>` from `url`, or remove it when the URL has no host. (5) Clear the tab's own badge text (see [Badges](#badges)). |
| `tabs.onRemoved` `(tabId)` | Remove `entry:`, `fromMail:`, `mailTab:`, `mailLevel:`, `blocked:` and `topHost:` for that tab. |
| a `mail`, `adapter`, `page` or `continue` message | As described under [Messages to the worker](#messages-to-the-worker). |

- `onCreatedNavigationTarget` is "Fired when a new window, or a new tab in an
  existing window, is created to host a navigation"; `sourceTabId` is "The ID of
  the tab in which the navigation is triggered" and `url` "The URL to be opened
  in the new window" ([webNavigation][wn]). Unverified: the documentation does
  not say whether it fires for a link the page marked `rel="noopener"`, which is
  how webmail opens links. `tabs.onCreated` with `openerTabId` ("The ID of the
  tab that opened this tab", [tabs][tabs]) is the documented alternative if it
  does not.
- The source tab's top frame is read with
  `chrome.webNavigation.getFrame({tabId: sourceTabId, frameId: 0})`, whose
  result has `url` ([web_navigation.json][wnjson]; the [reference][wn] gives
  only the result's type). This works whether or not the adapter could read the
  mail.
- `onBeforeNavigate` is "Fired when a navigation is about to occur"
  ([webNavigation][wn]), which is before any redirect; unverified: the
  reference does not describe its `url` field. It covers tabs that no page
  opened, such as a link clicked in another application.
- `onCommitted` is "Fired when a navigation is committed" and "has a
  transitionType and a transitionQualifiers property"; `onBeforeNavigate` has
  neither ([webNavigation][wn]).
- `from_address_bar` means "The user initiated the navigation from the address
  bar (aka Omnibox)" ([webNavigation][wn]). Only that clears the mark; links,
  redirects, reloads and back/forward keep it.
- Step 2 is the mail link that opens in the same tab as the mail view. `link`
  means "The user arrived at this page by clicking a link on another page"
  ([history][hist]) and `forward_back` "The user used the Forward or Back
  button to initiate the navigation" ([webNavigation][wn]), so a bookmark, the
  address bar, a reload and Back do not mark the tab. `entry` is then the
  address after redirects; the one first requested is not known at commit.
  Unverified in a browser.
- The page being left is known from `mailTab`, which step 3 wrote at the
  previous commit. It is not asked from `getFrame` when the navigation starts:
  the documentation does not say what `getFrame` returns while a navigation is
  pending, and `onBeforeNavigate` does not say what caused it. A tab that
  already showed mail when the extension was loaded has no `mailTab` until its
  next top-level commit.
- `frameId === 0` restricts all of this to the page the person sees: a
  prerendered page's top frame has another id ([instant navigation][inst]).
- `mailLevel` is what the mail verdicts of that tab have been, not the level of
  the mail a clicked link belongs to. With several messages open in one
  conversation the two can differ. Replies for the messages of a conversation
  arrive in any order, so keeping only the latest verdict would let a harmless
  message overwrite `danger` from another, and a page opened from the dangerous
  message would be told its mail was fine. Hence the highest level of the last
  30 minutes. A `mail` check that gets no verdict means "unknown" for that
  check only: it forgets a stored `none` and keeps any `caution` or `danger`
  seen within the 30 minutes. 31 minutes after a `danger`, the tab's mail level
  is no longer `danger`.
- `topHost` is the host a frame with an opaque origin falls back on when the
  browser gives no usable URL for the tab's top frame (see "The host of a web
  frame"). It is the host of the last top-level commit, not of the first
  navigation.
- `entry` is the host the tab was first sent to. If the mail view sends clicks
  through a redirector, that is the redirector's host, not the destination's.
- `blocked:<tabId>` is written before the tab is navigated to the warning page,
  so the entry exists when the page asks for it. It is not cleared when the tab
  simply leaves the warning page; only the warning page in that same tab can
  read it.

### Badges

The worker sets two badges on the toolbar icon with
`chrome.action.setBadgeText`, with no colour set. Both are text only and are
the one warning that a page cannot remove.

- **`!`, for one tab.** Set when a verdict with `show: true` and a level other
  than `none` is passed on, for a mail or a page, and before a block. It stays
  until the tab's next top-level commit, which clears the tab's own text with
  `text: null` (an empty string would hide the global badge on that tab). A
  later verdict never clears it, so a subframe with a clean verdict cannot
  remove the page's badge. Gmail does not commit while a mail is read, so after
  a flagged mail the `!` stays until the tab reloads or navigates.
- **`?`, global.** Shown while any mail adapter's latest report is `ok:
  false`, and recomputed whenever an adapter reports and when the browser
  starts (`runtime.onStartup`; session storage is empty then, so a `?` the
  browser kept is cleared). A tab's own `!` covers it in that tab.

### The banner call

`banner.js` defines one global function, used by `gmail.js` and `page.js`:

```js
riggsBanner(anchor, verdict)  // returns the banner Element, or null
```

- `anchor` is an `Element` in the document whose parent is an element too (so
  not `<html>`). `verdict` is a non-null reply to a `mail` or `page` message;
  callers skip the call when the reply is `null`.
- It first removes two banners, whatever `verdict.level` is: the banner an
  earlier call placed for this `anchor`, wherever the page has moved it, and a
  Riggs banner that is `anchor`'s previous element sibling, whichever anchor
  that one was placed for. The second is what a page leaves behind when it
  replaces an anchor element in place. So an anchor has at most one banner.
  `banner.js` knows its banners by identity, never by an attribute or a class,
  so an element that only looks like a banner is left alone.
- `level: "none"`: it shows nothing and returns `null`.
- `level: "caution"` or `"danger"`: it inserts one banner element immediately
  before `anchor`, as its previous sibling and never inside it, and returns
  that element. The banner shows a heading for the level, one line per entry
  of `verdict.reasons` in order, taken from `reason.text`, and a control that
  dismisses it. A dismissed banner stays away until the next call for that
  anchor. The dismiss control removes the banner element from the document
  inside its `click` handler and does not stop the event. A caller that listens
  for `click` on the returned element therefore finds it detached
  (`isConnected` is `false`) when the click came from the dismiss control, and
  still in the document after any other click. That is how a caller tells a
  dismissal from a removal by the page, which produces no click. The listener
  must not be a capturing one, which would run before the control's handler.
- Any other `level` is an error: it throws.
- All text is set through `textContent`. No `innerHTML`, `insertAdjacentHTML`
  or `document.write` ([messaging, cross-site scripting][msg]).
- There is no "safe" state: nothing is ever rendered for `none`, and no wording
  tells the person that a message or page is fine.
- The wording of the banner itself is neutral, since the same call serves mail
  and pages; the specifics come from `reasons`.
- It is self-contained: no messages, no storage, no network. It cannot use
  images, fonts or stylesheets from the extension either, because none are
  web-accessible ([web accessible resources][war]); it styles itself from
  script.

It reaches its callers because all content scripts of one extension share one
isolated world in a frame, "the execution environment unique to this
extension" ([scripting][scripting]; [content scripts][cs]), and files run in
`js` order, so a later file "can see global variables added by" an earlier one
([MDN content_scripts][mdncs]). `banner.js` therefore declares
`function riggsBanner` at its top level. Because it may be evaluated twice in
Gmail's top frame, its top level holds only `function` declarations: a second
`let`, `const` or `class` of the same name would be a redeclaration error. Its
own state (the banners placed, by anchor and as a set) is kept on the global
object under `Symbol.for("riggsBanner")`, which is not a name, so that a second
evaluation still finds what the first placed and `riggsBanner` stays the only
global name the file adds. A banner takes everything it needs from the
prototypes (`Document.prototype.createElement`, `Node.prototype.insertBefore`
and so on), never from `document` or from the anchor, because a page's element
named `createElement` or `insertBefore` would shadow those properties.

### The native host

`install/native-messaging/com.riggs.browser.json` registers the host:

| Field | Value | Rule ([native messaging][nm]) |
|---|---|---|
| `name` | `com.riggs.browser` | "can only contain lowercase alphanumeric characters, underscores and dots"; the file is named after it |
| `path` | `/usr/local/bin/riggs-browser-host` | "On Linux and macOS the path must be absolute" |
| `type` | `stdio` | "This parameter has one possible value: `stdio`" |
| `allowed_origins` | `chrome-extension://lilgnipcebaofalbkdgonmidhpdfomen/` | "`allowed_origins` values can't contain wildcards" |

Content scripts cannot reach it: the native-messaging methods "are not
available inside content scripts, only inside your extension's pages and
service worker" ([native messaging][nm]). Only the worker calls it.

**Process.** With `sendNativeMessage`, "Chrome starts a new native messaging
host process for each message"; "the first message generated by the host
process is handled as a response to the original request" and "All other
messages generated by the native messaging host in that case are ignored"
([native messaging][nm]). So the host reads one message from stdin, writes one
to stdout and exits.

- "The first argument to the native messaging host is the origin of the caller"
  ([native messaging][nm]). The host must accept that argument rather than
  fail on it.
- stdout carries the response and nothing else. Debug output goes to stderr
  ([native messaging][nm]), and nothing from a request may appear there.

**Framing.** "The same format is used to send messages in both directions;
each message is serialized using JSON, UTF-8 encoded and is preceded with
32-bit message length in native byte order" ([native messaging][nm]).

- "The maximum size of a single message from the native messaging host is
  1 MB" ([native messaging][nm]). A daemon response larger than that is
  answered with an `Error` instead.
- "The maximum size of the message sent to the native messaging host is
  64 MiB" ([native messaging][nm]). The host sets its own, lower limit: it
  refuses an input frame over 8,388,608 bytes (8 MiB) without reading it and
  answers with an `Error`. That is the daemon's default frame limit
  (`comms.ipc_max_message_bytes`), and the worker's 6 MiB budget (see
  [Wire protocol](#wire-protocol)) keeps every request under both. An
  operator who lowers the daemon's limit makes large observations fail with
  an `Error`, which means no verdict for those mails.

**Requests.** The host accepts exactly four: an object whose single key is
`CheckMail`, `CheckPage`, `LoginSeen` or `Status` (the last one arrives as
`{"Status": null}`). Anything else, the daemon's owner-only requests included,
is answered with an `Error` and never forwarded.

**Errors.** The host always answers. When it cannot reach the daemon, or the
daemon does not answer within 5 seconds, the answer is exactly:

```json
{"Error": "daemon unreachable"}
```

The worker compares that string. Every other `Error` text is free-form and
must not contain anything from an observation.

The worker maps failures to the `state` of the `status` reply:

| `state` | What happened | How the worker sees it |
|---|---|---|
| `ok` | the daemon answered | the response is `{"Status": {...}}` |
| `host_not_found` | the host manifest is missing, misnamed or invalid, or `path` does not exist | error `Specified native messaging host not found.` |
| `host_forbidden` | this extension's ID is not in `allowed_origins`, for example a copy loaded without the committed `key` | error `Access to the specified native messaging host is forbidden.` |
| `host_exited` | the host died before answering | error `Native host has exited.` |
| `daemon_unreachable` | the host ran but the daemon did not answer | the response is `{"Error": "daemon unreachable"}` |
| `error` | anything else | any other error text or response |

The error texts are the ones Chrome documents ([native messaging,
debugging][nm]). With a callback, a failed call invokes it with no arguments
and sets `runtime.lastError` ([runtime.json][rtjson]). "API functions that
return promises do not set this property" ([runtime][rt]); unverified: that the
rejected promise's `message` is the same text.

### References

[hello]: https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world
[manifest]: https://developer.chrome.com/docs/extensions/reference/manifest
[version]: https://developer.chrome.com/docs/extensions/reference/manifest/version
[key]: https://developer.chrome.com/docs/extensions/reference/manifest/key
[minver]: https://developer.chrome.com/docs/extensions/reference/manifest/minimum-chrome-version
[incog]: https://developer.chrome.com/docs/extensions/reference/manifest/incognito
[minvercc]: https://github.com/chromium/chromium/blob/main/chrome/common/extensions/manifest_handlers/minimum_chrome_version_checker.cc
[csm]: https://developer.chrome.com/docs/extensions/reference/manifest/content-scripts
[cs]: https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts
[mdncs]: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/content_scripts
[scripting]: https://developer.chrome.com/docs/extensions/reference/api/scripting
[csp]: https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy
[war]: https://developer.chrome.com/docs/extensions/reference/manifest/web-accessible-resources
[ec]: https://developer.chrome.com/docs/extensions/reference/manifest/externally-connectable
[sw]: https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/basics
[swl]: https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle
[action]: https://developer.chrome.com/docs/extensions/reference/api/action
[rt]: https://developer.chrome.com/docs/extensions/reference/api/runtime
[rtjson]: https://github.com/chromium/chromium/blob/main/extensions/common/api/runtime.json
[argspec]: https://github.com/chromium/chromium/blob/main/extensions/renderer/bindings/argument_spec.cc
[msgutil]: https://github.com/chromium/chromium/blob/main/extensions/renderer/api/messaging/messaging_util.cc
[quote]: https://tc39.es/ecma262/multipage/structured-data.html#sec-quotejsonstring
[msg]: https://developer.chrome.com/docs/extensions/develop/concepts/messaging
[nm]: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
[st]: https://developer.chrome.com/docs/extensions/reference/api/storage
[tabs]: https://developer.chrome.com/docs/extensions/reference/api/tabs
[wn]: https://developer.chrome.com/docs/extensions/reference/api/webNavigation
[wnjson]: https://github.com/chromium/chromium/blob/main/chrome/common/extensions/api/web_navigation.json
[hist]: https://developer.chrome.com/docs/extensions/reference/api/history
[inst]: https://developer.chrome.com/blog/extension-instantnav
[new]: https://developer.chrome.com/docs/extensions/whats-new
[idutil]: https://github.com/chromium/chromium/blob/main/components/crx_file/id_util.cc
[extcc]: https://github.com/chromium/chromium/blob/main/extensions/common/extension.cc
[origin]: https://developer.mozilla.org/en-US/docs/Web/API/Window/origin
[sop]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy#inherited_origins
[pageshow]: https://developer.mozilla.org/en-US/docs/Web/API/Window/pageshow_event
[persisted]: https://developer.mozilla.org/en-US/docs/Web/API/PageTransitionEvent/persisted
[prerender]: https://developer.mozilla.org/en-US/docs/Web/API/Document/prerendering
[node]: https://nodejs.org/api/packages.html#determining-module-system
