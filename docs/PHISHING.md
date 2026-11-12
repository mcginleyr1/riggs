# Riggs: Phishing Protection

Phishing happens inside the mail view and the browser, where Riggs has no
sensor. A Chromium extension (`extensions/riggs-browser`) fills that gap. Its
content scripts report the mail a person opens and the password pages they
visit, its service worker asks the daemon for a verdict through the
native-messaging host `riggs-browser-host`, and the daemon decides. The
extension holds no scoring logic and no public-suffix logic.

## Browser extension contract

This section is frozen. The worker, the popup, the page sensor, the warning
page, the Gmail adapter, the banner and the native host are written against it
independently, so a change here is a change to all of them.

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
  package.json                        must declare "type": "module"
install/native-messaging/
  com.riggs.browser.json              native-messaging host manifest, copied by the installer
```

| Package | Owns |
|---|---|
| 1B | `ext/manifest.json`, `test/manifest.test.js`, `install/native-messaging/com.riggs.browser.json`, this section |
| 2C | the host binary, `crates/riggs-cli/src/bin/riggs-browser-host.rs` |
| 2D | `ext/background.js`, `ext/popup.html`, `ext/popup.js`, `package.json`, `biome.json` |
| 2E | `ext/page.js`, `ext/interstitial.html`, `ext/interstitial.js` |
| 2F | `ext/gmail.js`, `ext/banner.js` |

An Outlook web adapter (`ext/outlook.js`) is planned for a later stage and is
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
| `minimum_chrome_version` | `"106"` | `MessageSender.documentLifecycle` is marked "Chrome 106+" ([runtime][rt]); see below |
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

- `tabs` is not requested. `chrome.tabs.update`, `chrome.tabs.goBack` and
  `chrome.tabs.onRemoved` work without it: "Most features don't require any
  permissions to use. For example: creating a new tab, reloading a tab,
  navigating to another URL" ([tabs][tabs]). The permission only unlocks a
  `Tab`'s `url`, `pendingUrl`, `title` and `favIconUrl`, so the worker reads
  `sender.tab.id` and nothing else from a `Tab`.
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

**`minimum_chrome_version`.** The newest API the contract depends on is
`MessageSender.documentLifecycle`, Chrome 106 ([runtime][rt]). The others are
older: `storage.session` Chrome 102, `match_origin_as_fallback` in a manifest
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
eleventh, `truncated`, is set by the worker and never by an adapter.

| Field | Type | Meaning |
|---|---|---|
| `provider` | string | which adapter read the message |
| `message_id` | string | the provider's id for the message; used only to dedupe |
| `from_name` | string | sender display name, `""` if none |
| `from_addr` | string | sender address |
| `reply_to` | string or `null` | Reply-To address, `null` if none is shown |
| `to` | string[] | recipient addresses |
| `subject` | string | subject line |
| `body_text` | string | message body as text |
| `links` | `{text, href}`[] | each link in the body: visible text and target |
| `attachments` | string[] | attachment file names |
| `truncated` | boolean | `true` when the worker cut or dropped anything to make the observation fit |

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

1. **Fields.** A list over its limit keeps its first entries. A string over
   its limit is cut to the longest prefix whose UTF-8 encoding fits, without
   splitting a code point.
2. **The whole request.** The field limits do not bound the serialized
   request: `JSON.stringify` writes a quotation mark or a backslash as two
   characters and a control character as up to six ([QuoteJSONString][quote]).
   If `new TextEncoder().encode(JSON.stringify({CheckMail: obs})).length` is
   over 6,291,456 (6 MiB), the worker drops links from the end, then
   recipients from the end, until it is not. Two steps are enough: with both
   lists empty, what remains is at most the body (64 KiB), 100 attachment
   names of 4 KiB and five other strings of 4 KiB. That is 484 KiB raw, and
   under 3 MiB even if every byte were a control character escaped to six.
3. **`truncated`.** The worker sets `obs.truncated` itself, replacing anything
   an adapter put there: `true` if step 1 or 2 cut a string, cut a list or
   dropped an entry, `false` otherwise. The size in step 2 is that of the
   request as it is sent, `truncated` included.

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
  takes the extension, tab, frame and origin from `sender`, which the browser
  fills in, never from the payload, and the only thing it sends a content
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
  ([instant navigation][inst]). Only an active document sends `page` and
  `login`, and the worker refuses a sender whose `documentLifecycle` is not
  `active`: a block triggered by a prerendering document would replace the page
  the person is actually looking at. Unverified: whether content scripts run in
  a prerendering document at all; the rule holds either way.

**The host of a web frame.** For `page` and `login` the worker needs a host,
and takes it from the browser's own record, never from the payload:

1. If `sender.origin` is an `http` or `https` origin, the host is
   `new URL(sender.origin).hostname`: the frame's own host.
2. Otherwise the origin is opaque (a sandboxed frame, a `data:` frame). The
   worker reads the tab's top frame with
   `chrome.webNavigation.getFrame({tabId: sender.tab.id, frameId: 0})` and
   uses the hostname of its `url`. The host is then the page's, not the
   frame's: a password form hidden in a sandboxed frame is judged by the page
   that shows it.
3. If that URL is not `http` or `https` either, there is no host: the worker
   makes no check and replies `null`.

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

`{t: "mail", obs}`

- Sent once per opened message. The adapter does not send the same
  `message_id` twice from one document; it keeps the reply to redraw the banner
  when the mail view re-renders. A message it cannot read completely is not
  sent (see `adapter`).
- `obs.provider` must be the provider of `sender.origin`, or the message is
  refused.
- The worker caps `obs` and sets `obs.truncated` (see
  [Wire protocol](#wire-protocol)), sends `{"CheckMail": obs}`, and on a
  `Verdict` writes `mailLevel:<tabId>` whatever `show` says. On anything else
  it removes `mailLevel:<tabId>`.
- When the reply is not `null` the adapter calls `riggsBanner(anchor, reply)`.

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
  `{"CheckPage": {...}}`.
- If the verdict has `show: true` and `level: "danger"` and there is no
  `allow:<host>`, the worker writes `blocked:<tabId>`, navigates the tab with
  `chrome.tabs.update(tabId, {url: chrome.runtime.getURL("interstitial.html")})`
  (no query, no fragment) and replies `null`. Unverified: the tabs reference
  shows an extension page opened with `tabs.create` ([tabs][tabs]) but does not
  spell out the same for `tabs.update`.
- Otherwise the reply follows the `show` rule, and the page sensor calls
  `riggsBanner(anchor, reply)` when it is not `null`.

`{t: "login", evidence}`

- Sent when a real user gesture submits a filled password field. Like `page`,
  only an active document sends it. `evidence` says how the sensor knows the
  field was filled: `typed` (trusted keyboard input), `autofill` (the browser
  filled it), `filled` (it held a value without either).
- The worker sends `{"LoginSeen": {"host": ..., "evidence": ...}}` with the
  host of the web frame (above).

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

- The warning page learns what it is showing by asking: `blocked` returns the
  value of `blocked:<tabId>` for `sender.tab.id`, or `null` when that tab has
  nothing blocked. Nothing is passed in the page's URL, so no host or reason
  text lands in the browser history and a hand-typed URL cannot fake a warning.
- `continue` means the person chose to go on. If `blocked:<tabId>` exists, the
  worker writes `allow:<host>`, removes `blocked:<tabId>` and calls
  `chrome.tabs.goBack(tabId)` ("Go back to the previous page", [tabs][tabs]).
  The blocked page returns, the page sensor checks it again, and this time the
  verdict goes to the banner. Unverified: that `tabs.update` adds a history
  entry, which is what makes `goBack` land on the blocked page.
- Leaving instead needs no message; the warning page handles it alone.

### Session state

Only the worker reads and writes state, and only in `chrome.storage.session`.

- "Session storage holds data in memory while an extension is loaded. The
  storage is cleared if the extension is disabled, reloaded, updated, and when
  the browser restarts" ([storage][st]). Nothing here reaches the disk.
- "By default, it's not exposed to content scripts" ([storage][st]). The worker
  never calls `setAccessLevel`.
- Worker variables are not state: Chrome stops an idle worker "After 30 seconds
  of inactivity" and "Any global variables you set will be lost if the service
  worker shuts down" ([service worker lifecycle][swl]).
- No other storage is used anywhere in the extension: no `storage.local`, no
  `storage.sync`, no IndexedDB.

`<tabId>` is the decimal tab id; "Tab IDs are unique within a browser session"
([tabs][tabs]). A host is always `new URL(...).hostname` of an `http` or `https`
URL; any other URL has no host. Writing a key "from `url`" below means writing
that URL's host, and writing nothing when it has none.

| Key | Value | Meaning |
|---|---|---|
| `entry:<tabId>` | string | the tab's first host: where it was first sent, before redirects, or where the person last sent it from the address bar |
| `fromMail:<tabId>` | `{level}` or `{}` | the tab was opened from mail; `level` is `none`, `caution` or `danger`, and missing when unknown |
| `mailTab:<tabId>` | `true` | the tab's top frame was on a mail origin at its last top-level commit |
| `mailLevel:<tabId>` | `"none"`, `"caution"` or `"danger"` | level of the latest mail verdict in a mail tab |
| `blocked:<tabId>` | `{host, reasons}` | a page replaced by the warning page; `reasons` as in the verdict |
| `allow:<host>` | `true` | the person chose to continue to this host in this browser session |
| `adapter:<provider>` | boolean | the latest health report of a mail adapter |

How they change:

| Event | Effect |
|---|---|
| `webNavigation.onCreatedNavigationTarget` `{sourceTabId, tabId, url}` | Write `entry:<tabId>` from `url`. If the source tab's top frame is on a mail origin, write `fromMail:<tabId>` with `level` from `mailLevel:<sourceTabId>` (`{}` when there is none); otherwise, if `fromMail:<sourceTabId>` exists, copy it to `fromMail:<tabId>`. |
| `webNavigation.onBeforeNavigate` with `frameId === 0` | If the tab has no `entry:<tabId>`, write it from `url`. |
| `webNavigation.onCommitted` with `frameId === 0` | In this order. (1) If `transitionQualifiers` contains `"from_address_bar"`: remove `fromMail:<tabId>`; write `entry:<tabId>` from `url`, or remove it when the URL has no host. (2) Otherwise, if `mailTab:<tabId>` exists, `url` is not on a mail origin, `transitionType` is `"link"` and `transitionQualifiers` does not contain `"forward_back"`: write `fromMail:<tabId>` with `level` from `mailLevel:<tabId>` (`{}` when there is none), and write `entry:<tabId>` from `url`. (3) Write `mailTab:<tabId>` if `url` is on a mail origin, remove it if not. |
| `tabs.onRemoved` `(tabId)` | Remove `entry:`, `fromMail:`, `mailTab:`, `mailLevel:` and `blocked:` for that tab. |
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
- `mailLevel` is the level of the latest verdict in that tab, not of the mail a
  clicked link belongs to. With several messages open in one conversation the
  two can differ.
- `entry` is the host the tab was first sent to. If the mail view sends clicks
  through a redirector, that is the redirector's host, not the destination's.
- `blocked:<tabId>` is written before the tab is navigated to the warning page,
  so the entry exists when the page asks for it. It is not cleared when the tab
  simply leaves the warning page; only the warning page in that same tab can
  read it.

### The banner call

`banner.js` defines one global function, used by `gmail.js` and `page.js`:

```js
riggsBanner(anchor, verdict)  // returns the banner Element, or null
```

- `anchor` is an `Element` in the document whose parent is an element too (so
  not `<html>`). `verdict` is a non-null reply to a `mail` or `page` message;
  callers skip the call when the reply is `null`.
- It first removes the banner an earlier call placed for this `anchor`, so an
  anchor has at most one banner.
- `level: "none"`: it shows nothing and returns `null`.
- `level: "caution"` or `"danger"`: it inserts one banner element immediately
  before `anchor`, as its previous sibling and never inside it, and returns
  that element. The banner shows a heading for the level, one line per entry
  of `verdict.reasons` in order, taken from `reason.text`, and a control that
  dismisses it. A dismissed banner stays away until the next call for that
  anchor.
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
`let`, `const` or `class` of the same name would be a redeclaration error.

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
