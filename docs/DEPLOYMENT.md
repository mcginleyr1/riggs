# Deploying Riggs to Macs with an MDM

This is for an IT administrator who has never seen Riggs. Riggs is an endpoint
protection agent: a root daemon (`riggs-daemon`) that watches processes, files
and network connections on the Mac and judges them, a command-line tool
(`riggs`), a menubar agent, a browser extension with its native-messaging host
(phishing protection), an optional Outlook for Mac bridge, and an optional
network filter (a macOS system extension in `Riggs Filter.app`) that enforces
egress and data-loss-prevention verdicts.

A source checkout installs with `sudo install/install.sh` (see `README.md`).
That builds with cargo on the target and installs a LaunchAgent for one user,
so it is not a deployment path. This document is.

Nothing in this repository has been signed, notarized or installed on a Mac by
the people who wrote these files: the package and the profiles were built and
linted, and every claim about how macOS behaves after installation is marked as
checked against a document or as unverified.

## 1. Build the packages

On a Mac with Xcode's command-line tools, from a checkout, with release
binaries built (`cargo build --release --locked`):

```
install/pkg/build-pkg.sh --out /path/to/out --app-identity "Developer ID Application: ..." \
    --installer-identity "Developer ID Installer: ..." [--filter-app "/path/to/Riggs Filter.app"]
```

Without `--installer-identity` the packages are built unsigned and the script
says so; without `--app-identity` the binaries are unsigned. The script prints,
and does not run, the notarization and stapling commands. It writes two
products:

| Package | Contents | Needed |
|---|---|---|
| `Riggs-VERSION.pkg` (`com.riggs.pkg.core`) | daemon, CLI, native-messaging host, menubar agent, defaults, rules, browser extension files, native-messaging manifests, launchd jobs, optional filter app | always |
| `Riggs-Outlook-VERSION.pkg` (`com.riggs.pkg.outlook`) | `riggs-mailbridge`, the add-in files, its LaunchAgent | only for Outlook for Mac |

Two products rather than one with an optional choice, because an MDM's package
install command has no way to pick choices.

## 2. What the core package installs

The Installer gives every payload entry the owner `root:wheel` (`pkgbuild
--ownership recommended`); modes are set by the build script. `postinstall`
creates and re-asserts the entries marked "postinstall". Existing files in
`/etc/riggs` are never overwritten. Compare with `install/install.sh`: every
path it installs system-wide is here; what differs is listed after the table.

| Path | Owner | Mode | Set by | Note |
|---|---|---|---|---|
| `/usr/local/bin/riggs`, `riggs-daemon`, `riggs-browser-host`, `riggs-menubar` | root:wheel | 755 | payload | |
| `/usr/local/share/riggs/` and its subdirectories | root:wheel | 755 | payload | |
| `/usr/local/share/riggs/browser-extension/**` | root:wheel | dirs 755, files 644 | payload | read by the browser as the user; root-owned so the user cannot rewrite it |
| `/usr/local/share/riggs/defaults/**` | root:wheel | dirs 755, files 644 | payload | `riggs.toml`, `phishing-policy.toml`, `rules/` |
| `/Library/LaunchDaemons/com.riggs.daemon.plist` | root:wheel | 644 | payload | |
| `/Library/LaunchAgents/com.riggs.menubar.plist` | root:wheel | 644 | payload | output discarded, see below |
| `/Library/Google/Chrome/NativeMessagingHosts/com.riggs.browser.json` | root:wheel | 644 | payload | |
| `/Library/Application Support/Chromium/NativeMessagingHosts/com.riggs.browser.json` | root:wheel | 644 | payload | |
| `/Library/Microsoft/Edge/NativeMessagingHosts/com.riggs.browser.json` | root:wheel | 644 | payload | |
| `/Applications/Riggs Filter.app` | root:wheel | as built | payload | only if built with `--filter-app` |
| `/Library/LaunchAgents/com.riggs.filter-activate.plist` | root:wheel | 644 | payload | only if built with `--filter-app`; activates the filter at login |
| `/etc/riggs` | root:wheel | 755 | postinstall | the CLI reads policy files here as the user |
| `/etc/riggs/riggs.toml`, `phishing-policy.toml` | root:wheel | 644 | postinstall | copied from `defaults/` only if absent |
| `/etc/riggs/rules/**` | root:wheel | dirs 755, files 644 | postinstall | refreshed on every install, as `install.sh` does |
| `/var/lib/riggs` | root:wheel | 700 | postinstall | the database; the daemon is root, users reach it through the socket |
| `/var/log/riggs` | root:wheel | 750 | postinstall | daemon logs |
| `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.riggs.browser.json` | that directory's owner | 644 | postinstall | only for users who have run Brave |
| `/var/run/riggs.sock` | root | 666 | launchd, from the daemon plist | the CLI and menubar talk to the daemon through it |

`install.sh` left `/etc/riggs`, `/var/lib/riggs` and `/var/log/riggs` to root's
umask. The package sets them explicitly. The modes `700` and `750` for the
database and logs are this package's choice (event data); nothing in the code
was found that reads either as a non-root user, but no installed Mac was used
to confirm that.

Differences from `install.sh`:

- It installs only `riggs.toml` and `phishing-policy.toml` into `/etc/riggs`,
  as `install.sh` does. Neither installer ships `config/dlp-policy.toml` or
  `config/egress-policy.toml`, and that is deliberate, read from the code
  (`crates/riggs-daemon/src/daemon.rs`, "DLP stage" and "Egress allowlist"):
  neither file is required. Without a DLP file the daemon uses the `[dlp]`
  section of `riggs.toml`, which the shipped config enables; installing the file
  would add a second place that takes priority over it. Without an egress file
  it uses `[egress]` from `riggs.toml`, which is off unless set; the shipped
  `egress-policy.toml` is a developer-tooling starter (`enabled = true`,
  monitor mode, an allowlist of github.com and internal ranges; `docs/STANDALONE.md`
  says to copy it when you want it), and installing it would turn egress
  monitoring on for every Mac with that list. Write your own file to
  `/etc/riggs/` (root:wheel, 644) when you want either; both are hot-reloaded.
  The rest of `config/policies/` is not read from `/etc/riggs` by anything I found.
- `riggs-menubar` is required by the package build; `install.sh` skips it if
  missing.
- The package does not build anything, and does not create `~/Library/Logs/riggs`.

### Per-user pieces

An MDM runs the package as root with no logged-in user, so no `$SUDO_USER`
exists. Each per-user piece of `install.sh` is decided as follows.

**Menubar agent.** It goes into `/Library/LaunchAgents`, owned by root, and
every user gets it at their next login. Apple's launchd documentation: agents
installed globally are in `/Library/LaunchAgents` ("Per-user agents installed
globally", loaded at login), and "Daemons and agents that are installed globally
must be owned by the root user" and must not be group or world writable
(https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html,
fetched; the page is from 2016 and adds a parenthetical of mode 600 or 400,
stricter than its own rule; 644 is what `install.sh` already used and satisfies
"not group or world writable"). If a user is at the desktop when the package
installs, `postinstall` also bootstraps the agent into that user's `gui/<uid>`
domain (`launchctl bootstrap`, domain targets in `man launchctl`); other users
who are logged in at that moment get it at their next login. The shared
`install/launchd/com.riggs.menubar.plist` sends its output to
`/tmp/riggs-menubar.log`, one file all users would fight over, so the package's
copy discards it. Fix the shared plist if you want the log.

**Network filter activation.** macOS activates a system extension only through
the app (`riggs-filter --activate`), from a user's session, so an MDM install
with nobody logged in cannot do it, and that is the normal case at enrolment. A
package built with `--filter-app` therefore also installs
`/Library/LaunchAgents/com.riggs.filter-activate.plist` (root:wheel, 644), which
runs `riggs-filter --activate` at each login; `postinstall` loads it for a user
already at the desktop, so there is one path. Read in
`extensions/riggs-filter/Sources/RiggsFilterHost/main.swift`: `--activate`
submits an activation request, then saves the content-filter configuration
(`isEnabled = true`) and exits; running it again re-submits the request and
re-saves the same configuration, and the code has no branch that fails when the
extension is already active. What macOS does with a request for an
already-active extension of the same version is Apple's behaviour and was not
checked. Two consequences: the filter is switched back on at every login, and
without the MDM approval profile the command waits for the user to approve the
extension, so a process stays running for that session.

**Brave.** Brave documents no system-wide native-messaging directory, so the
manifest has to be in each user's home. `postinstall` writes it for every local
account (UID 501 or more, listed by `dscl`, so `/Users/Shared` and `/Users/Guest`
never count) that already has Brave's directory. The step runs as that user
(`sudo -u "#<uid>"`, syntax from `man sudo`), never as root: a user owns
everything under their home and can replace a directory there with a link, and a
root `install -d` follows such a link and changes the target's mode (shown on a
scratch directory: a 700 target became 777). Neither `postinstall` nor
`uninstall-pkg.sh` runs any command as root on a path under a home directory. A user
who first runs Brave later, or an account created later, is not covered: run
the package again, or accept that phishing protection is absent in Brave for
them. Chrome, Chromium and Edge are covered system-wide.

**Outlook bridge.** Its state (token, certificate authority, manifest) is per
user and is created by `riggs-mailbridge setup`, which the user runs as
themselves and which prints two steps only the user can take (trust the
bridge's certificate authority in their login keychain, add the add-in to their
mailbox; see `docs/PHISHING.md`, "Outlook for Mac"). A root installer cannot do
either. So the Outlook package installs the binary, the add-in files and a
system-wide LaunchAgent whose command runs the bridge only if that user's state
directory exists (it exits 0, and launchd does not restart it, until then). A
user's setup therefore takes effect at their next login; to start it sooner,
that user runs `launchctl bootstrap gui/$(id -u) /Library/LaunchAgents/com.riggs.mailbridge.plist`
in their own session (`gui/<uid>` domain, `man launchctl`; if the agent is already
loaded, `launchctl kickstart -k gui/$(id -u)/com.riggs.mailbridge` restarts it).
The agent resolves
`$HOME` through `/bin/sh` at run time, because a launchd plist has no per-user
paths; that `HOME` is set for a user agent is assumed, not checked.

**Do not mix the two installers.** `install.sh` puts the menubar job (and with
`--outlook` the mailbridge job) in the user's own `~/Library/LaunchAgents`; the
package puts the same labels in `/Library/LaunchAgents`. On a Mac that used
`install.sh`, run `install/uninstall.sh` before installing the package. The
package does not touch user LaunchAgent folders.

## 3. Configuration profiles

Templates are in `install/mdm/`. Each is an XML property list, linted with
`plutil -lint`. **Never deploy a template**: an MDM accepts a literal `@TEAM_ID@`
(a dictionary key in the filter profile, so it approves nothing) without
complaint. Render copies with `install/mdm/render-profiles.sh`, which takes the
values as arguments, XML-escapes them, drops the template comments, refuses to
write a copy that still contains an `@...@` placeholder, lints each result and
exits non-zero if any copy was refused:

```
install/mdm/render-profiles.sh --out DIR --organization "Example Inc" --team-id TEAMID \
    --filter-requirement '...' --daemon-requirement '...' [--update-url https://...] \
    [riggs-network-filter.mobileconfig ...]
```

Name the templates you use (the extension profiles need `--update-url`; leave
them out until you have one). The templates carry fixed `PayloadUUID` values,
which stay valid; replace them only if you need a second copy of a profile to
coexist. Upload the rendered copies to your MDM
as custom profiles. Every key below was read in Apple's `apple/device-management`
repository (the source of Apple's developer documentation pages, which render
only with JavaScript) at the URL given.

Common keys (all profiles): `PayloadType`, `PayloadVersion`, `PayloadIdentifier`,
`PayloadUUID`, `PayloadContent`, `PayloadDisplayName`, `PayloadDescription`,
`PayloadOrganization`, `PayloadScope` (`System`):
https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/TopLevel.yaml
and `.../CommonPayloadKeys.yaml`.

| Profile | What it allows | Placeholders |
|---|---|---|
| `riggs-network-filter.mobileconfig` | the filter's system extension loads without a user prompt, and macOS activates it as a content filter | `@TEAM_ID@`, `@FILTER_EXTENSION_DESIGNATED_REQUIREMENT@`, `@ORGANIZATION@` |
| `riggs-full-disk-access.mobileconfig` | `riggs-daemon` reads protected files | `@DAEMON_CODE_REQUIREMENT@`, `@ORGANIZATION@` |
| `riggs-background-items.mobileconfig` | the Riggs launchd jobs are auto-enabled in Login Items | `@TEAM_ID@`, `@ORGANIZATION@` |
| `riggs-chrome-extension.mobileconfig` | Chrome force-installs the extension from your server | `@UPDATE_MANIFEST_URL@`, `@ORGANIZATION@` |
| `riggs-edge-extension.mobileconfig` | the same for Edge | `@UPDATE_MANIFEST_URL@`, `@ORGANIZATION@` |

### riggs-network-filter

Two payloads in one profile, so the approval cannot arrive without the filter
or the reverse.

`com.apple.system-extension-policy` (macOS only;
`.../mdm/profiles/com.apple.system-extension-policy.yaml`):

| Key | Value here | Meaning (Apple) |
|---|---|---|
| `AllowUserOverrides` | `false` | users cannot approve extensions the profile does not allow |
| `AllowedSystemExtensions` | `{TEAM: [com.riggs.filter.extension]}` | bundle identifiers approved per Team ID; a Team ID cannot also be in `AllowedTeamIdentifiers` |
| `AllowedSystemExtensionTypes` | `{TEAM: [NetworkExtension]}` | permitted types per Team ID (`DriverExtension`, `NetworkExtension`, `EndpointSecurityExtension`) |
| `RemovableSystemExtensions` (macOS 12.0+) | `{TEAM: [com.riggs.filter.extension]}` | the extension may remove itself, which `riggs-filter --deactivate` and the uninstall script rely on |

`com.apple.webcontent-filter` (`.../com.apple.webcontent-filter.yaml`):

| Key | Value here | Meaning (Apple) |
|---|---|---|
| `FilterType` | `Plugin` | on macOS only `Plugin` is supported |
| `UserDefinedName` | `Riggs` | required for `Plugin` |
| `PluginBundleID` | `com.riggs.filter` | "Bundle ID of the filtering plug-in", required for `Plugin`. Reading: the containing app, not the extension. Unverified on a Mac. |
| `FilterSockets` | `true` | filters socket traffic; this is what the filter implements (`FilterDataProvider`). `FilterBrowsers` is not available on macOS. |
| `FilterDataProviderBundleIdentifier` | `com.riggs.filter.extension` | required when `FilterSockets` is true |
| `FilterDataProviderDesignatedRequirement` | placeholder | the extension's designated requirement (below) |

Get the requirement from the signed, notarized app you will ship:

```
codesign -d -r- "/Applications/Riggs Filter.app/Contents/Library/SystemExtensions/com.riggs.filter.extension.systemextension"
```

Paste the text after `designated => ` into the placeholder (XML-escape `&`, `<`
and `>`). Bundle identifiers and the `Contents/Library/SystemExtensions` path
come from `extensions/riggs-filter/build.sh` and its `Bundle/` templates.

### riggs-full-disk-access

`com.apple.TCC.configuration-profile-policy`
(`.../com.apple.TCC.configuration-profile-policy.yaml`): `Services` is a
dictionary of service names; `SystemPolicyAllFiles` ("access to all protected
files, including system administration files") is an array of entries with
`Identifier` (`/usr/local/bin/riggs-daemon`), `IdentifierType` (`path`, for
binaries that are not bundles), `CodeRequirement` (required; obtained with
`codesign -display -r -`) and `Authorization` (`Allow`; macOS 11.0+, replaces
`Allowed`; exactly one of the two per entry). The user is not prompted and
cannot change a profile's decision. The page states no MDM restriction on
`Allow` for this service.

```
codesign -d -r- /usr/local/bin/riggs-daemon
```

Run it on the Developer ID signed binary and paste the text after `designated => `.
`build-pkg.sh --app-identity` signs each binary with a fixed identifier
(`com.riggs.riggs-daemon`), because `codesign` otherwise appends a hash of the
binary to the identifier and the requirement would change with every build.

Apple's page marks this payload as needing a user-approved MDM
(`userapprovedmdm`), so expect it to apply only to Macs enrolled that way.

### riggs-background-items

`com.apple.servicemanagement` (macOS 13.0+, device channel only, user-approved
MDM required; `.../com.apple.servicemanagement.yaml`): `Rules` is an array of
dictionaries with `RuleType` (`BundleIdentifier`, `BundleIdentifierPrefix`,
`Label`, `LabelPrefix`, `TeamIdentifier`), `RuleValue`, optional `Comment` and
an optional `TeamIdentifier` that narrows the rule. Apple: the payload "defines
rules for tagging login items as managed, which will auto-enable and auto-allow
matched items." Here: three `Label` rules, each narrowed to your Team ID.

Is it required? Apple's deployment guide
(https://support.apple.com/guide/deployment/managed-login-items-and-background-tasks-on-mac-depdca572563/web,
fetched) says the background-task framework "works with all types of apps,
regardless of how they were installed", and that an item matching a rule is
automatically approved. It does not say that an unmatched LaunchDaemon from a
package is blocked, nor what a user sees for it, and I found no statement that
the profile is mandatory. What it does state: users are notified when managed
items install, and macOS 26 asks a user whether to let an app's background
tasks stay active after the app quits. The profile removes the dependence on
each user's Login Items switch for the daemon and the agents. Treat it as
recommended, not proven required; try one Mac without it and read
`sfltool dumpbtm` (named on the same page).

### Browser extension

What the vendors' documentation says (fetched; policy pages as quoted):

- Chrome, `ExtensionInstallForcelist`
  (https://chromeenterprise.google/policies/extension-install-forcelist/ and
  its source,
  https://raw.githubusercontent.com/chromium/chromium/main/components/policy/resources/templates/policy_definitions/Extensions/ExtensionInstallForcelist.yaml):
  each entry is a 32-letter extension ID, optionally followed by `;` and an
  update URL (schemes http, https or file). "On macOS instances, apps and
  extensions from outside the Chrome Web Store can only be force installed if
  the instance is managed via MDM, joined to a domain via MCX or enrolled in
  Chrome Enterprise Core." The update URL is used for the first installation
  only; later updates use the `update_url` in the extension's manifest unless
  `ExtensionSettings` overrides it (`override_update_url`).
- Edge, `ExtensionInstallForcelist`
  (https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/extensioninstallforcelist):
  the same format; the update URL "should point to an Update Manifest XML
  document"; "On macOS instances, apps and extensions from outside the Microsoft
  Edge Add-ons website can only be force installed if the instance is managed
  via MDM, or joined to a domain via MCX." Mac preference key
  `ExtensionInstallForcelist`, list of strings. With the `ExtensionSettings`
  policy, `installation_mode: force_installed` and `update_url` "if you're hosting
  the extension on your own server, use the URL where Microsoft Edge can
  download the packed extension" (https://learn.microsoft.com/en-us/deployedge/microsoft-edge-manage-extensions-ref-guide).
- How a Mac gets the preference: Edge reads `com.microsoft.Edge`
  (https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge-on-mac);
  Google's Mac guide builds a profile from `com.google.Chrome`
  (https://support.google.com/chrome/a/answer/7517624, search summary only; the
  page itself I could read did not show those steps). The templates use Apple's
  `com.apple.ManagedClient.preferences` payload
  (`.../com.apple.ManagedClient.preferences.yaml`): a dictionary keyed by
  preference domain, each with `Forced` (array of dictionaries holding
  `mcx_preference_settings`). That the Chrome and Edge preference key is spelled
  as the policy name was confirmed for Edge only; confirm Chrome on a test Mac
  at `chrome://policy` and Edge at `edge://policy`.

So the repository's earlier statement that the extension can only be loaded
by hand (`docs/PHISHING.md`) is true for an unmanaged Mac and not true for an
MDM-managed one: both browsers document force-installing from a server you
control. It needs three things the repository does not contain:

1. A packed CRX of `extensions/riggs-browser/ext`, signed with the private key
   for the `key` in its `manifest.json`. The ID the native-messaging manifest
   allows (`lilgnipcebaofalbkdgonmidhpdfomen`, `install/native-messaging/com.riggs.browser.json`)
   comes from that key. The private key is deliberately not in the repository
   (checked: no `.pem` or `.crx` under `extensions/`; `docs/PHISHING.md` says it
   "is kept outside the repository"). Whether it still exists is for the owner to
   say: section 8.5.
2. An update manifest XML and the CRX on an https server. Edge's page links the
   format (https://go.microsoft.com/fwlink/?linkid=2095043); Chrome uses the same
   format (not read by me).
3. The `update_url` in the extension's manifest, if you want later updates from
   the same place: `manifest.json` has none today, so after the first
   installation the browser would have nothing to update from (or set
   `override_update_url` through `ExtensionSettings`).

The two extension templates cover the first installation only. The extension
is not a Chrome Web Store listing; if you publish one, replace the entry with
the bare 32-letter ID.

## 4. Order of operations for an MDM rollout

1. Do the owner's steps (section 8): certificates, App IDs and profiles, signed
   and notarized `Riggs Filter.app` (if you want egress enforcement), signed and
   notarized packages.
2. Print the two designated requirements from the shipped binaries and render
   the profiles with `install/mdm/render-profiles.sh` (section 3). Deploy the
   rendered copies, never the templates.
3. Upload and scope the profiles to a pilot group first: network filter,
   Full Disk Access, background items, then the browser profiles. Profiles
   before the package, so a Mac does not ask its user to approve what a profile
   was meant to approve.
4. Deploy `Riggs-VERSION.pkg` (an MDM's `InstallEnterpriseApplication` command
   takes a manifest URL over https;
   https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/application.install.enterprise.yaml;
   it returns `Acknowledged` before the install and reports no install errors to
   the server, so verify with section 5). Add `Riggs-Outlook-VERSION.pkg` where
   Outlook for Mac is used.
5. A fresh install records and does not act: the shipped `[response] mode` is
   `"record"`, so the daemon stores each response action it would take without
   running it. Set `mode = "act"` in `/etc/riggs/riggs.toml` when you want kills
   and quarantines to run (`"off"` evaluates nothing). A config that still has
   `auto_respond` fails to load.
6. Put your own `dlp-policy.toml` and `egress-policy.toml` in `/etc/riggs/`
   if you want them (section 2 says why the package does not); an MDM script is
   enough.
7. Verify a pilot Mac (section 5), then widen.

If the daemon cannot be loaded, `postinstall` retries `launchctl bootstrap` five
times two seconds apart (`man launchctl` documents only that it exits non-zero on
failure, not the code in a teardown race), finishes the remaining steps and exits
non-zero, so the MDM records a failed install.

Upgrades: deploy a package with a higher version. `preinstall` stops the daemon,
the payload replaces binaries, `postinstall` starts it. That is redeployment,
not an update mechanism (section 7).

## 5. Verify an installed Mac

```
pkgutil --pkg-info com.riggs.pkg.core
launchctl print system/com.riggs.daemon
riggs status
ls -led /etc/riggs /var/lib/riggs /var/log/riggs
codesign --verify --strict /usr/local/bin/riggs-daemon
profiles show
systemextensionsctl list
"/Applications/Riggs Filter.app/Contents/MacOS/riggs-filter" --status
sfltool dumpbtm
```

`riggs status` talks to the daemon through `/var/run/riggs.sock`; the filter's
`--status` is documented in `docs/STANDALONE.md`. The log is
`/var/log/riggs/daemon.log` and `daemon.err`. In a browser, the extension's
popup and `chrome://policy` / `edge://policy` show whether the forced
installation applied. `pkgutil --check-signature` on the package and
`spctl -a -t install` show whether it is signed and accepted.

## 6. Remove everything

`install/pkg/uninstall-pkg.sh [--purge]` runs as root from an MDM, with no
prompt. It boots out the agents of every local account, deactivates the filter
(needs a logged-in user; the profile's `RemovableSystemExtensions` is what lets
the app remove its own extension, per Apple's key description, not tested),
stops the daemon, removes every file in section 2, every user's Brave manifest,
Outlook state and logs, and runs `pkgutil --forget com.riggs.pkg.core` and
`...outlook`. `/etc/riggs` and `/var/lib/riggs` stay unless `--purge`.

If the filter could not be deactivated (nobody logged in, or the command
failed), the script keeps `/Applications/Riggs Filter.app`, because the app's
binary is the only thing that can remove the active extension; it says so,
finishes everything else and exits 1 so the MDM records it. Then either log in
as a user and run the script again, or remove the extension by hand in System
Settings > Network Extensions (the route `install/uninstall.sh` names) and delete
the app. I found no documented way for the MDM itself to remove the extension.
Finally remove the profiles from the MDM.

Left for the person at each Mac, as in `install/uninstall.sh`: the mail bridge's
certificate authority in the login keychain, the add-in in each mailbox, and
the browser's entry for a hand-loaded extension.

## 7. What this does not give you yet

- **No update mechanism.** New versions go out as a new package. Nothing checks
  for one and nothing is signed for a self-updater.
- **No tamper protection.** A root user, or malware with root, can stop the
  daemon, edit `/etc/riggs`, or replace the binaries. Nothing watches the
  daemon's own files (`docs/ARCHITECTURE.md` described that; it is planned, not
  built). `PayloadRemovalDisallowed` and `NonRemovableSystemExtensions` are not
  used here.
- **Binaries live under `/usr/local`.** On Intel Macs with Homebrew,
  `/usr/local/bin` and `/usr/local/share` belong to the admin user, so an
  admin account (not an ordinary user) can replace a binary launchd runs as
  root, or the defaults `postinstall` copies into `/etc/riggs`. `install.sh` has
  the same exposure. The remedy is planned, not built: install the binaries into
  a root-owned location outside `/usr/local`.
- **The filter fails open.** When the daemon does not answer, the network
  filter allows the traffic (`docs/STANDALONE.md`, "Fail-open").
- **macOS sensors are polling.** The process and socket sensors poll once a
  second, so a short-lived process or connection can be missed; file events come
  from FSEvents and carry no process. Endpoint Security would fix both and needs
  the entitlement below.
- **No central console that works end to end.** The Murtaugh console exists in
  the repository; nothing here deploys or enrols against it.
- Brave coverage is limited to users present at install time; Outlook needs
  per-user steps.

## 8. What only the owner can do

These need your Apple Developer Program account and cannot be done by
anything in the repository. Portal screens change; where a step names a
screen, its wording is from memory of the portal and is unverified.

### 8.1 Developer ID certificates

You need two: Developer ID Application (signs binaries and `Riggs Filter.app`)
and Developer ID Installer (signs the packages). Apple: use a "Developer ID"
application or installer certificate, not an Apple Development or Mac
Distribution one, and notarization needs the Hardened Runtime and a secure
timestamp (https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution,
via its DocC JSON, fetched).

1. In Certificates, Identifiers & Profiles, create a Certificate of type
   Developer ID Application, then one of type Developer ID Installer. Creating
   Developer ID certificates is, from memory, restricted to the Account Holder.
2. Generate each certificate signing request in Keychain Access, download the
   certificates and install them in the keychain of the Mac that builds.
3. Check: `security find-identity -v -p codesigning` lists the Application
   identity; the Installer identity shows with `-p basic`. Pass the names to
   `build-pkg.sh`.

### 8.2 App IDs and provisioning profiles for the filter

`docs/STANDALONE.md`, "macOS network filter", has the development version of
this. For distribution:

1. Identifiers: explicit macOS App IDs `com.riggs.filter` (System Extension and
   Network Extensions) and `com.riggs.filter.extension` (Network Extensions).
   The app group `<TEAM_ID>.com.riggs` needs no registration (per that document).
2. Profiles: a Developer ID profile (not Apple Development, and bound to no
   device UDIDs) for each App ID. `extensions/riggs-filter/build.sh` notes that
   Developer ID profiles grant `content-filter-provider-systemextension`, which
   is the value it then signs with.
3. Build, with your Team ID and Developer ID Application identity:
   `TEAM_ID=... IDENTITY="Developer ID Application: ..." extensions/riggs-filter/build.sh --app-profile ... --extension-profile ...`
   (`IDENTITY`, `TEAM_ID` are `build.sh` environment overrides; its default
   identity is a personal Apple Development certificate and must not ship).
   `comms.filter_socket_path` in `riggs.toml` carries the Team ID too and must
   match.
4. Notarize `Riggs Filter.app` (zip it with `ditto -c -k --keepParent`), staple
   it, and pass it to `build-pkg.sh --filter-app`. Whether `build.sh` produces
   a notarization-ready signature (timestamp, no `get-task-allow`) has not been
   checked; it signs with `--options runtime` and no `--timestamp`.

### 8.3 Notarization

Apple (https://developer.apple.com/documentation/security/customizing-the-notarization-workflow,
via its DocC JSON, fetched):

```
xcrun notarytool store-credentials "notarytool-password" --apple-id "<AppleID>" --team-id <TEAM_ID> --password <app-specific-password>
xcrun notarytool submit Riggs-VERSION.pkg --keychain-profile "notarytool-password" --wait
xcrun notarytool log <submission-id> --keychain-profile "notarytool-password" notary-log.json
xcrun stapler staple Riggs-VERSION.pkg
```

Always read the log, even on success. Flat installer packages are accepted for
notarization. Repeat for `Riggs-Outlook-VERSION.pkg`. Notarization checks every
Mach-O inside the package, so every binary must be signed with the Application
identity (`--app-identity`) before packaging; the build script warns when it was
not. Whether the Installer scripts need anything beyond that was not checked.

### 8.4 The Endpoint Security entitlement request

Apple: the `com.apple.developer.endpoint-security.client` entitlement is
"required to monitor system events for potentially malicious activity" and "You
must request this entitlement from Apple"; without it `es_new_client` fails
with `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`
(https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client).
The System Extensions page
(https://developer.apple.com/system-extensions/) says a developer who will use
the EndpointSecurity API needs to request an entitlement from Apple, through its
"Contact us" link to https://developer.apple.com/contact/request/system-extension/.
The form is behind an Apple ID sign-in, so its questions could not be read for
this document: the text below is a draft against questions unseen. Adjust it
to the form's actual fields. While a request is in review Apple says you can test
system extensions with System Integrity Protection turned off.

Also from Apple's Endpoint Security documentation: the extension is "packaged
in an app that uses the System Extensions framework". Today's daemon is a bare
`launchd` executable. Whether a bare executable can carry this entitlement was
not established by what was read; plan for the ES client to live in a system
extension inside an app, like the network filter does, and for `riggs-daemon` to
talk to it. That is design work, not covered here, and it also means the
`EndpointSecurityExtension` type must be added to `AllowedSystemExtensionTypes`
in the filter profile (or a second profile) when it ships.

Draft justification (fill the brackets; do not claim what is not true when you
send it):

> **Product.** Riggs is endpoint protection software for company-managed Macs,
> built by [company], distributed outside the Mac App Store as a notarized,
> Developer ID signed package deployed through MDM. It is not available to
> consumers. [Number of devices or customers, or "in development, internal
> testing only": state which.]
>
> **What it does today, without the entitlement.** A root launchd daemon
> detects malicious activity on the Mac: it watches process starts, file
> changes and network connections, matches them against YARA, indicator and
> behavioural rules and local models, and can contain a threat (kill a process,
> quarantine a file, isolate a host). On macOS it currently does this by
> polling the process table and open sockets once a second and by FSEvents.
>
> **Why Endpoint Security is needed.** Polling misses processes and connections
> that live less than a second, and FSEvents reports a changed path without the
> process that changed it, so a file event cannot be attributed to a process.
> Endpoint Security gives complete, ordered exec, fork, exit, file create,
> write, rename, delete and open events with the responsible process, and the
> code-signing and hash data of the executable, which our detection and
> response depend on.
>
> **Which events.** Process: exec, fork, exit. File: create, write, rename,
> unlink, close (with modification flag), open. Network: connect (macOS 13 and
> later), as available. Authentication and mount events, later, [only if you
> intend to use them]. We use NOTIFY events. We may later use AUTH events to block
> execution of known-malicious binaries before they start; we will tell Apple if
> that becomes a requirement rather than assume it is covered here.
>
> **Data handling.** Events are processed on the device. [State accurately what
> leaves the device: in standalone mode, nothing; with the Murtaugh console
> enrolled, what is sent, to whom, under what terms.] Nothing is sold or used
> for advertising. The extension does not monitor the content of user
> communications; it reads file and process metadata and, for files it scans for
> malware, their bytes locally.
>
> **Deployment and security.** The extension is signed with a Developer ID
> certificate for team [TEAM_ID], approved by an MDM system-extension policy,
> and granted Full Disk Access by an MDM profile. It runs as root, is not
> user-configurable, and is [not yet] protected against tampering by a local
> administrator.
>
> **Contact.** [Name, role, email, phone.]

Each factual sentence there comes from the code and documents in this
repository (`README.md`, `docs/PLATFORM_ABSTRACTION.md`, `docs/STANDALONE.md`);
the bracketed items are facts only you know. Delete any sentence you cannot
stand behind: Apple reviews these requests.

### 8.5 The browser extension's signing key

A force-installed extension must be a packed CRX signed with the private key
whose public half is the `key` in `extensions/riggs-browser/ext/manifest.json`.
`docs/PHISHING.md` says that key is kept outside the repository; nobody here
knows where. Do one of these:

- **Find the original key** (the `.pem` the manifest's `key` was made from; its
  public half must encode to the `key` string). Pack with Chrome's
  `--pack-extension=<dir> --pack-extension-key=<key.pem>` or Edge's equivalent
  (flags from memory, unverified), store the key in your secret store, and
  change nothing else.
- **Generate a new RSA 2048 key.** Then the extension ID changes, and all of
  these must change together:
  - `extensions/riggs-browser/ext/manifest.json`: `key` (the new public key,
    base64 DER SubjectPublicKeyInfo);
  - `install/native-messaging/com.riggs.browser.json`: `allowed_origins`;
  - `extensions/riggs-browser/test/worker.test.js` (line 5, the expected ID;
    the test fails if it disagrees with the native-messaging manifest);
  - `install/mdm/riggs-chrome-extension.mobileconfig` and
    `install/mdm/riggs-edge-extension.mobileconfig`: the ID before the `;`;
  - `docs/PHISHING.md` (the "Extension ID" section and the second place it is
    named) and this document.

  Rebuild the package afterwards (the native-messaging manifest is in it).
  Anyone who loaded the old extension by hand keeps an extension the native host
  now refuses.

Never commit the private key.

## 9. Sources

Fetched while writing this (none contained project or personal details):

- Apple device management, https://github.com/apple/device-management (release branch, `mdm/profiles/` and `mdm/commands/`).
- Apple, launchd job locations and ownership: the Daemons and Services Programming Guide URL above.
- Apple, managed login items and background tasks: the support.apple.com URL above.
- Apple, notarization requirements and `notarytool`/`stapler`: the two developer.apple.com URLs above (DocC JSON).
- Apple, Endpoint Security entitlement and system extensions: the URLs in section 8.4.
- Google and Microsoft: the policy pages and guides in section 3.
- Local manual pages: `pkgbuild(1)`, `launchctl(1)`.

Not fetched or not readable: Apple's rendered developer pages (script-only),
the Apple Developer portal, the entitlement request form (needs sign-in),
Google's Mac profile-building guide (only a search summary), Chrome's update
manifest format page.
