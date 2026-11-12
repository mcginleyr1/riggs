import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const repo = join(import.meta.dirname, "..", "..", "..");
const readJson = (path) => JSON.parse(readFileSync(join(repo, path), "utf8"));
const manifest = readJson("extensions/riggs-browser/ext/manifest.json");
const nativeHost = readJson("install/native-messaging/com.riggs.browser.json");

const FROZEN_FILES = [
  "manifest.json",
  "background.js",
  "popup.html",
  "popup.js",
  "banner.js",
  "gmail.js",
  "page.js",
  "interstitial.html",
  "interstitial.js",
];
const FORBIDDEN_KEYS = [
  "host_permissions",
  "optional_permissions",
  "optional_host_permissions",
  "declarative_net_request",
  "web_accessible_resources",
  "externally_connectable",
];

// Chromium's components/crx_file/id_util.cc: the first 16 bytes of SHA-256
// over the DER public key, each hex digit mapped from 0-f to a-p.
const extensionId = (key) =>
  createHash("sha256")
    .update(Buffer.from(key, "base64"))
    .digest("hex")
    .slice(0, 32)
    .replace(/./g, (digit) => String.fromCharCode(97 + parseInt(digit, 16)));

test("the native host allows exactly the extension the committed key yields", () => {
  assert.deepEqual(nativeHost.allowed_origins, [
    `chrome-extension://${extensionId(manifest.key)}/`,
  ]);
});

test("permissions are exactly the three the sensor needs", () => {
  assert.deepEqual(manifest.permissions.toSorted(), [
    "nativeMessaging",
    "storage",
    "webNavigation",
  ]);
  assert.deepEqual(
    FORBIDDEN_KEYS.filter((key) => key in manifest),
    [],
  );
});

test("the extension cannot be enabled in incognito windows", () => {
  assert.equal(manifest.incognito, "not_allowed");
});

test("the manifest references only files in the frozen list", () => {
  const referenced = [
    manifest.background.service_worker,
    manifest.action.default_popup,
    ...manifest.content_scripts.flatMap(({ js = [], css = [] }) => [
      ...js,
      ...css,
    ]),
  ];
  assert.deepEqual(
    referenced.filter((file) => !FROZEN_FILES.includes(file)),
    [],
  );
});
