import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const addin = join(import.meta.dirname, "..", "addin");

// Mail content crosses the pane. So text reaches the page through textContent
// only, nothing is logged, and nothing is kept anywhere: not in the web
// view's storage, not in Office's (roaming settings, custom properties,
// session data, internet headers, a saved item), and not as a notification
// that outlives the selection.
const BANNED = [
	/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/g,
	/[sS]torage|indexedDB|document\.cookie|\bcaches\./g,
	/roamingSettings|loadCustomPropertiesAsync|sessionData|\binternetHeaders\b|saveAsync/g,
	/persistent:\s*true/g,
	/console\./g,
];
// All of the pane's code is in taskpane.js, where the tests can reach it.
const INLINE_SCRIPT = [
	/<script\b(?![^>]*\ssrc\s*=)/gi,
	/(?<=\s)on[a-z]+\s*=/gi,
];
// The manifest template is filled in at install time; nothing that names one
// installation may be committed.
const INSTALLATION = [/\b[0-9a-f]{32}\b/gi, /localhost:\d/g];

const hits = (file, text, patterns) =>
	patterns.flatMap((pattern) =>
		Array.from(
			text.matchAll(pattern),
			(match) =>
				`${file}:${text.slice(0, match.index).split("\n").length}: ${match[0]}`,
		),
	);

const violations = (file, text) =>
	hits(
		file,
		text,
		file.endsWith(".html") ? [...BANNED, ...INLINE_SCRIPT] : BANNED,
	);

const read = (extensions) =>
	readdirSync(addin)
		.filter((file) => extensions.test(file))
		.map((file) => [file, readFileSync(join(addin, file), "utf8")]);

test("the checker reports each kind of violation with its file and line", () => {
	assert.deepEqual(
		violations(
			"a.js",
			"let b;\nb.innerHTML = 1;\nconsole.log(b);\nOffice.context.roamingSettings.set(b);\nc = { persistent: true };\nlocalStorage.b = 1;\nitem.getAllInternetHeadersAsync(d);\n",
		),
		[
			"a.js:2: innerHTML",
			"a.js:6: Storage",
			"a.js:4: roamingSettings",
			"a.js:5: persistent: true",
			"a.js:3: console.",
		],
	);
	assert.deepEqual(
		violations(
			"a.html",
			'<script src="a.js"></script>\n<script>\n</script>\n<p onclick="b()">',
		),
		["a.html:2: <script", "a.html:4: onclick="],
	);
	assert.deepEqual(
		hits(
			"a.xml",
			"https://localhost:{{PORT}}/{{TOKEN}}/a\nhttps://localhost:41443/0123456789abcdef0123456789abcdef/a\n72582e9d-f729-4689-91bf-0dac144aac75\n",
			INSTALLATION,
		),
		["a.xml:2: 0123456789abcdef0123456789abcdef", "a.xml:2: localhost:4"],
	);
});

test("no file under addin/ uses a banned API or inline script", () => {
	assert.deepEqual(
		read(/\.(js|html)$/).flatMap(([file, text]) => violations(file, text)),
		[],
	);
});

test("no file under addin/ names a port or a token", () => {
	assert.deepEqual(
		read(/\.(js|html|xml)$/).flatMap(([file, text]) =>
			hits(file, text, INSTALLATION),
		),
		[],
	);
});

test("taskpane.js is plain ASCII, so it reads the same whatever charset it is served with", () => {
	assert.ok(
		readFileSync(join(addin, "taskpane.js")).every((byte) => byte < 0x80),
	);
});
