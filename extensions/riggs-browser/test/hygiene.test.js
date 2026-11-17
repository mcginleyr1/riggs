import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const ext = join(import.meta.dirname, "..", "ext");

// The contract in docs/PHISHING.md: text goes through textContent only,
// chrome.storage.session is the only storage, and the worker neither takes
// external messages nor calls setAccessLevel. Mail content crosses this
// extension, so nothing is logged either.
const BANNED = [
	/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/g,
	/storage\.local|storage\.sync|localStorage|sessionStorage/g,
	/indexedDB|document\.cookie/g,
	/onMessageExternal|onConnectExternal|setAccessLevel/g,
	/console\./g,
];
// Extension pages run under script-src 'self', which refuses inline script.
const INLINE_SCRIPT = [
	/<script\b(?![^>]*\ssrc\s*=)/gi,
	/(?<=\s)on[a-z]+\s*=/gi,
];
// The page sensor may look at a password field's value once, to learn that it
// is not empty; nothing else in the extension reads form values. Only script
// can read a property, so pages are not searched: their CSS may say ".value".
const VALUE_READ = /\.value\b/g;

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

const sources = readdirSync(ext, { recursive: true })
	.filter((file) => /\.(js|html)$/.test(file))
	.map((file) => [file, readFileSync(join(ext, file), "utf8")]);

test("the checker reports each kind of violation with its file and line", () => {
	assert.deepEqual(violations("a.js", "let b;\nb.innerHTML = 1;\n"), [
		"a.js:2: innerHTML",
	]);
	assert.deepEqual(
		violations(
			"a.html",
			'<script src="a.js"></script>\n<script>\n</script>\n<p onclick="b()">',
		),
		["a.html:2: <script", "a.html:4: onclick="],
	);
	assert.deepEqual(hits("a.js", "b.values();\nb.value;\n", [VALUE_READ]), [
		"a.js:2: .value",
	]);
});

test("no file under ext/ uses a banned API or inline script", () => {
	assert.deepEqual(
		sources.flatMap(([file, text]) => violations(file, text)),
		[],
	);
});

test("only page.js reads .value, and only once", () => {
	const reads = sources
		.filter(([file]) => file.endsWith(".js"))
		.flatMap(([file, text]) => hits(file, text, [VALUE_READ]));
	assert.deepEqual(
		reads.filter((read) => !read.startsWith("page.js:")),
		[],
	);
	assert.deepEqual(reads.slice(1), []);
});
