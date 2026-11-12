import { strict as assert } from "node:assert";
import test from "node:test";
import { bridge, OFFICE_JS, open, SCRIPT_URL, WAITING } from "./pane.js";

// All mail here is constructed. The addresses use the domains reserved for
// documentation (RFC 2606).

const A = {
	label: "A",
	id: "<a@example.com>",
	from: { name: "Sender A", address: "a@example.com" },
	to: ["me@example.org", "other@example.org"],
	cc: ["copy@example.org"],
	subject: "Subject A",
	attachments: [
		{ name: "invoice.pdf", isInline: false },
		{ name: "logo.png", isInline: true },
	],
	html:
		"<html><head><title>ignored</title><style>p { color: red }</style></head><body>" +
		"<p>Dear customer,</p><p>Your account <b>needs</b> attention.</p>" +
		'<div>Visit <a href="https://example.com/login?a=1&amp;b=2">the <span>login</span>\n page</a><br>today.</div>' +
		"<script>ignored()</script><style>.x { display: none }</style>" +
		"<table><tr><td>Thanks</td><td>Human Resources</td></tr></table>" +
		'<a href="mailto:help@example.com">Write to us</a><a name="top">no target</a>' +
		"</body></html>",
	headers: [
		"Received: from mx.example.com by mail.example.org;",
		" Thu, 12 Nov 2026 10:00:00 +0000",
		"From: Sender A <a@example.com>",
		'Reply-To: "Replies"',
		" <replies@example.net>",
		"Subject: Subject A",
		"",
	].join("\r\n"),
};
const A_OBSERVATION = {
	provider: "outlook_addin",
	message_id: "<a@example.com>",
	from_name: "Sender A",
	from_addr: "a@example.com",
	reply_to: "replies@example.net",
	to: ["me@example.org", "other@example.org", "copy@example.org"],
	subject: "Subject A",
	body_text:
		"\nDear customer,\n\nYour account needs attention.\n\nVisit the login\n page\ntoday.\n" +
		"\n\n\nThanks\n\nHuman Resources\n\n\nWrite to usno target",
	links: [
		{ text: "the login page", href: "https://example.com/login?a=1&b=2" },
		{ text: "Write to us", href: "mailto:help@example.com" },
	],
	attachments: ["invoice.pdf"],
	truncated: false,
};

const B = {
	label: "B",
	id: "<b@example.com>",
	from: { name: "", address: "b@example.com" },
	to: ["me@example.org"],
	subject: "Subject B",
	html: "<p>No links here.</p>",
	headers:
		"From: b@example.com\r\nX-Reply-To: decoy@example.net\r\nSubject: Subject B\r\n",
};
const B_OBSERVATION = {
	provider: "outlook_addin",
	message_id: "<b@example.com>",
	from_name: "",
	from_addr: "b@example.com",
	reply_to: null,
	to: ["me@example.org"],
	subject: "Subject B",
	body_text: "\nNo links here.\n",
	links: [],
	attachments: [],
	truncated: false,
};

const CAUTION = {
	level: "caution",
	reasons: [
		{ cue: "example_cue_1", text: "First reason." },
		{ cue: "example_cue_2", text: "Second reason." },
	],
	show: true,
};
const DANGER = {
	level: "danger",
	reasons: [{ cue: "example_cue_3", text: "Third reason." }],
	show: true,
};
const verdict = (level, ...texts) => ({
	level,
	reasons: texts.map((text) => ({ cue: "example_cue", text })),
	show: true,
});

const CAUTION_HEADING = "Be careful with this message.";
const DANGER_HEADING = "This message may be phishing.";
const CHECKING = "Checking this message.";
const NOTHING =
	"Riggs has nothing to show for this message. That is not a promise about it.";
const UNREADABLE = "Riggs could not read this message, so it was not checked.";
const NO_ANSWER =
	"Riggs did not check this message. It may be stopped, or phishing protection may be switched off.";
const UNEXPECTED = "Riggs could not check this message (unexpected answer).";
const BUDGET = 6 * 1024 * 1024;

const notificationCalls = (pane) =>
	pane.calls.filter(({ op }) => ["getAll", "replace", "remove"].includes(op));
const replaced = (pane) => pane.calls.filter(({ op }) => op === "replace");
// Notification calls made through an item that was no longer selected: in
// Outlook they could land on another message.
const misdirected = (pane) =>
	notificationCalls(pane).filter(({ stale }) => stale);

// The observation the pane posts for one message.
const observed = async (item, options = {}) => {
	const pane = await open({ items: [item], ...options });
	await pane.settled();
	assert.equal(pane.posts.length, 1);
	return JSON.parse(pane.posts[0].body);
};

const until = async (done) => {
	for (let turn = 0; turn < 1000; turn += 1) {
		if (done()) return;
		await new Promise(setImmediate);
	}
	assert.fail("the awaited condition never held");
};

test("the page loads Office.js from Microsoft's address and its own script, nothing else", async () => {
	const pane = await open({ items: [A] });
	await pane.settled();
	assert.deepEqual(pane.requests, [OFFICE_JS, SCRIPT_URL]);
	assert.equal(
		pane.document.head.querySelector("script").getAttribute("src"),
		OFFICE_JS,
	);
});

test("the first load posts one observation to the relative address", async () => {
	const pane = await open({ items: [A] });
	await pane.settled();
	assert.equal(pane.posts.length, 1);
	const [{ body, ...request }] = pane.posts;
	assert.deepEqual(request, {
		url: "observe",
		method: "POST",
		headers: { "Content-Type": "application/json" },
	});
	assert.deepEqual(JSON.parse(body), A_OBSERVATION);
});

test("ItemChanged posts one observation for the newly selected message", async () => {
	const pane = await open({ items: [A, B] });
	await pane.settled();
	assert.deepEqual(
		pane.calls.filter(({ op }) => op === "addHandler"),
		[{ op: "addHandler", type: "olkItemSelectedChanged" }],
	);
	pane.select(1);
	await pane.settled();
	assert.equal(pane.posts.length, 2);
	assert.deepEqual(JSON.parse(pane.posts[1].body), B_OBSERVATION);
});

test("without the headers API (Mailbox 1.7) reply_to is null and nothing else changes", async () => {
	const pane = await open({ items: [A], maxMinor: 7 });
	await pane.settled();
	assert.deepEqual(JSON.parse(pane.posts[0].body), {
		...A_OBSERVATION,
		reply_to: null,
	});
	assert.deepEqual(
		pane.calls.filter(({ op }) => op === "headers"),
		[],
	);
});

test("a failing headers call gives reply_to null and nothing else changes", async () => {
	const pane = await open({ items: [{ ...A, headers: null }] });
	await pane.settled();
	assert.deepEqual(JSON.parse(pane.posts[0].body), {
		...A_OBSERVATION,
		reply_to: null,
	});
	assert.equal(pane.calls.filter(({ op }) => op === "headers").length, 1);
});

for (const [name, headers, expected] of [
	[
		"a bare address",
		"Reply-To: replies@example.net\r\n",
		"replies@example.net",
	],
	[
		"a display name",
		"Reply-To: Replies <replies@example.net>\r\n",
		"replies@example.net",
	],
	[
		"a lower-case name after other headers",
		"From: a@example.com\r\nreply-to: replies@example.net\r\nSubject: s\r\n",
		"replies@example.net",
	],
	[
		"the first of several addresses",
		"Reply-To: one@example.net, two@example.org\r\n",
		"one@example.net",
	],
	[
		"an address inside a quoted display name is not the reply address",
		'Reply-To: "x <a@example.com>" <other@example.net>\r\n',
		"other@example.net",
	],
	[
		"an address inside a comment is not the reply address",
		"Reply-To: (see <a@example.com>) other@example.net\r\n",
		"other@example.net",
	],
	[
		"a nested comment does not end at its inner parenthesis",
		"Reply-To: (x (y) <a@example.com>) <other@example.net>\r\n",
		"other@example.net",
	],
	[
		"a comment nested twice",
		"Reply-To: (x (y (z) <a@example.com>) <b@example.com>) <other@example.net>\r\n",
		"other@example.net",
	],
	[
		"a parenthesis inside a quoted display name",
		'Reply-To: "a (b" <x@example.com>\r\n',
		"x@example.com",
	],
	[
		"a quote inside a comment",
		'Reply-To: (a "b) <x@example.com>\r\n',
		"x@example.com",
	],
	[
		"an escaped parenthesis inside a comment",
		"Reply-To: (a \\) <fake@example.com>) <x@example.com>\r\n",
		"x@example.com",
	],
	[
		"an unterminated comment hides the rest",
		"Reply-To: (a <fake@example.com>\r\n",
		null,
	],
	[
		`a comment nested 50000 levels deep`,
		`Reply-To: ${"(".repeat(50000)}<a@example.com>${")".repeat(50000)} <x@example.com>\r\n`,
		"x@example.com",
	],
	[
		"a Reply-To that is only the continuation of another header",
		"Subject: s\r\n Reply-To: replies@example.net\r\n",
		null,
	],
	["an empty header", "Reply-To:\r\nSubject: s\r\n", null],
	["no headers at all", "", null],
]) {
	test(`reply_to: ${name}`, async () => {
		const { reply_to } = await observed({ ...A, headers });
		assert.equal(reply_to, expected);
	});
}

// The rule every Riggs mail sensor follows for body text and link text.
for (const [name, html, body_text, links = []] of [
	[
		"two adjacent blocks are two lines",
		"<p>Thanks</p><p>Human Resources</p>",
		"\nThanks\n\nHuman Resources\n",
	],
	[
		"br and hr each break a line once",
		"one<br>two<hr>three",
		"one\ntwo\nthree",
	],
	[
		"adjacent table cells do not glue",
		"<table><tr><th>a</th><td>b</td></tr></table>",
		"\n\n\na\n\nb\n\n\n",
	],
	[
		"script and style contribute nothing",
		"a<script>b()</script><style>c { d: e }</style><svg><script>f()</script></svg>g",
		"ag",
	],
	[
		"inline elements add nothing",
		'An <b>inline</b> <span>sentence</span> with <a href="https://example.com/">a link</a>.',
		"An inline sentence with a link.",
		[{ text: "a link", href: "https://example.com/" }],
	],
	[
		"link text over several children is one line with single spaces",
		'<a href="https://example.com/">\n <div>Sign</div>\n<span>in</span>\t<b>now</b> </a>',
		"\n \nSign\n\nin\tnow ",
		[{ text: "Sign in now", href: "https://example.com/" }],
	],
	[
		"text is not trimmed or collapsed, and hidden text is included",
		'<span>  a  </span><span style="display:none">hidden</span>  ',
		"  a  hidden  ",
	],
	[
		"a target is sent as written, and an anchor without one is not a link",
		'<a href=" HTTPS://EXAMPLE.COM/a b ">x</a><a href="relative">y</a><a href="">z</a><a>none</a>',
		"xyznone",
		[
			{ text: "x", href: " HTTPS://EXAMPLE.COM/a b " },
			{ text: "y", href: "relative" },
			{ text: "z", href: "" },
		],
	],
	[
		"an image map's region is a link without text, in document order",
		'<a href="https://example.com/1">one</a><map name="m"><area shape="rect" coords="0,0,9,9" href="https://example.com/2"><area shape="default"></map><a href="https://example.com/3">three</a>',
		"onethree",
		[
			{ text: "one", href: "https://example.com/1" },
			{ text: "", href: "https://example.com/2" },
			{ text: "three", href: "https://example.com/3" },
		],
	],
	["an empty body is still a message", "", ""],
]) {
	test(`body: ${name}`, async () => {
		const observation = await observed({ ...A, html });
		assert.equal(observation.body_text, body_text);
		assert.deepEqual(observation.links, links);
	});
}

test("a deeply nested body is read without exhausting the stack", async () => {
	const depth = 5000;
	const { body_text } = await observed({
		...A,
		html: `${"<div>".repeat(depth)}deep${"</div>".repeat(depth)}`,
	});
	assert.equal(body_text, `${"\n".repeat(depth)}deep${"\n".repeat(depth)}`);
});

for (const [name, change] of [
	["no id", { id: undefined }],
	["an empty id", { id: "" }],
	["no sender", { from: undefined }],
	["no sender address", { from: { name: "Sender A", address: "" } }],
	["a failing body call", { html: null }],
]) {
	test(`fail closed: ${name} posts nothing`, async () => {
		const pane = await open({ items: [{ ...A, ...change }] });
		await pane.settled();
		assert.equal(pane.state(), UNREADABLE);
		assert.equal(pane.level(), "");
		assert.deepEqual(pane.posts, []);
		assert.deepEqual(notificationCalls(pane), []);
	});
}

test("no selected item is a neutral line, before and after a verdict", async () => {
	const pane = await open({
		items: [A],
		selected: -1,
		answers: [bridge.json(CAUTION)],
	});
	await pane.settled();
	assert.equal(pane.state(), "No message is selected.");
	assert.deepEqual(pane.posts, []);

	pane.select(0);
	await pane.settled();
	assert.equal(pane.state(), CAUTION_HEADING);

	pane.select(-1);
	assert.equal(pane.state(), "No message is selected.");
	assert.equal(pane.level(), "");
	assert.deepEqual(pane.reasons(), []);
	assert.equal(pane.posts.length, 1);
});

for (const [name, raw] of [
	["a message being composed", { itemType: "message", subject: {} }],
	["an appointment", { itemType: "appointment", subject: "Subject" }],
]) {
	test(`${name} is not checked`, async () => {
		const pane = await open({ items: [{ label: "other", raw }] });
		await pane.settled();
		assert.equal(
			pane.state(),
			"Riggs checks messages you are reading. This item is not one.",
		);
		assert.deepEqual(pane.posts, []);
	});
}

test("two selections in quick succession: only the later message is posted and shown", async () => {
	const pane = await open({
		items: [A, B],
		selected: -1,
		answers: [bridge.json(CAUTION)],
	});
	await pane.settled();
	pane.select(0);
	pane.select(1);
	await pane.settled();
	assert.deepEqual(
		pane.posts.map(({ body }) => JSON.parse(body).message_id),
		["<b@example.com>"],
	);
	assert.equal(pane.state(), CAUTION_HEADING);
	assert.deepEqual(
		replaced(pane).map(({ item }) => item),
		["B"],
	);
	assert.deepEqual(misdirected(pane), []);
});

test("an answer that arrives after a newer selection is neither shown nor put on a message", async () => {
	const late = Promise.withResolvers();
	const pane = await open({
		items: [A, B],
		answers: [() => late.promise, bridge.json(null)],
	});
	await until(() => pane.posts.length === 1);

	pane.select(1);
	assert.equal(pane.state(), CHECKING);
	late.resolve(new Response(JSON.stringify(DANGER)));
	await pane.settled();

	assert.equal(pane.posts.length, 2);
	assert.equal(pane.state(), NOTHING);
	assert.deepEqual(pane.reasons(), []);
	assert.deepEqual(replaced(pane), []);
	assert.deepEqual(misdirected(pane), []);
});

test("a new selection clears the verdict of the previous message at once", async () => {
	const pending = Promise.withResolvers();
	const pane = await open({
		items: [A, B],
		answers: [bridge.json(DANGER), () => pending.promise],
	});
	await pane.settled();
	assert.equal(pane.state(), DANGER_HEADING);

	pane.select(1);
	assert.equal(pane.state(), CHECKING);
	assert.equal(pane.level(), "");
	assert.deepEqual(pane.reasons(), []);
	pending.resolve(new Response("null"));
	await pane.settled();
});

for (const [answer, heading] of [
	[CAUTION, CAUTION_HEADING],
	[DANGER, DANGER_HEADING],
]) {
	test(`a ${answer.level} verdict is shown in the pane and in one notification`, async () => {
		const pane = await open({ items: [A], answers: [bridge.json(answer)] });
		await pane.settled();
		assert.equal(pane.state(), heading);
		assert.equal(pane.level(), answer.level);
		assert.deepEqual(
			pane.reasons(),
			answer.reasons.map(({ text }) => text),
		);
		assert.deepEqual(notificationCalls(pane), [
			{
				op: "replace",
				item: "A",
				key: "riggs",
				details: {
					type: "informationalMessage",
					icon: "icon-16",
					persistent: false,
					message: `Riggs: ${heading} ${answer.reasons[0].text}`,
				},
			},
		]);
	});
}

test("a verdict without reasons shows its heading alone", async () => {
	const pane = await open({
		items: [A],
		answers: [bridge.json(verdict("danger"))],
	});
	await pane.settled();
	assert.equal(pane.state(), DANGER_HEADING);
	assert.deepEqual(pane.reasons(), []);
	assert.equal(replaced(pane)[0].details.message, `Riggs: ${DANGER_HEADING}`);
});

test("a reason longer than the notification limit is cut inside it, and shown whole in the pane", async () => {
	const reason = `${"Long reason. ".repeat(30)}End.`;
	const pane = await open({
		items: [A],
		answers: [bridge.json(verdict("danger", reason))],
	});
	await pane.settled();
	assert.deepEqual(pane.reasons(), [reason]);
	const [{ details, problem }] = replaced(pane);
	assert.equal(problem, undefined);
	assert.equal(details.message.length, 150);
	assert.equal(
		details.message,
		`${`Riggs: ${DANGER_HEADING} ${reason}`.slice(0, 149)}\u{2026}`,
	);
});

test("the cut does not leave half of a surrogate pair in the notification", async () => {
	const prefix = `Riggs: ${DANGER_HEADING} `;
	// The first emoji's two halves sit at indexes 148 and 149, across the cut.
	const filler = "x".repeat(148 - prefix.length);
	const pane = await open({
		items: [A],
		answers: [
			bridge.json(verdict("danger", `${filler}\u{1f600}\u{1f600}\u{1f600}`)),
		],
	});
	await pane.settled();
	const [{ details, problem }] = replaced(pane);
	assert.equal(problem, undefined);
	assert.equal(details.message, `${prefix}${filler}\u{2026}`);
});

test("markup in a reason is shown as text", async () => {
	const reason =
		'<img src="https://example.com/x.png" onerror="window.ran = true"><b>bold</b><script>window.ran = true</script>';
	const pane = await open({
		items: [A],
		answers: [bridge.json(verdict("caution", reason))],
	});
	await pane.settled();
	assert.deepEqual(pane.reasons(), [reason]);
	assert.equal(pane.document.querySelector("#reasons li").children.length, 0);
	assert.equal(pane.document.querySelectorAll("img, b").length, 0);
	assert.equal(pane.document.querySelectorAll("script").length, 2);
	assert.equal(pane.window.ran, undefined);
	assert.deepEqual(pane.requests, [OFFICE_JS, SCRIPT_URL]);
});

// Words and marks that would read as a promise that the message is fine.
const POSITIVE =
	/\b(safe|clean|secure|trusted|trustworthy|legitimate|genuine|harmless|fine|ok|okay|verified|passed|good|no threats?|no problems?|nothing wrong)\b|[\u{2713}\u{2714}\u{2705}]/iu;

for (const [name, answer] of [
	["null", null],
	["a verdict of level none", verdict("none")],
]) {
	test(`${name} shows one neutral line, no positive wording and no notification`, async () => {
		const pane = await open({ items: [A], answers: [bridge.json(answer)] });
		await pane.settled();
		assert.equal(pane.state(), NOTHING);
		assert.equal(pane.level(), "");
		assert.deepEqual(pane.reasons(), []);
		assert.doesNotMatch(pane.document.body.textContent, POSITIVE);
		assert.deepEqual(notificationCalls(pane), [{ op: "getAll", item: "A" }]);
	});
}

test("null removes the notification Riggs put on the message earlier", async () => {
	const pane = await open({
		items: [A],
		answers: [bridge.json(CAUTION), bridge.json(null)],
	});
	await pane.settled();
	assert.deepEqual(Array.from(pane.items[0].placed.keys()), ["riggs"]);

	pane.select(0);
	await pane.settled();
	assert.equal(pane.state(), NOTHING);
	assert.equal(pane.level(), "");
	assert.deepEqual(pane.reasons(), []);
	await until(() => pane.items[0].placed.size === 0);
	assert.deepEqual(notificationCalls(pane).slice(1), [
		{ op: "getAll", item: "A" },
		{ op: "remove", item: "A", key: "riggs" },
	]);
});

test("a removal that a newer selection overtakes is dropped, not made on the newly selected message", async () => {
	const pane = await open({
		items: [A, B],
		answers: [bridge.json(CAUTION), bridge.json(null), bridge.json(null)],
	});
	await pane.settled();
	pane.select(0);
	// The pane has asked which notifications A carries; the answer is a turn away.
	await until(() => notificationCalls(pane).length === 2);
	pane.select(1);
	await pane.settled();
	for (let turn = 0; turn < 20; turn += 1) await new Promise(setImmediate);

	assert.deepEqual(
		notificationCalls(pane).map(({ op, item }) => [op, item]),
		[
			["replace", "A"],
			["getAll", "A"],
			["getAll", "B"],
		],
	);
});

for (const [name, notifications] of [
	["fail", "fail"],
	["are refused outright", "throw"],
]) {
	test(`when notification calls ${name}, the pane still shows what the bridge answered`, async () => {
		const pane = await open({
			items: [A],
			notifications,
			answers: [bridge.json(DANGER), bridge.json(null)],
		});
		await pane.settled();
		assert.equal(pane.state(), DANGER_HEADING);
		assert.deepEqual(pane.reasons(), ["Third reason."]);

		pane.select(0);
		await pane.settled();
		assert.equal(pane.state(), NOTHING);
		for (let turn = 0; turn < 20; turn += 1) await new Promise(setImmediate);
		assert.deepEqual(
			notificationCalls(pane).map(({ op }) => op),
			["replace", "getAll"],
		);
	});
}

for (const [name, answer] of [
	["503", bridge.status(503)],
	["an unreachable bridge", bridge.unreachable()],
]) {
	// A 503 is the bridge's answer when the daemon is stopped and when it runs
	// with phishing protection switched off; the line has to be true of both.
	test(`${name} says Riggs did not check the message and puts no notification on it`, async () => {
		const pane = await open({ items: [A], answers: [answer] });
		await pane.settled();
		assert.equal(pane.state(), NO_ANSWER);
		assert.equal(pane.level(), "");
		assert.deepEqual(notificationCalls(pane), []);
	});
}

for (const [name, answer, line] of [
	["an answer that is not JSON", bridge.text("<html>no</html>"), UNEXPECTED],
	["an empty answer", bridge.text(""), UNEXPECTED],
	["an unknown level", bridge.json(verdict("severe")), UNEXPECTED],
	[
		"a level named like an Object method",
		bridge.json(verdict("constructor")),
		UNEXPECTED,
	],
	[
		"reasons that are not a list",
		bridge.json({ level: "danger", reasons: "none", show: true }),
		UNEXPECTED,
	],
	[
		"a reason without text",
		bridge.json({ level: "danger", reasons: [{ cue: "c" }], show: true }),
		UNEXPECTED,
	],
	["a JSON answer that is not a verdict", bridge.json("Ok"), UNEXPECTED],
	[
		"a refusal",
		bridge.status(403),
		"Riggs could not check this message (bridge status 403).",
	],
]) {
	test(`${name} is reported as not checked, without a notification`, async () => {
		const pane = await open({ items: [A], answers: [answer] });
		await pane.settled();
		assert.equal(pane.state(), line);
		assert.equal(pane.level(), "");
		assert.deepEqual(pane.reasons(), []);
		assert.deepEqual(notificationCalls(pane), []);
	});
}

test("lists and strings at their limits are sent whole and truncated stays false", async () => {
	const observation = await observed({
		...A,
		id: "i".repeat(4096),
		from: { name: "n".repeat(4096), address: "f".repeat(4096) },
		to: Array.from({ length: 300 }, (_, index) => `to${index}@example.org`),
		cc: Array.from({ length: 200 }, (_, index) => `cc${index}@example.org`),
		subject: "s".repeat(4096),
		attachments: Array.from({ length: 100 }, (_, index) => ({
			name: `${index}${".".repeat(4096)}`.slice(0, 4096),
			isInline: false,
		})),
		// Words with spaces between them: one long run of letters in the body
		// would be removed as filler, which sets truncated.
		html:
			`<a href="${"h".repeat(8192)}">${"t ".repeat(2047)}tt</a> ` +
			'<a href="https://example.com/">l</a> '.repeat(499),
		headers: `Reply-To: ${"r".repeat(4096)}\r\n`,
	});
	assert.equal(observation.truncated, false);
	assert.equal(observation.message_id.length, 4096);
	assert.equal(observation.from_name.length, 4096);
	assert.equal(observation.from_addr.length, 4096);
	assert.equal(observation.reply_to.length, 4096);
	assert.equal(observation.subject.length, 4096);
	assert.equal(observation.to.length, 500);
	assert.equal(observation.links.length, 500);
	assert.equal(observation.links[0].href.length, 8192);
	assert.equal(observation.links[0].text.length, 4096);
	assert.equal(observation.attachments.length, 100);
	assert.equal(observation.attachments[99].length, 4096);
});

// The bridge cuts the body to the daemon's limit after it has removed filler,
// so the pane must not cut there itself. These bodies are words, not filler.
test("a body past the daemon's limit is sent whole and truncated stays false", async () => {
	const { body_text, truncated } = await observed({
		...A,
		html: `<p>${"a ".repeat(35000)}</p>`,
	});
	assert.equal(body_text.length, 70002);
	assert.equal(truncated, false);
});

test("a body of exactly 1000000 characters is sent whole and truncated stays false", async () => {
	const { body_text, truncated } = await observed({
		...A,
		html: `<p>${"a ".repeat(499999)}</p>`,
	});
	assert.equal(body_text.length, 1000000);
	assert.equal(truncated, false);
});

// Filler: a run of more than 256 characters from the two base64 alphabets.
// Phishing puts it before the visible text, where a cut would keep only it,
// so each run becomes one space before anything is cut.
const run = (length) => "Ab0+/=_-".repeat(length / 8 + 1).slice(0, length);

for (const [name, html, body_text, truncated] of [
	[
		"a 300-character run before a sentence becomes one space",
		`<div>${run(300)}</div><p>Then a sentence.</p>`,
		"\n \n\nThen a sentence.\n",
		true,
	],
	[
		"a run of exactly 256 characters stays",
		`<div>${run(256)}</div><p>Then a sentence.</p>`,
		`\n${run(256)}\n\nThen a sentence.\n`,
		false,
	],
	[
		"a run of 257 characters goes",
		`<div>${run(257)}</div><p>Then a sentence.</p>`,
		"\n \n\nThen a sentence.\n",
		true,
	],
	...[" ", ".", "\u{e9}"].map((other) => [
		`a run interrupted at its 256th character by ${JSON.stringify(other)} stays`,
		`<p>${run(255)}${other}${run(255)}</p>`,
		`\n${run(255)}${other}${run(255)}\n`,
		false,
	]),
	[
		"two runs around prose both go and the prose stays",
		`<p>${run(400)} prose in between ${run(500)}</p>`,
		"\n  prose in between  \n",
		true,
	],
	[
		"long text in a script written without spaces is untouched",
		`<p>${"\u{3042}".repeat(20000)}</p>`,
		`\n${"\u{3042}".repeat(20000)}\n`,
		false,
	],
	[
		"1200000 characters of filler before a sentence leave the sentence inside the cut",
		`<div style="display:none">${run(1200000)}</div><p>Then a sentence.</p>`,
		"\n \n\nThen a sentence.\n",
		true,
	],
]) {
	test(`filler: ${name}`, async () => {
		const observation = await observed({ ...A, html });
		// Not assert.equal: a failure could print a megabyte.
		assert.ok(
			observation.body_text === body_text,
			`${observation.body_text.length} characters`,
		);
		assert.equal(observation.truncated, truncated);
	});
}

test("filler: only the body is treated, not the subject or a link's own text", async () => {
	const observation = await observed({
		...A,
		subject: run(300),
		html: `<p>Text.</p><a href="https://example.com/${run(300)}">${run(300)}</a>`,
	});
	assert.equal(observation.subject, run(300));
	assert.deepEqual(observation.links, [
		{ text: run(300), href: `https://example.com/${run(300)}` },
	]);
	assert.equal(observation.body_text, "\nText.\n ");
	assert.equal(observation.truncated, true);
});

for (const [name, change, check] of [
	[
		"an over-long body",
		{ html: `<p>${"a ".repeat(500000)}</p>` },
		// Not assert.equal: a failure would print both strings.
		({ body_text }) => assert.ok(body_text === `\n${"a ".repeat(499999)}a`),
	],
	[
		"more than 500 links",
		{
			html: Array.from(
				{ length: 501 },
				(_, index) => `<a href="https://example.com/${index}">${index}</a>`,
			).join(" "),
		},
		({ links }) => {
			assert.equal(links.length, 500);
			assert.deepEqual(links[499], {
				text: "499",
				href: "https://example.com/499",
			});
		},
	],
	[
		"more than 500 recipients",
		{
			to: Array.from({ length: 300 }, (_, index) => `to${index}@example.org`),
			cc: Array.from({ length: 201 }, (_, index) => `cc${index}@example.org`),
		},
		({ to }) => {
			assert.equal(to.length, 500);
			assert.equal(to[499], "cc199@example.org");
		},
	],
	[
		"more than 100 attachments",
		{
			attachments: Array.from({ length: 101 }, (_, index) => ({
				name: `${index}.pdf`,
				isInline: false,
			})),
		},
		({ attachments }) => {
			assert.equal(attachments.length, 100);
			assert.equal(attachments[99], "99.pdf");
		},
	],
	[
		"an over-long subject",
		{ subject: "s".repeat(4097) },
		({ subject }) => assert.equal(subject, "s".repeat(4096)),
	],
	[
		"an over-long id",
		{ id: "i".repeat(4097) },
		({ message_id }) => assert.equal(message_id, "i".repeat(4096)),
	],
	[
		"an over-long sender name",
		{ from: { name: "n".repeat(4097), address: "a@example.com" } },
		({ from_name }) => assert.equal(from_name, "n".repeat(4096)),
	],
	[
		"an over-long sender address",
		{ from: { name: "Sender A", address: "f".repeat(4097) } },
		({ from_addr }) => assert.equal(from_addr, "f".repeat(4096)),
	],
	[
		"an over-long Reply-To",
		{ headers: `Reply-To: ${"r".repeat(4097)}\r\n` },
		({ reply_to }) => assert.equal(reply_to, "r".repeat(4096)),
	],
	[
		"an over-long recipient",
		{ to: ["t".repeat(4097)], cc: [] },
		({ to }) => assert.deepEqual(to, ["t".repeat(4096)]),
	],
	[
		"an over-long attachment name",
		{ attachments: [{ name: "n".repeat(4097), isInline: false }] },
		({ attachments }) => assert.deepEqual(attachments, ["n".repeat(4096)]),
	],
	[
		"an over-long link target",
		{ html: `<a href="${"h".repeat(8193)}">x</a>` },
		({ links }) =>
			assert.deepEqual(links, [{ text: "x", href: "h".repeat(8192) }]),
	],
	[
		"an over-long link text",
		{ html: `<a href="https://example.com/">${"t ".repeat(2048)}t</a>` },
		({ links }) =>
			assert.deepEqual(links, [
				{ text: "t ".repeat(2048), href: "https://example.com/" },
			]),
	],
]) {
	test(`cutting: ${name} is cut and truncated is set`, async () => {
		const observation = await observed({ ...A, ...change });
		check(observation);
		assert.equal(observation.truncated, true);
	});
}

test("an over-budget request loses links from the end until it fits", async () => {
	// A control character costs six bytes in JSON, so 500 such targets are
	// about 24 MiB.
	const target = "\u0001".repeat(8192);
	const pane = await open({
		items: [
			{
				...A,
				html: Array.from(
					{ length: 500 },
					(_, index) => `<a href="${target}">${index}</a>`,
				).join(""),
			},
		],
	});
	await pane.settled();
	const [{ body }] = pane.posts;
	const observation = JSON.parse(body);
	const size = Buffer.byteLength(body);
	const oneLink = Buffer.byteLength(JSON.stringify(observation.links[0]));

	assert.ok(size <= BUDGET, `${size} bytes`);
	assert.ok(size + 2 * oneLink > BUDGET, "at most one link too many went");
	assert.ok(observation.links.length > 0);
	assert.deepEqual(
		observation.links.map(({ text }) => text),
		observation.links.map((_, index) => String(index)),
	);
	assert.deepEqual(observation.to, A_OBSERVATION.to);
	assert.equal(observation.truncated, true);
});

test("when dropping every link is not enough, recipients go from the end", async () => {
	const pane = await open({
		items: [
			{
				...A,
				to: Array.from(
					{ length: 500 },
					(_, index) => `${index}@${"\u0001".repeat(4000)}`,
				),
				cc: [],
				html: '<a href="https://example.com/">dropped first</a>',
			},
		],
	});
	await pane.settled();
	const [{ body }] = pane.posts;
	const observation = JSON.parse(body);
	const size = Buffer.byteLength(body);
	const oneRecipient = Buffer.byteLength(JSON.stringify(observation.to[0]));

	assert.ok(size <= BUDGET, `${size} bytes`);
	assert.ok(size + 2 * oneRecipient > BUDGET, "at most one too many went");
	assert.deepEqual(observation.links, []);
	assert.ok(observation.to.length > 0);
	assert.deepEqual(
		observation.to.map((address) => address.split("@")[0]),
		observation.to.map((_, index) => String(index)),
	);
	assert.equal(observation.truncated, true);
});

test("with a body at the pane's limit, an over-budget request still fits by losing links", async () => {
	// Three bytes a character: the body alone is 3 MB of the 6 MiB.
	const filler = "\u{4e00}".repeat(1000000);
	const target = "\u0001".repeat(8192);
	const pane = await open({
		items: [
			{
				...A,
				html: `<span>${filler}</span>${Array.from(
					{ length: 500 },
					(_, index) => `<a href="${target}">${index}</a>`,
				).join("")}`,
			},
		],
	});
	await pane.settled();
	const [{ body }] = pane.posts;
	const observation = JSON.parse(body);
	const size = Buffer.byteLength(body);
	const oneLink = Buffer.byteLength(JSON.stringify(observation.links[0]));

	assert.ok(size <= BUDGET, `${size} bytes`);
	assert.ok(size + 2 * oneLink > BUDGET, "at most one link too many went");
	// Not assert.equal: a failure would print both strings.
	assert.ok(observation.body_text === filler);
	assert.ok(observation.links.length > 0);
	assert.deepEqual(observation.to, A_OBSERVATION.to);
	assert.equal(observation.truncated, true);
});

test("when both lists are empty and the request is still over budget, the body is cut to fit", async () => {
	// Only characters that JSON escapes get this far. A control character is
	// six bytes, so this body is 6 MB and the attachment names 2.4 MB more.
	const pane = await open({
		items: [
			{
				...A,
				to: ["me@example.org"],
				cc: [],
				attachments: Array.from({ length: 100 }, () => ({
					name: "\u0001".repeat(4096),
					isInline: false,
				})),
				html: `<span>${"\u0001".repeat(1000000)}</span><a href="https://example.com/">dropped first</a>`,
			},
		],
	});
	await pane.settled();
	const [{ body }] = pane.posts;
	const observation = JSON.parse(body);
	const size = Buffer.byteLength(body);
	const kept = observation.body_text.length;

	assert.ok(size <= BUDGET, `${size} bytes`);
	assert.ok(size > BUDGET - 16, `${size} bytes: more went than had to`);
	assert.deepEqual(observation.links, []);
	assert.deepEqual(observation.to, []);
	assert.equal(observation.attachments.length, 100);
	assert.ok(kept > 600000 && kept < 1000000, `${kept} characters`);
	assert.ok(observation.body_text === "\u0001".repeat(kept));
	assert.equal(observation.truncated, true);
});

// JSON.stringify writes a lone surrogate as an escape, which is what the
// bridge's parser refuses; a paired one is written as it is.
const LONE_SURROGATE_ESCAPE = /\\ud[89a-f]/i;

test("a lone surrogate in any field of the mail is replaced, so the bridge can parse the request", async () => {
	const lone = "\ud83d";
	const pane = await open({
		items: [
			{
				...A,
				id: `<${lone}@example.com>`,
				from: { name: "\udc00", address: `${lone}@example.com` },
				to: [`${lone}@example.org`],
				cc: [`${lone}@example.net`],
				subject: `before ${lone} after \u{1f600}`,
				attachments: [{ name: `${lone}.pdf`, isInline: false }],
				html: `<p>body ${lone}</p><a href="https://example.com/${lone}">link ${lone}</a>`,
				headers: `Reply-To: ${lone}@example.net\r\n`,
			},
		],
	});
	await pane.settled();
	const [{ body }] = pane.posts;
	assert.doesNotMatch(body, LONE_SURROGATE_ESCAPE);
	assert.deepEqual(JSON.parse(body), {
		provider: "outlook_addin",
		message_id: "<\u{fffd}@example.com>",
		from_name: "\u{fffd}",
		from_addr: "\u{fffd}@example.com",
		reply_to: "\u{fffd}@example.net",
		to: ["\u{fffd}@example.org", "\u{fffd}@example.net"],
		subject: "before \u{fffd} after \u{1f600}",
		body_text: "\nbody \u{fffd}\nlink \u{fffd}",
		links: [{ text: "link \u{fffd}", href: "https://example.com/\u{fffd}" }],
		attachments: ["\u{fffd}.pdf"],
		truncated: false,
	});
});

test("a cut that falls inside a surrogate pair leaves a request the bridge can parse", async () => {
	const pane = await open({
		items: [
			{
				...A,
				// The emoji's halves sit at indexes 4095 and 4096, across the cut.
				subject: `${"s".repeat(4095)}\u{1f600}`,
				// With the leading line break, at 999999 and 1000000.
				html: `<p>${"a ".repeat(499999)}\u{1f600}</p>`,
			},
		],
	});
	await pane.settled();
	const [{ body }] = pane.posts;
	// Not assert.doesNotMatch or assert.equal: a failure would print a megabyte.
	assert.ok(!LONE_SURROGATE_ESCAPE.test(body));
	const observation = JSON.parse(body);
	assert.equal(observation.subject, `${"s".repeat(4095)}\u{fffd}`);
	assert.ok(observation.body_text === `\n${"a ".repeat(499999)}\u{fffd}`);
	assert.equal(observation.truncated, true);
});

test("a recipient or attachment without a usable value is left out, not sent as null", async () => {
	const pane = await open({ items: [A] });
	await pane.settled();
	pane.items[0].to[1].emailAddress = undefined;
	pane.items[0].attachments.push({ name: undefined, isInline: false });
	pane.select(0);
	await pane.settled();
	const observation = JSON.parse(pane.posts[1].body);
	assert.deepEqual(observation.to, ["me@example.org", "copy@example.org"]);
	assert.deepEqual(observation.attachments, ["invoice.pdf"]);
});

test("script, frames, stylesheets and handlers in a mail body run nothing and request nothing", async () => {
	const pane = await open({
		items: [
			{
				...A,
				html:
					"<script>window.mailRan = true</script>" +
					'<script src="https://example.com/mail.js"></script>' +
					'<link rel="stylesheet" href="https://example.com/mail.css">' +
					'<iframe src="https://example.com/frame.html"></iframe>' +
					'<img src="https://example.com/pixel.png" onerror="window.mailRan = true" onload="window.mailRan = true">' +
					'<body onload="window.mailRan = true"><p onclick="window.mailRan = true">Visible <a href="https://example.com/next">text</a></p>',
			},
		],
		answers: [bridge.json(DANGER)],
	});
	await pane.settled();
	// A few more turns, for anything the body might have started.
	for (let turn = 0; turn < 20; turn += 1) await new Promise(setImmediate);

	assert.equal(pane.window.mailRan, undefined);
	assert.deepEqual(pane.requests, [OFFICE_JS, SCRIPT_URL]);
	// Nothing of the mail is in the pane's own document.
	assert.equal(
		pane.document.querySelectorAll("img, iframe, link, a, [onclick]").length,
		0,
	);
	assert.equal(pane.document.querySelectorAll("script").length, 2);
	const observation = JSON.parse(pane.posts[0].body);
	assert.equal(observation.body_text, "\nVisible text\n");
	assert.deepEqual(observation.links, [
		{ text: "text", href: "https://example.com/next" },
	]);
});

test("the pane says once that it has to stay pinned", async () => {
	const pane = await open({ items: [A] });
	await pane.settled();
	assert.equal(
		pane.document.getElementById("pin").textContent,
		"Keep this pane pinned. Outlook gives an add-in no way to start by itself, so Riggs checks a message only while this pane is open.",
	);
	assert.equal(pane.document.body.textContent.match(/pinned/g).length, 1);
});

test("a refused ItemChanged registration is said in the pane, and the open message is still checked", async () => {
	const pane = await open({ items: [A], handlerFails: true });
	await pane.settled();
	await until(
		() =>
			pane.document.getElementById("pin").textContent ===
			"Outlook did not let Riggs follow your selection, so only the message this pane was opened on is checked.",
	);
	assert.equal(pane.posts.length, 1);
});

test("until its script has heard from Office.js, the page says that no message is checked", () => {
	assert.equal(
		WAITING,
		"Riggs is waiting for Outlook. No message is checked until this line changes.",
	);
});

test("outside Outlook the page says what it is and does nothing", async () => {
	const pane = await open({ items: [A], host: null });
	await pane.settled();
	assert.equal(
		pane.state(),
		"This page is the Riggs pane for Outlook. It does nothing outside Outlook.",
	);
	assert.deepEqual(pane.posts, []);
	assert.deepEqual(pane.calls, []);
});
