import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { Script } from "node:vm";
import { JSDOM } from "jsdom";

const ext = join(import.meta.dirname, "..", "ext");
const script = (name) =>
	new Script(readFileSync(join(ext, name), "utf8"), {
		filename: join(ext, name),
	});
const bannerScript = script("banner.js");
const gmailScript = script("gmail.js");

// The captured pages (fixtures/gmail/README.md). Every value in them is a
// placeholder and the message body is empty.
const fixture = (name) =>
	readFileSync(join(import.meta.dirname, "fixtures", "gmail", name), "utf8");
const SINGLE = fixture("gmail-single-message-attachments.html");
const THREAD = fixture("gmail-thread-two-collapsed-one-expanded.html");
const DETAILS = fixture("gmail-details-table.html");

// A constructed body, since the capture holds none. The attribute names on its
// links are the ones the capture saw on body links.
const BODY =
	'<p>Your invoice is ready.</p><p><a href="https://example.com/invoice?id=1" target="_blank">View invoice</a> or <a href="http://example.com/help" target="_blank" data-saferedirecturl="https://example.com/redirect?q=help">ask for help</a>.</p>';

const CAUTION = {
	level: "caution",
	reasons: [{ cue: "constructed-cue", text: "A constructed reason." }],
	show: true,
};
const DANGER = {
	level: "danger",
	reasons: [{ cue: "constructed-cue", text: "Another reason." }],
	show: true,
};
const NONE = { level: "none", reasons: [], show: true };
const forMail = (verdict) => async (message) =>
	message.t === "mail" ? verdict : null;

// Loads a captured page, puts a body into its expanded message and starts the
// adapter against a fake worker: `answer` is what chrome.runtime.sendMessage
// does with a message, `banner` stands in for banner.js when given. Time
// passes only in settle() and fire(), so a test decides when the adapter
// notices what "Gmail" did to the page.
const gmail = (
	html,
	{ body = BODY, prepare = () => {}, answer = async () => null, banner } = {},
) => {
	const dom = new JSDOM(html, { runScripts: "outside-only" });
	const { window } = dom;
	const { document } = window;
	document.querySelector(".a3s")?.append(JSDOM.fragment(body));
	prepare(document);

	const sent = [];
	const timers = new Map();
	const calls = [];
	window.chrome = {
		runtime: {
			sendMessage: (message) => {
				sent.push(structuredClone(message));
				return answer(message);
			},
		},
	};
	let lastTimer = 0;
	window.setTimeout = (callback, delay) => {
		lastTimer += 1;
		timers.set(lastTimer, { callback, delay });
		return lastTimer;
	};
	window.clearTimeout = (id) => timers.delete(id);
	const context = dom.getInternalVMContext();
	bannerScript.runInContext(context);
	const riggsBanner = banner ?? window.riggsBanner;
	window.riggsBanner = (anchor, verdict) => {
		const placed = riggsBanner(anchor, verdict);
		calls.push({ anchor, verdict, banner: placed });
		return placed;
	};
	const globals = Object.getOwnPropertyNames(window);
	gmailScript.runInContext(context);

	// Lets time pass until the pending timer with this delay fires.
	const fire = (delay) => {
		const [id, { callback }] = Array.from(timers).find(
			([, timer]) => timer.delay === delay,
		);
		timers.delete(id);
		callback();
	};
	// Delivers observer records and worker replies, then leaves the page quiet
	// so that the scans they armed run, until the adapter is idle. Resolves to
	// the number of timers that fired.
	const settle = async () => {
		await new Promise(setImmediate);
		let fired = 0;
		for (; timers.size > 0; fired++) {
			assert.ok(fired < 10, "the adapter never stops rescanning");
			fire(Math.min(...Array.from(timers.values(), ({ delay }) => delay)));
			await new Promise(setImmediate);
		}
		return fired;
	};
	return { window, document, sent, calls, timers, globals, fire, settle };
};

const mails = (sent) => sent.filter((message) => message.t === "mail");
const ids = (sent) => mails(sent).map(({ obs }) => obs.message_id);
const health = (sent) =>
	sent.filter((message) => message.t === "adapter").map(({ ok }) => ok);
const FAILURE = { t: "adapter", provider: "gmail", ok: false };

// Expanding a message changes the page. The capture holds one expanded
// message, so a second one is a copy of it under another id.
const expandAnother = (document, id) => {
	const expanded = document.querySelector(".h7");
	const another = expanded.cloneNode(true);
	another.querySelector("[role=alert]")?.remove();
	another.querySelector(".adn.ads").setAttribute("data-legacy-message-id", id);
	expanded.after(another);
};

test("the single-message capture gives one exact observation and a health report", async () => {
	const { sent, settle } = gmail(SINGLE);
	await settle();
	assert.deepEqual(sent, [
		{
			t: "mail",
			obs: {
				provider: "gmail",
				message_id: "id1",
				from_name: "Sender Name",
				from_addr: "user@example.com",
				reply_to: null,
				to: ["user@example.com"],
				subject: "x",
				body_text:
					"\nYour invoice is ready.\n\nView invoice or ask for help.\n",
				links: [
					{ text: "View invoice", href: "https://example.com/invoice?id=1" },
					{ text: "ask for help", href: "http://example.com/help" },
				],
				attachments: ["x", "x"],
			},
		},
		{ t: "adapter", provider: "gmail", ok: true },
	]);
});

test("the three-message capture gives one exact observation, for its expanded message", async () => {
	const { sent, settle } = gmail(THREAD);
	await settle();
	assert.deepEqual(sent, [
		{
			t: "mail",
			obs: {
				provider: "gmail",
				message_id: "id3",
				from_name: "Sender Name",
				from_addr: "user@example.com",
				reply_to: null,
				to: ["user@example.com"],
				subject: "x",
				body_text:
					"\nYour invoice is ready.\n\nView invoice or ask for help.\n",
				links: [
					{ text: "View invoice", href: "https://example.com/invoice?id=1" },
					{ text: "ask for help", href: "http://example.com/help" },
				],
				attachments: [],
			},
		},
		{ t: "adapter", provider: "gmail", ok: true },
	]);
});

test("collapsed messages produce nothing", async () => {
	const { document, sent, settle } = gmail(THREAD, {
		prepare: (document) => document.querySelector(".h7").remove(),
	});
	await settle();
	assert.equal(document.querySelectorAll(".kv .adf.ads").length, 2);
	assert.deepEqual(sent, []);
});

test("an open details table changes nothing in the observation", async () => {
	const plain = gmail(SINGLE);
	const detailed = gmail(SINGLE, {
		prepare: (document) =>
			document.querySelector(".adn.ads .gs").prepend(JSDOM.fragment(DETAILS)),
	});
	await plain.settle();
	await detailed.settle();
	assert.equal(detailed.document.querySelectorAll(".gs > .ajC").length, 1);
	assert.equal(mails(plain.sent).length, 1);
	assert.deepEqual(detailed.sent, plain.sent);
});

test("a conversation opened after the adapter started is observed", async () => {
	const { document, sent, settle } = gmail(
		"<!doctype html><div id=view></div>",
	);
	await settle();
	assert.deepEqual(sent, []);
	const conversation = JSDOM.fragment(SINGLE);
	conversation.querySelector(".a3s").append(JSDOM.fragment(BODY));
	document.getElementById("view").append(conversation);
	await settle();
	assert.deepEqual(ids(sent), ["id1"]);
	assert.deepEqual(health(sent), [true]);
});

test("a prerendering document is not observed until it is shown", async () => {
	// jsdom has no Document.prerendering; a browser has it on the prototype.
	let prerendering = true;
	const { window, document, sent, settle } = gmail(SINGLE, {
		prepare: (document) =>
			Object.defineProperty(
				document.defaultView.Document.prototype,
				"prerendering",
				{ get: () => prerendering },
			),
	});
	await settle();
	document.body.append(document.createElement("div"));
	await settle();
	assert.deepEqual(sent, []);
	prerendering = false;
	document.dispatchEvent(new window.Event("prerenderingchange"));
	await settle();
	assert.deepEqual(ids(sent), ["id1"]);
	assert.deepEqual(health(sent), [true]);
});

test("re-renders never repeat an observation", async () => {
	const { document, sent, settle } = gmail(SINGLE);
	await settle();
	const message = document.querySelector(".adn.ads");
	message.setAttribute("data-rendered", "again");
	await settle();
	message.querySelector(".a3s").append("More text.");
	await settle();
	message.replaceWith(message.cloneNode(true));
	await settle();
	const view = document.querySelector('[role="main"]');
	const parent = view.parentElement;
	view.remove();
	await settle();
	parent.append(view);
	await settle();
	assert.deepEqual(ids(sent), ["id1"]);
	assert.deepEqual(health(sent), [true]);
});

test("a second expanded message in the conversation gets its own observation", async () => {
	const { document, sent, settle } = gmail(THREAD);
	await settle();
	expandAnother(document, "id4");
	await settle();
	assert.deepEqual(ids(sent), ["id3", "id4"]);
	assert.deepEqual(health(sent), [true, true]);
});

for (const [what, damage] of Object.entries({
	"a missing message id": (message) =>
		message.removeAttribute("data-legacy-message-id"),
	"an empty message id": (message) =>
		message.setAttribute("data-legacy-message-id", ""),
	"a missing sender address": (message) =>
		message.querySelector("span.gD").removeAttribute("email"),
	"an empty sender address": (message) =>
		message.querySelector("span.gD").setAttribute("email", ""),
	"a missing sender element": (message) =>
		message.querySelector("span.gD").remove(),
	"a missing subject element": (message) =>
		message.ownerDocument.querySelector("h2.hP").remove(),
	"a conversation outside the main region": (message) =>
		message.closest('[role="main"]').removeAttribute("role"),
	"a missing body element": (message) => message.querySelector(".a3s").remove(),
	"a missing attachment name element": (message) =>
		message.querySelectorAll(".aZo .aV3")[1].remove(),
	"an empty attachment name": (message) =>
		message.querySelector(".aZo .aV3").replaceChildren(),
})) {
	test(`fail closed: ${what} gives no mail and one adapter failure`, async () => {
		const { document, sent, settle } = gmail(SINGLE, {
			prepare: (document) => damage(document.querySelector(".adn.ads")),
		});
		await settle();
		assert.deepEqual(sent, [FAILURE]);
		// The page changing around the message is not a reason to report again.
		document.body.append(document.createElement("div"));
		await settle();
		document.querySelector(".adn.ads").setAttribute("data-rendered", "again");
		await settle();
		assert.deepEqual(sent, [FAILURE]);
	});
}

// Each breaks the message and returns what completes it again, one for every
// kind of change the adapter has to notice.
for (const [how, breakUntil] of Object.entries({
	"its body element is added": (message) => {
		const body = message.querySelector(".a3s");
		body.remove();
		return () => message.querySelector(".ii.gt").append(body);
	},
	"its id attribute is set": (message) => {
		const id = message.getAttribute("data-legacy-message-id");
		message.removeAttribute("data-legacy-message-id");
		return () => message.setAttribute("data-legacy-message-id", id);
	},
	"an attachment name is written": (message) => {
		const text = message.querySelector(".aZo .aV3").firstChild;
		const name = text.data;
		text.data = "";
		return () => {
			text.data = name;
		};
	},
})) {
	test(`a message that could not be read is observed once ${how}`, async () => {
		let complete;
		const { sent, settle } = gmail(SINGLE, {
			prepare: (document) => {
				complete = breakUntil(document.querySelector(".adn.ads"));
			},
		});
		await settle();
		assert.deepEqual(sent, [FAILURE]);
		complete();
		await settle();
		assert.deepEqual(ids(sent), ["id1"]);
		assert.deepEqual(health(sent), [false, true]);
	});
}

test("a burst of page changes is scanned once, when the page has been quiet for a tenth of a second", async () => {
	const { document, timers, settle } = gmail(SINGLE);
	// The first scan, which took timers 1 and 2.
	assert.equal(await settle(), 1);
	for (const change of ["first", "second", "third"]) {
		document.body.setAttribute("data-change", change);
		await new Promise(setImmediate);
	}
	// Timers 3 and 5 were the quiet periods that the next change cut short.
	assert.deepEqual(
		Array.from(timers, ([id, { delay }]) => [id, delay]),
		[
			[4, 1000],
			[6, 100],
		],
	);
	assert.equal(await settle(), 1);
});

test("a page that never goes quiet is still scanned, a second after the first change", async () => {
	const { document, sent, timers, fire } = gmail(
		"<!doctype html><div id=view></div>",
	);
	const keepChanging = async () => {
		for (const change of ["first", "second", "third"]) {
			await new Promise(setImmediate);
			document.body.setAttribute("data-change", change);
		}
		await new Promise(setImmediate);
	};
	const conversation = JSDOM.fragment(THREAD);
	conversation.querySelector(".a3s").append(JSDOM.fragment(BODY));
	document.getElementById("view").append(conversation);
	await keepChanging();
	fire(1000);
	assert.deepEqual(ids(sent), ["id3"]);
	assert.equal(timers.size, 0);

	expandAnother(document, "id4");
	await keepChanging();
	fire(1000);
	assert.deepEqual(ids(sent), ["id3", "id4"]);
	assert.equal(timers.size, 0);
});

test("a re-rendered copy of an unreadable message is reported again", async () => {
	const { document, sent, settle } = gmail(SINGLE, {
		prepare: (document) => document.querySelector(".a3s").remove(),
	});
	await settle();
	const message = document.querySelector(".adn.ads");
	message.replaceWith(message.cloneNode(true));
	await settle();
	assert.deepEqual(sent, [FAILURE, FAILURE]);
});

test("an empty display name and an empty recipient list are not failures", async () => {
	const { sent, settle } = gmail(SINGLE, {
		prepare: (document) => {
			document.querySelector(".adn.ads span.gD").removeAttribute("name");
			document.querySelector(".adn.ads .hb span.g2").remove();
		},
	});
	await settle();
	const [{ obs }] = mails(sent);
	assert.equal(obs.from_name, "");
	assert.deepEqual(obs.to, []);
	assert.deepEqual(health(sent), [true]);
});

test("link hrefs are sent as written, and data-saferedirecturl is not used", async () => {
	const { sent, settle } = gmail(SINGLE, {
		body: [
			'<a href="https://example.com/a" data-saferedirecturl="https://example.com/redirect?q=a">wrapped</a>',
			'<a href="/relative?x=1#top">relative</a>',
			'<a href="HTTPS://EXAMPLE.COM/A b">not normalised</a>',
			'<a href="mailto:user@example.com">mail</a>',
			'<a href="">empty</a>',
			'<a name="top" data-saferedirecturl="https://example.com/redirect?q=b">no href</a>',
			'<a href="https://example.com/image"><img alt="picture"></a>',
		].join(" "),
	});
	await settle();
	assert.deepEqual(mails(sent)[0].obs.links, [
		{ text: "wrapped", href: "https://example.com/a" },
		{ text: "relative", href: "/relative?x=1#top" },
		{ text: "not normalised", href: "HTTPS://EXAMPLE.COM/A b" },
		{ text: "mail", href: "mailto:user@example.com" },
		{ text: "empty", href: "" },
		{ text: "", href: "https://example.com/image" },
	]);
});

// The walk that every builder of a mail observation shares: a body, and the
// exact body_text it gives.
for (const [what, body, text] of [
	[
		"two adjacent blocks give two lines",
		"<p>Thanks</p><p>Human Resources</p>",
		"\nThanks\n\nHuman Resources\n",
	],
	[
		"br and hr break a line",
		"Dear user,<br>please read on<hr>Regards",
		"Dear user,\nplease read on\nRegards",
	],
	[
		"adjacent table cells do not glue",
		"<table><tr><td>Total</td><td>100</td></tr><tr><th>Due</th><td>now</td></tr></table>",
		"\n\n\nTotal\n\n100\n\n\n\nDue\n\nnow\n\n\n",
	],
	[
		"script and style content is absent",
		"<style>p { color: red }</style>Visible<script>var hidden = 1;</script> text",
		"Visible text",
	],
	[
		"inline elements inside a sentence add nothing",
		'Please <b>confirm</b> your <span>account</span> <a href="https://example.com/">now</a>.',
		"Please confirm your account now.",
	],
	[
		"nested blocks each add their newlines",
		"<div><ul><li>one</li><li>two</li></ul></div>",
		"\n\n\none\n\ntwo\n\n\n",
	],
	["an empty block still adds its two newlines", "a<div></div>b", "a\n\nb"],
	["a comment adds nothing", "a<!-- not text -->b", "ab"],
	[
		"text is neither trimmed nor collapsed",
		"  two  spaces \n and a tab\t",
		"  two  spaces \n and a tab\t",
	],
	[
		"text hidden by styling is included",
		'seen<span style="display: none">unseen</span>',
		"seenunseen",
	],
]) {
	test(`body text: ${what}`, async () => {
		const { sent, settle } = gmail(SINGLE, { body });
		await settle();
		assert.equal(mails(sent)[0].obs.body_text, text);
	});
}

test("body text: exactly the listed elements make a line of their own", async () => {
	// The block list of the rule; br and hr are in it too and have no content.
	const blocks =
		"address article aside blockquote dd div dl dt fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header li main nav ol p pre section table td th tr ul".split(
			" ",
		);
	const others =
		"a abbr b caption center code em font i label small span strong sub sup tbody tfoot thead u".split(
			" ",
		);
	const { sent, settle } = gmail(SINGLE, {
		body: "",
		// Built node by node: the parser would move a bare td or tr.
		prepare: (document) => {
			const body = document.querySelector(".a3s");
			for (const tag of [...blocks, "br", "hr", ...others]) {
				const element = document.createElement(tag);
				if (tag !== "br" && tag !== "hr") element.append(`in-${tag}`);
				body.append(`before-${tag}`, element, `after-${tag} `);
			}
		},
	});
	await settle();
	assert.equal(
		mails(sent)[0].obs.body_text,
		[
			...blocks.map((tag) => `before-${tag}\nin-${tag}\nafter-${tag} `),
			"before-br\nafter-br ",
			"before-hr\nafter-hr ",
			...others.map((tag) => `before-${tag}in-${tag}after-${tag} `),
		].join(""),
	);
});

test("link text is one line with single spaces, whatever the link contains", async () => {
	const { sent, settle } = gmail(SINGLE, {
		body: [
			'<a href="https://example.com/inline"><span>Open</span>\n   <b>the document</b></a>',
			'<a href="https://example.com/blocks"><div>Sign in</div><div>to continue</div></a>',
			'<a href="https://example.com/br">first line<br>second line</a>',
			'<a href="https://example.com/padded">  padded&nbsp;\t text  </a>',
			'<a href="https://example.com/style"><style>a { color: red }</style>styled</a>',
		].join(""),
	});
	await settle();
	assert.deepEqual(mails(sent)[0].obs.links, [
		{ text: "Open the document", href: "https://example.com/inline" },
		{ text: "Sign in to continue", href: "https://example.com/blocks" },
		{ text: "first line second line", href: "https://example.com/br" },
		{ text: "padded text", href: "https://example.com/padded" },
		{ text: "styled", href: "https://example.com/style" },
	]);
});

test("link text collapses exactly the characters that \\s matches", async () => {
	// The set the body-text rule names. It is not Unicode's White_Space:
	// U+FEFF is in it and U+0085 is not. A zero-width space is in neither.
	const whitespace = String.fromCodePoint(
		...[
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002,
			0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028,
			0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
		],
	);
	const notWhitespace = String.fromCodePoint(0x85, 0x200b);
	const { sent, settle } = gmail(SINGLE, {
		body: "",
		prepare: (document) => {
			const link = document.createElement("a");
			link.setAttribute("href", "https://example.com/");
			link.append(
				`${whitespace}one${whitespace}two${notWhitespace}three${whitespace}`,
			);
			document.querySelector(".a3s").append(link);
		},
	});
	await settle();
	assert.deepEqual(mails(sent)[0].obs.links, [
		{ text: `one two${notWhitespace}three`, href: "https://example.com/" },
	]);
});

test("an image map's regions are links too, with empty text, in document order", async () => {
	const { sent, settle } = gmail(SINGLE, {
		body: [
			'<a href="https://example.com/before">before</a>',
			'<img usemap="#regions" alt="A picture">',
			'<map name="regions">',
			'<area href="https://example.com/region" shape="rect" coords="0,0,10,10" alt="Sign in">',
			'<area shape="default" alt="Not a link">',
			"</map>",
			'<a href="https://example.com/after">after</a>',
		].join(""),
	});
	await settle();
	assert.deepEqual(mails(sent)[0].obs.links, [
		{ text: "before", href: "https://example.com/before" },
		{ text: "", href: "https://example.com/region" },
		{ text: "after", href: "https://example.com/after" },
	]);
});

test("a form in a body cannot answer for the properties the walk reads", async () => {
	const { sent, settle } = gmail(SINGLE, {
		body: '<form><input name="childNodes"><input name="nodeName">Text in a form, <a href="https://example.com/form">and a link</a></form>',
		// jsdom leaves out a form's named properties: plant what a browser
		// gives, where the form answers with its controls of those names.
		prepare: (document) => {
			const form = document.querySelector(".a3s form");
			for (const control of form.querySelectorAll("input")) {
				Object.defineProperty(form, control.name, { value: control });
			}
		},
	});
	await settle();
	const [{ obs }] = mails(sent);
	assert.equal(obs.body_text, "\nText in a form, and a link\n");
	assert.deepEqual(obs.links, [
		{ text: "and a link", href: "https://example.com/form" },
	]);
	assert.deepEqual(health(sent), [true]);
});

test("an element named like a property of the document cannot stop the adapter", async () => {
	const { sent, settle } = gmail(SINGLE, {
		// jsdom leaves out a document's named properties: plant what a browser
		// gives for <img name="querySelectorAll"> and the like.
		prepare: (document) => {
			const image = document.createElement("img");
			for (const name of [
				"querySelectorAll",
				"addEventListener",
				"prerendering",
			]) {
				Object.defineProperty(document, name, { value: image });
			}
		},
	});
	await settle();
	assert.deepEqual(ids(sent), ["id1"]);
	assert.deepEqual(health(sent), [true]);
});

test("markup inside a body is never taken for Gmail's structure", async () => {
	const { sent, settle } = gmail(SINGLE, {
		prepare: (document) => {
			// What a sender could write if Gmail let its own class names through:
			// copies of the captured structure, placed inside the body.
			const message = document.querySelector(".adn.ads");
			const fakeMessage = message.cloneNode(true);
			fakeMessage.setAttribute("data-legacy-message-id", "id9");
			const namelessCards = message.querySelector(".aQH").cloneNode(true);
			for (const name of namelessCards.querySelectorAll(".aV3")) name.remove();
			message
				.querySelector(".a3s")
				.append(
					fakeMessage,
					namelessCards,
					message.querySelector(".hb").cloneNode(true),
					message.querySelector("span.gD").cloneNode(true),
					document.querySelector("h2.hP").cloneNode(true),
				);
		},
	});
	await settle();
	assert.deepEqual(health(sent), [true]);
	assert.deepEqual(ids(sent), ["id1"]);
	const [{ obs }] = mails(sent);
	assert.deepEqual(obs.to, ["user@example.com"]);
	assert.deepEqual(obs.attachments, ["x", "x"]);
});

test("a verdict is drawn directly above the body, outside it", async () => {
	const { document, calls, settle } = gmail(SINGLE, {
		answer: forMail(CAUTION),
	});
	await settle();
	assert.equal(calls.length, 1);
	const [{ anchor, verdict, banner }] = calls;
	const body = document.querySelector(".a3s");
	assert.equal(verdict, CAUTION);
	assert.equal(anchor, document.querySelector(".adn.ads .ii.gt"));
	assert.equal(body.contains(anchor), false);
	assert.equal(body.contains(banner), false);
	assert.equal(banner.nextElementSibling, body.parentElement);
	assert.equal(document.querySelector(".adn.ads").contains(banner), true);
	assert.match(banner.textContent, /A constructed reason\./);
});

test("the banner is requested again after a re-render removed it or replaced its anchor", async () => {
	const { document, calls, settle } = gmail(SINGLE, {
		answer: forMail(CAUTION),
	});
	await settle();
	const shown = () => Array.from(document.querySelectorAll("[role=alert]"));

	calls[0].banner.remove();
	await settle();
	assert.equal(calls.length, 2);
	assert.equal(calls[1].anchor, calls[0].anchor);
	assert.deepEqual(shown(), [calls[1].banner]);
	assert.equal(calls[1].banner.nextElementSibling, calls[1].anchor);

	// Gmail replaces the body's wrapper and leaves the banner where it was.
	const wrapper = document.querySelector(".adn.ads .ii.gt");
	const rendered = wrapper.cloneNode(true);
	wrapper.replaceWith(rendered);
	await settle();
	assert.equal(calls.length, 3);
	assert.equal(calls[2].anchor, rendered);
	assert.deepEqual(shown(), [calls[2].banner]);
	assert.equal(calls[2].banner.nextElementSibling, rendered);

	// Gmail rebuilds the whole message, which takes the banner with it.
	const message = document.querySelector(".adn.ads");
	const rebuilt = message.cloneNode(true);
	rebuilt.querySelector("[role=alert]").remove();
	message.replaceWith(rebuilt);
	await settle();
	assert.equal(calls.length, 4);
	assert.equal(calls[3].anchor, rebuilt.querySelector(".ii.gt"));
	assert.deepEqual(shown(), [calls[3].banner]);
	assert.equal(calls[3].banner.nextElementSibling, calls[3].anchor);

	// Changes that leave the banner in place ask for nothing.
	rebuilt.setAttribute("data-rendered", "again");
	document.body.append(document.createElement("div"));
	await settle();
	assert.equal(calls.length, 4);
});

for (const [what, answer] of Object.entries({
	"a null reply": async () => null,
	"a rejected sendMessage": async () => {
		throw new Error("Could not establish connection.");
	},
	"a sendMessage that throws": () => {
		throw new Error("Extension context invalidated.");
	},
})) {
	test(`no banner is requested for ${what}`, async () => {
		const { document, sent, calls, settle } = gmail(SINGLE, { answer });
		await settle();
		document.querySelector(".adn.ads").setAttribute("data-rendered", "again");
		await settle();
		assert.deepEqual(ids(sent), ["id1"]);
		assert.deepEqual(health(sent), [true]);
		assert.deepEqual(calls, []);
		assert.equal(document.querySelector("[role=alert]"), null);
	});
}

test("a dismissed banner stays away for the rest of the document", async () => {
	const { document, calls, settle } = gmail(SINGLE, {
		answer: forMail(CAUTION),
	});
	const pristine = document.querySelector(".adn.ads").cloneNode(true);
	await settle();
	calls[0].banner.querySelector("button").click();
	await settle();
	assert.equal(calls.length, 1);
	document.querySelector(".adn.ads").replaceWith(pristine);
	await settle();
	assert.equal(calls.length, 1);
	assert.equal(document.querySelector("[role=alert]"), null);
});

for (const [what, options] of Object.entries({
	"a none verdict": { answer: forMail(NONE) },
	"a verdict for which the banner function returns nothing": {
		answer: forMail(CAUTION),
		banner: () => {},
	},
})) {
	test(`${what} is passed on once for each anchor and draws nothing`, async () => {
		const { document, calls, settle } = gmail(SINGLE, {
			...options,
			// Something else already sits between the header and the body.
			prepare: (document) =>
				document
					.querySelector(".adn.ads .ii.gt")
					.before(document.createElement("div")),
		});
		const pristine = document.querySelector(".adn.ads").cloneNode(true);
		await settle();
		document.querySelector(".adn.ads").setAttribute("data-rendered", "again");
		await settle();
		assert.equal(calls.length, 1);
		document.querySelector(".adn.ads").replaceWith(pristine);
		await settle();
		pristine.setAttribute("data-rendered", "again");
		await settle();
		assert.deepEqual(
			calls.map(({ anchor }) => anchor.isConnected),
			[false, true],
		);
		assert.equal(document.querySelector("[role=alert]"), null);
	});
}

test("each expanded message gets the banner of its own verdict", async () => {
	const { document, calls, settle } = gmail(THREAD, {
		answer: async (message) =>
			message.t === "mail"
				? {
						level: "danger",
						reasons: [
							{
								cue: "constructed-cue",
								text: `Reason for ${message.obs.message_id}.`,
							},
						],
						show: true,
					}
				: null,
	});
	await settle();
	expandAnother(document, "id4");
	await settle();
	assert.equal(calls.length, 2);
	for (const id of ["id3", "id4"]) {
		const message = document.querySelector(
			`.adn.ads[data-legacy-message-id="${id}"]`,
		);
		const banners = message.querySelectorAll("[role=alert]");
		assert.equal(banners.length, 1);
		assert.equal(
			banners[0].nextElementSibling,
			message.querySelector(".ii.gt"),
		);
		assert.match(banners[0].textContent, new RegExp(`Reason for ${id}\\.`));
	}
});

// Not seen in the capture, but nothing rules it out: Gmail putting another
// message into an element that already has a banner.
const otherMessage = (message) =>
	message.setAttribute("data-legacy-message-id", "id7");
for (const [what, first, reuse, second, expected] of [
	["a message without a verdict", CAUTION, otherMessage, null, []],
	[
		"a message with a verdict of its own",
		CAUTION,
		otherMessage,
		DANGER,
		[/^Riggs: this may be phishingAnother reason\./],
	],
	[
		"a message with a verdict, after one that showed nothing,",
		NONE,
		otherMessage,
		DANGER,
		[/^Riggs: this may be phishingAnother reason\./],
	],
	[
		"a message that cannot be read",
		CAUTION,
		(message) => message.removeAttribute("data-legacy-message-id"),
		null,
		[],
	],
]) {
	test(`an element reused for ${what} shows that message's banner or none`, async () => {
		const { document, settle } = gmail(SINGLE, {
			answer: async (message) =>
				message.t !== "mail"
					? null
					: message.obs.message_id === "id1"
						? first
						: second,
		});
		await settle();
		assert.equal(
			document.querySelectorAll("[role=alert]").length,
			first === NONE ? 0 : 1,
		);
		reuse(document.querySelector(".adn.ads"));
		await settle();
		const shown = Array.from(
			document.querySelectorAll("[role=alert]"),
			(banner) => banner.textContent,
		);
		assert.equal(shown.length, expected.length);
		for (const [index, text] of shown.entries()) {
			assert.match(text, expected[index]);
		}
	});
}

test("a verdict the banner refuses throws once and blocks nothing after it", async () => {
	const refused = { level: "safe", reasons: [], show: true };
	const { document, sent, calls, fire, settle } = gmail(THREAD, {
		answer: async (message) =>
			message.t !== "mail"
				? null
				: message.obs.message_id === "id3"
					? refused
					: CAUTION,
	});
	fire(100);
	await new Promise(setImmediate);
	// The refused verdict has arrived. A second message, which follows the
	// first in the page, is expanded before the scan that will throw.
	expandAnother(document, "id4");
	await assert.rejects(settle(), /unknown level/);
	assert.deepEqual(ids(sent), ["id3"]);
	await settle();
	assert.deepEqual(ids(sent), ["id3", "id4"]);
	assert.deepEqual(
		calls.map(({ verdict }) => verdict.level),
		["caution"],
	);
	assert.equal(document.querySelectorAll("[role=alert]").length, 1);
	const refusedMessage = document.querySelector(".adn.ads");
	refusedMessage.replaceWith(refusedMessage.cloneNode(true));
	await settle();
	assert.equal(calls.length, 1);
});

test("the adapter declares no global", async () => {
	const { window, globals, settle } = gmail(SINGLE);
	await settle();
	assert.deepEqual(
		Object.getOwnPropertyNames(window).filter(
			(name) => !globals.includes(name),
		),
		[],
	);
});
