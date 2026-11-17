import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { Script } from "node:vm";
import { JSDOM } from "jsdom";

const file = join(import.meta.dirname, "..", "ext", "page.js");
const script = new Script(readFileSync(file, "utf8"), { filename: file });
const settle = () => new Promise(setImmediate);
// What page.js creates belongs to the page's realm, which deepEqual tells
// apart from this one; a message is JSON on the wire in any case.
const plain = (value) => JSON.parse(JSON.stringify(value));

const FORM =
	"<form><input id=user><input id=secret type=password><button id=go type=button></button></form>";
const VERDICT = {
	level: "caution",
	reasons: [{ cue: "c1", text: "one" }],
	show: true,
};
const PAGE = { t: "page" };
const login = (evidence) => [PAGE, { t: "login", evidence }];
const LISTENED = [
	"click",
	"focusin",
	"keydown",
	"pageshow",
	"paste",
	"prerenderingchange",
];

// The listeners page.js registers are collected, and fire() calls them with
// plain event objects, trusted unless the test says otherwise. jsdom's own
// events are untrusted, except the ones focus() sends. chrome, riggsBanner,
// document.prerendering and the autofill state do not exist in jsdom and are
// stand-ins.
const load = async (body, options = {}) => {
	const { reply = null, prerendering = false, xhtml = false } = options;
	const { respond = async (message) => (message.t === "page" ? reply : null) } =
		options;
	const dom = xhtml
		? new JSDOM(
				`<html xmlns="http://www.w3.org/1999/xhtml"><body>${body}</body></html>`,
				{ runScripts: "outside-only", contentType: "application/xhtml+xml" },
			)
		: new JSDOM(`<!doctype html><body>${body}`, { runScripts: "outside-only" });
	const { window } = dom;
	const { document } = window;

	const sent = [];
	window.chrome = {
		runtime: {
			sendMessage: (message) => {
				sent.push(plain(message));
				return respond(message);
			},
		},
	};

	// chrome.dom as Chromium's dom.json declares it: it takes an HTMLElement,
	// throws on anything else, and answers null when the element hosts no
	// shadow tree. shadow() notes each tree it attaches, which is how the
	// stand-in knows the closed ones. "dead" makes every call throw, as an API
	// may once its extension is gone; without the option there is no chrome.dom.
	const roots = new WeakMap();
	const asked = [];
	if (options.dom) {
		window.chrome.dom = {
			openOrClosedShadowRoot: (element) => {
				asked.push(element);
				if (options.dom === "dead") {
					throw new Error("Extension context invalidated.");
				}
				if (!(element instanceof window.HTMLElement)) {
					throw new TypeError(
						"Error in invocation of dom.openOrClosedShadowRoot",
					);
				}
				return roots.get(element) ?? null;
			},
		};
	}
	const shadow = (host, mode, html) => {
		const root = host.attachShadow({ mode });
		roots.set(host, root);
		root.append(document.createRange().createContextualFragment(html));
		return root;
	};

	const banners = [];
	window.riggsBanner = (anchor, verdict) => {
		banners.push({ anchor, verdict });
		return null;
	};

	// jsdom's selector engine adds listeners of its own to the window; the
	// ones page.js adds are functions of the page's realm. As in a browser,
	// adding the same listener a second time changes nothing.
	const listeners = [];
	const delivered = [];
	for (const target of [window, document]) {
		const add = target.addEventListener.bind(target);
		target.addEventListener = (type, listener, capture) => {
			if (!(listener instanceof window.Function)) {
				add(type, listener, capture);
				return;
			}
			const known = listeners.some(
				(entry) =>
					entry.target === target &&
					entry.type === type &&
					entry.listener === listener &&
					entry.capture === capture,
			);
			if (known) return;
			const wrapper = (event) => {
				delivered.push(event.type);
				listener(event);
			};
			listeners.push({ target, type, listener, capture, wrapper });
			add(type, wrapper, capture);
		};
	}

	const observers = [];
	const observing = [];
	const numbered = (observer) => {
		if (!observing.includes(observer)) observing.push(observer);
		return observing.indexOf(observer);
	};
	const { observe, disconnect } = window.MutationObserver.prototype;
	window.MutationObserver.prototype.observe = function (target, init) {
		observers.push([
			"observe",
			numbered(this),
			target === document,
			plain(init),
		]);
		return observe.call(this, target, init);
	};
	window.MutationObserver.prototype.disconnect = function () {
		observers.push(["disconnect", numbered(this)]);
		return disconnect.call(this);
	};

	const autofilled = new Set();
	const { matches } = window.Element.prototype;
	window.Element.prototype.matches = function (selector) {
		return selector === ":-webkit-autofill"
			? autofilled.has(this)
			: matches.call(this, selector);
	};

	const state = { prerendering };
	Object.defineProperty(window.Document.prototype, "prerendering", {
		get: () => state.prerendering,
	});

	const insert = (html) =>
		document.body.append(document.createRange().createContextualFragment(html));

	// What the HTML standard has document.open() do, and jsdom's does only in
	// part: every listener of the window is erased and the document's children
	// go. The new root element then arrives as it would from the parser.
	const reopen = () => {
		for (const { target, type, wrapper, capture } of listeners.splice(0)) {
			target.removeEventListener(type, wrapper, capture);
		}
		document.replaceChildren();
		const root = document.createElement("html");
		root.append(document.createElement("body"));
		document.append(root);
	};

	options.setup?.({ document, shadow });
	script.runInContext(dom.getInternalVMContext());
	await settle();

	return {
		window,
		document,
		state,
		sent,
		banners,
		listeners,
		delivered,
		observers,
		autofilled,
		asked,
		shadow,
		insert,
		reopen,
		byId: (id) => document.getElementById(id),
		fire: (type, event = {}) => {
			const registered = listeners.filter((entry) => entry.type === type);
			assert.notEqual(registered.length, 0, `no ${type} listener`);
			for (const { listener } of registered) {
				listener({ isTrusted: true, type, ...event });
			}
		},
	};
};

test("a password field that is already there is checked once", async () => {
	const page = await load("<input type=password>");
	assert.deepEqual(page.sent, [PAGE]);
});

test("a password field inserted later is checked once, alone or inside what was inserted", async () => {
	for (const html of [
		"<input type=password>",
		"<form><p><input type=password></p></form>",
	]) {
		const page = await load("<input type=text>");
		assert.deepEqual(page.sent, []);
		page.insert(html);
		await settle();
		assert.deepEqual(page.sent, [PAGE]);
	}
});

test("an input whose type becomes password is checked once", async () => {
	const page = await load("<input id=field type=text>");
	page.byId("field").type = "password";
	await settle();
	assert.deepEqual(page.sent, [PAGE]);
});

// Only an HTML document compares a type attribute without regard to case in
// a selector; the input is a password field in either kind of document.
test("a password field of an XHTML page is seen whatever the case of its type", async () => {
	const page = await load('<input id="secret" type="PASSWORD" value="x"/>', {
		xhtml: true,
	});
	assert.equal(page.byId("secret").type, "password");
	assert.deepEqual(page.sent, [PAGE]);
	page.fire("click", { target: page.byId("secret") });
	assert.deepEqual(page.sent, login("filled"));
});

// The observer on document does not reach into a shadow tree. jsdom's focus()
// sends a trusted focusin that names the outermost host at the window, as a
// browser does; a key or a click from inside a tree is fired by hand in the
// same way, with the host as its target.
test("a password field in an open shadow tree is checked when it takes focus", async () => {
	const page = await load("<div id=host></div><input id=plain>");
	const host = page.byId("host");
	const root = page.shadow(host, "open", "<input type=password>");
	await settle();
	assert.deepEqual(page.sent, []);

	page.byId("plain").focus();
	assert.deepEqual(page.sent, []);
	root.firstChild.focus();
	assert.deepEqual(page.delivered, ["focusin", "focusin"]);
	assert.deepEqual(page.sent, [PAGE]);

	page.fire("keydown", { key: "a", target: host });
	page.fire("keydown", { key: "Enter", target: host });
	assert.deepEqual(page.sent, login("typed"));
});

// When focus only moves inside one shadow tree, the focus event does not
// leave that tree (its path ends where target and related target are the
// same), in jsdom as in the DOM standard: the window hears of the first
// focus only. The sensor hears the second inside the tree.
test("a field reached by moving focus inside a shadow tree is checked at that focus", async () => {
	const page = await load("<div id=host></div>");
	const root = page.shadow(
		page.byId("host"),
		"open",
		"<input><input type=password>",
	);
	root.firstChild.focus();
	assert.deepEqual(page.sent, []);
	root.lastChild.focus();
	assert.deepEqual(page.delivered, ["focusin"]);
	assert.deepEqual(page.sent, [PAGE]);

	const deeper = await load("<div id=host></div>", { dom: true });
	const outer = deeper.shadow(
		deeper.byId("host"),
		"closed",
		"<input><div></div>",
	);
	const nested = deeper.shadow(
		outer.lastChild,
		"closed",
		"<input><input type=password>",
	);
	outer.firstChild.focus();
	nested.firstChild.focus();
	assert.deepEqual(deeper.sent, []);
	nested.lastChild.focus();
	assert.deepEqual(deeper.delivered, ["focusin"]);
	assert.deepEqual(deeper.sent, [PAGE]);
});

// The focus was there before the sensor could hear of it.
test("a field that already has the focus is checked at the next key, paste or click", async () => {
	for (const type of ["keydown", "paste", "click"]) {
		const page = await load("<div id=host></div>", {
			setup: ({ document, shadow }) =>
				shadow(
					document.getElementById("host"),
					"open",
					"<input type=password>",
				).firstChild.focus(),
		});
		assert.deepEqual(page.sent, []);
		page.fire(type, { key: "Shift", target: page.byId("host") });
		assert.deepEqual(page.sent, [PAGE]);
	}
});

test("a password field in a closed shadow tree is reached through chrome.dom", async () => {
	const page = await load("<div id=host></div>", { dom: true });
	const host = page.byId("host");
	const root = page.shadow(host, "closed", "<input type=password>");
	assert.equal(host.shadowRoot, null);

	root.firstChild.focus();
	assert.deepEqual(page.sent, [PAGE]);
	page.fire("paste", { target: host });
	page.fire("click", { target: host });
	assert.deepEqual(page.sent, login("typed"));
});

test("without chrome.dom a closed shadow tree stays closed", async () => {
	const page = await load("<div id=host></div>");
	const host = page.byId("host");
	page.shadow(host, "closed", "<input type=password>").firstChild.focus();
	page.fire("keydown", { key: "a", target: host });
	page.fire("keydown", { key: "Enter", target: host });
	assert.deepEqual(page.delivered, ["focusin"]);
	assert.deepEqual(page.sent, []);
});

test("a password field two shadow trees deep is found, with chrome.dom and without", async () => {
	for (const dom of [true, false]) {
		const page = await load("<div id=host></div>", { dom });
		const host = page.byId("host");
		const outer = page.shadow(host, "open", "<div></div>");
		const inner = page.shadow(
			outer.firstChild,
			dom ? "closed" : "open",
			"<input type=password>",
		);
		inner.firstChild.focus();
		assert.deepEqual(page.sent, [PAGE]);

		page.fire("keydown", { key: "a", target: host });
		page.fire("keydown", { key: "Enter", target: host });
		assert.deepEqual(page.sent, login("typed"));
	}
});

test("an untrusted focusin on a shadow host is ignored", async () => {
	const page = await load("<div id=host></div>", {
		setup: ({ document, shadow }) =>
			shadow(
				document.getElementById("host"),
				"open",
				"<input type=password>",
			).firstChild.focus(),
	});
	assert.deepEqual(page.sent, []);
	page.fire("focusin", { isTrusted: false, target: page.byId("host") });
	assert.deepEqual(page.sent, []);
	page.fire("focusin", { target: page.byId("host") });
	assert.deepEqual(page.sent, [PAGE]);

	const inside = await load("<div id=host></div>");
	const root = inside.shadow(
		inside.byId("host"),
		"open",
		"<input><input type=password>",
	);
	root.firstChild.focus();
	root.lastChild.dispatchEvent(
		new inside.window.FocusEvent("focusin", { bubbles: true }),
	);
	assert.deepEqual(inside.sent, []);
});

test("a field in a shadow tree belongs to the form around its host", async () => {
	const page = await load(
		"<form><div id=box></div><button id=go type=button></button></form><form><div id=other></div></form>",
	);
	const box = page.byId("box");
	const other = page.byId("other");
	page.shadow(box, "open", "<input type=password>").firstChild.focus();
	page.fire("keydown", { key: "a", target: box });

	page
		.shadow(other, "open", "<button type=button></button>")
		.firstChild.focus();
	page.fire("click", { target: other });
	assert.deepEqual(page.sent, [PAGE]);

	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("typed"));
});

test("a field that is shown as text, or has left the document, no longer counts", async () => {
	for (const leave of [
		(field) => field.setAttribute("type", "text"),
		(field) => field.getRootNode().host.remove(),
	]) {
		const page = await load(
			"<div id=host></div><button id=go type=button></button>",
		);
		const host = page.byId("host");
		const field = page.shadow(host, "open", "<input type=password>").firstChild;
		field.focus();
		page.fire("keydown", { key: "a", target: host });
		leave(field);
		page.fire("click", { target: page.byId("go") });
		assert.deepEqual(page.sent, [PAGE]);
	}
});

test("chrome.dom is asked about HTML elements only", async () => {
	const page = await load(FORM, { dom: true });
	const svg = page.document.createElementNS(
		"http://www.w3.org/2000/svg",
		"svg",
	);
	page.byId("go").append(svg);
	page.byId("secret").value = "x";
	page.fire("focusin", { target: page.window });
	page.fire("focusin", { target: page.byId("user") });
	page.fire("click", { target: svg });
	// The focused box, then the form's elements at the click; not the window
	// and not the svg, at the focus or in the form.
	assert.deepEqual(
		page.asked.map((element) => element.id),
		["user", "user", "secret", "go"],
	);
	assert.deepEqual(page.sent, login("filled"));
});

test("a chrome.dom that throws leaves the open shadow tree to work with", async () => {
	const page = await load("<div id=host></div>", { dom: "dead" });
	const host = page.byId("host");
	page.shadow(host, "open", "<input type=password>").firstChild.focus();
	assert.deepEqual(page.sent, [PAGE]);
	page.fire("keydown", { key: "a", target: host });
	page.fire("keydown", { key: "Enter", target: host });
	assert.deepEqual(page.sent, login("typed"));
});

const LOGIN_TREE = "<input type=password><button type=button></button>";
const filler = (count) => "<span></span>".repeat(count);

// What a password manager leaves: a filled field that never had the focus.
// The click names the host at the window, nothing in the tree is the active
// element, and no focus event came before. Only a click or Enter looks.
test("a field nobody focused is found by a click or Enter on its shadow tree", async () => {
	for (const [dom, mode] of [
		[false, "open"],
		[true, "closed"],
	]) {
		const page = await load("<div id=host></div>", { dom });
		const host = page.byId("host");
		page.shadow(host, mode, LOGIN_TREE).firstChild.value = "x";
		page.fire("keydown", { key: "a", target: host });
		page.fire("paste", { target: host });
		assert.deepEqual(page.sent, []);
		page.fire("click", { target: host });
		assert.deepEqual(page.delivered, []);
		assert.deepEqual(page.sent, login("filled"));

		const other = await load("<div id=host></div>", { dom });
		other.autofilled.add(
			other.shadow(other.byId("host"), mode, LOGIN_TREE).firstChild,
		);
		other.fire("keydown", { key: "Enter", target: other.byId("host") });
		assert.deepEqual(other.sent, login("autofill"));
	}
});

// The button took the focus before the sensor could hear of it, so the click
// is about an element inside the tree and not about the host.
test("a field nobody focused is found by a click on a button beside it in the tree", async () => {
	const page = await load("<div id=host></div>", {
		setup: ({ document, shadow }) => {
			const root = shadow(document.getElementById("host"), "open", LOGIN_TREE);
			root.firstChild.value = "x";
			root.lastChild.focus();
		},
	});
	assert.deepEqual(page.sent, []);
	page.fire("click", { target: page.byId("host") });
	assert.deepEqual(page.sent, login("filled"));
});

// A field and a button that are components of their own, side by side in a
// third tree: the button's tree holds no field, the tree around both does.
test("a field in a neighbouring component's tree is found from the tree around both", async () => {
	const page = await load("<div id=host></div>", {
		dom: true,
		setup: ({ document, shadow }) => {
			const outer = shadow(
				document.getElementById("host"),
				"closed",
				"<div></div><div></div>",
			);
			shadow(outer.firstChild, "closed", "<input type=password value=x>");
			shadow(
				outer.lastChild,
				"closed",
				"<button type=button></button>",
			).firstChild.focus();
		},
	});
	page.fire("click", { target: page.byId("host") });
	assert.deepEqual(page.sent, login("filled"));
});

// A component's password box inside an ordinary form with an ordinary button:
// the click is nowhere near a shadow tree, the form is what they share.
test("a field in a shadow tree inside a form is found by a click on the form's button", async () => {
	const page = await load(
		"<form><div id=box></div><button id=go type=button></button></form><div id=outside></div>",
	);
	page.autofilled.add(
		page.shadow(page.byId("box"), "open", "<input type=password>").firstChild,
	);
	page.fire("click", { target: page.byId("outside") });
	assert.deepEqual(page.sent, []);
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("autofill"));
});

test("a click looks at 500 elements and no further, across all the trees it enters", async () => {
	for (const [before, expected] of [
		[499, login("filled")],
		[500, []],
	]) {
		const page = await load("<div id=host></div>");
		page.shadow(
			page.byId("host"),
			"open",
			`${filler(before)}<input type=password value=x>`,
		);
		page.fire("click", { target: page.byId("host") });
		assert.deepEqual(page.sent, expected);
	}

	for (const [nested, expected] of [
		[498, login("filled")],
		[499, []],
	]) {
		const page = await load("<div id=host></div>");
		const root = page.shadow(
			page.byId("host"),
			"open",
			"<div></div><input type=password value=x>",
		);
		page.shadow(root.firstChild, "open", filler(nested));
		page.fire("click", { target: page.byId("host") });
		assert.deepEqual(page.sent, expected);
	}
});

// The tree is larger than the bound and the form is at its end. The focus is
// on the form's button, taken before the sensor could hear of it.
test("the form around a click is looked through before the tree the form is in", async () => {
	const page = await load("<div id=host></div>", {
		setup: ({ document, shadow }) =>
			shadow(
				document.getElementById("host"),
				"open",
				`${filler(600)}<form><input type=password value=x><button type=button></button></form>`,
			).lastChild.lastChild.focus(),
	});
	page.fire("click", { target: page.byId("host") });
	assert.deepEqual(page.sent, login("filled"));
});

// In a browser an element named like a built-in answers for it on its
// document or form. jsdom does not do that, so the test puts an element
// there itself: first on the path of the observer, then on that of the scan.
test("elements named like built-ins do not blind the sensor", async () => {
	const shadow = (object, names, document) => {
		const decoy = document.createElement("img");
		for (const name of names) {
			Object.defineProperty(object, name, { value: decoy });
		}
	};
	const OF_DOCUMENT = ["body", "prerendering", "querySelectorAll"];
	const OF_FORM = ["matches", "closest", "querySelector", "getRootNode"];

	const page = await load("", { reply: VERDICT });
	const { body } = page.document;
	const { firstChild: form } = page.document
		.createRange()
		.createContextualFragment(FORM);
	shadow(form, OF_FORM, page.document);
	shadow(page.document, OF_DOCUMENT, page.document);
	body.append(form);
	await settle();
	assert.deepEqual(page.sent, [PAGE]);
	assert.equal(page.banners[0].anchor, body);

	page.byId("secret").value = "x";
	page.fire("click", { target: form });
	assert.deepEqual(page.sent, login("filled"));

	const other = await load(FORM, { prerendering: true });
	shadow(other.document, OF_DOCUMENT, other.document);
	other.state.prerendering = false;
	other.fire("prerenderingchange");
	assert.deepEqual(other.sent, [PAGE]);
});

test("a field that is there, inserted, changed and focused still makes one check", async () => {
	const page = await load("<input id=first type=password><input id=second>");
	page.insert("<input type=password>");
	page.byId("second").type = "password";
	page.fire("focusin", { target: page.byId("first") });
	await settle();
	assert.deepEqual(page.sent, [PAGE]);
});

test("a document that never has a password field sends nothing", async () => {
	const page = await load("<form><input id=user type=text></form>");
	page.insert("<input type=email><textarea></textarea>");
	page.byId("user").type = "search";
	page.fire("focusin", { target: page.byId("user") });
	page.fire("focusin", { target: page.window });
	page.fire("pageshow", { persisted: true });
	page.fire("click", { target: page.byId("user") });
	await settle();
	assert.deepEqual(page.sent, []);
});

test("two observers watch the document, and the one for fields stops at the first", async () => {
	const page = await load("");
	assert.deepEqual(page.observers, [
		["observe", 0, true, { childList: true }],
		[
			"observe",
			1,
			true,
			{ subtree: true, childList: true, attributeFilter: ["type"] },
		],
	]);
	page.insert("<input type=password>");
	await settle();
	assert.deepEqual(page.observers.slice(2), [["disconnect", 1]]);
});

test("after document.open() the sensor listens again and still sees a new field", async () => {
	const page = await load("");
	page.reopen();
	assert.deepEqual(page.listeners, []);
	await settle();
	assert.deepEqual(page.listeners.map(({ type }) => type).toSorted(), LISTENED);

	page.insert(FORM);
	await settle();
	assert.deepEqual(page.sent, [PAGE]);
	page.fire("pageshow", { persisted: true });
	page.byId("secret").value = "x";
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, [PAGE, PAGE, { t: "login", evidence: "filled" }]);
});

test("document.open() does not make a document check or report a second time", async () => {
	const page = await load(FORM);
	page.byId("secret").value = "x";
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("filled"));

	page.reopen();
	page.insert(FORM);
	await settle();
	page.byId("secret").value = "x";
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("filled"));
	page.fire("pageshow", { persisted: true });
	assert.deepEqual(page.sent, [...login("filled"), PAGE]);
});

test("a page that reopens its document while prerendering is scanned on activation", async () => {
	const page = await load("", { prerendering: true });
	page.reopen();
	page.insert(FORM);
	await settle();
	assert.deepEqual(page.sent, []);

	page.state.prerendering = false;
	page.fire("prerenderingchange");
	assert.deepEqual(page.sent, [PAGE]);
});

// The activation went by unnoticed here, as it does when a page stops the
// event from a listener it added before the sensor's were back.
test("a change of the document's own children looks for a waiting field", async () => {
	const page = await load(FORM, { prerendering: true });
	page.state.prerendering = false;
	page.document.append(page.document.createComment(""));
	await settle();
	assert.deepEqual(page.sent, [PAGE]);
});

test("a new root element alone does not add the listeners a second time", async () => {
	const page = await load("<input type=password>");
	const root = page.document.createElement("html");
	page.document.documentElement.replaceWith(root);
	await settle();
	assert.equal(page.listeners.length, 6);
	page.fire("pageshow", { persisted: true });
	assert.deepEqual(page.sent, [PAGE, PAGE]);
});

test("a verdict in the reply goes to the banner, anchored on body", async () => {
	const page = await load("<input type=password>", { reply: VERDICT });
	assert.equal(page.banners.length, 1);
	const [{ anchor, verdict }] = page.banners;
	assert.equal(anchor, page.document.body);
	assert.equal(anchor.parentElement, page.document.documentElement);
	assert.equal(verdict, VERDICT);
});

test("a null reply calls no banner", async () => {
	const page = await load("<input type=password>");
	assert.deepEqual(page.sent, [PAGE]);
	assert.deepEqual(page.banners, []);
});

test("a document without a body has no anchor, so no banner", async () => {
	const page = await load("", { reply: VERDICT });
	const field = page.document.createElement("input");
	field.type = "password";
	page.document.body.remove();
	page.document.documentElement.append(field);
	await settle();
	assert.deepEqual(page.sent, [PAGE]);
	assert.deepEqual(page.banners, []);
});

test("an unreachable worker is a null reply: no exception, no banner", async () => {
	const rejections = [];
	const collect = (reason) => rejections.push(reason);
	process.on("unhandledRejection", collect);
	for (const respond of [
		async () => {
			throw new Error("Could not establish connection.");
		},
		() => {
			throw new Error("Extension context invalidated.");
		},
	]) {
		const page = await load(FORM, { respond });
		page.byId("secret").value = "x";
		page.fire("click", { target: page.byId("go") });
		page.fire("pageshow", { persisted: true });
		await settle();
		assert.deepEqual(page.sent, [...login("filled"), PAGE]);
		assert.deepEqual(page.banners, []);
	}
	process.off("unhandledRejection", collect);
	assert.deepEqual(rejections, []);
});

test("coming back from the back/forward cache checks again, each time", async () => {
	const page = await load("<input type=password>", { reply: VERDICT });
	page.fire("pageshow", { persisted: true });
	page.fire("pageshow", { persisted: true });
	await settle();
	assert.deepEqual(page.sent, [PAGE, PAGE, PAGE]);
	assert.equal(page.banners.length, 3);
});

test("a document that had a password field checks again even when the field is gone", async () => {
	const page = await load("<input id=field type=password>");
	page.byId("field").remove();
	page.fire("pageshow", { persisted: true });
	assert.deepEqual(page.sent, [PAGE, PAGE]);
});

// A field can exist unchecked only if activation went unnoticed.
test("a document that comes back unchecked is looked at again", async () => {
	const page = await load("<input type=password>", { prerendering: true });
	page.state.prerendering = false;
	page.fire("pageshow", { persisted: true });
	page.fire("pageshow", { persisted: true });
	assert.deepEqual(page.sent, [PAGE, PAGE]);
});

test("a pageshow that is not from the cache, or not trusted, checks nothing", async () => {
	const page = await load("<input type=password>");
	page.fire("pageshow", { persisted: false });
	page.fire("pageshow", { isTrusted: false, persisted: true });
	page.window.dispatchEvent(
		new page.window.PageTransitionEvent("pageshow", { persisted: true }),
	);
	await settle();
	assert.deepEqual(page.delivered, ["pageshow"]);
	assert.deepEqual(page.sent, [PAGE]);
});

test("nothing is sent while prerendering, and activation sends the check", async () => {
	const page = await load("<input id=field type=password>", {
		prerendering: true,
	});
	page.insert("<input type=password>");
	page.fire("focusin", { target: page.byId("field") });
	page.fire("prerenderingchange");
	await settle();
	assert.deepEqual(page.sent, []);

	page.state.prerendering = false;
	page.fire("prerenderingchange", { isTrusted: false });
	assert.deepEqual(page.sent, []);
	page.fire("prerenderingchange");
	assert.deepEqual(page.sent, [PAGE]);
});

test("a field that appears after activation is still seen", async () => {
	const page = await load("", { prerendering: true });
	page.state.prerendering = false;
	page.fire("prerenderingchange");
	page.insert("<input type=password>");
	await settle();
	assert.deepEqual(page.sent, [PAGE]);
});

test("a character key in the field, then Enter, reports typed", async () => {
	const page = await load(FORM);
	page.fire("keydown", { key: "a", target: page.byId("secret") });
	page.fire("keydown", { key: "Enter", target: page.byId("secret") });
	assert.deepEqual(page.sent, login("typed"));
});

test("a paste into the field, then a click, reports typed", async () => {
	const page = await load(FORM);
	page.fire("paste", { target: page.byId("secret") });
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("typed"));
});

test("a field the browser filled reports autofill", async () => {
	const page = await load(FORM);
	page.autofilled.add(page.byId("secret"));
	page.fire("keydown", { key: "Enter", target: page.byId("user") });
	assert.deepEqual(page.sent, login("autofill"));
});

test("a field that only holds something reports filled", async () => {
	const page = await load(FORM);
	page.byId("secret").value = "x";
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("filled"));
});

test("typed outranks autofill, which outranks filled", async () => {
	const page = await load(FORM);
	page.byId("secret").value = "x";
	page.autofilled.add(page.byId("secret"));
	page.fire("keydown", { key: "a", target: page.byId("secret") });
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("typed"));

	const other = await load(FORM);
	other.byId("secret").value = "x";
	other.autofilled.add(other.byId("secret"));
	other.fire("click", { target: other.byId("go") });
	assert.deepEqual(other.sent, login("autofill"));
});

// The keydown without a key is what Chrome's autofill sends to the field it
// fills; Enter and Tab are how a person leaves a field they did not type in.
test("a key that types nothing is not evidence of typing", async () => {
	const page = await load(FORM);
	const secret = page.byId("secret");
	for (const key of ["Tab", "Shift", "Backspace", "Unidentified", undefined]) {
		page.fire("keydown", { key, target: secret });
	}
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, [PAGE]);

	page.autofilled.add(secret);
	page.fire("keydown", { key: "Enter", target: secret });
	assert.deepEqual(page.sent, login("autofill"));
});

test("typing while the password is shown as text counts once it is hidden again", async () => {
	const page = await load(FORM);
	const secret = page.byId("secret");
	secret.type = "text";
	page.fire("keydown", { key: "a", target: secret });
	secret.type = "password";
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("typed"));
});

test("untrusted events cause nothing and leave no evidence", async () => {
	const page = await load(FORM);
	const { KeyboardEvent, Event } = page.window;
	const secret = page.byId("secret");
	const go = page.byId("go");

	secret.dispatchEvent(new KeyboardEvent("keydown", { key: "a" }));
	secret.dispatchEvent(new Event("paste"));
	page.fire("keydown", { isTrusted: false, key: "a", target: secret });
	page.fire("paste", { isTrusted: false, target: secret });
	page.fire("click", { target: go });
	assert.deepEqual(page.sent, [PAGE]);

	secret.value = "x";
	go.click();
	secret.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
	page.fire("click", { isTrusted: false, target: go });
	page.fire("keydown", { isTrusted: false, key: "Enter", target: secret });
	assert.deepEqual(page.delivered, ["keydown", "paste", "click", "keydown"]);
	assert.deepEqual(page.sent, [PAGE]);
});

test("a click with an empty password field is not a login", async () => {
	const page = await load(FORM);
	page.fire("click", { target: page.byId("go") });
	page.fire("keydown", { key: "Enter", target: page.byId("secret") });
	assert.deepEqual(page.sent, [PAGE]);
});

test("a password field in another form does not count", async () => {
	const page = await load(
		`${FORM}<form><input id=query><button id=search type=button></button></form>`,
	);
	page.byId("secret").value = "x";
	page.fire("click", { target: page.byId("search") });
	page.fire("keydown", { key: "Enter", target: page.byId("query") });
	assert.deepEqual(page.sent, [PAGE]);

	page.fire("keydown", { key: "Enter", target: page.byId("user") });
	assert.deepEqual(page.sent, login("filled"));
});

// A page with a filled login form must not report a login at the first click
// on a cookie banner.
test("outside any form, a field inside a form does not count", async () => {
	const page = await load(`${FORM}<div id=outside></div>`);
	page.byId("secret").value = "x";
	page.fire("click", { target: page.document.body });
	page.fire("click", { target: page.byId("outside") });
	page.fire("keydown", { key: "Enter", target: page.document.body });
	assert.deepEqual(page.sent, [PAGE]);

	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("filled"));
});

test("a field outside any form counts for any click or Enter outside any form", async () => {
	for (const trigger of [
		(page) => page.fire("click", { target: page.document.body }),
		(page) => page.fire("click", { target: page.byId("outside") }),
		(page) =>
			page.fire("keydown", { key: "Enter", target: page.byId("secret") }),
	]) {
		const page = await load(
			"<input id=secret type=password><div id=outside></div><form><button id=other type=button></button></form>",
		);
		page.byId("secret").value = "x";
		page.fire("click", { target: page.byId("other") });
		assert.deepEqual(page.sent, [PAGE]);

		trigger(page);
		assert.deepEqual(page.sent, login("filled"));
	}
});

test("a document reports one login", async () => {
	const page = await load(FORM);
	page.byId("secret").value = "x";
	page.fire("click", { target: page.byId("go") });
	page.fire("keydown", { key: "a", target: page.byId("secret") });
	page.fire("keydown", { key: "Enter", target: page.byId("secret") });
	page.fire("click", { target: page.byId("go") });
	assert.deepEqual(page.sent, login("filled"));
});

test("a submit event reaches no listener", async () => {
	const page = await load(FORM);
	const { form } = page.byId("secret");
	page.byId("secret").value = "x";
	form.dispatchEvent(
		new page.window.Event("submit", { bubbles: true, cancelable: true }),
	);
	assert.deepEqual(page.delivered, []);
	assert.deepEqual(page.sent, [PAGE]);
});

test("listeners are on window, capturing, and none waits for the page to load", async () => {
	const page = await load("");
	assert.deepEqual(
		page.listeners.map(({ target, capture }) => [target, capture]),
		page.listeners.map(() => [page.window, true]),
	);
	assert.deepEqual(page.listeners.map(({ type }) => type).toSorted(), LISTENED);
});

// banner.js and gmail.js share this script's world. A second run would also
// fail on any top-level let, const or class.
test("page.js adds no name to the world it shares with other content scripts", () => {
	const dom = new JSDOM("", { runScripts: "outside-only" });
	const names = Object.getOwnPropertyNames(dom.window);
	script.runInContext(dom.getInternalVMContext());
	script.runInContext(dom.getInternalVMContext());
	assert.deepEqual(Object.getOwnPropertyNames(dom.window), names);
});
