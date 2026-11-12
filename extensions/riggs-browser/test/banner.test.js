import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { Script } from "node:vm";
import { JSDOM } from "jsdom";

const file = join(import.meta.dirname, "..", "ext", "banner.js");
const script = new Script(readFileSync(file, "utf8"), { filename: file });

// A content script is a classic script, so the file is evaluated, not imported.
const page = () => {
	const dom = new JSDOM(
		"<!doctype html><main><p id=before></p><p id=anchor></p></main>",
		{ runScripts: "outside-only" },
	);
	const evaluate = () => script.runInContext(dom.getInternalVMContext());
	evaluate();
	const { document } = dom.window;
	return {
		window: dom.window,
		document,
		anchor: document.getElementById("anchor"),
		evaluate,
		riggsBanner: (...args) => dom.window.riggsBanner(...args),
	};
};

const verdict = (level, ...texts) => ({
	level,
	reasons: texts.map((text, index) => ({ cue: `cue-${index}`, text })),
	show: true,
});

const texts = (banner) =>
	Array.from(banner.firstElementChild.children, (line) => line.textContent);

test("none renders nothing and returns null", () => {
	const { document, anchor, riggsBanner } = page();
	const before = document.documentElement.outerHTML;
	assert.equal(riggsBanner(anchor, verdict("none", "A reason")), null);
	assert.equal(document.documentElement.outerHTML, before);
});

for (const [level, heading] of [
	["caution", "Riggs: this looks unusual"],
	["danger", "Riggs: this may be phishing"],
]) {
	test(`${level} inserts one banner immediately before the anchor, outside it`, () => {
		const { document, anchor, riggsBanner } = page();
		const banner = riggsBanner(anchor, verdict(level, "First reason"));
		assert.equal(anchor.previousElementSibling, banner);
		assert.equal(banner.parentElement, anchor.parentElement);
		assert.equal(anchor.childElementCount, 0);
		assert.deepEqual(
			Array.from(document.querySelector("main").children, (child) => child.id),
			["before", "", "anchor"],
		);
		assert.deepEqual(texts(banner), [heading, "First reason"]);
	});
}

test("reasons render in order, as text and never as markup", () => {
	const { anchor, riggsBanner } = page();
	const markup = '<img src="x" onerror="alert(1)"><b>bold</b> &amp;';
	const banner = riggsBanner(
		anchor,
		verdict("danger", "First reason", markup, "Third reason"),
	);
	assert.deepEqual(texts(banner), [
		"Riggs: this may be phishing",
		"First reason",
		markup,
		"Third reason",
	]);
	assert.equal(banner.querySelector("img, b"), null);
});

test("a verdict without reasons shows the heading alone", () => {
	const { anchor, riggsBanner } = page();
	const banner = riggsBanner(anchor, verdict("caution"));
	assert.deepEqual(texts(banner), ["Riggs: this looks unusual"]);
});

test("a second call replaces the banner of the first", () => {
	const { document, anchor, riggsBanner } = page();
	const first = riggsBanner(anchor, verdict("caution", "Old reason"));
	const second = riggsBanner(anchor, verdict("danger", "New reason"));
	assert.notEqual(second, first);
	assert.equal(first.isConnected, false);
	assert.equal(anchor.previousElementSibling, second);
	assert.equal(document.querySelector("main").childElementCount, 3);
	assert.deepEqual(texts(second), [
		"Riggs: this may be phishing",
		"New reason",
	]);
});

test("a call with none removes the banner an earlier call placed", () => {
	const { document, anchor, riggsBanner } = page();
	const first = riggsBanner(anchor, verdict("danger", "A reason"));
	assert.equal(riggsBanner(anchor, verdict("none")), null);
	assert.equal(first.isConnected, false);
	assert.equal(document.querySelector("main").childElementCount, 2);
});

test("the earlier banner is removed even after the page moved it", () => {
	const { document, anchor, riggsBanner } = page();
	const first = riggsBanner(anchor, verdict("caution", "A reason"));
	document.body.append(first);
	const second = riggsBanner(anchor, verdict("caution", "A reason"));
	assert.equal(first.isConnected, false);
	assert.equal(anchor.previousElementSibling, second);
});

for (const level of ["danger", "none"]) {
	test(`a banner left directly before a replaced anchor is removed by a ${level} call for the new anchor`, () => {
		const { document, anchor, riggsBanner } = page();
		const left = riggsBanner(anchor, verdict("caution", "Old reason"));
		const replacement = anchor.cloneNode(true);
		anchor.replaceWith(replacement);
		assert.equal(replacement.previousElementSibling, left);
		const banner = riggsBanner(replacement, verdict(level, "New reason"));
		assert.equal(left.isConnected, false);
		assert.deepEqual(
			Array.from(document.querySelectorAll("[role=alert]")),
			level === "none" ? [] : [banner],
		);
	});
}

test("an element directly before the anchor is left alone, even a copy of a banner", () => {
	const { document, anchor, riggsBanner } = page();
	const other = document.getElementById("before");
	const copy = riggsBanner(anchor, verdict("danger", "A reason")).cloneNode(
		true,
	);
	other.before(copy);
	const plain = document.createElement("div");
	anchor.before(plain);
	const first = riggsBanner(other, verdict("danger", "A reason"));
	const second = riggsBanner(anchor, verdict("danger", "A reason"));
	assert.deepEqual(Array.from(document.querySelector("main").children), [
		copy,
		first,
		other,
		plain,
		second,
		anchor,
	]);
});

test("each anchor keeps its own banner", () => {
	const { document, anchor, riggsBanner } = page();
	const other = document.getElementById("before");
	const first = riggsBanner(other, verdict("caution", "One"));
	const second = riggsBanner(anchor, verdict("danger", "Two"));
	assert.equal(first.isConnected, true);
	assert.equal(other.previousElementSibling, first);
	assert.equal(anchor.previousElementSibling, second);
});

test("dismissing removes the banner and a later call shows one again", () => {
	const { document, anchor, riggsBanner } = page();
	const banner = riggsBanner(anchor, verdict("danger", "A reason"));
	const dismiss = banner.querySelector("button");
	assert.equal(dismiss.textContent, "Dismiss");
	dismiss.click();
	assert.equal(banner.isConnected, false);
	assert.equal(document.querySelector("main").childElementCount, 2);
	const again = riggsBanner(anchor, verdict("danger", "A reason"));
	assert.equal(anchor.previousElementSibling, again);
});

test("a click listener on the banner finds it detached after the dismiss control, and the click goes on", () => {
	const { document, anchor, riggsBanner } = page();
	const banner = riggsBanner(anchor, verdict("danger", "A reason"));
	const seen = [];
	for (const [where, target] of [
		["banner", banner],
		["document", document],
	]) {
		target.addEventListener("click", () =>
			seen.push(`${where}: ${banner.isConnected ? "in place" : "detached"}`),
		);
	}
	banner.querySelector("strong").click();
	banner.querySelector("button").click();
	assert.deepEqual(seen, [
		"banner: in place",
		"document: in place",
		"banner: detached",
		"document: detached",
	]);
});

test("the dismiss control is a real button that takes keyboard focus and never submits a form", () => {
	const { document, anchor, riggsBanner } = page();
	const form = document.createElement("form");
	anchor.replaceWith(form);
	form.append(anchor);
	let submitted = false;
	form.addEventListener("submit", () => {
		submitted = true;
	});
	const banner = riggsBanner(anchor, verdict("caution", "A reason"));
	const buttons = banner.querySelectorAll("button");
	assert.equal(buttons.length, 1);
	assert.equal(buttons[0].type, "button");
	assert.equal(buttons[0].tabIndex, 0);
	assert.equal(buttons[0].disabled, false);
	buttons[0].focus();
	assert.equal(document.activeElement, buttons[0]);
	buttons[0].click();
	assert.equal(submitted, false);
});

test("an unknown level throws and leaves no banner", () => {
	const { document, anchor, riggsBanner } = page();
	riggsBanner(anchor, verdict("danger", "A reason"));
	for (const level of ["safe", "constructor", "Danger", "", undefined]) {
		assert.throws(() => riggsBanner(anchor, verdict(level)), /unknown level/);
		assert.equal(document.querySelector("main").childElementCount, 2);
	}
});

test("an anchor without a parent element throws", () => {
	const { document, riggsBanner } = page();
	assert.throws(() =>
		riggsBanner(document.documentElement, verdict("danger", "A reason")),
	);
	assert.throws(() =>
		riggsBanner(document.createElement("p"), verdict("danger", "A reason")),
	);
	assert.equal(document.querySelector("[role=alert]"), null);
});

test("elements named like DOM properties cannot stop the banner", () => {
	const { document, anchor, riggsBanner } = page();
	// The anchor is a form inside a form, put where an earlier anchor and its
	// banner were. jsdom leaves out the named properties of documents and forms,
	// so this plants what a browser gives a page that names an image or a
	// control after each property the banner could use.
	const parent = document.createElement("form");
	const form = document.createElement("form");
	anchor.replaceWith(parent);
	parent.append(anchor);
	const left = riggsBanner(anchor, verdict("caution", "Old reason"));
	anchor.replaceWith(form);
	const named = document.createElement("input");
	for (const [object, names] of [
		[document, ["createElement", "createTextNode", "body", "append"]],
		[parent, ["insertBefore", "append", "prepend", "children", "firstChild"]],
		[form, ["parentElement", "parentNode", "before", "previousElementSibling"]],
	]) {
		for (const name of names) {
			Object.defineProperty(object, name, { value: named });
		}
	}
	const banner = riggsBanner(form, verdict("danger", "A reason"));
	assert.equal(left.isConnected, false);
	assert.equal(banner.nextElementSibling, form);
	assert.equal(banner.parentNode, parent);
	assert.equal(parent.querySelectorAll("[role=alert]").length, 1);
	assert.deepEqual(texts(banner), ["Riggs: this may be phishing", "A reason"]);
	banner.querySelector("button").click();
	assert.equal(banner.isConnected, false);
});

test("no level shows wording that calls anything safe", () => {
	const { anchor, riggsBanner } = page();
	for (const level of ["caution", "danger"]) {
		const banner = riggsBanner(anchor, verdict(level));
		assert.doesNotMatch(
			banner.textContent,
			/safe|secure|trusted|verified|legitimate|genuine|no problem/i,
		);
	}
});

test("every element styles itself inline, all of it !important, starting from a reset", () => {
	const { window, anchor, riggsBanner } = page();
	// A declaration the CSS parser refuses would silently fall back to the reset.
	const refused = [];
	const { setProperty } = window.CSSStyleDeclaration.prototype;
	window.CSSStyleDeclaration.prototype.setProperty = function (
		property,
		...rest
	) {
		setProperty.call(this, property, ...rest);
		if (this.getPropertyValue(property) === "") refused.push(property);
	};
	const banner = riggsBanner(anchor, verdict("danger", "A reason"));
	assert.deepEqual(refused, []);
	const elements = [banner, ...banner.querySelectorAll("*")];
	assert.equal(elements.length, 5);
	for (const element of elements) {
		const declarations = element
			.getAttribute("style")
			.split(";")
			.map((declaration) => declaration.trim())
			.filter(Boolean);
		assert.match(declarations[0], /^all: (initial|unset|revert) !important$/);
		assert.deepEqual(
			declarations.filter(
				(declaration) => !declaration.endsWith(" !important"),
			),
			[],
		);
		for (const property of ["direction", "unicode-bidi"]) {
			assert.equal(element.style.getPropertyPriority(property), "important");
		}
		assert.equal(element.getAttribute("class"), null);
		assert.equal(element.getAttribute("id"), null);
	}
	assert.equal(banner.style.getPropertyValue("all"), "initial");
});

test("the file can be evaluated twice in one window", () => {
	const { window, anchor, evaluate, riggsBanner } = page();
	const first = riggsBanner(anchor, verdict("caution", "A reason"));
	const firstFunction = window.riggsBanner;
	evaluate();
	assert.notEqual(window.riggsBanner, firstFunction);
	const second = riggsBanner(anchor, verdict("danger", "A reason"));
	assert.equal(first.isConnected, false);
	assert.equal(anchor.previousElementSibling, second);
});

test("the function is the only global name the file adds, also after a call", () => {
	const dom = new JSDOM("<!doctype html><main><p id=anchor></p></main>", {
		runScripts: "outside-only",
	});
	const before = new Set(Object.getOwnPropertyNames(dom.window));
	script.runInContext(dom.getInternalVMContext());
	dom.window.riggsBanner(
		dom.window.document.getElementById("anchor"),
		verdict("danger", "A reason"),
	);
	assert.deepEqual(
		Object.getOwnPropertyNames(dom.window).filter((name) => !before.has(name)),
		["riggsBanner"],
	);
	assert.equal(typeof dom.window.riggsBanner, "function");
});
