import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { Script } from "node:vm";
import { JSDOM } from "jsdom";

const ext = join(import.meta.dirname, "..", "ext");
const html = readFileSync(join(ext, "interstitial.html"), "utf8");
const file = join(ext, "interstitial.js");
const script = new Script(readFileSync(file, "utf8"), { filename: file });
const settle = () => new Promise(setImmediate);

const BLOCKED = {
	host: "example.com",
	reasons: [
		{ cue: "c1", text: "one" },
		{ cue: "c2", text: "<b>two</b> & <a href=//example.org>three</a>" },
	],
};

// The page is parsed without running its script tag; the file text is then
// evaluated as the classic script it is, against stand-ins for chrome. Time
// does not pass: a timer the page sets waits in `timers` until a test runs it.
const open = async (blocked) => {
	const dom = new JSDOM(html, { runScripts: "outside-only" });
	const { document } = dom.window;
	const sent = [];
	const removed = [];
	const timers = [];
	dom.window.setTimeout = (callback, delay) => timers.push({ callback, delay });
	dom.window.chrome = {
		runtime: {
			sendMessage: async (message) => {
				sent.push(JSON.parse(JSON.stringify(message)));
				if (blocked instanceof Error) throw blocked;
				return message.t === "blocked" ? blocked : null;
			},
		},
		tabs: {
			getCurrent: async () => ({ id: 7 }),
			remove: async (tabId) => {
				removed.push(tabId);
			},
		},
	};
	script.runInContext(dom.getInternalVMContext());
	await settle();
	return {
		document,
		sent,
		removed,
		timers,
		byId: (id) => document.getElementById(id),
		shown: () =>
			Array.from(document.querySelectorAll("section, button"))
				.filter((element) => !element.hidden)
				.map((element) => element.id),
	};
};

test("a blocked page is shown with its host and reasons as plain text", async () => {
	const page = await open(BLOCKED);
	assert.deepEqual(page.sent, [{ t: "blocked" }]);
	assert.deepEqual(page.shown(), ["blocked", "close", "continue"]);
	assert.equal(page.document.title, "Riggs stopped this page");

	assert.equal(page.byId("host").textContent, "example.com");
	assert.deepEqual(
		Array.from(page.byId("reasons").children, (item) => [
			item.localName,
			item.textContent,
			item.childElementCount,
		]),
		BLOCKED.reasons.map((reason) => ["li", reason.text, 0]),
	);
	assert.equal(page.document.querySelector("a, b"), null);
});

test("without a blocked page it says so and offers only to close the tab", async () => {
	for (const reply of [null, new Error("Could not establish connection.")]) {
		const page = await open(reply);
		assert.deepEqual(page.sent, [{ t: "blocked" }]);
		assert.deepEqual(page.shown(), ["clear", "close"]);
		assert.equal(page.document.title, "Nothing is blocked in this tab");
		assert.equal(page.byId("host").textContent, "");
		assert.equal(page.byId("continue").disabled, true);
		assert.deepEqual(page.timers, []);
	}
});

test("Continue anyway is shown but cannot be clicked for its first two seconds", async () => {
	const page = await open(BLOCKED);
	const proceed = page.byId("continue");
	assert.deepEqual([proceed.hidden, proceed.disabled], [false, true]);
	assert.equal(page.byId("close").disabled, false);
	proceed.click();
	assert.deepEqual(page.sent, [{ t: "blocked" }]);

	assert.deepEqual(
		page.timers.map(({ delay }) => delay),
		[2000],
	);
	page.timers[0].callback();
	assert.deepEqual([proceed.hidden, proceed.disabled], [false, false]);
});

test("Continue anyway sends continue once and disables both controls", async () => {
	const page = await open(BLOCKED);
	page.timers[0].callback();
	page.byId("continue").click();
	page.byId("continue").click();
	page.byId("close").click();
	await settle();
	assert.deepEqual(page.sent, [{ t: "blocked" }, { t: "continue" }]);
	assert.equal(page.byId("continue").disabled, true);
	assert.equal(page.byId("close").disabled, true);
	assert.deepEqual(page.removed, []);
});

// Whether the page then opens is up to the worker, and the warning page is
// not told. The line has to be true either way.
test("after Continue one line stands where the reasons and the hint were", async () => {
	const page = await open(BLOCKED);
	const visible = () =>
		["host", "advice", "continued"].filter((id) => !page.byId(id).hidden);
	assert.deepEqual(
		Array.from(page.byId("advice").children, (element) => element.localName),
		["ul", "p"],
	);
	assert.equal(page.byId("reasons").parentElement, page.byId("advice"));
	assert.deepEqual(visible(), ["host", "advice"]);

	page.timers[0].callback();
	page.byId("continue").click();
	assert.deepEqual(visible(), ["host", "continued"]);
	assert.equal(
		page.byId("continued").textContent.replace(/\s+/g, " ").trim(),
		"You chose to continue. If the page does not open by itself, open it again yourself: Riggs will not stop this site again until the browser is restarted.",
	);
});

test("Close this tab removes the tab the page is in and sends nothing", async () => {
	const page = await open(BLOCKED);
	page.byId("close").click();
	await settle();
	assert.deepEqual(page.removed, [7]);
	assert.deepEqual(page.sent, [{ t: "blocked" }]);
});

test("the controls are two buttons, the safe one first and focused", async () => {
	for (const reply of [BLOCKED, null]) {
		const page = await open(reply);
		assert.deepEqual(
			Array.from(page.document.querySelectorAll("button, a, input"), (el) => [
				el.localName,
				el.id,
				el.textContent,
			]),
			[
				["button", "close", "Close this tab"],
				["button", "continue", "Continue anyway"],
			],
		);
		assert.equal(page.document.activeElement, page.byId("close"));
	}
});

test("the page needs no image, font, stylesheet or address outside itself", () => {
	assert.deepEqual(html.match(/https?:|\/\/|<img|<link|@import|url\(/gi), null);
	assert.deepEqual(html.match(/<script[^>]*>/g), [
		'<script src="interstitial.js">',
	]);
});
