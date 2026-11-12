// The banner call of docs/PHISHING.md. This file may be evaluated twice in one
// frame, so its top level holds this one function declaration and nothing else.
// biome-ignore lint/correctness/noUnusedVariables: called by gmail.js and page.js
function riggsBanner(anchor, verdict) {
	// biome-ignore lint/suspicious/noRedundantUseStrict: a content script is a classic script
	"use strict";

	// The banners placed so far: by anchor, and all of them, so that a banner is
	// known by identity and never by markup a page could copy. Kept on the
	// global object, so that a second evaluation of this file still finds what
	// the first one placed, and under a symbol, so that the function stays the
	// only global name.
	const state = Symbol.for("riggsBanner");
	globalThis[state] ??= { byAnchor: new WeakMap(), banners: new WeakSet() };
	const { byAnchor, banners } = globalThis[state];

	// A document answers for the names of its elements and a form for the names
	// of its controls, ahead of their own properties: <img name="createElement">
	// makes `document.createElement` an image. So nothing is looked up on
	// `document`, on the anchor or on its parent; the prototypes are used.
	//
	// Two banners go first, whatever the level: the one an earlier call placed
	// for this anchor, and one that sits directly before it, which belonged to
	// an anchor that the page has since replaced with this one.
	byAnchor.get(anchor)?.remove();
	const before = Reflect.get(
		Element.prototype,
		"previousElementSibling",
		anchor,
	);
	if (banners.has(before)) before.remove();
	if (verdict.level === "none") return null;
	if (verdict.level !== "caution" && verdict.level !== "danger")
		throw new Error(`riggsBanner: unknown level ${verdict.level}`);
	const danger = verdict.level === "danger";

	// An inline !important declaration outranks every rule in a page's
	// stylesheets, and `all` covers every property except these two.
	const make = (tag, text, all, style) => {
		const node = Document.prototype.createElement.call(document, tag);
		node.textContent = text;
		const declarations = {
			all,
			direction: "ltr",
			"unicode-bidi": "isolate",
			...style,
		};
		for (const [property, value] of Object.entries(declarations))
			node.style.setProperty(property, value, "important");
		return node;
	};

	const banner = make("div", "", "initial", {
		display: "flex",
		"align-items": "flex-start",
		gap: "12px",
		margin: "8px 0",
		padding: "10px 12px",
		"border-left": `6px solid ${danger ? "#b3261e" : "#b06000"}`,
		background: danger ? "#fce8e6" : "#fef7e0",
		color: "#1f1f1f",
		font: "14px/1.4 system-ui, sans-serif",
		"overflow-wrap": "anywhere",
		"color-scheme": "light",
	});
	banner.setAttribute("role", "alert");
	const lines = make("div", "", "unset", {
		display: "block",
		flex: "1 1 0%",
		"min-width": "0",
	});
	lines.append(
		make(
			"strong",
			danger ? "Riggs: this may be phishing" : "Riggs: this looks unusual",
			"unset",
			{ display: "block", "font-weight": "700" },
		),
		...verdict.reasons.map((reason) =>
			make("div", reason.text, "unset", { display: "block" }),
		),
	);
	// `revert` keeps the browser's own button, focus ring included.
	const dismiss = make("button", "Dismiss", "revert", {
		flex: "none",
		cursor: "pointer",
	});
	dismiss.type = "button";
	// Callers rely on this: the banner has left the document by the time the
	// click reaches a listener on the banner itself, and the click is not stopped.
	dismiss.addEventListener("click", () => banner.remove());
	banner.append(lines, dismiss);

	const parent = Reflect.get(Node.prototype, "parentElement", anchor);
	Node.prototype.insertBefore.call(parent, banner, anchor);
	byAnchor.set(anchor, banner);
	banners.add(banner);
	return banner;
}
