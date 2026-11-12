import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { JSDOM } from "jsdom";

const addin = join(import.meta.dirname, "..", "addin");
const template = readFileSync(join(addin, "manifest.template.xml"), "utf8");

// What riggs-mailbridge serves from its assets directory, besides the
// template it fills in. Outlook can fetch nothing else.
const SERVED = [
	"taskpane.html",
	"taskpane.js",
	"icon-16.png",
	"icon-32.png",
	"icon-64.png",
	"icon-80.png",
	"icon-128.png",
];
const BASE = "https://localhost:{{PORT}}/{{TOKEN}}/";

const { DOMParser } = new JSDOM("").window;
const parse = (xml) => new DOMParser().parseFromString(xml, "application/xml");
const manifest = parse(template);
const elements = (document, name) =>
	Array.from(document.querySelectorAll("*")).filter(
		(element) => element.localName === name,
	);
const childNames = (element) =>
	Array.from(element.children, (child) => child.localName);

// Every address in the manifest, as written. Namespace names look like
// addresses but are only names.
const urls = (document) =>
	Array.from(document.querySelectorAll("*"))
		.flatMap((element) => Array.from(element.attributes))
		.filter(({ name }) => name !== "xmlns" && !name.startsWith("xmlns:"))
		.map(({ value }) => value)
		.filter((value) => value.includes("://"));

test("the template is well-formed XML", () => {
	assert.equal(manifest.querySelector("parsererror"), null);
	assert.equal(manifest.documentElement.localName, "OfficeApp");
	// The check can fail: a template cut short is reported.
	assert.notEqual(
		parse(template.replace("</OfficeApp>", "")).querySelector("parsererror"),
		null,
	);
});

test("PORT and TOKEN are the only placeholders", () => {
	assert.deepEqual(
		Array.from(new Set(template.match(/\{\{.*?\}\}/g))).toSorted(),
		["{{PORT}}", "{{TOKEN}}"],
	);
	assert.doesNotMatch(template.replace(/\{\{(PORT|TOKEN)\}\}/g, ""), /[{}]/);
});

test("every address is under the bridge's and names a file the bridge serves", () => {
	const addresses = urls(manifest);
	assert.equal(addresses.length, 8);
	for (const address of addresses) {
		assert.ok(address.startsWith(BASE), address);
		assert.ok(SERVED.includes(address.slice(BASE.length)), address);
	}
	// No address hides outside an attribute either.
	assert.equal(
		template.match(/[a-z]+:\/\/(?!schemas\.microsoft\.com\/|www\.w3\.org\/)/g)
			.length,
		addresses.length,
	);
});

test("addin/ holds exactly what the bridge expects, and each icon has the size in its name", () => {
	assert.deepEqual(
		readdirSync(addin).toSorted(),
		[...SERVED, "manifest.template.xml"].toSorted(),
	);
	for (const size of [16, 32, 64, 80, 128]) {
		const png = readFileSync(join(addin, `icon-${size}.png`));
		// PNG: an eight-byte signature, then the IHDR chunk with width and height.
		assert.equal(png.subarray(0, 8).toString("latin1"), "\x89PNG\r\n\x1a\n");
		assert.equal(png.subarray(12, 16).toString("latin1"), "IHDR");
		assert.deepEqual(
			[png.readUInt32BE(16), png.readUInt32BE(20)],
			[size, size],
		);
	}
});

test("the icons are the sizes Outlook asks for", () => {
	const file = (address) => address.slice(BASE.length);
	const value = (name) =>
		file(elements(manifest, name)[0].getAttribute("DefaultValue"));
	// IconUrl and HighResolutionIconUrl in the manifest reference: 64 and 128
	// pixels for a mail add-in. A button needs 16, 32 and 80.
	assert.equal(value("IconUrl"), "icon-64.png");
	assert.equal(value("HighResolutionIconUrl"), "icon-128.png");
	const [icon] = elements(manifest, "Icon");
	for (const image of icon.children) {
		const resource = manifest.querySelector(
			`[id="${image.getAttribute("resid")}"]`,
		);
		assert.equal(
			file(resource.getAttribute("DefaultValue")),
			`icon-${image.getAttribute("size")}.png`,
		);
	}
	assert.deepEqual(
		Array.from(icon.children, (image) => image.getAttribute("size")),
		["16", "32", "80"],
	);
});

test("every resource that is used is defined, within the documented limits", () => {
	// The Resources element in the manifest reference: an id is unique and at
	// most 32 characters; a short string at most 125, a long one 250.
	const [resources] = elements(manifest, "Resources");
	const defined = Array.from(resources.querySelectorAll("[id]"), (resource) =>
		resource.getAttribute("id"),
	);
	assert.equal(new Set(defined).size, defined.length);
	assert.deepEqual(
		defined.filter((id) => id.length > 32),
		[],
	);
	const used = Array.from(manifest.querySelectorAll("[resid]"), (element) =>
		element.getAttribute("resid"),
	);
	assert.deepEqual(
		used.filter((id) => !defined.includes(id)),
		[],
	);
	const lengths = (group) =>
		Array.from(
			elements(manifest, group)[0].children,
			(text) => text.getAttribute("DefaultValue").length,
		);
	assert.ok(lengths("ShortStrings").every((length) => length <= 125));
	assert.ok(lengths("LongStrings").every((length) => length <= 250));
});

test("the notification icon the pane names is an image in the manifest", () => {
	const [, icon] = readFileSync(join(addin, "taskpane.js"), "utf8").match(
		/const NOTIFICATION_ICON = "([^"]+)"/,
	);
	const [images] = elements(manifest, "Images");
	assert.ok(
		Array.from(images.children, (image) => image.getAttribute("id")).includes(
			icon,
		),
	);
});

test("the add-in is Riggs, reads the item only, needs Mailbox 1.5 and can be pinned", () => {
	const text = (name) => elements(manifest, name)[0].textContent;
	const value = (name) =>
		elements(manifest, name)[0].getAttribute("DefaultValue");
	// Fixed: Outlook would take a different Id for a different add-in.
	assert.equal(text("Id"), "72582e9d-f729-4689-91bf-0dac144aac75");
	assert.equal(text("ProviderName"), "Riggs");
	assert.equal(value("DisplayName"), "Riggs");
	assert.match(value("Description"), /^[^.]+\.$/);
	assert.equal(text("Permissions"), "ReadItem");
	assert.deepEqual(
		elements(manifest, "Set").map((set) => set.getAttribute("MinVersion")),
		["1.5", null],
	);
	assert.equal(
		elements(manifest, "Sets")[1].getAttribute("DefaultMinVersion"),
		"1.5",
	);
	assert.equal(
		elements(manifest, "ExtensionPoint")[0].getAttribute("xsi:type"),
		"MessageReadCommandSurface",
	);
	assert.equal(
		elements(manifest, "Action")[0].getAttribute("xsi:type"),
		"ShowTaskpane",
	);
	assert.equal(text("SupportsPinning"), "true");
});

// Microsoft's "How to find the proper order of manifest elements": a child in
// the wrong place makes the manifest invalid, and only Microsoft's online
// validator would say so. SupportsPinning after SourceLocation is from the
// page on pinnable task panes.
const ORDER = {
	OfficeApp: [
		"Id",
		"AlternateId",
		"Version",
		"ProviderName",
		"DefaultLocale",
		"DisplayName",
		"Description",
		"IconUrl",
		"HighResolutionIconUrl",
		"SupportUrl",
		"AppDomains",
		"Hosts",
		"Requirements",
		"FormSettings",
		"Permissions",
		"Rule",
		"DisableEntityHighlighting",
		"VersionOverrides",
	],
	DesktopSettings: ["SourceLocation", "RequestedHeight"],
	VersionOverrides: [
		"Description",
		"Requirements",
		"Hosts",
		"Resources",
		"VersionOverrides",
	],
	Group: ["Label", "Tooltip", "Control"],
	Control: ["Label", "Supertip", "Icon", "Action"],
	Supertip: ["Title", "Description"],
	Action: ["SourceLocation", "SupportsPinning"],
	Resources: ["Images", "Urls", "ShortStrings", "LongStrings"],
};

test("child elements are in the order Microsoft's schema requires", () => {
	for (const [parent, order] of Object.entries(ORDER)) {
		for (const element of elements(manifest, parent)) {
			const children = childNames(element);
			assert.deepEqual(
				children,
				order.filter((name) => children.includes(name)),
				parent,
			);
		}
	}
});

test("a filled-in template is a manifest whose addresses point at the bridge", () => {
	const token = "0123456789abcdef0123456789abcdef";
	const filled = parse(
		template.replaceAll("{{PORT}}", "41443").replaceAll("{{TOKEN}}", token),
	);
	assert.equal(filled.querySelector("parsererror"), null);
	for (const address of urls(filled)) {
		const { protocol, host, pathname, search, hash } = new URL(address);
		assert.deepEqual(
			{ protocol, host, search, hash },
			{ protocol: "https:", host: "localhost:41443", search: "", hash: "" },
		);
		const [, first, file, ...rest] = pathname.split("/");
		assert.deepEqual([first, rest], [token, []]);
		assert.ok(SERVED.includes(file), address);
		// The Resources element in the manifest reference: at most 2048 characters.
		assert.ok(address.length <= 2048);
	}
});
