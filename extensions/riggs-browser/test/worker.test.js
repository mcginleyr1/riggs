import { strict as assert } from "node:assert";
import test from "node:test";

// The extension ID of docs/PHISHING.md, "Extension ID".
const ID = "lilgnipcebaofalbkdgonmidhpdfomen";
const extensionUrl = (path) => `chrome-extension://${ID}/${path}`;
const MAIL = "https://mail.google.com";
const BUDGET = 6 * 1024 * 1024;

// What mailLevel:<tabId> holds: the time each level was last seen in the tab.
const seenNow = (level) => ({ [level]: Date.now() });

const settled = () => new Promise((resolve) => setImmediate(resolve));
const jsonBytes = (value) =>
	new TextEncoder().encode(JSON.stringify(value)).length;

// The chrome.* surface the worker uses, behaving as its documentation says.
// `respond` plays the native host: it is given the request as the host would
// read it and returns the response, or throws the error Chrome reports.
// `changes` lists every call that is not a read, in order. `frames` is what
// getFrame finds by tab and frame, `documents` what it finds by document: null
// for one that has gone, and a document the test does not name is still shown.
const fakeChrome = ({ storage, frames, documents, respond }) => {
	const listeners = {};
	const event = (name) => ({
		addListener: (listener) => {
			listeners[name] = [...(listeners[name] ?? []), listener];
		},
	});
	const keysOf = (keys) => {
		const list = [keys].flat();
		assert.ok(list.every((key) => typeof key === "string"));
		return list;
	};
	const fake = {
		listeners,
		storage,
		requests: [],
		changes: [],
		badges: new Map(),
		errors: [],
	};
	fake.chrome = {
		runtime: {
			id: ID,
			getURL: extensionUrl,
			onMessage: event("message"),
			onStartup: event("startup"),
			sendNativeMessage: async (application, request) => {
				assert.equal(application, "com.riggs.browser");
				assert.equal(typeof request, "object");
				// Chrome serializes the request with JSON.stringify.
				const wire = JSON.parse(JSON.stringify(request));
				fake.requests.push(wire);
				fake.changes.push("native");
				return respond(wire);
			},
		},
		storage: {
			session: {
				get: async (keys) =>
					Object.fromEntries(
						keysOf(keys)
							.filter((key) => storage.has(key))
							.map((key) => [key, structuredClone(storage.get(key))]),
					),
				set: async (items) => {
					for (const [key, value] of Object.entries(items)) {
						assert.notEqual(value, undefined, key);
						storage.set(key, structuredClone(value));
						fake.changes.push(`set ${key}`);
					}
				},
				remove: async (keys) => {
					for (const key of keysOf(keys)) {
						storage.delete(key);
						fake.changes.push(`remove ${key}`);
					}
				},
			},
		},
		webNavigation: {
			onCreatedNavigationTarget: event("created"),
			onBeforeNavigate: event("beforeNavigate"),
			onCommitted: event("committed"),
			getFrame: async ({ tabId, frameId, documentId }) => {
				if (documentId !== undefined)
					return documentId in documents
						? documents[documentId]
						: { documentLifecycle: "active" };
				// The text of Chromium's web_navigation_api.cc.
				if (tabId === undefined || frameId === undefined)
					throw new Error(
						"Either documentId or both tabId and frameId must be specified.",
					);
				return frames[`${tabId}:${frameId}`] ?? null;
			},
		},
		// No goBack: Chrome lets it skip the blocked page, so the worker must
		// not use it.
		tabs: {
			onRemoved: event("removed"),
			update: async (tabId, properties) => {
				fake.changes.push(`update ${tabId} ${JSON.stringify(properties)}`);
			},
		},
		action: {
			// A tab's own text wins over the global one; null clears it.
			setBadgeText: async ({ tabId = "all", text }) => {
				fake.changes.push(`badge ${tabId}`);
				if (text === null || text === undefined) fake.badges.delete(tabId);
				else fake.badges.set(tabId, text);
			},
		},
	};
	return fake;
};

const badgeOn = (worker, tabId) =>
	worker.badges.has(tabId)
		? worker.badges.get(tabId)
		: (worker.badges.get("all") ?? "");

// Starts a new worker: the module is evaluated again against a new fake, the
// way Chrome starts the service worker again after stopping it.
let boots = 0;
const boot = async ({
	storage = new Map(),
	frames = {},
	documents = {},
	respond = () => {
		throw new Error("unexpected native call");
	},
} = {}) => {
	const worker = fakeChrome({ storage, frames, documents, respond });
	globalThis.chrome = worker.chrome;
	globalThis.reportError = (error) => worker.errors.push(error);
	boots += 1;
	await import(`../ext/background.js?boot=${boots}`);
	return worker;
};

// Delivers a message and returns the list its replies are collected in.
const dispatch = (worker, message, sender) => {
	const replies = [];
	const [listener] = worker.listeners.message;
	const kept = listener(message, sender, (reply) => replies.push(reply));
	assert.equal(kept, true, "the listener returns the literal true");
	return replies;
};

// Delivers a message, waits for the worker to finish and returns its reply.
const send = async (worker, message, sender) => {
	const replies = dispatch(worker, message, sender);
	await settled();
	assert.equal(replies.length, 1, "answered exactly once");
	assert.deepEqual(worker.errors, []);
	return replies[0];
};

const fire = async (worker, event, ...details) => {
	for (const listener of worker.listeners[event]) listener(...details);
	await settled();
	assert.deepEqual(worker.errors, []);
};

const web = (overrides = {}) => ({
	id: ID,
	tab: { id: 7 },
	frameId: 0,
	origin: "https://example.com",
	url: "https://example.com/login",
	documentId: "document-a",
	documentLifecycle: "active",
	...overrides,
});
const mailFrame = (overrides = {}) =>
	web({ origin: MAIL, url: `${MAIL}/mail/u/0/`, ...overrides });
const warningPage = (overrides = {}) =>
	web({
		origin: `chrome-extension://${ID}`,
		url: extensionUrl("interstitial.html"),
		...overrides,
	});
const popup = {
	id: ID,
	origin: `chrome-extension://${ID}`,
	url: extensionUrl("popup.html"),
};

const observation = (overrides = {}) => ({
	provider: "gmail",
	message_id: "m1",
	from_name: "Example Sender",
	from_addr: "sender@example.com",
	reply_to: null,
	to: ["recipient@example.com"],
	subject: "Example subject",
	body_text: "Example body.",
	links: [{ text: "Example link", href: "https://example.com/" }],
	attachments: ["example.txt"],
	...overrides,
});

const reasons = [{ cue: "example_cue", text: "Example reason." }];
const verdict = (level, show = true) => ({
	level,
	reasons: level === "none" ? [] : reasons,
	show,
});
const commit = (overrides = {}) => ({
	tabId: 5,
	frameId: 0,
	url: "https://example.org/landing",
	transitionType: "link",
	transitionQualifiers: [],
	...overrides,
});

// Sends each message and requires a null reply, no call to the native host
// and no change to anything.
const assertRefused = async (worker, cases) => {
	const before = Object.fromEntries(worker.storage);
	for (const [message, sender] of cases)
		assert.equal(await send(worker, message, sender), null);
	assert.deepEqual(worker.changes, []);
	assert.deepEqual(Object.fromEntries(worker.storage), before);
};

const BLOCKED_URL = "https://example.com/login?next=inbox#form";
const blockedState = () =>
	new Map([["blocked:7", { host: "example.com", reasons, url: BLOCKED_URL }]]);
const navigation = (url) => `update 7 ${JSON.stringify({ url })}`;
const TO_WARNING_PAGE = navigation(extensionUrl("interstitial.html"));

test("the worker registers one listener per event while it loads", async () => {
	const worker = await boot();
	assert.deepEqual(
		Object.entries(worker.listeners).map(([name, list]) => [name, list.length]),
		[
			["message", 1],
			["created", 1],
			["beforeNavigate", 1],
			["committed", 1],
			["removed", 1],
			["startup", 1],
		],
	);
});

test("a message with another extension's id is refused", async () => {
	const worker = await boot({ storage: blockedState() });
	const other = { id: "another-extension" };
	await assertRefused(worker, [
		[{ t: "mail", obs: observation() }, mailFrame(other)],
		[{ t: "adapter", provider: "gmail", ok: false }, mailFrame(other)],
		[{ t: "page" }, web(other)],
		[{ t: "login", evidence: "typed" }, web(other)],
		[{ t: "status" }, { ...popup, ...other }],
		[{ t: "blocked" }, warningPage(other)],
		[{ t: "continue" }, warningPage(other)],
		[{ t: "page" }, web({ id: undefined })],
	]);
});

test("mail and adapter are refused unless the top frame of the mail origin sends them for its own provider", async () => {
	const worker = await boot();
	const mail = { t: "mail", obs: observation() };
	const adapter = { t: "adapter", provider: "gmail", ok: false };
	await assertRefused(worker, [
		[mail, web()],
		[mail, mailFrame({ origin: "http://mail.google.com" })],
		[mail, mailFrame({ origin: "https://mail.google.com.example.net" })],
		[mail, mailFrame({ origin: "null" })],
		[mail, mailFrame({ frameId: 2 })],
		[mail, mailFrame({ documentLifecycle: "prerender" })],
		[mail, mailFrame({ tab: undefined })],
		[{ t: "mail", obs: observation({ provider: "outlook_web" }) }, mailFrame()],
		[{ t: "mail" }, mailFrame()],
		[adapter, web()],
		[adapter, mailFrame({ frameId: 2 })],
		[adapter, mailFrame({ documentLifecycle: "cached" })],
		[{ ...adapter, provider: "outlook_web" }, mailFrame()],
		[{ ...adapter, ok: "false" }, mailFrame()],
		[{ t: "adapter", provider: "gmail" }, mailFrame()],
	]);
});

test("a mail observation with a missing or mistyped field is refused", async () => {
	const worker = await boot({
		storage: new Map([["mailLevel:7", seenNow("caution")]]),
	});
	const malformed = [
		{ message_id: undefined },
		{ from_name: null },
		{ from_addr: 7 },
		{ reply_to: undefined },
		{ reply_to: 7 },
		{ to: "recipient@example.com" },
		{ to: ["recipient@example.com", 7] },
		{ subject: ["Example subject"] },
		{ body_text: { text: "Example body." } },
		{ links: [null] },
		{ links: [{ text: "Example link" }] },
		{ links: [{ text: 7, href: "https://example.com/" }] },
		{ links: { text: "Example link", href: "https://example.com/" } },
		{ attachments: "example.txt" },
		{ attachments: [null] },
	];
	await assertRefused(
		worker,
		malformed.map((fields) => [
			{ t: "mail", obs: observation(fields) },
			mailFrame(),
		]),
	);
});

test("page and login are refused from a document that is not active or has no tab", async () => {
	const worker = await boot();
	const senders = [
		web({ documentLifecycle: "prerender" }),
		web({ documentLifecycle: "cached" }),
		web({ documentLifecycle: "pending_deletion" }),
		web({ documentLifecycle: undefined }),
		web({ tab: undefined }),
	];
	await assertRefused(worker, [
		...senders.map((sender) => [{ t: "page" }, sender]),
		...senders.map((sender) => [{ t: "login", evidence: "typed" }, sender]),
		[{ t: "login", evidence: "pasted" }, web()],
		[{ t: "login" }, web()],
	]);
});

test("status is refused from anything but the popup", async () => {
	const worker = await boot();
	await assertRefused(worker, [
		[{ t: "status" }, web()],
		[{ t: "status" }, mailFrame()],
		[{ t: "status" }, warningPage()],
		[{ t: "status" }, { ...popup, url: `${popup.url}?tab=1` }],
		[{ t: "status" }, { ...popup, url: undefined }],
	]);
});

test("blocked and continue are refused from anything but the warning page in frame 0", async () => {
	const worker = await boot({ storage: blockedState() });
	const senders = [
		web(),
		mailFrame(),
		{ ...popup, tab: { id: 7 }, frameId: 0 },
		warningPage({ frameId: 1 }),
		warningPage({ tab: undefined }),
		warningPage({
			url: `${extensionUrl("interstitial.html")}?host=example.com`,
		}),
		warningPage({ url: `${extensionUrl("interstitial.html")}#continue` }),
		warningPage({ url: "https://example.com/interstitial.html" }),
	];
	await assertRefused(worker, [
		...senders.map((sender) => [{ t: "blocked" }, sender]),
		...senders.map((sender) => [{ t: "continue" }, sender]),
	]);
});

test("a message without a known t is refused", async () => {
	const worker = await boot({ storage: blockedState() });
	const messages = [{ t: "verdict" }, { t: 7 }, {}, null, "page", 7, ["page"]];
	await assertRefused(
		worker,
		messages.flatMap((message) => [
			[message, web()],
			[message, warningPage()],
			[message, popup],
		]),
	);
});

test("an https frame is judged by its own host, whatever the payload says", async () => {
	const worker = await boot({
		frames: { "7:0": { url: "https://example.org/embedding-page" } },
		respond: (request) =>
			request.CheckPage ? { Verdict: verdict("none") } : "Ok",
	});
	const frame = web({ frameId: 3, origin: "https://login.example.com:8443" });
	await send(worker, { t: "page", host: "example.net" }, frame);
	await send(
		worker,
		{ t: "login", evidence: "autofill", host: "example.net" },
		frame,
	);
	assert.deepEqual(worker.requests, [
		{ CheckPage: { host: "login.example.com", opened_from_mail: false } },
		{ LoginSeen: { host: "login.example.com", evidence: "autofill" } },
	]);
});

test("a frame with an opaque origin is judged by the host of the tab's top frame", async () => {
	const worker = await boot({
		frames: { "7:0": { url: "https://shop.example.org/cart?step=2" } },
		respond: (request) =>
			request.CheckPage ? { Verdict: verdict("none") } : "Ok",
	});
	const sandboxed = web({ frameId: 4, origin: "null", url: "about:srcdoc" });
	await send(worker, { t: "page" }, sandboxed);
	await send(worker, { t: "login", evidence: "filled" }, sandboxed);
	assert.deepEqual(worker.requests, [
		{ CheckPage: { host: "shop.example.org", opened_from_mail: false } },
		{ LoginSeen: { host: "shop.example.org", evidence: "filled" } },
	]);
});

test("filled is not reported from a frame on another host than its page's; typed and autofill are, and so is filled from the page's own hosts", async () => {
	const worker = await boot({
		frames: { "7:0": { url: "https://example.com/page" } },
		respond: () => "Ok",
	});
	const advert = (overrides) =>
		web({
			frameId: 3,
			origin: "https://ads.example.net",
			documentId: "document-3",
			...overrides,
		});
	const own = web({ frameId: 4, documentId: "document-4" });
	const login = (evidence) => ({ t: "login", evidence });
	const loginSeen = (host, evidence) => ({ LoginSeen: { host, evidence } });

	assert.equal(await send(worker, login("filled"), advert()), null);
	assert.deepEqual(worker.requests, []);

	await send(worker, login("typed"), advert());
	await send(worker, login("autofill"), advert());
	await send(worker, login("filled"), web());
	await send(worker, login("filled"), own);
	assert.deepEqual(worker.requests, [
		loginSeen("ads.example.net", "typed"),
		loginSeen("ads.example.net", "autofill"),
		loginSeen("example.com", "filled"),
		loginSeen("example.com", "filled"),
	]);
});

// A blob: URL as Chrome writes it: the origin of the page that made it, then
// an id.
const blobOf = (origin) =>
	`blob:${origin}/0f8fad5b-d9cb-469f-a165-70867728950e`;

test("a blob: URL has the host of the page that made it", async () => {
	// The top frame of a page that built itself as a blob and went there. This
	// fake hands its URL over. Chromium's web_navigation_api.cc reads as if
	// getFrame answered null for a blob: frame; then the frame has no host, as
	// with any top frame that cannot be read.
	const worker = await boot({
		frames: { "7:0": { url: blobOf("https://example.com:8443") } },
		respond: (request) =>
			request.CheckPage ? { Verdict: verdict("none") } : "Ok",
	});
	const sandboxed = web({ frameId: 4, origin: "null", url: "about:srcdoc" });
	await send(worker, { t: "page" }, sandboxed);
	await send(worker, { t: "login", evidence: "typed" }, sandboxed);
	assert.deepEqual(worker.requests, [
		{ CheckPage: { host: "example.com", opened_from_mail: false } },
		{ LoginSeen: { host: "example.com", evidence: "typed" } },
	]);

	await fire(worker, "created", {
		sourceTabId: 7,
		tabId: 9,
		url: blobOf("https://example.org"),
	});
	await fire(
		worker,
		"committed",
		commit({
			url: blobOf("http://example.net"),
			transitionType: "typed",
			transitionQualifiers: ["from_address_bar"],
		}),
	);
	assert.deepEqual(Object.fromEntries(worker.storage), {
		"entry:9": "example.org",
		"entry:5": "example.net",
		"topHost:5": "example.net",
	});
});

test("an opaque frame in a tab whose last commit was a blob: URL is checked with the host of the page that made it", async () => {
	const worker = await boot({
		respond: (request) =>
			request.CheckPage ? { Verdict: verdict("none") } : "Ok",
	});
	const sandboxed = web({ frameId: 4, origin: "null", url: "about:srcdoc" });
	const commitTo = (url) => commit({ tabId: 7, url });
	await fire(worker, "committed", commitTo(blobOf("https://example.com")));
	assert.equal(worker.storage.get("topHost:7"), "example.com");
	// The browser answers null for the top frame of a blob: page.
	await send(worker, { t: "page" }, sandboxed);
	assert.deepEqual(worker.requests, [
		{ CheckPage: { host: "example.com", opened_from_mail: false } },
	]);

	// What the browser says about the top frame wins over the stored host.
	worker.chrome.webNavigation.getFrame = async () => ({
		url: "https://example.org/",
		documentLifecycle: "active",
	});
	await send(worker, { t: "page" }, sandboxed);
	assert.equal(worker.requests.at(-1).CheckPage.host, "example.org");
	worker.chrome.webNavigation.getFrame = async () => null;

	// A commit to a URL with no host removes the key, and the frame has no host.
	await fire(worker, "committed", commitTo("about:blank"));
	assert.equal(worker.storage.has("topHost:7"), false);
	const calls = worker.requests.length;
	assert.equal(await send(worker, { t: "page" }, sandboxed), null);
	assert.equal(worker.requests.length, calls);

	await fire(worker, "committed", commitTo("https://example.net/"));
	assert.equal(worker.storage.get("topHost:7"), "example.net");
	await fire(worker, "removed", 7, { windowId: 1, isWindowClosing: false });
	assert.equal(worker.storage.has("topHost:7"), false);
});

test("a blob: URL made in an opaque origin, or by anything but a web page, has no host", async () => {
	const hostless = [
		blobOf("null"),
		blobOf("file://"),
		blobOf(`chrome-extension://${ID}`),
		blobOf("blob:https://example.com"),
		`blob:https://${"a".repeat(250)}.example/0f8fad5b`,
	];
	for (const url of hostless) {
		const worker = await boot({ frames: { "7:0": { url } } });
		await assertRefused(worker, [
			[{ t: "page" }, web({ frameId: 4, origin: "null" })],
		]);
		await fire(worker, "created", { sourceTabId: 7, tabId: 9, url });
		assert.deepEqual(Object.fromEntries(worker.storage), {}, url);
	}
});

test("an opaque frame in a tab whose top URL is not http or https has no host: no call, null", async () => {
	for (const top of [
		{ url: "file:///example.html" },
		{ url: "about:blank" },
		null,
	]) {
		const worker = await boot({ frames: { "7:0": top } });
		const sandboxed = web({ frameId: 4, origin: "null" });
		await assertRefused(worker, [
			[{ t: "page" }, sandboxed],
			[{ t: "login", evidence: "typed" }, sandboxed],
		]);
	}

	const unreadable = await boot();
	unreadable.chrome.webNavigation.getFrame = async () => {
		throw new Error("constructed failure");
	};
	await assertRefused(unreadable, [
		[{ t: "page" }, web({ frameId: 4, origin: "null" })],
	]);
});

test("a hostname longer than the daemon's 255 bytes is no host", async () => {
	const long = `${"a".repeat(250)}.example`;
	const worker = await boot({
		frames: { "7:0": { url: "https://example.org/" } },
	});
	await assertRefused(worker, [
		[{ t: "page" }, web({ frameId: 2, origin: `https://${long}` })],
	]);
	await fire(worker, "created", {
		sourceTabId: 7,
		tabId: 9,
		url: `https://${long}/`,
	});
	await fire(worker, "beforeNavigate", {
		tabId: 9,
		frameId: 0,
		url: "https://example.net/",
	});
	assert.deepEqual(Object.fromEntries(worker.storage), {
		"entry:9": "example.net",
	});
});

test("a page observation carries entry_host, opened_from_mail and mail_level from session state", async () => {
	const states = [
		[[], { host: "example.com", opened_from_mail: false }],
		[
			[
				["entry:7", "redirect.example.net"],
				["fromMail:7", { level: "caution" }],
			],
			{
				host: "example.com",
				entry_host: "redirect.example.net",
				opened_from_mail: true,
				mail_level: "caution",
			},
		],
		[
			[
				["entry:7", "example.com"],
				["fromMail:7", {}],
				["entry:8", "example.net"],
				["fromMail:8", { level: "danger" }],
			],
			{
				host: "example.com",
				entry_host: "example.com",
				opened_from_mail: true,
			},
		],
	];
	for (const [entries, expected] of states) {
		const worker = await boot({
			storage: new Map(entries),
			respond: () => ({ Verdict: verdict("none") }),
		});
		await send(worker, { t: "page" }, web());
		assert.deepEqual(worker.requests, [{ CheckPage: expected }]);
	}
});

test("a page verdict with show false is answered null and writes nothing", async () => {
	for (const level of ["none", "caution", "danger"]) {
		const worker = await boot({
			respond: () => ({ Verdict: verdict(level, false) }),
		});
		assert.equal(await send(worker, { t: "page" }, web()), null);
		assert.deepEqual(worker.changes, ["native"]);
	}
});

test("a shown none or caution page verdict is passed through unchanged", async () => {
	for (const level of ["none", "caution"]) {
		const worker = await boot({ respond: () => ({ Verdict: verdict(level) }) });
		assert.deepEqual(await send(worker, { t: "page" }, web()), verdict(level));
		assert.deepEqual(Object.fromEntries(worker.storage), {});
		assert.deepEqual(
			worker.changes.filter((change) => change.startsWith("update")),
			[],
		);
	}
});

test("a shown danger verdict stores the block with the page's URL, then sends the tab to the warning page, and answers null", async () => {
	const worker = await boot({
		storage: new Map([["allow:example.org", true]]),
		frames: { "7:0": { url: BLOCKED_URL } },
		respond: () => ({ Verdict: verdict("danger") }),
	});
	assert.equal(await send(worker, { t: "page" }, web()), null);
	assert.deepEqual(worker.storage.get("blocked:7"), {
		host: "example.com",
		reasons,
		url: BLOCKED_URL,
	});
	assert.deepEqual(worker.changes, [
		"native",
		"badge 7",
		"set blocked:7",
		TO_WARNING_PAGE,
	]);
});

test("a block asked for by a subframe keeps the URL of the page that shows it", async () => {
	const page = "https://example.org/article?id=1";
	const worker = await boot({
		frames: { "7:0": { url: page } },
		respond: () => ({ Verdict: verdict("danger") }),
	});
	const frame = web({ frameId: 3, origin: "https://login.example.com" });
	assert.equal(await send(worker, { t: "page" }, frame), null);
	assert.deepEqual(worker.storage.get("blocked:7"), {
		host: "login.example.com",
		reasons,
		url: page,
	});
});

test("a block keeps no URL it could not go back to, and blocks all the same", async () => {
	const longest = `https://example.com/${"a".repeat(8172)}`;
	const unusable = [
		{},
		{ "7:0": { url: "about:blank" } },
		{ "7:0": { url: "file:///example.html" } },
		{ "7:0": { url: blobOf("https://example.com") } },
		{ "7:0": { url: `${longest}a` } },
	];
	for (const frames of unusable) {
		const worker = await boot({
			frames,
			respond: () => ({ Verdict: verdict("danger") }),
		});
		assert.equal(await send(worker, { t: "page" }, web()), null);
		assert.deepEqual(worker.storage.get("blocked:7"), {
			host: "example.com",
			reasons,
		});
		assert.equal(worker.changes.at(-1), TO_WARNING_PAGE);
	}

	const atTheLimit = await boot({
		frames: { "7:0": { url: longest } },
		respond: () => ({ Verdict: verdict("danger") }),
	});
	await send(atTheLimit, { t: "page" }, web());
	assert.equal(atTheLimit.storage.get("blocked:7").url, longest);

	const unreadable = await boot({
		respond: () => ({ Verdict: verdict("danger") }),
	});
	unreadable.chrome.webNavigation.getFrame = async () => {
		throw new Error("constructed failure");
	};
	assert.equal(await send(unreadable, { t: "page" }, web()), null);
	assert.deepEqual(unreadable.storage.get("blocked:7"), {
		host: "example.com",
		reasons,
	});
	assert.equal(unreadable.changes.at(-1), TO_WARNING_PAGE);
});

test("a verdict that arrives after its document has gone blocks nothing, sets no badge and is answered null", async () => {
	const gone = [
		null,
		{ documentLifecycle: "cached" },
		{ documentLifecycle: "pending_deletion" },
	];
	const senders = [
		web(),
		web({ frameId: 3, origin: "https://login.example.com" }),
	];
	for (const now of gone)
		for (const sender of senders)
			for (const level of ["none", "caution", "danger"]) {
				const documents = {};
				const worker = await boot({
					documents,
					frames: { "7:0": { url: "https://example.net/elsewhere" } },
					respond: () => {
						documents["document-a"] = now;
						return { Verdict: verdict(level) };
					},
				});
				assert.equal(await send(worker, { t: "page" }, sender), null);
				assert.deepEqual(worker.changes, ["native"]);
			}
});

test("a navigation queued between the verdict and the block prevents the block, the badge and the stored entry", async () => {
	const worker = await boot({
		frames: { "7:0": { url: BLOCKED_URL } },
		respond: () => {
			// The commit that replaces the page arrives while the verdict does.
			const [committed] = worker.listeners.committed;
			committed(commit({ tabId: 7 }));
			return { Verdict: verdict("danger") };
		},
	});
	// Handling the commit is slow, the block is not: without the turn, the block
	// would be through before the commit is handled.
	const { get } = worker.chrome.storage.session;
	worker.chrome.storage.session.get = async (keys) => {
		if ([keys].flat().includes("mailTab:7")) await settled();
		return get(keys);
	};
	// The browser reports the document as replaced once that commit is handled.
	const { getFrame } = worker.chrome.webNavigation;
	worker.chrome.webNavigation.getFrame = async (details) =>
		details.documentId !== undefined && !worker.changes.includes("badge 7")
			? getFrame(details)
			: null;
	const replies = dispatch(worker, { t: "page" }, web());
	await settled();
	await settled();
	assert.deepEqual(replies, [null]);
	assert.equal(worker.storage.has("blocked:7"), false);
	assert.deepEqual(
		worker.changes.filter((change) => change.startsWith("update")),
		[],
	);
	assert.equal(badgeOn(worker, 7), "");
});

test("the URL kept for a block is the one read before the document was confirmed", async () => {
	// The tab moves on right after the browser has vouched for the document.
	const frames = { "7:0": { url: BLOCKED_URL } };
	const worker = await boot({
		frames,
		respond: () => ({ Verdict: verdict("danger") }),
	});
	const { getFrame } = worker.chrome.webNavigation;
	worker.chrome.webNavigation.getFrame = async (details) => {
		const frame = await getFrame(details);
		if (details.documentId !== undefined)
			frames["7:0"] = { url: "https://example.net/elsewhere" };
		return frame;
	};
	assert.equal(await send(worker, { t: "page" }, web()), null);
	assert.equal(worker.storage.get("blocked:7").url, BLOCKED_URL);
});

test("the browser's word on a document is taken by its id, whatever its tab shows now", async () => {
	const worker = await boot({
		documents: { "document-b": null },
		frames: { "7:0": { url: BLOCKED_URL } },
		respond: () => ({ Verdict: verdict("danger") }),
	});
	const shown = web({ frameId: 3, origin: "https://login.example.com" });
	const replaced = { ...shown, documentId: "document-b" };
	assert.equal(await send(worker, { t: "page" }, replaced), null);
	assert.deepEqual(worker.changes, ["native"]);
	assert.equal(await send(worker, { t: "page" }, shown), null);
	assert.equal(worker.changes.at(-1), TO_WARNING_PAGE);
});

test("a document the browser cannot answer for counts as shown, so that its verdict is not lost", async () => {
	// webNavigation does not see a document with a blob: URL, alive or not.
	const blob = web({
		url: "blob:https://example.com/0f8fad5b-d9cb-469f-a165-70867728950e",
	});
	const unseen = await boot({
		documents: { "document-a": null },
		respond: () => ({ Verdict: verdict("caution") }),
	});
	assert.deepEqual(await send(unseen, { t: "page" }, blob), verdict("caution"));
	assert.equal(badgeOn(unseen, 7), "!");

	const failing = await boot({
		respond: () => ({ Verdict: verdict("caution") }),
	});
	failing.chrome.webNavigation.getFrame = async () => {
		throw new Error("constructed failure");
	};
	assert.deepEqual(
		await send(failing, { t: "page" }, web()),
		verdict("caution"),
	);

	const withoutId = await boot({
		respond: () => ({ Verdict: verdict("caution") }),
	});
	const sender = web({ documentId: undefined });
	assert.deepEqual(
		await send(withoutId, { t: "page" }, sender),
		verdict("caution"),
	);
});

test("a shown danger verdict for a host the person allowed is passed through instead", async () => {
	const worker = await boot({
		storage: new Map([["allow:example.com", true]]),
		respond: () => ({ Verdict: verdict("danger") }),
	});
	assert.deepEqual(await send(worker, { t: "page" }, web()), verdict("danger"));
	assert.deepEqual(worker.changes, ["native", "badge 7"]);
	assert.equal(worker.storage.has("blocked:7"), false);
});

test("anything but a verdict is no answer to a page check", async () => {
	const responses = [
		"Ok",
		{ Status: { mode: "warn", logins: 1 } },
		{ Error: "daemon unreachable" },
		{ Error: "malformed request" },
		{ Verdict: { level: "severe", reasons, show: true } },
		{ Verdict: null },
		null,
	];
	for (const response of responses) {
		const worker = await boot({ respond: () => response });
		assert.equal(await send(worker, { t: "page" }, web()), null);
		assert.deepEqual(worker.changes, ["native"]);
	}
	const worker = await boot({
		respond: () => {
			throw new Error("Native host has exited.");
		},
	});
	assert.equal(await send(worker, { t: "page" }, web()), null);
	assert.deepEqual(worker.changes, ["native"]);
});

test("a login is reported with the frame's host and answered null whatever the host says", async () => {
	for (const response of ["Ok", { Error: "daemon unreachable" }]) {
		const worker = await boot({ respond: () => response });
		const message = { t: "login", evidence: "typed" };
		assert.equal(await send(worker, message, web()), null);
		assert.deepEqual(worker.requests, [
			{ LoginSeen: { host: "example.com", evidence: "typed" } },
		]);
		assert.deepEqual(worker.changes, ["native"]);
	}
});

test("blocked tells the warning page the host and the reasons of its own tab, never the URL", async () => {
	const worker = await boot({ storage: blockedState() });
	assert.deepEqual(await send(worker, { t: "blocked" }, warningPage()), {
		host: "example.com",
		reasons,
	});
	const elsewhere = warningPage({ tab: { id: 8 } });
	assert.equal(await send(worker, { t: "blocked" }, elsewhere), null);
	assert.deepEqual(worker.changes, []);
});

test("continue writes the allow, removes the block and sends the tab to the stored URL", async () => {
	const other = { host: "example.org", reasons, url: "https://example.org/" };
	const worker = await boot({
		storage: new Map([...blockedState(), ["blocked:8", other]]),
	});
	const message = {
		t: "continue",
		host: "example.org",
		tabId: 8,
		url: other.url,
	};
	assert.equal(await send(worker, message, warningPage()), null);
	assert.deepEqual(worker.changes, [
		"set allow:example.com",
		"remove blocked:7",
		navigation(BLOCKED_URL),
	]);
	assert.deepEqual(Object.fromEntries(worker.storage), {
		"allow:example.com": true,
		"blocked:8": other,
	});
});

test("continue without a stored http or https URL navigates nowhere but still allows and clears", async () => {
	const stored = [
		{},
		{ url: "file:///example.html" },
		{ url: "chrome://settings/" },
		{ url: "javascript:void(0)" },
		{ url: "about:blank" },
		{ url: "example.com/login" },
		{ url: "" },
		{ url: blobOf("https://example.com") },
	];
	for (const fields of stored) {
		const block = { host: "example.com", reasons, ...fields };
		const worker = await boot({ storage: new Map([["blocked:7", block]]) });
		assert.equal(await send(worker, { t: "continue" }, warningPage()), null);
		assert.deepEqual(worker.changes, [
			"set allow:example.com",
			"remove blocked:7",
		]);
		assert.deepEqual(Object.fromEntries(worker.storage), {
			"allow:example.com": true,
		});
	}
});

test("continue without a block does nothing, also when it is sent twice at once", async () => {
	const worker = await boot({ storage: blockedState() });
	const first = dispatch(worker, { t: "continue" }, warningPage());
	const second = dispatch(worker, { t: "continue" }, warningPage());
	await settled();
	assert.deepEqual([first, second], [[null], [null]]);
	assert.equal(await send(worker, { t: "continue" }, warningPage()), null);
	assert.deepEqual(worker.changes, [
		"set allow:example.com",
		"remove blocked:7",
		navigation(BLOCKED_URL),
	]);
});

test("a navigation that fails at continue is reported without Chrome's text, which can quote the URL", async () => {
	const worker = await boot({ storage: blockedState() });
	// Chromium's kInvalidUrlError, with the URL in the place of its asterisk.
	worker.chrome.tabs.update = async (_, { url }) => {
		throw new Error(`Invalid url: "${url}".`);
	};
	const replies = dispatch(worker, { t: "continue" }, warningPage());
	await settled();
	assert.deepEqual(replies, [null]);
	assert.deepEqual(
		worker.errors.map((error) => error.message),
		["the blocked page could not be opened again"],
	);
});

test("a tab opened from a mail tab is marked with the mail tab's level", async () => {
	const cases = [
		[[["mailLevel:3", seenNow("danger")]], { level: "danger" }],
		[[["mailLevel:3", seenNow("none")]], { level: "none" }],
		[
			[["mailLevel:3", { ...seenNow("caution"), none: Date.now() }]],
			{ level: "caution" },
		],
		[[], {}],
	];
	for (const [entries, mark] of cases) {
		const worker = await boot({
			storage: new Map(entries),
			frames: { "3:0": { url: `${MAIL}/mail/u/0/#inbox` } },
		});
		await fire(worker, "created", {
			sourceTabId: 3,
			tabId: 9,
			url: "https://redirect.example.net/r?to=example.org",
		});
		assert.deepEqual(Object.fromEntries(worker.storage), {
			...Object.fromEntries(entries),
			"entry:9": "redirect.example.net",
			"fromMail:9": mark,
		});
	}
});

test("a tab opened from a marked tab inherits the mark", async () => {
	const worker = await boot({
		storage: new Map([
			["fromMail:9", { level: "caution" }],
			["mailLevel:9", seenNow("danger")],
		]),
		frames: { "9:0": { url: "https://example.org/landing" } },
	});
	await fire(worker, "created", {
		sourceTabId: 9,
		tabId: 12,
		url: "https://example.com/login",
	});
	assert.deepEqual(worker.storage.get("fromMail:12"), { level: "caution" });
	assert.equal(worker.storage.get("entry:12"), "example.com");
});

test("a tab opened from an unmarked tab that is not on mail is not marked", async () => {
	for (const frames of [{ "9:0": { url: "https://example.org/" } }, {}]) {
		const worker = await boot({ frames });
		await fire(worker, "created", {
			sourceTabId: 9,
			tabId: 12,
			url: "https://example.com/login",
		});
		assert.deepEqual(Object.fromEntries(worker.storage), {
			"entry:12": "example.com",
		});
	}
});

test("the first top-level navigation of a tab writes its entry host, later ones do not", async () => {
	const worker = await boot();
	const navigate = (details) =>
		fire(worker, "beforeNavigate", { tabId: 5, frameId: 0, ...details });
	await navigate({ url: "about:blank" });
	await navigate({ frameId: 2, url: "https://frame.example.net/" });
	assert.deepEqual(Object.fromEntries(worker.storage), {});
	await navigate({ url: "https://example.com/start" });
	await navigate({ url: "https://example.org/next" });
	assert.deepEqual(Object.fromEntries(worker.storage), {
		"entry:5": "example.com",
	});
});

test("a link followed in the tab that shows mail marks the tab", async () => {
	const cases = [
		[[["mailLevel:5", seenNow("caution")]], { level: "caution" }],
		[[], {}],
	];
	for (const [entries, mark] of cases) {
		const worker = await boot({
			storage: new Map([
				["mailTab:5", true],
				["entry:5", "mail.google.com"],
				...entries,
			]),
		});
		await fire(worker, "committed", commit());
		assert.deepEqual(Object.fromEntries(worker.storage), {
			...Object.fromEntries(entries),
			"entry:5": "example.org",
			"fromMail:5": mark,
			"topHost:5": "example.org",
		});
	}
});

test("leaving mail by the address bar, by something other than a link, or by Back does not mark the tab", async () => {
	const leaving = [
		{ transitionType: "typed", transitionQualifiers: ["from_address_bar"] },
		{ transitionQualifiers: ["from_address_bar"] },
		{ transitionType: "auto_bookmark" },
		{ transitionType: "form_submit" },
		{ transitionType: "reload" },
		{ transitionQualifiers: ["forward_back"] },
		{ transitionQualifiers: ["server_redirect", "forward_back"] },
	];
	for (const how of leaving) {
		const worker = await boot({
			storage: new Map([
				["mailTab:5", true],
				["mailLevel:5", seenNow("danger")],
			]),
		});
		await fire(worker, "committed", commit(how));
		assert.equal(worker.storage.has("fromMail:5"), false, JSON.stringify(how));
		assert.equal(worker.storage.has("mailTab:5"), false);
	}
});

test("a commit marks the tab only when the page it leaves was mail and the new one is not", async () => {
	const unmarked = [
		[[], commit()],
		[[["mailTab:5", true]], commit({ url: `${MAIL}/mail/u/0/#inbox` })],
		[[["mailTab:5", true]], commit({ frameId: 3 })],
		[[["mailTab:6", true]], commit()],
	];
	for (const [entries, details] of unmarked) {
		const worker = await boot({ storage: new Map(entries) });
		await fire(worker, "committed", details);
		assert.equal(worker.storage.has("fromMail:5"), false);
	}
});

test("a commit records whether the tab now shows mail", async () => {
	const worker = await boot();
	await fire(worker, "committed", commit({ url: `${MAIL}/mail/u/0/` }));
	const onMail = { "mailTab:5": true, "topHost:5": "mail.google.com" };
	assert.deepEqual(Object.fromEntries(worker.storage), onMail);
	await fire(worker, "committed", commit({ frameId: 2 }));
	assert.deepEqual(Object.fromEntries(worker.storage), onMail);
	await fire(worker, "committed", commit({ transitionType: "reload" }));
	assert.deepEqual(Object.fromEntries(worker.storage), {
		"topHost:5": "example.org",
	});
});

test("a navigation from the address bar clears the mark and rewrites the entry host", async () => {
	const marked = () =>
		new Map([
			["fromMail:5", { level: "danger" }],
			["entry:5", "redirect.example.net"],
		]);
	const typed = {
		transitionType: "typed",
		transitionQualifiers: ["from_address_bar"],
	};

	const worker = await boot({ storage: marked() });
	await fire(worker, "committed", commit(typed));
	assert.deepEqual(Object.fromEntries(worker.storage), {
		"entry:5": "example.org",
		"topHost:5": "example.org",
	});

	const hostless = await boot({ storage: marked() });
	await fire(hostless, "committed", commit({ ...typed, url: "about:blank" }));
	assert.deepEqual(Object.fromEntries(hostless.storage), {});
});

test("links, redirects, reloads and Back keep the mark and the entry host", async () => {
	const kept = [
		{},
		{ transitionQualifiers: ["server_redirect"] },
		{ transitionQualifiers: ["client_redirect"] },
		{ transitionType: "reload" },
		{ transitionQualifiers: ["forward_back"] },
	];
	for (const how of kept) {
		const worker = await boot({
			storage: new Map([
				["fromMail:5", { level: "danger" }],
				["entry:5", "redirect.example.net"],
			]),
		});
		await fire(worker, "committed", commit(how));
		assert.deepEqual(Object.fromEntries(worker.storage), {
			"fromMail:5": { level: "danger" },
			"entry:5": "redirect.example.net",
			"topHost:5": "example.org",
		});
	}
});

test("closing a tab removes its six keys and nothing else", async () => {
	const others = [
		["entry:50", "example.net"],
		["fromMail:50", {}],
		["mailTab:50", true],
		["mailLevel:50", seenNow("none")],
		["blocked:50", { host: "example.net", reasons }],
		["topHost:50", "example.net"],
		["allow:example.com", true],
		["allow:5", true],
		["adapter:gmail", true],
	];
	const worker = await boot({
		storage: new Map([
			["entry:5", "example.com"],
			["fromMail:5", { level: "caution" }],
			["mailTab:5", true],
			["mailLevel:5", seenNow("caution")],
			["blocked:5", { host: "example.com", reasons }],
			["topHost:5", "example.com"],
			...others,
		]),
	});
	await fire(worker, "removed", 5, { windowId: 1, isWindowClosing: false });
	assert.deepEqual(
		Object.fromEntries(worker.storage),
		Object.fromEntries(others),
	);
});

test("a worker that starts again honours the mark an earlier one wrote", async () => {
	const storage = new Map([["mailLevel:3", seenNow("danger")]]);
	const first = await boot({
		storage,
		frames: { "3:0": { url: `${MAIL}/mail/u/0/` } },
	});
	await fire(first, "created", {
		sourceTabId: 3,
		tabId: 9,
		url: "https://redirect.example.net/r",
	});

	const second = await boot({
		storage,
		respond: () => ({ Verdict: verdict("none") }),
	});
	await send(second, { t: "page" }, web({ tab: { id: 9 } }));
	assert.deepEqual(second.requests, [
		{
			CheckPage: {
				host: "example.com",
				entry_host: "redirect.example.net",
				opened_from_mail: true,
				mail_level: "danger",
			},
		},
	]);
	assert.deepEqual(first.requests, []);
});

test("a page check sees what the navigation events that arrived just before it wrote", async () => {
	const worker = await boot({
		storage: new Map([["mailLevel:3", seenNow("caution")]]),
		frames: { "3:0": { url: `${MAIL}/mail/u/0/` } },
		respond: () => ({ Verdict: verdict("none") }),
	});
	// Not awaited: a worker woken by a click gets all of these at once.
	const [created] = worker.listeners.created;
	const [beforeNavigate] = worker.listeners.beforeNavigate;
	const [committed] = worker.listeners.committed;
	const url = "https://example.org/login";
	created({ sourceTabId: 3, tabId: 9, url: "https://redirect.example.net/r" });
	beforeNavigate({
		tabId: 9,
		frameId: 0,
		url: "https://redirect.example.net/r",
	});
	committed(
		commit({ tabId: 9, url, transitionQualifiers: ["server_redirect"] }),
	);
	const sender = web({ tab: { id: 9 }, origin: "https://example.org", url });
	await send(worker, { t: "page" }, sender);
	assert.deepEqual(worker.requests, [
		{
			CheckPage: {
				host: "example.org",
				entry_host: "redirect.example.net",
				opened_from_mail: true,
				mail_level: "caution",
			},
		},
	]);
});

const checkMail = async (obs) => {
	const worker = await boot({
		respond: () => ({ Verdict: verdict("none", false) }),
	});
	await send(worker, { t: "mail", obs }, mailFrame());
	assert.equal(worker.requests.length, 1);
	return worker.requests[0].CheckMail;
};

test("a mail observation within every limit is sent as it came, with truncated false", async () => {
	const sent = await checkMail(observation());
	assert.deepEqual(sent, { ...observation(), truncated: false });
	assert.deepEqual(Object.keys(sent), [
		...Object.keys(observation()),
		"truncated",
	]);

	const link = { text: "Example link", href: "https://example.com/" };
	const atEveryLimit = observation({
		message_id: "a".repeat(4096),
		from_name: `${"€".repeat(1365)}a`,
		from_addr: "a".repeat(4096),
		reply_to: "a".repeat(4096),
		to: ["a".repeat(4096), ...Array(499).fill("recipient@example.com")],
		subject: "é".repeat(2048),
		body_text: "😀".repeat(16384),
		links: [
			{ text: "a".repeat(4096), href: "a".repeat(8192) },
			...Array(499).fill(link),
		],
		attachments: ["a".repeat(4096), ...Array(99).fill("example.txt")],
	});
	assert.deepEqual(await checkMail(atEveryLimit), {
		...atEveryLimit,
		truncated: false,
	});
});

test("a string over its limit is cut to the longest prefix that fits in UTF-8, between code points", async () => {
	const link = { text: "Example link", href: "https://example.com/" };
	const cuts = [
		[{ message_id: "a".repeat(4097) }, { message_id: "a".repeat(4096) }],
		[{ from_name: "€".repeat(1366) }, { from_name: "€".repeat(1365) }],
		[{ from_addr: `${"a".repeat(4094)}😀` }, { from_addr: "a".repeat(4094) }],
		[{ reply_to: `${"a".repeat(4095)}é` }, { reply_to: "a".repeat(4095) }],
		[{ to: ["€".repeat(2000)] }, { to: ["€".repeat(1365)] }],
		[{ subject: `${"a".repeat(4093)}😀😀` }, { subject: "a".repeat(4093) }],
		[{ body_text: `${"é".repeat(32767)}😀` }, { body_text: "é".repeat(32767) }],
		[
			{ links: [{ ...link, text: "é".repeat(2049) }] },
			{ links: [{ ...link, text: "é".repeat(2048) }] },
		],
		[
			{ links: [{ ...link, href: `${"a".repeat(8191)}é` }] },
			{ links: [{ ...link, href: "a".repeat(8191) }] },
		],
		[
			{ attachments: [`${"a".repeat(4096)}.txt`] },
			{ attachments: ["a".repeat(4096)] },
		],
	];
	for (const [over, cut] of cuts)
		assert.deepEqual(await checkMail(observation(over)), {
			...observation(cut),
			truncated: true,
		});
});

test("a list over its limit keeps its first entries", async () => {
	const numbered = (count, entry) =>
		Array.from({ length: count }, (_, n) => entry(n));
	const recipient = (n) => `recipient${n}@example.com`;
	const link = (n) => ({ text: `Link ${n}`, href: `https://example.com/${n}` });
	const attachment = (n) => `example${n}.txt`;
	const cuts = [
		[{ to: numbered(501, recipient) }, { to: numbered(500, recipient) }],
		[{ links: numbered(501, link) }, { links: numbered(500, link) }],
		[
			{ attachments: numbered(101, attachment) },
			{ attachments: numbered(100, attachment) },
		],
	];
	for (const [over, cut] of cuts)
		assert.deepEqual(await checkMail(observation(over)), {
			...observation(cut),
			truncated: true,
		});
});

test("only the contract's fields are sent, and an adapter's truncated is overwritten", async () => {
	const sent = await checkMail(
		observation({
			truncated: true,
			raw_html: "<p>Example body.</p>",
			links: [{ text: "Example link", href: "https://example.com/", rel: "x" }],
		}),
	);
	assert.deepEqual(sent, { ...observation(), truncated: false });
});

// Written as numbers: U+FEFF is invisible in a source file, U+FFFD looks like
// damage, and a lone surrogate has no UTF-8 form at all.
const BYTE_ORDER_MARK = String.fromCharCode(0xfeff);
const REPLACEMENT = String.fromCharCode(0xfffd);
const LONE_SURROGATES = [
	String.fromCharCode(0xd83d),
	String.fromCharCode(0xde00),
];
// A lone surrogate as JSON.stringify writes it: \ud800 to \udfff.
const SURROGATE_ESCAPE = /\\ud[89a-f]/i;

test("a lone surrogate, high or low, is sent as U+FFFD in every string and is not a truncation", async () => {
	const withMark = (mark) =>
		observation({
			message_id: `m${mark}1`,
			from_name: `Example ${mark} Sender`,
			from_addr: `sender${mark}@example.com`,
			reply_to: `reply${mark}@example.com`,
			to: [`recipient${mark}@example.com`],
			subject: `Example ${mark}subject`,
			body_text: `Example ${mark} body.${mark}`,
			links: [
				{ text: `Example${mark}link`, href: `https://example.com/${mark}` },
			],
			attachments: [`example${mark}.txt`],
		});
	for (const lone of LONE_SURROGATES) {
		assert.match(JSON.stringify(withMark(lone)), SURROGATE_ESCAPE);
		const sent = await checkMail(withMark(lone));
		assert.deepEqual(sent, { ...withMark(REPLACEMENT), truncated: false });
		assert.doesNotMatch(JSON.stringify(sent), SURROGATE_ESCAPE);
	}
});

test("a cut between the two halves of a surrogate pair drops the whole pair", async () => {
	const cuts = [
		[{ subject: `${"a".repeat(4093)}😀b` }, { subject: "a".repeat(4093) }],
		[{ subject: `${"a".repeat(4095)}😀b` }, { subject: "a".repeat(4095) }],
		[
			{ body_text: `${"é".repeat(32767)}😀b` },
			{ body_text: "é".repeat(32767) },
		],
	];
	for (const [over, cut] of cuts) {
		const sent = await checkMail(observation(over));
		assert.deepEqual(sent, { ...observation(cut), truncated: true });
		assert.doesNotMatch(JSON.stringify(sent), SURROGATE_ESCAPE);
	}
});

test("a leading U+FEFF is kept", async () => {
	const body_text = `${BYTE_ORDER_MARK}Example body.`;
	assert.deepEqual(await checkMail(observation({ body_text })), {
		...observation({ body_text }),
		truncated: false,
	});
});

const FILLER = "Az09+/=_-".repeat(40);

test("a run of more than 256 filler characters in the body is replaced by one space, and that is a truncation", async () => {
	assert.equal(FILLER.length, 360);
	const cases = [
		[`${"A".repeat(300)} Example sentence.`, "  Example sentence."],
		[`${"A".repeat(257)}\nExample sentence.`, " \nExample sentence."],
		[`${FILLER} Example sentence.`, "  Example sentence."],
		[`Example prose.\n${FILLER}`, "Example prose.\n "],
		[`${FILLER} Example prose. ${FILLER}`, "  Example prose.  "],
		[`${"A".repeat(210000)}Example sentence.`, "  sentence."],
	];
	for (const [body_text, kept] of cases)
		assert.deepEqual(await checkMail(observation({ body_text })), {
			...observation({ body_text: kept }),
			truncated: true,
		});
});

test("a body that is over its limit only because of filler fits afterwards, with the prose inside the cut", async () => {
	const prose = "Example sentence. ".repeat(100);
	const body_text = `${FILLER.repeat(600)}\n${prose}`;
	assert.ok(body_text.length > 3 * 65536);
	assert.deepEqual(await checkMail(observation({ body_text })), {
		...observation({ body_text: ` \n${prose}` }),
		truncated: true,
	});
});

test("a run of 256 filler characters, or one broken by any other character, stays", async () => {
	const bodies = [
		`${"A".repeat(256)} Example sentence.`,
		"A".repeat(256),
		...[" ", ".", "é", "\n", "%", ":", "@"].flatMap((other) => [
			`${"A".repeat(255)}${other}${"A".repeat(255)}`,
			`${"A".repeat(256)}${other}${"A".repeat(256)}`,
			`${FILLER.slice(0, 200)}${other}${FILLER}`.slice(0, 457),
		]),
	];
	for (const body_text of bodies)
		assert.deepEqual(await checkMail(observation({ body_text })), {
			...observation({ body_text }),
			truncated: false,
		});
});

test("long text in a script written without spaces is not filler", async () => {
	for (const letter of ["文", "ก", "я"]) {
		const body_text = letter.repeat(2000);
		assert.deepEqual(await checkMail(observation({ body_text })), {
			...observation({ body_text }),
			truncated: false,
		});
	}
});

test("filler is removed from the body only", async () => {
	const elsewhere = observation({
		message_id: FILLER,
		from_name: FILLER,
		from_addr: `${FILLER}@example.com`,
		reply_to: FILLER,
		to: [FILLER],
		subject: FILLER,
		links: [{ text: FILLER, href: `https://example.com/?token=${FILLER}` }],
		attachments: [`${FILLER}.txt`],
	});
	assert.deepEqual(await checkMail(elsewhere), {
		...elsewhere,
		truncated: false,
	});
});

// A mail as it should be sent, with body_text padded so that the request has
// exactly `size` bytes. The padding is dots, which are not filler.
const padded = (mail, size) => ({
	...mail,
	body_text: ".".repeat(
		size - jsonBytes({ CheckMail: { ...mail, body_text: "" } }),
	),
});
const withoutTruncated = ({ truncated: _, ...obs }) => obs;
// 24,597 and 24,578 bytes in JSON: a quotation mark is written as two
// characters and a control character as six.
const heavyLink = { text: '"'.repeat(4096), href: '"'.repeat(8192) };
const heavyRecipient = "\u0001".repeat(4096);

test("a request of exactly the budget is sent whole; one byte more costs one link", async () => {
	const fits = padded(
		{ ...observation({ links: Array(255).fill(heavyLink) }), truncated: false },
		BUDGET,
	);
	assert.deepEqual(await checkMail(withoutTruncated(fits)), fits);

	const over = { ...fits, body_text: `${fits.body_text}.` };
	const sent = await checkMail(withoutTruncated(over));
	assert.deepEqual(sent, {
		...over,
		links: Array(254).fill(heavyLink),
		truncated: true,
	});
});

test("a request over the budget loses links from the end until it fits", async () => {
	const fits = padded(
		{ ...observation({ links: Array(255).fill(heavyLink) }), truncated: true },
		BUDGET,
	);
	const tooMany = { links: Array(300).fill(heavyLink) };
	const sent = await checkMail({ ...withoutTruncated(fits), ...tooMany });
	assert.deepEqual(sent, fits);
	assert.equal(jsonBytes({ CheckMail: sent }), BUDGET);

	const over = { ...fits, body_text: `${fits.body_text}.` };
	assert.deepEqual(await checkMail({ ...withoutTruncated(over), ...tooMany }), {
		...over,
		links: Array(254).fill(heavyLink),
	});
});

test("a request still over the budget without links loses recipients from the end", async () => {
	const fits = padded(
		{
			...observation({ links: [], to: Array(255).fill(heavyRecipient) }),
			truncated: true,
		},
		BUDGET,
	);
	const tooMany = {
		links: [
			{ text: "Example link", href: "https://example.com/" },
			{ text: "Another link", href: "https://example.org/" },
		],
		to: Array(300).fill(heavyRecipient),
	};
	const sent = await checkMail({ ...withoutTruncated(fits), ...tooMany });
	assert.deepEqual(sent, fits);
	assert.equal(jsonBytes({ CheckMail: sent }), BUDGET);

	const over = { ...fits, body_text: `${fits.body_text}.` };
	assert.deepEqual(await checkMail({ ...withoutTruncated(over), ...tooMany }), {
		...over,
		to: Array(254).fill(heavyRecipient),
	});
});

const NOW = 1_800_000_000_000;
const MINUTE = 60 * 1000;

test("a mail verdict is noted in the tab's mail level whatever show says", async (t) => {
	t.mock.method(Date, "now", () => NOW);
	const cases = [
		[verdict("caution"), verdict("caution")],
		[verdict("danger", false), null],
		[verdict("none"), verdict("none")],
	];
	for (const [given, reply] of cases) {
		const worker = await boot({
			storage: new Map([["mailLevel:7", { none: NOW - MINUTE }]]),
			respond: () => ({ Verdict: given }),
		});
		const message = { t: "mail", obs: observation() };
		assert.deepEqual(await send(worker, message, mailFrame()), reply);
		assert.deepEqual(Object.fromEntries(worker.storage), {
			"mailLevel:7": { none: NOW - MINUTE, [given.level]: NOW },
		});
	}
});

test("a mail check without a verdict forgets none and keeps what warned", async (t) => {
	t.mock.method(Date, "now", () => NOW);
	const responses = [
		() => ({ Error: "daemon unreachable" }),
		() => "Ok",
		() => {
			throw new Error("Specified native messaging host not found.");
		},
	];
	for (const respond of responses) {
		const worker = await boot({
			storage: new Map([
				["mailLevel:7", { danger: NOW - MINUTE, none: NOW - 1000 }],
				["mailLevel:8", { caution: NOW - MINUTE }],
				["mailLevel:9", { none: NOW - 1000 }],
			]),
			respond,
		});
		const message = { t: "mail", obs: observation() };
		for (const tab of [7, 9])
			assert.equal(
				await send(worker, message, mailFrame({ tab: { id: tab } })),
				null,
			);
		assert.deepEqual(Object.fromEntries(worker.storage), {
			"mailLevel:7": { danger: NOW - MINUTE },
			"mailLevel:8": { caution: NOW - MINUTE },
		});
	}
});

test("the highest level seen in a tab in the last 30 minutes is the mail level of a page opened from it", async (t) => {
	let now = NOW;
	t.mock.method(Date, "now", () => now);
	const worker = await boot({
		frames: { "7:0": { url: `${MAIL}/mail/u/0/` } },
		respond: (request) =>
			request.CheckMail
				? {
						Verdict: verdict(
							request.CheckMail.message_id === "m1" ? "danger" : "none",
						),
					}
				: { Verdict: verdict("none") },
	});
	for (const message_id of ["m1", "m2"])
		await send(
			worker,
			{ t: "mail", obs: observation({ message_id }) },
			mailFrame(),
		);
	assert.deepEqual(worker.storage.get("mailLevel:7"), {
		danger: NOW,
		none: NOW,
	});

	const openedFromMail = async (tabId) => {
		await fire(worker, "created", {
			sourceTabId: 7,
			tabId,
			url: "https://example.com/login",
		});
		worker.requests.length = 0;
		await send(worker, { t: "page" }, web({ tab: { id: tabId } }));
		return worker.requests[0].CheckPage.mail_level;
	};
	assert.equal(await openedFromMail(9), "danger");

	now = NOW + 31 * MINUTE;
	assert.equal(await openedFromMail(10), undefined);
});

test("a mail check without a verdict after danger leaves danger in force", async (t) => {
	t.mock.method(Date, "now", () => NOW);
	let given = { Verdict: verdict("danger") };
	const worker = await boot({
		frames: { "7:0": { url: `${MAIL}/mail/u/0/` } },
		respond: (request) =>
			request.CheckMail ? given : { Verdict: verdict("none") },
	});
	await send(worker, { t: "mail", obs: observation() }, mailFrame());
	given = { Error: "daemon unreachable" };
	await send(worker, { t: "mail", obs: observation() }, mailFrame());
	await fire(worker, "created", {
		sourceTabId: 7,
		tabId: 9,
		url: "https://example.com/login",
	});
	worker.requests.length = 0;
	await send(worker, { t: "page" }, web({ tab: { id: 9 } }));
	assert.equal(worker.requests[0].CheckPage.mail_level, "danger");
});

test("status reports the daemon's mode and logins and each adapter's health", async () => {
	const worker = await boot({
		storage: new Map([["adapter:gmail", true]]),
		respond: () => ({ Status: { mode: "monitor", logins: 3 } }),
	});
	assert.deepEqual(await send(worker, { t: "status" }, popup), {
		state: "ok",
		mode: "monitor",
		logins: 3,
		adapters: { gmail: true },
	});
	assert.deepEqual(worker.requests, [{ Status: null }]);
});

test("status names each way the native host or the daemon can fail", async () => {
	const failed = (text) => () => {
		throw new Error(text);
	};
	const rows = [
		[failed("Specified native messaging host not found."), "host_not_found"],
		[
			failed("Access to the specified native messaging host is forbidden."),
			"host_forbidden",
		],
		[failed("Native host has exited."), "host_exited"],
		[failed("Failed to start native messaging host."), "error"],
		[
			failed("Error when communicating with the native messaging host."),
			"error",
		],
		[() => Promise.reject(undefined), "error"],
		[() => ({ Error: "daemon unreachable" }), "daemon_unreachable"],
		[() => ({ Error: "request not allowed" }), "error"],
		[() => "Ok", "error"],
		[() => ({ Verdict: verdict("none") }), "error"],
		[() => ({ Status: null }), "error"],
		[() => ({ Status: { mode: "block", logins: 0 } }), "error"],
		[() => ({ Status: { mode: "warn" } }), "error"],
		[() => null, "error"],
	];
	for (const [respond, state] of rows) {
		const worker = await boot({ respond });
		assert.deepEqual(await send(worker, { t: "status" }, popup), {
			state,
			adapters: {},
		});
	}
});

test("an adapter report is stored and shows a global badge while any adapter is broken", async () => {
	const worker = await boot();
	const report = (ok) =>
		send(worker, { t: "adapter", provider: "gmail", ok }, mailFrame());

	assert.equal(await report(false), null);
	assert.equal(worker.storage.get("adapter:gmail"), false);
	assert.equal(badgeOn(worker, 7), "?");
	assert.equal(badgeOn(worker, 8), "?");

	assert.equal(await report(true), null);
	assert.equal(worker.storage.get("adapter:gmail"), true);
	assert.equal(badgeOn(worker, 7), "");
	assert.deepEqual(worker.requests, []);
});

test("a shown caution or danger verdict sets the tab's badge until its next top-level commit", async () => {
	for (const t of ["page", "mail"]) {
		for (const level of ["caution", "danger"]) {
			const worker = await boot({
				storage: new Map([["allow:example.com", true]]),
				respond: () => ({ Verdict: verdict(level) }),
			});
			const [message, sender] =
				t === "page"
					? [{ t }, web()]
					: [{ t, obs: observation() }, mailFrame()];
			await send(worker, message, sender);
			assert.equal(badgeOn(worker, 7), "!", `${t} ${level}`);
			assert.equal(badgeOn(worker, 8), "");

			await fire(worker, "committed", commit({ tabId: 7, frameId: 2 }));
			await fire(worker, "committed", commit({ tabId: 8 }));
			assert.equal(badgeOn(worker, 7), "!");
			await fire(worker, "committed", commit({ tabId: 7 }));
			assert.equal(badgeOn(worker, 7), "");
		}
	}
});

test("a verdict that is not shown or does not warn sets no badge", async () => {
	for (const given of [
		verdict("none"),
		verdict("caution", false),
		verdict("danger", false),
	]) {
		const worker = await boot({ respond: () => ({ Verdict: given }) });
		await send(worker, { t: "page" }, web());
		await send(worker, { t: "mail", obs: observation() }, mailFrame());
		assert.deepEqual([...worker.badges], []);
	}
});

test("a tab's badge covers the global one and gives way to it again", async () => {
	const worker = await boot({
		respond: () => ({ Verdict: verdict("caution") }),
	});
	await send(
		worker,
		{ t: "adapter", provider: "gmail", ok: false },
		mailFrame(),
	);
	await send(worker, { t: "page" }, web({ tab: { id: 9 } }));
	assert.equal(badgeOn(worker, 9), "!");
	assert.equal(badgeOn(worker, 7), "?");
	await fire(worker, "committed", commit({ tabId: 9 }));
	assert.equal(badgeOn(worker, 9), "?");
});

// A native host whose answers to page and login requests the test gives one at
// a time, by the host they name. Status and mail are answered at once.
const slowHost = () => {
	const open = new Map();
	const respond = (request) => {
		if ("Status" in request) return { Status: { mode: "warn", logins: 0 } };
		if (request.CheckMail) return { Verdict: verdict("none") };
		const { host } = request.CheckPage ?? request.LoginSeen;
		return new Promise((resolve) => open.set(host, resolve));
	};
	return { open, respond };
};
const PAGE = { t: "page" };
const LOGIN = { t: "login", evidence: "typed" };
// Frame n of tab 7, on a site and with a document of its own.
const frameOf = (n, overrides = {}) =>
	web({
		frameId: n,
		origin: `https://site${n}.example.com`,
		documentId: `document-${n}`,
		...overrides,
	});
const pageRequest = (host) => ({
	CheckPage: { host, opened_from_mail: false },
});
const loginRequest = (host) => ({ LoginSeen: { host, evidence: "typed" } });
// Fills the eight places with page checks of frames 1 to 8 of tab 7.
const busy = async () => {
	const { open, respond } = slowHost();
	const documents = {};
	const worker = await boot({ documents, respond });
	for (let n = 1; n <= 8; n += 1) dispatch(worker, PAGE, frameOf(n));
	await settled();
	assert.equal(worker.requests.length, 8);
	const free = async (n, response = { Verdict: verdict("none") }) => {
		open.get(`site${n}.example.com`)(response);
		await settled();
	};
	return { worker, open, documents, free };
};

test("nine frames of one host in one tab cause one call and get nine answers", async () => {
	const { open, respond } = slowHost();
	const worker = await boot({ respond });
	const replies = Array.from({ length: 9 }, (_, n) =>
		dispatch(worker, PAGE, web({ frameId: n, documentId: `document-${n}` })),
	);
	await settled();
	assert.deepEqual(worker.requests, [pageRequest("example.com")]);

	open.get("example.com")({ Verdict: verdict("caution") });
	await settled();
	assert.deepEqual(replies, Array(9).fill([verdict("caution")]));
	assert.deepEqual(worker.errors, []);

	dispatch(worker, PAGE, web());
	await settled();
	assert.equal(worker.requests.length, 2);
});

test("only messages of one tab that make the same request share a call", async () => {
	const worker = await boot({ respond: () => new Promise(() => {}) });
	const elsewhere = { tab: { id: 8 } };
	const subframe = { frameId: 3, origin: "https://example.org" };
	const messages = [
		[PAGE, web()],
		[PAGE, web(elsewhere)],
		[PAGE, web(subframe)],
		[LOGIN, web()],
		[{ t: "login", evidence: "autofill" }, web()],
		[PAGE, web({ frameId: 4 })],
		[LOGIN, web({ frameId: 4 })],
	];
	for (const [message, sender] of messages) dispatch(worker, message, sender);
	await settled();
	const sorted = (requests) => requests.map(JSON.stringify).sort();
	assert.deepEqual(
		sorted(worker.requests),
		sorted([
			pageRequest("example.com"),
			pageRequest("example.com"),
			pageRequest("example.org"),
			loginRequest("example.com"),
			{ LoginSeen: { host: "example.com", evidence: "autofill" } },
		]),
	);
});

test("nine hosts cause nine calls, eight at once, and none is refused; status does not wait, mail does", async () => {
	const { worker, free, open } = await busy();
	const ninth = dispatch(worker, PAGE, frameOf(9));
	await settled();
	const tenth = dispatch(worker, LOGIN, frameOf(10));
	await settled();
	assert.equal(worker.requests.length, 8);
	assert.deepEqual([ninth, tenth], [[], []]);

	const status = await send(worker, { t: "status" }, popup);
	assert.equal(status.state, "ok");
	assert.equal(worker.requests.length, 9);
	const mail = dispatch(worker, { t: "mail", obs: observation() }, mailFrame());
	await settled();
	assert.equal(worker.requests.length, 9);
	assert.deepEqual(mail, []);

	// A call that ends, with an answer or with a failure, gives its place on;
	// mail is a top frame's call, so it goes before the waiting subframes.
	// The host answers the mail at once, which gives its place on in turn.
	await free(1);
	assert.equal(worker.requests[9].CheckMail?.message_id, "m1");
	assert.equal(worker.requests.length, 11);
	assert.deepEqual(worker.requests[10], pageRequest("site9.example.com"));
	assert.deepEqual(mail, [verdict("none")]);
	await free(2, Promise.reject(new Error("Native host has exited.")));
	assert.deepEqual(worker.requests.at(-1), loginRequest("site10.example.com"));
	assert.equal(worker.requests.length, 12);

	for (const answer of open.values()) answer({ Verdict: verdict("caution") });
	await settled();
	assert.deepEqual([ninth, tenth], [[verdict("caution")], [null]]);
	assert.deepEqual(worker.errors, []);
});

// A host that holds every mail request until the test lets it go, and counts
// how many are held at once.
const heldMail = () => {
	const held = [];
	const peak = { held: 0 };
	const respond = (request) => {
		if ("Status" in request) return { Status: { mode: "warn", logins: 0 } };
		if (request.CheckPage) return { Verdict: verdict("none") };
		return new Promise((resolve) => {
			held.push(() => resolve({ Verdict: verdict("none") }));
			peak.held = Math.max(peak.held, held.length);
		});
	};
	const release = async () => {
		for (const let_go of held.splice(0)) let_go();
		await settled();
	};
	return { respond, release, peak };
};

test("thirty mails at once cause thirty calls, eight at a time, and a page from a top frame behind them goes in arrival order; status does not wait", async () => {
	const { respond, release, peak } = heldMail();
	const worker = await boot({ respond });
	const mails = Array.from({ length: 30 }, (_, n) =>
		dispatch(
			worker,
			{ t: "mail", obs: observation({ message_id: `m${n}` }) },
			mailFrame(),
		),
	);
	await settled();
	assert.equal(worker.requests.length, 8);

	const status = await send(worker, { t: "status" }, popup);
	assert.equal(status.state, "ok");

	const subframe = dispatch(worker, PAGE, frameOf(1, { tab: { id: 8 } }));
	const top = dispatch(worker, PAGE, web({ tab: { id: 9 } }));
	await settled();
	assert.equal(worker.requests.length, 9);

	for (
		let rounds = 0;
		mails.some((replies) => replies.length === 0);
		rounds += 1
	) {
		assert.ok(rounds < 30, "every mail is answered");
		await release();
	}
	await settled();
	assert.equal(peak.held, 8);
	const calls = worker.requests.filter((request) => !("Status" in request));
	assert.deepEqual(
		calls.map((request) => request.CheckMail?.message_id ?? "page"),
		[...Array.from({ length: 30 }, (_, n) => `m${n}`), "page", "page"],
	);
	assert.deepEqual(calls.at(-2).CheckPage.host, "example.com");
	assert.deepEqual(calls.at(-1).CheckPage.host, "site1.example.com");
	assert.deepEqual(mails, Array(30).fill([verdict("none")]));
	assert.deepEqual([top, subframe], [[verdict("none")], [verdict("none")]]);
	assert.deepEqual(worker.errors, []);
});

test("a mail whose document has gone while it waited is not sent", async () => {
	const { worker, free, documents } = await busy();
	const mail = dispatch(
		worker,
		{ t: "mail", obs: observation() },
		mailFrame({ documentId: "document-mail" }),
	);
	await settled();
	documents["document-mail"] = null;
	await free(1);
	assert.equal(worker.requests.length, 8);
	assert.deepEqual(mail, [null]);
	assert.deepEqual(worker.errors, []);
});

test("a top frame's message goes ahead of waiting subframe messages", async () => {
	const { worker, free } = await busy();
	const top = (tabId, host) =>
		web({
			tab: { id: tabId },
			origin: `https://${host}`,
			documentId: `document-${host}`,
		});
	const later = [
		[PAGE, frameOf(9)],
		[LOGIN, frameOf(10)],
		[PAGE, top(8, "page.example.org")],
		[LOGIN, top(9, "login.example.org")],
	];
	for (const [message, sender] of later) {
		dispatch(worker, message, sender);
		await settled();
	}
	assert.equal(worker.requests.length, 8);

	for (const n of [1, 2, 3, 4]) await free(n);
	assert.deepEqual(worker.requests.slice(8), [
		pageRequest("page.example.org"),
		loginRequest("login.example.org"),
		pageRequest("site9.example.com"),
		loginRequest("site10.example.com"),
	]);
});

test("a top frame that asks for a waiting call takes it ahead", async () => {
	const { worker, free } = await busy();
	const later = [
		frameOf(9),
		web({ frameId: 10, documentId: "document-10" }),
		web(),
	];
	for (const sender of later) {
		dispatch(worker, PAGE, sender);
		await settled();
	}

	await free(1);
	await free(2);
	assert.deepEqual(worker.requests.slice(8), [
		pageRequest("example.com"),
		pageRequest("site9.example.com"),
	]);
});

test("a call that had to wait is not made once every document that asked for it has gone", async () => {
	const { worker, free, open, documents } = await busy();
	const later = [
		[LOGIN, web({ tab: { id: 8 }, documentId: "document-gone" })],
		[PAGE, frameOf(9)],
		[PAGE, web({ frameId: 10, documentId: "document-10" })],
		[PAGE, web({ frameId: 11, documentId: "document-11" })],
	];
	const replies = [];
	for (const [message, sender] of later) {
		replies.push(dispatch(worker, message, sender));
		await settled();
	}
	documents["document-gone"] = null;
	documents["document-9"] = { documentLifecycle: "cached" };
	documents["document-10"] = null;

	// One place is enough: a call that is not made gives its place on at once.
	await free(1);
	assert.deepEqual(worker.requests.slice(8), [pageRequest("example.com")]);
	assert.deepEqual(replies.slice(0, 2), [[null], [null]]);

	// The call two frames shared is made for the one that is still shown.
	open.get("example.com")({ Verdict: verdict("caution") });
	await settled();
	assert.deepEqual(replies.slice(2), [[null], [verdict("caution")]]);
	assert.deepEqual(worker.errors, []);
});

test("a shared verdict acts only for the documents that are still shown", async () => {
	const { open, respond } = slowHost();
	const documents = {};
	const worker = await boot({ documents, respond });
	const replies = [
		dispatch(worker, PAGE, web({ frameId: 3, documentId: "document-3" })),
		dispatch(worker, PAGE, web({ frameId: 4, documentId: "document-4" })),
	];
	await settled();
	documents["document-3"] = null;
	open.get("example.com")({ Verdict: verdict("caution") });
	await settled();
	assert.deepEqual(replies, [[null], [verdict("caution")]]);
});

test("a login that did not have to wait is reported although its document has gone", async () => {
	const worker = await boot({
		documents: { "document-a": null },
		respond: () => "Ok",
	});
	assert.equal(await send(worker, LOGIN, web()), null);
	assert.deepEqual(worker.requests, [loginRequest("example.com")]);
});

test("starting the browser recomputes the global badge", async () => {
	const stale = await boot();
	stale.badges.set("all", "?");
	await fire(stale, "startup");
	assert.equal(badgeOn(stale, 7), "");

	const broken = await boot({ storage: new Map([["adapter:gmail", false]]) });
	await fire(broken, "startup");
	assert.equal(badgeOn(broken, 7), "?");
});

test("a step that fails still answers null, once, and reports the error", async () => {
	const worker = await boot({
		respond: () => ({ Verdict: verdict("danger") }),
	});
	const failure = new Error("constructed failure");
	worker.chrome.tabs.update = async () => {
		throw failure;
	};
	const replies = dispatch(worker, { t: "page" }, web());
	await settled();
	assert.deepEqual(replies, [null]);
	assert.deepEqual(worker.errors, [failure]);
});

test("a step that fails in its turn does not hold up the steps behind it", async () => {
	const worker = await boot({
		storage: blockedState(),
		respond: () => ({ Verdict: verdict("caution") }),
	});
	const failure = new Error("constructed failure");
	const { set } = worker.chrome.storage.session;
	worker.chrome.storage.session.set = async () => {
		throw failure;
	};
	const replies = dispatch(worker, { t: "continue" }, warningPage());
	await settled();
	assert.deepEqual(replies, [null]);
	assert.deepEqual(worker.errors.splice(0), [failure]);

	worker.chrome.storage.session.set = set;
	assert.deepEqual(
		await send(worker, { t: "page" }, web()),
		verdict("caution"),
	);
});
