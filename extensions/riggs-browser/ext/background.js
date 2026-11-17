// Service worker of the Riggs browser extension: the only part that talks to
// the daemon and the only part that holds state. It implements "Browser
// extension contract" in docs/PHISHING.md; quoted names are its sections.

const NATIVE_HOST = "com.riggs.browser";
const MAIL_PROVIDERS = new Map([["https://mail.google.com", "gmail"]]);
const ADAPTER_KEYS = Array.from(
	MAIL_PROVIDERS.values(),
	(provider) => `adapter:${provider}`,
);
const TAB_KEYS = [
	"entry",
	"fromMail",
	"mailTab",
	"mailLevel",
	"blocked",
	"topHost",
];
// In rising order.
const LEVELS = ["none", "caution", "danger"];
const MODES = ["off", "monitor", "warn"];
const EVIDENCE = ["typed", "autofill", "filled"];
// "The native host": the error texts Chrome documents for a failed call.
const HOST_FAILURES = new Map([
	["Specified native messaging host not found.", "host_not_found"],
	[
		"Access to the specified native messaging host is forbidden.",
		"host_forbidden",
	],
	["Native host has exited.", "host_exited"],
]);
const POPUP = chrome.runtime.getURL("popup.html");
const WARNING_PAGE = chrome.runtime.getURL("interstitial.html");
const REQUEST_BUDGET = 6 * 1024 * 1024;
const MAX_HOST_BYTES = 255;
const MAX_URL_BYTES = 8192;
const MAX_CALLS = 8;
// The daemon's window for links from recently checked mail.
const MAIL_LEVEL_AGE = 30 * 60 * 1000;
// "Capping": what filler is made of. Prose in any language has no run of more
// than 256 of these.
const FILLER = /[A-Za-z0-9+/=_-]+/g;

const session = chrome.storage.session;
const encoder = new TextEncoder();
// ignoreBOM keeps a leading U+FEFF instead of dropping it.
const decoder = new TextDecoder("utf-8", { ignoreBOM: true });

const parsed = (url) => {
	try {
		return new URL(url);
	} catch {
		return undefined;
	}
};

// Whether a parsed URL is a web page's own address.
const isWeb = (url) => url?.protocol === "http:" || url?.protocol === "https:";

// The hostname of an http or https URL. A blob: URL has the host of the page
// that made it, whose origin it carries (URL Standard, "Origin"): a page can
// build its form as a blob and navigate to it. Any other URL has no host, and
// neither has one made in an opaque origin. A hostname over the daemon's limit
// is no host either: no DNS name is that long, and a page could otherwise fill
// session state with it or have every check in a tab refused by sending the
// tab there first.
const hostOf = (url) => {
	const given = parsed(url);
	const web = given?.protocol === "blob:" ? parsed(given.origin) : given;
	return isWeb(web) && encoder.encode(web.hostname).length <= MAX_HOST_BYTES
		? web.hostname
		: undefined;
};

const providerOf = (url) => MAIL_PROVIDERS.get(parsed(url)?.origin);

const stored = async (key) => (await session.get(key))[key];

// The URL of a tab's top frame, or undefined when it cannot be read.
const topUrl = (tabId) =>
	chrome.webNavigation.getFrame({ tabId, frameId: 0 }).then(
		(frame) => frame?.url,
		() => undefined,
	);

// Writing a key "from url" writes that URL's host, and nothing when it has none.
const writeHost = async (key, url) => {
	const host = hostOf(url);
	if (host !== undefined) await session.set({ [key]: host });
	return host;
};

// mailLevel:<tabId> holds, for each level, when a mail verdict in the tab last
// had it. The tab's mail level is the highest of the last half hour, so that a
// harmless message cannot hide a dangerous one opened beside it.
const mailLevelOf = (seen) =>
	LEVELS.findLast((level) => Date.now() - seen?.[level] <= MAIL_LEVEL_AGE);

const mailMark = (seen) => {
	const level = mailLevelOf(seen);
	return level === undefined ? {} : { level };
};

// A failure to set the badge is ignored: the tab may be gone.
const badge = (details) => chrome.action.setBadgeText(details).catch(() => {});

// Steps that read session state and then act on it run one at a time, in
// arrival order. A worker woken by a click gets the tab's navigation events and
// the new page's first message together, and that page's check must see the
// provenance the events write. The chain is this worker's pending work, not
// state: a new worker has none.
let turn = Promise.resolve();
const inTurn = (step) => {
	const done = turn.then(step);
	turn = done.catch(() => {});
	return done;
};

// The host of the page a tab shows. The browser does not show the worker the
// top frame of a blob: page, so the host of the tab's last top-level commit
// stands in when the frame gives none.
const pageHost = async (tabId) =>
	hostOf(await topUrl(tabId)) ?? inTurn(() => stored(`topHost:${tabId}`));

// "Session state", one function per row of the event table.

const created = async ({ sourceTabId, tabId, url }) => {
	await writeHost(`entry:${tabId}`, url);
	const mark =
		providerOf(await topUrl(sourceTabId)) === undefined
			? await stored(`fromMail:${sourceTabId}`)
			: mailMark(await stored(`mailLevel:${sourceTabId}`));
	if (mark !== undefined) await session.set({ [`fromMail:${tabId}`]: mark });
};

const navigating = async ({ tabId, url }) => {
	const entry = `entry:${tabId}`;
	if ((await stored(entry)) === undefined) await writeHost(entry, url);
};

const committed = async ({
	tabId,
	url,
	transitionType,
	transitionQualifiers,
}) => {
	const entry = `entry:${tabId}`;
	const fromMail = `fromMail:${tabId}`;
	const mailTab = `mailTab:${tabId}`;
	const mailLevel = `mailLevel:${tabId}`;
	const topHost = `topHost:${tabId}`;
	const onMail = providerOf(url) !== undefined;
	const state = await session.get([mailTab, mailLevel]);
	if (transitionQualifiers.includes("from_address_bar")) {
		await session.remove(fromMail);
		if ((await writeHost(entry, url)) === undefined)
			await session.remove(entry);
	} else if (
		state[mailTab] !== undefined &&
		!onMail &&
		transitionType === "link" &&
		!transitionQualifiers.includes("forward_back")
	) {
		await session.set({ [fromMail]: mailMark(state[mailLevel]) });
		await writeHost(entry, url);
	}
	await (onMail ? session.set({ [mailTab]: true }) : session.remove(mailTab));
	if ((await writeHost(topHost, url)) === undefined)
		await session.remove(topHost);
	// null clears the tab's own badge text, so the global one shows again.
	await badge({ tabId, text: null });
};

const removed = (tabId) =>
	session.remove(TAB_KEYS.map((name) => `${name}:${tabId}`));

// "Wire protocol".

const native = (request) =>
	chrome.runtime.sendNativeMessage(NATIVE_HOST, request);

// The daemon's verdict, or undefined for "no answer": no response, an Error or
// any other response.
const verdictIn = (response) =>
	LEVELS.includes(response?.Verdict?.level) ? response.Verdict : undefined;

// Whether the document that sent a message is still the one its frame shows:
// not replaced, not removed, not in the back/forward cache. Where the browser
// cannot say, the document counts as shown, so that a verdict is not lost for
// it: when the call fails, and for a document with a blob: URL, which
// webNavigation does not see at all (Chromium's frame_navigation_state.cc). A
// page must not be able to shed its verdict by putting its form in one.
const isShown = (sender) =>
	sender.url?.startsWith("blob:")
		? true
		: chrome.webNavigation.getFrame({ documentId: sender.documentId }).then(
				(frame) => frame?.documentLifecycle === "active",
				() => true,
			);

// Native calls for mail, page and login; each starts a host process and holds
// a connection to the daemon, and a page can create frames faster than hosts
// can be spawned. At most MAX_CALLS run at once. The others wait and none is
// refused; those a top frame asked for go first, in arrival order, so a page
// full of frames can hold up subframes but never a top frame. Page and login
// messages from one tab that make the same request share one call. All of this
// is the worker's pending work, not state: a new worker has none.
let running = 0;
const waiting = [];
const calls = new Map();

const startWaiting = () => {
	while (running < MAX_CALLS && waiting.length > 0) {
		const top = waiting.findIndex((call) => call.top);
		const [call] = waiting.splice(Math.max(top, 0), 1);
		running += 1;
		call.start();
	}
};

const make = async (call, request) => {
	const turn = new Promise((start) => {
		call.start = start;
	});
	waiting.push(call);
	startWaiting();
	const waited = waiting.includes(call);
	await turn;
	try {
		// A call that had to wait is not made once every document that asked for
		// it has gone.
		if (waited) {
			let shown = false;
			for (const sender of call.senders) shown ||= await isShown(sender);
			if (!shown) return undefined;
		}
		return await native(request).catch(() => undefined);
	} finally {
		running -= 1;
		startWaiting();
	}
};

// The host's response to a page or login request, or undefined for none.
// Mail requests are not shared: each is its own call.
const called = (sender, request) => {
	const key = `${sender.tab.id} ${JSON.stringify(request)}`;
	const call = calls.get(key) ?? { top: false, senders: [] };
	calls.set(key, call);
	call.top ||= sender.frameId === 0;
	// One sender for each document that asks, however often it asks.
	if (!call.senders.some((other) => other.documentId === sender.documentId))
		call.senders.push(sender);
	call.response ??= make(call, request).finally(() => calls.delete(key));
	return call.response;
};

const isString = (value) => typeof value === "string";
const isStrings = (value) => Array.isArray(value) && value.every(isString);

// "CheckMail fields": what an adapter sends, with exactly these types.
const isMail = (obs) =>
	[
		obs.message_id,
		obs.from_name,
		obs.from_addr,
		obs.subject,
		obs.body_text,
	].every(isString) &&
	(obs.reply_to === null || isString(obs.reply_to)) &&
	isStrings(obs.to) &&
	isStrings(obs.attachments) &&
	Array.isArray(obs.links) &&
	obs.links.every((link) => isString(link?.text) && isString(link?.href));

const jsonBytes = (value) => encoder.encode(JSON.stringify(value)).length;

// "Capping": the observation as it is sent. Only the known fields are copied,
// so nothing an adapter adds can outgrow the request budget.
const capped = (obs) => {
	const buffer = new Uint8Array(65536);
	let truncated = false;
	// Filler goes first, each run for one space: left in, it would use up the
	// body's limit before the prose starts.
	const body = obs.body_text.replace(FILLER, (run) =>
		run.length > 256 ? " " : run,
	);
	truncated ||= body.length < obs.body_text.length;
	// encodeInto stops before a code point that does not fit. Decoding its bytes
	// also turns a lone surrogate into U+FFFD; left as it is, JSON would carry it
	// as an escape that the host refuses, and the mail would get no verdict.
	const text = (value, limit = 4096) => {
		const { read, written } = encoder.encodeInto(
			value,
			buffer.subarray(0, limit),
		);
		truncated ||= read < value.length;
		return decoder.decode(buffer.subarray(0, written));
	};
	const first = (list, limit) => {
		truncated ||= list.length > limit;
		return list.slice(0, limit);
	};
	const mail = {
		provider: obs.provider,
		message_id: text(obs.message_id),
		from_name: text(obs.from_name),
		from_addr: text(obs.from_addr),
		reply_to: obs.reply_to === null ? null : text(obs.reply_to),
		to: first(obs.to, 500).map((address) => text(address)),
		subject: text(obs.subject),
		body_text: text(body, 65536),
		links: first(obs.links, 500).map((link) => ({
			text: text(link.text),
			href: text(link.href, 8192),
		})),
		attachments: first(obs.attachments, 100).map((name) => text(name)),
	};
	mail.truncated = truncated;
	// JSON.stringify joins array entries with commas, so dropping an entry saves
	// its own bytes and, unless it was the only one, a comma. The first drop
	// also turns "false" into "true", which is one byte shorter.
	let size = jsonBytes({ CheckMail: mail });
	for (const list of [mail.links, mail.to]) {
		while (size > REQUEST_BUDGET && list.length > 0) {
			size -= jsonBytes(list.pop());
			size -= list.length > 0 ? 1 : 0;
			size -= mail.truncated ? 0 : 1;
			mail.truncated = true;
		}
	}
	return mail;
};

// "Messages to the worker".

// A verdict is passed on only when it may be displayed. One that warns also
// sets the tab's badge, the one warning a page cannot remove; it stays until
// the tab's next top-level commit.
const displayed = async (tabId, verdict) => {
	if (verdict?.show !== true) return null;
	if (verdict.level !== "none") await badge({ tabId, text: "!" });
	return verdict;
};

// A verdict's level is noted with the time. A check without a verdict forgets
// "none": the tab's mail level is unknown again, unless a warning was seen.
const noteMailLevel = async (tabId, level) => {
	const key = `mailLevel:${tabId}`;
	const before = (await stored(key)) ?? {};
	const { none: _, ...warnings } = before;
	const seen =
		level === undefined ? warnings : { ...before, [level]: Date.now() };
	await (Object.keys(seen).length > 0
		? session.set({ [key]: seen })
		: session.remove(key));
};

const checkMail = async (sender, obs) => {
	const tabId = sender.tab.id;
	// A mail frame is a top frame, so its call is never behind a subframe's.
	const call = { top: true, senders: [sender] };
	const verdict = verdictIn(await make(call, { CheckMail: capped(obs) }));
	await inTurn(() => noteMailLevel(tabId, verdict?.level));
	return displayed(tabId, verdict);
};

// The latest report of each adapter that has reported, by provider.
const adapterHealth = async () =>
	Object.fromEntries(
		Object.entries(await session.get(ADAPTER_KEYS)).map(([key, ok]) => [
			key.slice("adapter:".length),
			ok,
		]),
	);

// The global badge shows while any adapter is broken; a tab's own badge
// covers it.
const showAdapterHealth = async () => {
	const broken = Object.values(await adapterHealth()).includes(false);
	await badge({ text: broken ? "?" : "" });
};

const reportAdapter = async (provider, ok) => {
	await session.set({ [`adapter:${provider}`]: ok });
	await showAdapterHealth();
	return null;
};

// "The host of a web frame": its own, or the page's when its origin is opaque.
const frameHost = async (sender) =>
	/^https?:\/\//.test(sender.origin)
		? hostOf(sender.origin)
		: pageHost(sender.tab.id);

const checkPage = async (sender) => {
	const tabId = sender.tab.id;
	const host = await frameHost(sender);
	if (host === undefined) return null;
	const entry = `entry:${tabId}`;
	const fromMail = `fromMail:${tabId}`;
	const state = await inTurn(() => session.get([entry, fromMail]));
	// JSON leaves out a field that is undefined: entry_host and mail_level when
	// there is none.
	const observation = {
		host,
		entry_host: state[entry],
		opened_from_mail: state[fromMail] !== undefined,
		mail_level: state[fromMail]?.level,
	};
	const verdict = verdictIn(await called(sender, { CheckPage: observation }));
	if (verdict?.show !== true) return null;
	// A verdict acts only on the document it was asked for, and in one turn, so
	// that no navigation event is handled in between. What a block needs is read
	// first; then the browser is asked whether the document is still shown, and
	// only the badge, the block and the navigation follow its answer.
	return inTurn(async () => {
		const blocks =
			verdict.level === "danger" &&
			(await stored(`allow:${host}`)) === undefined;
		const url = blocks ? await topUrl(tabId) : undefined;
		if (!(await isShown(sender))) return null;
		await displayed(tabId, verdict);
		if (!blocks) return verdict;
		// The URL is kept for `continue`, in session state and nowhere else,
		// unless it is not a web page's own (a blob: page cannot be opened again
		// from here) or so long that storing it could fail. Without it the tab
		// is blocked all the same.
		const block = { host, reasons: verdict.reasons };
		if (isWeb(parsed(url)) && encoder.encode(url).length <= MAX_URL_BYTES)
			block.url = url;
		await session.set({ [`blocked:${tabId}`]: block });
		await chrome.tabs.update(tabId, { url: WARNING_PAGE });
		return null;
	});
};

const reportLogin = async (sender, evidence) => {
	const host = await frameHost(sender);
	if (host === undefined) return null;
	// A page can make a field of its own look filled, so "filled" is weak
	// evidence. From a frame on another host than its page's, such as an
	// advertisement, it is not reported: the frame could otherwise make a login
	// known for its host from any site that embeds it.
	if (
		evidence === "filled" &&
		sender.frameId !== 0 &&
		(await pageHost(sender.tab.id)) !== host
	)
		return null;
	await called(sender, { LoginSeen: { host, evidence } });
	return null;
};

// "The native host": the state of a status reply, with the daemon's fields
// when it is ok.
const daemonStatus = async () => {
	try {
		const response = await native({ Status: null });
		const { mode, logins } = response?.Status ?? {};
		if (MODES.includes(mode) && Number.isInteger(logins))
			return { state: "ok", mode, logins };
		const unreachable = response?.Error === "daemon unreachable";
		return { state: unreachable ? "daemon_unreachable" : "error" };
	} catch (error) {
		return { state: HOST_FAILURES.get(error?.message) ?? "error" };
	}
};

// What the warning page is told about its tab: never the URL.
const blockedPage = async (tabId) => {
	const block = await stored(`blocked:${tabId}`);
	return block === undefined
		? null
		: { host: block.host, reasons: block.reasons };
};

const proceed = async (tabId) => {
	const key = `blocked:${tabId}`;
	const block = await inTurn(async () => {
		const found = await stored(key);
		if (found === undefined) return undefined;
		await session.set({ [`allow:${found.host}`]: true });
		await session.remove(key);
		return found;
	});
	// The tab is sent to the blocked page, not back to it: Chrome lets Back skip
	// a page that an extension navigated away from before the person clicked or
	// typed in it. Chrome's own error may quote the URL, so it is not reported.
	if (isWeb(parsed(block?.url)))
		await chrome.tabs.update(tabId, { url: block.url }).catch(() => {
			throw new Error("the blocked page could not be opened again");
		});
	return null;
};

// "Who may send": everything about the sender comes from the browser's record.
const answer = async (message, sender) => {
	if (sender.id !== chrome.runtime.id) return null;
	const webFrame =
		sender.tab !== undefined && sender.documentLifecycle === "active";
	const provider =
		webFrame && sender.frameId === 0
			? MAIL_PROVIDERS.get(sender.origin)
			: undefined;
	const warningPage =
		sender.url === WARNING_PAGE &&
		sender.tab !== undefined &&
		sender.frameId === 0;
	switch (message?.t) {
		case "mail":
			return provider !== undefined &&
				message.obs?.provider === provider &&
				isMail(message.obs)
				? checkMail(sender, message.obs)
				: null;
		case "adapter":
			return provider !== undefined &&
				message.provider === provider &&
				typeof message.ok === "boolean"
				? reportAdapter(provider, message.ok)
				: null;
		case "page":
			return webFrame ? checkPage(sender) : null;
		case "login":
			return webFrame && EVIDENCE.includes(message.evidence)
				? reportLogin(sender, message.evidence)
				: null;
		case "status":
			return sender.url === POPUP
				? { ...(await daemonStatus()), adapters: await adapterHealth() }
				: null;
		case "blocked":
			return warningPage ? blockedPage(sender.tab.id) : null;
		case "continue":
			return warningPage ? proceed(sender.tab.id) : null;
		default:
			return null;
	}
};

// Listeners are registered here, synchronously, so that an event which wakes
// the worker finds them.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	// A step that fails still answers, with null, and the error is reported as
	// an uncaught one.
	answer(message, sender).then(sendResponse, (error) => {
		sendResponse(null);
		reportError(error);
	});
	return true;
});

chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
	inTurn(() => created(details));
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
	if (details.frameId === 0) inTurn(() => navigating(details));
});

chrome.webNavigation.onCommitted.addListener((details) => {
	if (details.frameId === 0) inTurn(() => committed(details));
});

chrome.tabs.onRemoved.addListener((tabId) => {
	inTurn(() => removed(tabId));
});

// Session state is empty when the browser starts; a global badge the browser
// kept from before would be stale.
chrome.runtime.onStartup.addListener(() => {
	showAdapterHealth();
});
