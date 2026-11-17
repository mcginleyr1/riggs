// A stand-in for the parts of Office.js the pane calls, written from
// Microsoft's reference pages (learn.microsoft.com/javascript/api/outlook, the
// Mailbox 1.14 view). It enforces the documented argument rules for
// notification messages, so a call the real API would reject fails here too,
// and it answers every call a turn later, as the real API does.
//
// It runs in the test's realm while the pane runs in jsdom's, so what it
// records is copied into this realm first: strict deepEqual compares
// prototypes.

const succeeded = (value) => ({ status: "succeeded", value });
const failed = (message) => ({ status: "failed", error: { message } });
const answer = (callback, result) => setImmediate(() => callback?.(result));
const copy = (value) => JSON.parse(JSON.stringify(value));

// NotificationMessageDetails and NotificationMessages in the reference: a key
// "can't be longer than 32 characters"; a message's "maximum length is 150
// characters"; "an icon must be specified for InformationalMessage", for which
// `persistent` is the only type it applies to; for the ProgressIndicator and
// ErrorMessage types "the icon and persistent properties aren't valid".
const notificationProblem = (key, details) => {
	if (typeof key !== "string" || key.length > 32) return "invalid key";
	if (typeof details.message !== "string" || details.message.length > 150) {
		return "message over 150 characters";
	}
	if (details.type === "informationalMessage") {
		return typeof details.icon === "string" &&
			typeof details.persistent === "boolean"
			? null
			: "an informational message needs icon and persistent";
	}
	if (details.type === "errorMessage" || details.type === "progressIndicator") {
		return "icon" in details || "persistent" in details
			? "icon and persistent are not valid for this type"
			: null;
	}
	return "unknown type";
};

// `items` describe what can be selected. A plain description becomes a
// message in read mode:
//   { label, id, from: { name, address }, to, cc, subject, attachments, html, headers }
// where `html: null` and `headers: null` make that call fail. `{ label, raw }`
// is handed to the pane as it is, for items that are not such a message.
//
// `calls` lists every Office call the pane made, in order. A call made
// through an item that is no longer the selected one is marked `stale`: the
// pinnable task pane page says the item object "is already updated to reflect
// the currently selected item" when ItemChanged fires, so in Outlook such a
// call may act on another message than the one it was meant for.
//
// `notifications` is "work", "fail" (every notification call reports
// failure) or "throw" (every notification call throws).
export const standIn = ({
	items = [],
	selected = 0,
	maxMinor = 14,
	host = "Outlook",
	handlerFails = false,
	notifications = "work",
} = {}) => {
	const calls = [];
	let handler = null;
	let current = null;
	const broken = (callback) => {
		if (notifications === "work") return false;
		if (notifications === "throw") throw new Error("notifications refused");
		answer(callback, failed("notifications unavailable"));
		return true;
	};

	const message = ({
		label,
		id,
		from,
		to = [],
		cc = [],
		subject,
		attachments = [],
		html,
		headers = "",
	}) => {
		const placed = new Map();
		const recipients = (addresses) =>
			addresses.map((emailAddress) => ({ displayName: "", emailAddress }));
		const record = (call) =>
			calls.push({
				...call,
				item: label,
				...(current !== self && { stale: true }),
			});
		const self = {
			label,
			placed,
			itemType: "message",
			internetMessageId: id,
			from: from && { displayName: from.name, emailAddress: from.address },
			to: recipients(to),
			cc: recipients(cc),
			subject,
			attachments,
			body: {
				getAsync: (coercion, callback) => {
					record({ op: "body", coercion });
					answer(
						callback,
						html === null ? failed("body unavailable") : succeeded(html),
					);
				},
			},
			getAllInternetHeadersAsync: (callback) => {
				record({ op: "headers" });
				answer(
					callback,
					headers === null ? failed("headers unavailable") : succeeded(headers),
				);
			},
			notificationMessages: {
				getAllAsync: (callback) => {
					record({ op: "getAll" });
					if (broken(callback)) return;
					answer(
						callback,
						succeeded(
							Array.from(placed, ([key, details]) => ({ key, ...details })),
						),
					);
				},
				replaceAsync: (key, details, callback) => {
					const problem = notificationProblem(key, details);
					record({
						op: "replace",
						key,
						details: copy(details),
						...(problem && { problem }),
					});
					if (broken(callback)) return;
					if (!problem) placed.set(key, copy(details));
					answer(callback, problem ? failed(problem) : succeeded());
				},
				// What the real API does for a key that is not there is not
				// documented; failing is the stricter assumption.
				removeAsync: (key, callback) => {
					record({ op: "remove", key });
					if (broken(callback)) return;
					answer(
						callback,
						placed.delete(key) ? succeeded() : failed("no such notification"),
					);
				},
			},
		};
		return self;
	};

	const built = items.map((item) =>
		"raw" in item ? { label: item.label, ...item.raw } : message(item),
	);
	current = built[selected] ?? null;

	const Office = {
		HostType: { Outlook: "Outlook" },
		AsyncResultStatus: { Succeeded: "succeeded", Failed: "failed" },
		CoercionType: { Html: "html", Text: "text" },
		EventType: { ItemChanged: "olkItemSelectedChanged" },
		MailboxEnums: {
			ItemType: { Message: "message", Appointment: "appointment" },
			ItemNotificationMessageType: {
				ProgressIndicator: "progressIndicator",
				InformationalMessage: "informationalMessage",
				ErrorMessage: "errorMessage",
				InsightMessage: "insightMessage",
			},
		},
		// Outside an Office application the real library reports null for both.
		onReady: (callback) =>
			new Promise((resolve) => {
				setImmediate(() => {
					const info = { host, platform: host === null ? null : "Mac" };
					callback?.(info);
					resolve(info);
				});
			}),
		context: {
			requirements: {
				isSetSupported: (name, version) =>
					name === "Mailbox" && Number(version.split(".")[1]) <= maxMinor,
			},
			mailbox: {
				get item() {
					return current;
				},
				addHandlerAsync: (type, added, callback) => {
					calls.push({ op: "addHandler", type });
					if (!handlerFails) handler = added;
					answer(
						callback,
						handlerFails ? failed("handler refused") : succeeded(),
					);
				},
			},
		},
	};

	return {
		Office,
		calls,
		items: built,
		// Selects the item at `index` (none when there is no such index) and
		// raises ItemChanged, as Outlook does for a pinned pane.
		select: (index) => {
			current = built[index] ?? null;
			handler?.({ type: "olkItemSelectedChanged" });
		},
	};
};
