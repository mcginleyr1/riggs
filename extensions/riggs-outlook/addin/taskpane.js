// biome-ignore lint/suspicious/noRedundantUseStrict: the pane loads this file as a classic script
"use strict";

// The Riggs pane for Outlook. For the selected message it builds one mail
// observation, posts it to the bridge that served this page, and shows the
// daemon's verdict in the pane and in one notification on the message. The
// daemon decides; nothing is scored here. Mail content is only ever handled as
// text: the body is parsed with DOMParser and never enters this document.
//
// Everything is inside one function because Office.js shares the page's global
// scope: a name declared at the top level here could collide with one of its
// own, and a collision is a SyntaxError for whichever script loads second.
(() => {
	const NOTIFICATION_KEY = "riggs";
	// An image id from the manifest's Resources: Office requires one for an
	// informational message.
	const NOTIFICATION_ICON = "icon-16";
	const NOTIFICATION_LIMIT = 150;

	// docs/PHISHING.md, "Capping". The daemon's field limits are UTF-8 bytes;
	// the pane cuts at the same numbers counted in UTF-16 units and keeps the
	// whole request under the budget, so that it always arrives. The bridge
	// then cuts to the byte. The body is the exception: filler is removed from
	// it before any cut, here and again in the bridge, and the pane's own cut
	// is far above the daemon's 65,536 bytes.
	const BODY_LIMIT = 1000000;
	const PADDING_RUN = 256;
	const HREF_LIMIT = 8192;
	const STRING_LIMIT = 4096;
	const LIST_LIMIT = 500;
	const ATTACHMENT_LIMIT = 100;
	const REQUEST_BUDGET = 6 * 1024 * 1024;

	const HEADINGS = {
		caution: "Be careful with this message.",
		danger: "This message may be phishing.",
	};
	const CHECKING = "Checking this message.";
	const NOTHING_TO_SHOW =
		"Riggs has nothing to show for this message. That is not a promise about it.";
	const UNREADABLE =
		"Riggs could not read this message, so it was not checked.";
	const NO_ANSWER =
		"Riggs did not check this message. It may be stopped, or phishing protection may be switched off.";
	const UNEXPECTED_ANSWER =
		"Riggs could not check this message (unexpected answer).";
	const NO_MESSAGE = "No message is selected.";
	const NOT_A_MESSAGE =
		"Riggs checks messages you are reading. This item is not one.";
	const OUTSIDE_OUTLOOK =
		"This page is the Riggs pane for Outlook. It does nothing outside Outlook.";
	const NOT_FOLLOWING =
		"Outlook did not let Riggs follow your selection, so only the message this pane was opened on is checked.";

	// Every Riggs mail sensor turns a body into text by the same walk, so that
	// the daemon sees the same lines whichever sensor read the message: a block
	// element is a line of its own, script and style are skipped, and no layout
	// is needed, which a parsed but unrendered document does not have.
	const BLOCKS = new Set([
		"address",
		"article",
		"aside",
		"blockquote",
		"br",
		"dd",
		"div",
		"dl",
		"dt",
		"fieldset",
		"figcaption",
		"figure",
		"footer",
		"form",
		"h1",
		"h2",
		"h3",
		"h4",
		"h5",
		"h6",
		"header",
		"hr",
		"li",
		"main",
		"nav",
		"ol",
		"p",
		"pre",
		"section",
		"table",
		"td",
		"th",
		"tr",
		"ul",
	]);

	// Iterative, so that deeply nested markup cannot exhaust the stack.
	const textOf = (root) => {
		const parts = [];
		const pending = [root];
		while (pending.length > 0) {
			const node = pending.pop();
			if (typeof node === "string") {
				parts.push(node);
			} else if (node.nodeType === Node.TEXT_NODE) {
				parts.push(node.data);
			} else if (
				node.nodeType === Node.ELEMENT_NODE &&
				node.localName !== "script" &&
				node.localName !== "style"
			) {
				if (BLOCKS.has(node.localName)) {
					parts.push("\n");
					// br and hr have no content: one line break, not two.
					if (node.localName !== "br" && node.localName !== "hr") {
						pending.push("\n");
					}
				}
				for (let child = node.lastChild; child; child = child.previousSibling) {
					pending.push(child);
				}
			}
		}
		return parts.join("");
	};

	// RFC 5322: a folded header continues on lines that start with a space or
	// a tab; a display name may be a quoted string and a comment sits in
	// parentheses, and comments nest. Both are removed in one pass before the
	// address is taken, so that an address written inside them cannot stand in
	// for the one replies go to. A backslash escapes the next character, a quote
	// inside a comment and a parenthesis inside a quoted string are plain text.
	// An unterminated comment or quoted string runs to the end of the value:
	// mail clients disagree there, and dropping the rest never reports an
	// address the sender hid inside it.
	const replyToAddress = (headers) => {
		const field = headers
			.replace(/\r?\n[ \t]+/g, " ")
			.match(/^Reply-To:(.*)$/im);
		if (!field) return null;
		let depth = 0;
		let quoted = false;
		let value = "";
		for (let i = 0; i < field[1].length; i++) {
			const c = field[1][i];
			if (c === "\\") {
				i++;
				if (depth === 0 && !quoted) value += c + (field[1][i] ?? "");
			} else if (quoted) quoted = c !== '"';
			else if (depth > 0) depth += c === "(" ? 1 : c === ")" ? -1 : 0;
			else if (c === "(") depth = 1;
			else if (c === '"') quoted = true;
			else value += c;
		}
		const address = (
			value.match(/<([^<>]*)>/)?.[1] ?? value.split(",")[0]
		).trim();
		return address === "" ? null : address;
	};

	// Office.js answers through a callback that receives an AsyncResult. A
	// failed call, or one that Office refuses outright, gives null.
	const call = (start) =>
		new Promise((resolve) => {
			start((result) =>
				resolve(
					result.status === Office.AsyncResultStatus.Succeeded
						? result.value
						: null,
				),
			);
		}).catch(() => null);

	const bytes = (text) => new TextEncoder().encode(text).length;

	// A cut must not leave half of a surrogate pair behind.
	const fit = (text, limit) =>
		text.length <= limit
			? text
			: `${text.slice(0, limit - 1).replace(/[\ud800-\udbff]$/, "")}\u{2026}`;

	const show = (line, level = "", reasons = []) => {
		const state = document.getElementById("state");
		state.textContent = line;
		state.className = level;
		document.getElementById("reasons").replaceChildren(
			...reasons.map((reason) => {
				const row = document.createElement("li");
				row.textContent = reason;
				return row;
			}),
		);
	};

	// The request body for the selected message, or null when its id, its
	// sender address or its body cannot be read: a half-read message must not
	// be judged.
	const request = async (item) => {
		// The item object follows the selection, so its plain properties are
		// read before the first await.
		const id = item.internetMessageId;
		const sender = item.from?.emailAddress;
		const senderName = item.from?.displayName;
		const subject = item.subject;
		const recipients = [...item.to, ...item.cc]
			.map((recipient) => recipient.emailAddress)
			.filter((address) => typeof address === "string");
		const attachments = item.attachments
			.filter((attachment) => !attachment.isInline)
			.map((attachment) => attachment.name)
			.filter((name) => typeof name === "string");
		if (typeof id !== "string" || id === "") return null;
		if (typeof sender !== "string" || sender === "") return null;

		const html = await call((done) =>
			item.body.getAsync(Office.CoercionType.Html, done),
		);
		if (typeof html !== "string") return null;
		const headers = Office.context.requirements.isSetSupported("Mailbox", "1.8")
			? await call((done) => item.getAllInternetHeadersAsync(done))
			: null;
		const replyTo =
			typeof headers === "string" ? replyToAddress(headers) : null;
		const body = new DOMParser().parseFromString(html, "text/html").body;

		let truncated = false;
		// A lone surrogate, which a cut can create and a mail can contain,
		// would make the bridge's JSON parser refuse the whole request. With
		// the u flag a pattern reads a surrogate pair as one character, so only
		// a lone one matches.
		const text = (value, limit) => {
			truncated ||= value.length > limit;
			return value.slice(0, limit).replace(/\p{Surrogate}/gu, "\u{fffd}");
		};
		const first = (values, limit) => {
			truncated ||= values.length > limit;
			return values.slice(0, limit);
		};
		// Phishing hides its text behind filler: one long run of these
		// characters, which a cut would keep in place of the text. No prose has
		// such a run, so each becomes one space before anything is cut; the
		// bridge applies the same rule. Every run is matched once and judged by
		// its length: a {257,} pattern would start again at each character of
		// every shorter run.
		const bodyText = textOf(body).replace(/[A-Za-z0-9+/=_-]+/g, (run) => {
			if (run.length <= PADDING_RUN) return run;
			truncated = true;
			return " ";
		});
		const observation = {
			provider: "outlook_addin",
			message_id: text(id, STRING_LIMIT),
			from_name: text(
				typeof senderName === "string" ? senderName : "",
				STRING_LIMIT,
			),
			from_addr: text(sender, STRING_LIMIT),
			reply_to: replyTo === null ? null : text(replyTo, STRING_LIMIT),
			to: first(recipients, LIST_LIMIT).map((address) =>
				text(address, STRING_LIMIT),
			),
			subject: text(subject, STRING_LIMIT),
			body_text: text(bodyText, BODY_LIMIT),
			// An area is an image map's clickable region; it has no text.
			links: first(
				Array.from(body.querySelectorAll("a[href], area[href]")),
				LIST_LIMIT,
			).map((link) => ({
				text: text(textOf(link).replace(/\s+/g, " ").trim(), STRING_LIMIT),
				href: text(link.getAttribute("href"), HREF_LIMIT),
			})),
			attachments: first(attachments, ATTACHMENT_LIMIT).map((name) =>
				text(name, STRING_LIMIT),
			),
			truncated: false,
		};
		observation.truncated = truncated;

		let json = JSON.stringify(observation);
		let size = bytes(json);
		if (size > REQUEST_BUDGET) {
			// Whole entries go, from the end: links first, then recipients.
			for (const list of [observation.links, observation.to]) {
				while (size > REQUEST_BUDGET && list.length > 0) {
					size -= bytes(JSON.stringify(list.pop()));
				}
			}
			// With both lists empty, everything but the body is under 3 MiB
			// whatever it contains. Only a body made of characters that JSON
			// escapes is still too much then. None takes more than six bytes,
			// and the body's two quotation marks take two.
			if (size > REQUEST_BUDGET) {
				const rest = size - bytes(JSON.stringify(observation.body_text));
				observation.body_text = text(
					observation.body_text,
					Math.floor((REQUEST_BUDGET - rest - 2) / 6),
				);
			}
			observation.truncated = true;
			json = JSON.stringify(observation);
		}
		return json;
	};

	// What the bridge's answer means for the display: null when there is
	// nothing to show, the level and its reasons for a verdict, undefined for
	// an answer that is neither.
	const display = (verdict) => {
		if (verdict === null || verdict?.level === "none") return null;
		if (!Object.hasOwn(HEADINGS, verdict?.level)) return undefined;
		if (!Array.isArray(verdict.reasons)) return undefined;
		const reasons = verdict.reasons.map((reason) => reason?.text);
		return reasons.every((reason) => typeof reason === "string")
			? { level: verdict.level, reasons }
			: undefined;
	};

	let latest = 0;

	// A newer selection supersedes a check that is still waiting: the older
	// one stops without showing anything and without touching a notification,
	// because by then the item object stands for the newly selected message.
	const check = async () => {
		latest += 1;
		const run = latest;
		const superseded = () => run !== latest;
		const item = Office.context.mailbox.item;
		if (!item) {
			show(NO_MESSAGE);
			return;
		}
		if (
			item.itemType !== Office.MailboxEnums.ItemType.Message ||
			typeof item.subject !== "string"
		) {
			show(NOT_A_MESSAGE);
			return;
		}
		show(CHECKING);

		const body = await request(item).catch(() => null);
		if (superseded()) return;
		if (body === null) {
			show(UNREADABLE);
			return;
		}

		// A relative address: the token in this page's path never appears here.
		const response = await fetch("observe", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body,
		}).catch(() => null);
		if (superseded()) return;
		if (response === null || response.status === 503) {
			show(NO_ANSWER);
			return;
		}
		if (!response.ok) {
			show(
				`Riggs could not check this message (bridge status ${response.status}).`,
			);
			return;
		}
		const result = display(await response.json().catch(() => undefined));
		if (superseded()) return;

		const notifications = item.notificationMessages;
		if (result === undefined) {
			show(UNEXPECTED_ANSWER);
		} else if (result === null) {
			show(NOTHING_TO_SHOW);
			const placed = await call((done) => notifications.getAllAsync(done));
			if (superseded()) return;
			if (placed?.some(({ key }) => key === NOTIFICATION_KEY)) {
				call((done) => notifications.removeAsync(NOTIFICATION_KEY, done));
			}
		} else {
			const heading = HEADINGS[result.level];
			show(heading, result.level, result.reasons);
			// Not persistent: nothing Riggs writes may stay stored on a message.
			call((done) =>
				notifications.replaceAsync(
					NOTIFICATION_KEY,
					{
						type: Office.MailboxEnums.ItemNotificationMessageType
							.InformationalMessage,
						icon: NOTIFICATION_ICON,
						persistent: false,
						message: fit(
							["Riggs:", heading, ...result.reasons.slice(0, 1)].join(" "),
							NOTIFICATION_LIMIT,
						),
					},
					done,
				),
			);
		}
	};

	Office.onReady((info) => {
		if (info.host !== Office.HostType.Outlook) {
			show(OUTSIDE_OUTLOOK);
			return;
		}
		Office.context.mailbox.addHandlerAsync(
			Office.EventType.ItemChanged,
			check,
			(result) => {
				if (result.status !== Office.AsyncResultStatus.Succeeded) {
					document.getElementById("pin").textContent = NOT_FOLLOWING;
				}
			},
		);
		check();
	});
})();
