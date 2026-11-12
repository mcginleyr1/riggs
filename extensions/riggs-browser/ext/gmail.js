// biome-ignore lint/suspicious/noRedundantUseStrict: a content script is a classic script
"use strict";

// The Gmail adapter of docs/PHISHING.md: one observation for each message the
// person opens. It shares an isolated world with banner.js and page.js, so
// everything stays inside this function and no global is declared.
(() => {
	// Gmail's page structure, as captured from a live mailbox
	// (test/fixtures/gmail/README.md). A message body is written by its sender,
	// so nothing inside one is ever taken for Gmail's own structure.
	const OUTSIDE_BODY = ":not(.a3s *)";
	const MESSAGE = `.adn.ads${OUTSIDE_BODY}`;
	const BODY = `.ii.gt > .a3s${OUTSIDE_BODY}`;
	const SUBJECT = `h2.hP${OUTSIDE_BODY}`;
	const SENDER = `span.gD[email]${OUTSIDE_BODY}`;
	const RECIPIENT = `.hb span.g2[email]${OUTSIDE_BODY}`;
	const ATTACHMENT = `.aQH > span.aZo[download_url]${OUTSIDE_BODY}`;
	const ATTACHMENT_NAME = "span.aV3";
	const QUIET_MS = 100;
	const LATEST_MS = 1000;
	// The elements that make a line of their own in a body's text.
	const BLOCKS = new Set(
		(
			"address article aside blockquote br dd div dl dt fieldset figcaption " +
			"figure footer form h1 h2 h3 h4 h5 h6 header hr li main nav ol p pre " +
			"section table td th tr ul"
		).split(" "),
	);

	const verdicts = new Map(); // id of a sent message -> verdict still to show, or null
	const asked = new WeakMap(); // anchor -> { id, banner } of the last banner call for it
	const unreadable = new WeakSet(); // expanded messages already reported as broken
	let quiet;
	let latest;

	// The worker being unreachable is the same as its answer `null`.
	const send = async (message) => {
		try {
			return await chrome.runtime.sendMessage(message);
		} catch {
			return null;
		}
	};

	// Gmail re-renders constantly, so a scan waits until the page has been quiet
	// for QUIET_MS. A page that never goes quiet is still scanned, LATEST_MS
	// after its first change.
	const schedule = () => {
		clearTimeout(quiet);
		quiet = setTimeout(scan, QUIET_MS);
		latest ??= setTimeout(scan, LATEST_MS);
	};

	// The text under a node as the daemon reads it, line by line: text nodes as
	// they are, a newline on each side of a block element, one newline for br and
	// hr, nothing from script and style. It needs no layout, so every builder
	// of a mail observation produces the same text. The nodes are written by the
	// sender and a form answers for the names of its controls (`form.childNodes`
	// may be an <input>), so both properties are read through the prototype.
	const textOf = (node) => {
		let text = "";
		for (const child of Reflect.get(Node.prototype, "childNodes", node)) {
			const tag = Reflect.get(Node.prototype, "nodeName", child).toLowerCase();
			if (tag === "#text") text += child.data;
			else if (tag === "br" || tag === "hr") text += "\n";
			else if (BLOCKS.has(tag)) text += `\n${textOf(child)}\n`;
			else if (tag !== "script" && tag !== "style") text += textOf(child);
		}
		return text;
	};

	// The observation for a message, or null when any required part is missing.
	const read = (message, id, body) => {
		const sender = message.querySelector(SENDER);
		const subject = message.closest('[role="main"]')?.querySelector(SUBJECT);
		const attachments = Array.from(
			message.querySelectorAll(ATTACHMENT),
			(card) => card.querySelector(ATTACHMENT_NAME)?.textContent,
		);
		const complete =
			id &&
			body &&
			subject &&
			sender?.getAttribute("email") &&
			attachments.every((name) => name);
		if (!complete) return null;
		return {
			provider: "gmail",
			message_id: id,
			from_name: sender.getAttribute("name") ?? "",
			from_addr: sender.getAttribute("email"),
			reply_to: null,
			to: Array.from(message.querySelectorAll(RECIPIENT), (recipient) =>
				recipient.getAttribute("email"),
			),
			subject: subject.textContent,
			body_text: textOf(body),
			links: Array.from(
				body.querySelectorAll("a[href], area[href]"),
				(link) => ({
					text: textOf(link).replace(/\s+/g, " ").trim(),
					href: link.getAttribute("href"),
				}),
			),
			attachments,
		};
	};

	// Brings what is shown directly above a message's body in line with that
	// message's verdict: asks for the banner once for each anchor, and again
	// when the banner it was given is no longer the anchor's previous sibling.
	// A banner that a replaced anchor left behind is the banner call's to remove.
	const refresh = (id, anchor) => {
		const verdict = verdicts.get(id);
		const last = asked.get(anchor);
		// Gmail has put another message into this element: its banner goes.
		if (last && last.id !== id) last.banner?.remove();
		const shown =
			last?.id === id &&
			(last.banner === null || last.banner === anchor.previousElementSibling);
		if (!verdict || shown) return;
		let banner;
		try {
			banner = riggsBanner(anchor, verdict) ?? null;
		} catch (error) {
			// A verdict the banner refuses is dropped, so that it throws once
			// instead of on every scan, and the rest of the page is scanned again.
			verdicts.set(id, null);
			schedule();
			throw error;
		}
		asked.set(anchor, { id, banner });
		if (!banner) return;
		// The dismiss control has removed the banner by the time its click
		// arrives here (docs/PHISHING.md, "The banner call"). A banner the person
		// dismissed stays away; one that Gmail removed is drawn again.
		banner.addEventListener("click", () => {
			if (!banner.isConnected) verdicts.set(id, null);
		});
	};

	const scan = () => {
		clearTimeout(quiet);
		clearTimeout(latest);
		latest = undefined;
		// An element named like a property of `document` shadows that property
		// (<img name="querySelectorAll">), and a mail may bring one into the page,
		// so the document is only reached through its prototype.
		//
		// The worker refuses a document that is not shown yet (docs/PHISHING.md,
		// "Who may send"), and a message it refused would never be sent again.
		if (Reflect.get(Document.prototype, "prerendering", document)) return;
		const messages = Document.prototype.querySelectorAll.call(
			document,
			MESSAGE,
		);
		for (const message of messages) {
			const id = message.getAttribute("data-legacy-message-id");
			const body = message.querySelector(BODY);
			if (!verdicts.has(id)) {
				const obs = read(message, id, body);
				if (obs) {
					verdicts.set(id, null);
					send({ t: "mail", obs }).then((reply) => {
						if (!reply) return;
						verdicts.set(id, reply);
						schedule();
					});
					send({ t: "adapter", provider: "gmail", ok: true });
				} else if (!unreadable.has(message)) {
					unreadable.add(message);
					send({ t: "adapter", provider: "gmail", ok: false });
				}
			}
			if (body) refresh(id, body.parentElement);
		}
	};

	new MutationObserver(schedule).observe(document, {
		subtree: true,
		childList: true,
		attributes: true,
		characterData: true,
	});
	Document.prototype.addEventListener.call(
		document,
		"prerenderingchange",
		schedule,
	);
	schedule();
})();
