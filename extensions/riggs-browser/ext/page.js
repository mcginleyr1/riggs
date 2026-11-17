// biome-ignore lint/suspicious/noRedundantUseStrict: a content script is a classic script
"use strict";

// One block, no top-level names: banner.js and gmail.js run in the same
// isolated world, where two scripts declaring one name collide.
{
	// The i is for XHTML documents: there a selector compares the type attribute
	// by case, while the input itself does not.
	const FIELD = "input[type=password i]";
	// An element named "body" or "matches" answers for that property of its
	// document or form (LegacyOverrideBuiltIns in the HTML standard), and a
	// content script shares the page's DOM. So nothing is looked up on the
	// document or on a node that may be a form: built-ins come from the
	// prototypes, which the page cannot reach.
	const { closest, matches, querySelector } = Element.prototype;
	const { createTreeWalker, querySelectorAll } = Document.prototype;
	const { getRootNode } = Node.prototype;
	const ofDocument = (name) => Reflect.get(Document.prototype, name, document);
	// How many elements one click or Enter may look at in the shadow trees
	// around it.
	const LIMIT = 500;

	const typed = new WeakSet();
	// The password fields an event has led to. One inside a shadow tree is
	// known in no other way.
	const met = new Set();
	// Strongest first. Chrome marks a saved password as autofilled before a
	// script can read it, so that kind is asked of the selector and not of the
	// field's content. The prefixed selector works from Chrome 1, the bare one
	// needs 110 and the manifest allows 106.
	const EVIDENCE = [
		["typed", (field) => typed.has(field)],
		["autofill", (field) => matches.call(field, ":-webkit-autofill")],
		["filled", (field) => field.value !== ""],
	];
	let checked = false;
	let reported = false;

	const send = async (message) => {
		try {
			return await chrome.runtime.sendMessage(message);
		} catch {
			return null;
		}
	};

	const checkPage = async () => {
		const reply = await send({ t: "page" });
		const body = ofDocument("body");
		if (reply && body) riggsBanner(body, reply);
	};

	const holdsField = (node) =>
		node instanceof Element &&
		(matches.call(node, FIELD) || querySelector.call(node, FIELD) !== null);

	const onField = () => {
		if (checked || ofDocument("prerendering")) return;
		checked = true;
		fieldObserver.disconnect();
		checkPage();
	};

	const scan = () => {
		if (querySelectorAll.call(document, FIELD).length > 0) onField();
	};

	const fieldObserver = new MutationObserver((records) => {
		const appeared = records.some((record) =>
			record.type === "attributes"
				? holdsField(record.target)
				: Array.from(record.addedNodes).some(holdsField),
		);
		if (appeared) onField();
	});

	// chrome.dom opens closed shadow trees too and takes HTML elements only.
	// Where it is missing, or dead because the extension was reloaded, the
	// open tree is all there is.
	const shadowOf = (node) => {
		if (!(node instanceof HTMLElement)) return null;
		try {
			return chrome.dom.openOrClosedShadowRoot(node);
		} catch {
			return Reflect.get(Element.prototype, "shadowRoot", node);
		}
	};

	// At the window an event from inside a shadow tree names the tree's host.
	// The element it is about is the focused one, one tree further in at each
	// step. Focus that only moves inside a tree is announced inside it alone,
	// so each tree passed gets the focus listener as well.
	const focusedIn = (node) => {
		const root = shadowOf(node);
		root?.addEventListener("focusin", listeners.focusin, true);
		const inner = root?.activeElement;
		return inner ? focusedIn(inner) : node;
	};

	const meet = (field) => {
		met.add(field);
		onField();
	};

	const reach = (event) => {
		const target = focusedIn(event.target);
		if (target instanceof Element && matches.call(target, FIELD)) meet(target);
		return target;
	};

	// The form around a node, through the shadow trees it sits in.
	const formOf = (node) => {
		const root = getRootNode.call(node);
		return (
			closest.call(node, "form") ??
			(root instanceof ShadowRoot ? formOf(root.host) : null)
		);
	};

	// A password manager fills fields that nobody focuses, and in a shadow tree
	// nothing else finds them. So a click or Enter looks for them itself,
	// nearest first: in the tree its element hosts, then in each tree that
	// element sits in, with the form around it ahead of the tree the form is
	// in, and in every tree nested in those. It stops after LIMIT elements, so
	// that no page is stalled by a click.
	const lookAround = (target, form) => {
		let left = LIMIT;
		const seen = new Set();
		const look = (place) => {
			if (!place || seen.has(place)) return;
			seen.add(place);
			const walker = createTreeWalker.call(
				document,
				place,
				NodeFilter.SHOW_ELEMENT,
			);
			while (left > 0 && walker.nextNode()) {
				left -= 1;
				const node = walker.currentNode;
				if (matches.call(node, FIELD)) meet(node);
				look(shadowOf(node));
			}
		};
		const formRoot = form && getRootNode.call(form);
		look(shadowOf(target));
		for (
			let root = getRootNode.call(target);
			root instanceof ShadowRoot;
			root = getRootNode.call(root.host)
		) {
			if (root === formRoot) look(form);
			look(root);
		}
		look(form);
	};

	// A field counts for a click or Enter in its own form, and one outside any
	// form for a click or Enter outside any form.
	const reportLogin = (target) => {
		if (reported) return;
		const form = formOf(target);
		lookAround(target, form);
		const fields = [...querySelectorAll.call(document, FIELD), ...met].filter(
			(field) =>
				field.isConnected &&
				matches.call(field, FIELD) &&
				(field.form ?? formOf(field)) === form,
		);
		const [evidence] = EVIDENCE.find(([, holds]) => fields.some(holds)) ?? [];
		if (!evidence) return;
		reported = true;
		send({ t: "login", evidence });
	};

	const handlers = {
		prerenderingchange: scan,
		focusin: reach,
		pageshow: (event) => {
			if (!event.persisted) return;
			if (checked) checkPage();
			else scan();
		},
		// Chrome's autofill sends the field it fills a trusted keydown that has
		// no key (WebFormControlElement::SetAutofillValue), so only a key that
		// types a character counts as typing.
		keydown: (event) => {
			const target = reach(event);
			if (event.key === "Enter") reportLogin(target);
			else if (event.key?.length === 1) typed.add(target);
		},
		paste: (event) => typed.add(reach(event)),
		click: (event) => reportLogin(reach(event)),
	};
	const listeners = Object.fromEntries(
		Object.entries(handlers).map(([type, handler]) => [
			type,
			(event) => {
				if (event.isTrusted) handler(event);
			},
		]),
	);

	// On window, capturing, registered at document_start: nothing of the page
	// runs before these, so it cannot stop them, and it cannot mint a trusted
	// event. Adding the same function again changes nothing.
	const arm = () => {
		for (const [type, listener] of Object.entries(listeners)) {
			window.addEventListener(type, listener, true);
		}
		scan();
	};

	// document.open() erases every listener of the window and replaces the
	// document's children; observers stay. The listeners come back here, but
	// the page may by then have added some of its own ahead of them.
	new MutationObserver(arm).observe(document, { childList: true });
	fieldObserver.observe(document, {
		subtree: true,
		childList: true,
		attributeFilter: ["type"],
	});
	arm();
}
