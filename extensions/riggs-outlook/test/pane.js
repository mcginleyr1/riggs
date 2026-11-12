// Loads the real pane page in jsdom the way a browser would: the page asks
// for its two scripts itself. Nothing reaches the network: every request
// jsdom makes is answered here and recorded, Office.js is replaced by the
// stand-in, and fetch is scripted by the test.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { JSDOM, requestInterceptor, VirtualConsole } from "jsdom";
import { standIn } from "./office-stand-in.js";

const addin = join(import.meta.dirname, "..", "addin");
const page = readFileSync(join(addin, "taskpane.html"), "utf8");
const script = readFileSync(join(addin, "taskpane.js"), "utf8");

export const PAGE_URL =
	"https://localhost:41443/0123456789abcdef0123456789abcdef/taskpane.html";
export const SCRIPT_URL = new URL("taskpane.js", PAGE_URL).href;
// The address Microsoft documents for the library (see taskpane.html).
export const OFFICE_JS =
	"https://officeapis.public.onecdn.static.microsoft/1/office.js";
// What the page says by itself, until its script has heard from Office.js.
export const WAITING = new JSDOM(page).window.document.getElementById(
	"state",
).textContent;

const javascript = (text) =>
	new Response(text, { headers: { "Content-Type": "text/javascript" } });

// What the bridge can answer to POST observe; each is one entry of `answers`.
export const bridge = {
	json: (value) => () =>
		Promise.resolve(
			new Response(JSON.stringify(value), {
				headers: { "Content-Type": "application/json" },
			}),
		),
	status: (status) => () => Promise.resolve(new Response(null, { status })),
	text: (text) => () => Promise.resolve(new Response(text)),
	unreachable: () => () => Promise.reject(new TypeError("Load failed")),
};

// `answers` are used in order, one per POST; after the last one the bridge
// answers null. Every other option goes to the Office stand-in.
export const open = async ({ answers = [], ...options } = {}) => {
	const office = standIn(options);
	const requests = [];
	const posts = [];
	const errors = [];
	const virtualConsole = new VirtualConsole();
	virtualConsole.on("jsdomError", (error) => errors.push(error));

	const dom = new JSDOM(page, {
		url: PAGE_URL,
		runScripts: "dangerously",
		virtualConsole,
		resources: {
			interceptors: [
				requestInterceptor((request) => {
					requests.push(request.url);
					if (request.url === OFFICE_JS) return javascript("");
					if (request.url === SCRIPT_URL) return javascript(script);
					return new Response(null, { status: 404 });
				}),
			],
		},
		beforeParse: (window) => {
			window.Office = office.Office;
			// jsdom has neither; every engine the pane runs in has both.
			window.TextEncoder = TextEncoder;
			window.fetch = (url, { method, headers, body }) => {
				posts.push({ url, method, headers: { ...headers }, body });
				return (answers.shift() ?? bridge.json(null))();
			};
		},
	});
	const { document } = dom.window;
	await new Promise((resolve) => {
		dom.window.addEventListener("load", resolve);
	});
	if (errors.length > 0) throw errors[0];

	const state = () => document.getElementById("state").textContent;
	return {
		document,
		window: dom.window,
		calls: office.calls,
		items: office.items,
		select: office.select,
		requests,
		posts,
		state,
		level: () => document.getElementById("state").className,
		reasons: () =>
			Array.from(
				document.querySelectorAll("#reasons li"),
				(row) => row.textContent,
			),
		// Waits until the pane shows something other than its two waiting lines.
		settled: async () => {
			for (let turn = 0; turn < 1000; turn += 1) {
				await new Promise(setImmediate);
				if (errors.length > 0) throw errors[0];
				if (state() !== WAITING && state() !== "Checking this message.") return;
			}
			throw new Error(`the pane did not settle; it shows "${state()}"`);
		},
	};
};
