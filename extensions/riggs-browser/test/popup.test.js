import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { Script } from "node:vm";
import { JSDOM } from "jsdom";

const ext = join(import.meta.dirname, "..", "ext");
const html = readFileSync(join(ext, "popup.html"), "utf8");
const file = join(ext, "popup.js");
const script = new Script(readFileSync(file, "utf8"), { filename: file });

const UNPROTECTED = "Riggs is not protecting this browser";
const REINSTALL = "If you still see this, run the Riggs installer again.";

const text = ({ document }) => [
	document.querySelector("h1").textContent,
	...Array.from(document.querySelectorAll("p"), (line) => line.textContent),
];

// Opens the popup with a worker that answers the status message with
// `answer()`, and returns the text it then shows: the headline, then each line.
const popup = async (answer) => {
	const dom = new JSDOM(html, { runScripts: "outside-only" });
	const sent = [];
	dom.window.chrome = {
		runtime: {
			sendMessage: async (message) => {
				sent.push(structuredClone(message));
				return answer();
			},
		},
	};
	script.runInContext(dom.getInternalVMContext());
	assert.deepEqual(text(dom.window), ["Checking Riggs…"]);
	await new Promise((resolve) => setImmediate(resolve));
	assert.deepEqual(sent, [{ t: "status" }]);
	return text(dom.window);
};

const shows = async (status, expected) =>
	assert.deepEqual(await popup(() => status), expected);

test("warn mode: protection is on, with the login sites and each mail site's health", async () => {
	const on = [
		"Protection is on",
		"Riggs checks the mail you open and the pages that ask for a password, and warns you when one looks like a trick to steal your password.",
		'A "!" on the Riggs icon means Riggs warned you about something in that tab.',
	];
	await shows({ state: "ok", mode: "warn", logins: 12, adapters: {} }, [
		...on,
		"Sites where Riggs has seen you sign in: 12",
		"Mail in Gmail: no message opened yet.",
	]);
	await shows(
		{ state: "ok", mode: "warn", logins: 0, adapters: { gmail: true } },
		[
			...on,
			"Sites where Riggs has seen you sign in: 0",
			"Mail in Gmail: working.",
		],
	);
	await shows(
		{ state: "ok", mode: "warn", logins: 1, adapters: { gmail: false } },
		[
			...on,
			"Sites where Riggs has seen you sign in: 1",
			"Mail in Gmail: not working. Riggs could not read the last message you opened, so it was not checked. If this goes on, Riggs needs an update.",
		],
	);
});

test("monitor mode is explained in one line", async () => {
	await shows(
		{ state: "ok", mode: "monitor", logins: 3, adapters: { gmail: true } },
		[
			"Monitor mode",
			"Riggs is recording what it would flag and showing no warnings.",
			"Sites where Riggs has seen you sign in: 3",
			"Mail in Gmail: working.",
		],
	);
});

test("off mode says who can switch protection on, and how", async () => {
	await shows(
		{ state: "ok", mode: "off", logins: 3, adapters: { gmail: true } },
		[
			"Protection is switched off",
			"Riggs is not checking mail or pages. Whoever looks after Riggs on this computer can switch it on with: sudo riggs phishing mode warn",
		],
	);
});

test("each failure state says that Riggs is not protecting and what to do", async () => {
	const failures = {
		host_not_found:
			"Riggs is not installed on this computer, or its installer did not finish. Run the Riggs installer, then open this window again.",
		host_forbidden:
			"This copy of the Riggs extension is not the one the Riggs installer set up, so Riggs will not answer it. Remove it, run the Riggs installer again and load the extension it provides.",
		host_exited: `The Riggs helper stopped before it could answer. Open this window again. ${REINSTALL}`,
		daemon_unreachable: `The Riggs service is not running. Restart your computer. ${REINSTALL}`,
		error: `Riggs gave an answer this extension does not understand. Open this window again. ${REINSTALL}`,
	};
	for (const [state, line] of Object.entries(failures))
		await shows({ state, adapters: { gmail: true } }, [UNPROTECTED, line]);
});

test("no status at all, refused or unreachable, says the extension is not answering", async () => {
	const unanswered = [
		UNPROTECTED,
		"The Riggs extension is not answering. Restart the browser. If you still see this, remove the Riggs extension and load it again.",
	];
	await shows(null, unanswered);
	assert.deepEqual(
		await popup(() => {
			throw new Error("constructed rejection");
		}),
		unanswered,
	);
});
