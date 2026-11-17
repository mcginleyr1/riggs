// Toolbar popup: asks the worker for its status (docs/PHISHING.md, "Messages to
// the worker") and says in plain words what it means and what to do.

const UNPROTECTED = "Riggs is not protecting this browser";
const REINSTALL = "If you still see this, run the Riggs installer again.";

// Each text is a headline followed by lines.
const MODE_TEXT = {
	warn: [
		"Protection is on",
		"Riggs checks the mail you open and the pages that ask for a password, and warns you when one looks like a trick to steal your password.",
		'A "!" on the Riggs icon means Riggs warned you about something in that tab.',
	],
	monitor: [
		"Monitor mode",
		"Riggs is recording what it would flag and showing no warnings.",
	],
	off: [
		"Protection is switched off",
		"Riggs is not checking mail or pages. Whoever looks after Riggs on this computer can switch it on with: sudo riggs phishing mode warn",
	],
};
const FAILURE_TEXT = {
	host_not_found: [
		UNPROTECTED,
		"Riggs is not installed on this computer, or its installer did not finish. Run the Riggs installer, then open this window again.",
	],
	host_forbidden: [
		UNPROTECTED,
		"This copy of the Riggs extension is not the one the Riggs installer set up, so Riggs will not answer it. Remove it, run the Riggs installer again and load the extension it provides.",
	],
	host_exited: [
		UNPROTECTED,
		`The Riggs helper stopped before it could answer. Open this window again. ${REINSTALL}`,
	],
	daemon_unreachable: [
		UNPROTECTED,
		`The Riggs service is not running. Restart your computer. ${REINSTALL}`,
	],
	error: [
		UNPROTECTED,
		`Riggs gave an answer this extension does not understand. Open this window again. ${REINSTALL}`,
	],
};
// No status at all: the worker refused, failed or could not be reached.
const NO_ANSWER = [
	UNPROTECTED,
	"The Riggs extension is not answering. Restart the browser. If you still see this, remove the Riggs extension and load it again.",
];

const MAIL_SITES = { gmail: "Gmail" };
// Keyed by an adapter's latest report: true, false, or none yet.
const MAIL_HEALTH = {
	true: "working.",
	false:
		"not working. Riggs could not read the last message you opened, so it was not checked. If this goes on, Riggs needs an update.",
	undefined: "no message opened yet.",
};

const textFor = (status) => {
	if (status?.state !== "ok") return FAILURE_TEXT[status?.state] ?? NO_ANSWER;
	if (status.mode === "off") return MODE_TEXT.off;
	return [
		...MODE_TEXT[status.mode],
		`Sites where Riggs has seen you sign in: ${status.logins}`,
		...Object.entries(MAIL_SITES).map(
			([provider, site]) =>
				`Mail in ${site}: ${MAIL_HEALTH[status.adapters[provider]]}`,
		),
	];
};

const show = (status) => {
	const [headline, ...lines] = textFor(status);
	document.getElementById("headline").textContent = headline;
	document.getElementById("lines").replaceChildren(
		...lines.map((line) => {
			const paragraph = document.createElement("p");
			paragraph.textContent = line;
			return paragraph;
		}),
	);
};

chrome.runtime.sendMessage({ t: "status" }).then(show, () => show(null));
