// biome-ignore lint/suspicious/noRedundantUseStrict: the page loads this as a classic script
"use strict";

const closeButton = document.getElementById("close");
const continueButton = document.getElementById("continue");
const ask = (t) => chrome.runtime.sendMessage({ t }).catch(() => null);

closeButton.focus();
closeButton.addEventListener("click", async () => {
	const tab = await chrome.tabs.getCurrent();
	chrome.tabs.remove(tab.id);
});

// The worker opens the page again when it knows the address and answers null
// either way, so what is shown afterwards has to hold in both cases.
continueButton.addEventListener("click", () => {
	ask("continue");
	closeButton.disabled = true;
	continueButton.disabled = true;
	document.getElementById("advice").hidden = true;
	document.getElementById("continued").hidden = false;
});

ask("blocked").then((blocked) => {
	const state = document.getElementById(blocked ? "blocked" : "clear");
	if (blocked) {
		document.getElementById("host").textContent = blocked.host;
		document.getElementById("reasons").append(
			...blocked.reasons.map((reason) => {
				const item = document.createElement("li");
				item.textContent = reason.text;
				return item;
			}),
		);
		// The page behind this warning chose the moment it appeared, so a click
		// that was already on its way must not be able to land on Continue.
		continueButton.hidden = false;
		setTimeout(() => {
			continueButton.disabled = false;
		}, 2000);
	}
	document.title = state.querySelector("h1").textContent;
	state.hidden = false;
});
