/**
 * Explicitly authorized Dive authentication probe. Tokens stay in memory; existing
 * ./tokens-real files are never overwritten. Add --yes-write-to-real-account for
 * one private, excluded-from-numbering fixture, read-back and fixture-only cleanup.
 */
import "./load-env.js";
import { randomUUID } from "node:crypto";
import { GarminClient, Garmin, FileTokenStore, GarminHttpError } from "../src/index.js";
import { setExpirations, type RawOAuth2Token } from "../src/auth/tokens.js";

const saved = await new FileTokenStore("./tokens-real").load();
if (!saved) throw new Error("No valid tokens in ./tokens-real; run npm run login:real.");
const normalClient = new GarminClient({ retries: 0 });
normalClient.setTokens(saved);
const normal = new Garmin(normalClient);
const profile = await normal.getUserProfile();
if (String(profile.profileId) === process.env["GARMIN_TEST_PROFILE_ID"]) {
  throw new Error("Expected the explicitly authorized real account, not the test account.");
}
const expected = process.env["GARMIN_REAL_PROFILE_ID"];
if (expected && String(profile.profileId) !== expected) throw new Error("Real profile mismatch.");
const tokens = normalClient.getTokens()!;
const scopes = (value: string | string[]) => new Set(Array.isArray(value) ? value : value.split(/\s+/));
const originalScopes = scopes(tokens.oauth2.scope);
const clientId = "DIVE_MOBILE_ANDROID_DI";
const body = new URLSearchParams({
  client_id: clientId,
  subject_token: tokens.oauth2.access_token,
  subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
});
if (tokens.oauth1.mfa_token) body.set("mfa_token", tokens.oauth1.mfa_token);
const exchangeStarted = performance.now();
const response = await fetch("https://connectapi.garmin.com/di-oauth2-service/oauth/token", {
  method: "POST",
  headers: {
    authorization: `Basic ${Buffer.from(`${clientId}:`).toString("base64")}`,
    "content-type": "application/x-www-form-urlencoded",
    "user-agent": "com.garmin.android.apps.dive",
  },
  body,
  signal: AbortSignal.timeout(30000),
});
console.log("Dive token exchange HTTP status:", response.status);
if (!response.ok) {
  // Never print arbitrary authentication responses: they may contain credentials.
  throw new Error("Dive token exchange rejected; response body intentionally withheld.");
}
const raw = await response.json() as RawOAuth2Token;
if (!raw.access_token || !Number.isFinite(raw.expires_in) || raw.expires_in < 120) {
  throw new Error("Exchange did not return a usable access token.");
}
console.log("Dive token lifetime (seconds):", raw.expires_in);
console.log("Dive refresh-token lifetime (seconds):", raw.refresh_token_expires_in ?? "not supplied");
console.log("Dive token exchange duration (ms):", Math.round(performance.now() - exchangeStarted));
const diveScopes = scopes(raw.scope);
console.log("Original scope count:", originalScopes.size);
console.log("Dive scope count:", diveScopes.size);
console.log("Scopes added:", [...diveScopes].filter((s) => !originalScopes.has(s)).sort());
console.log("Scopes removed:", [...originalScopes].filter((s) => !diveScopes.has(s)).sort());
console.log("Dive write scope:", diveScopes.has("DIVE_API_WRITE"));

const diveClient = new GarminClient({ retries: 0 });
diveClient.setTokens({ oauth1: tokens.oauth1, oauth2: setExpirations(raw) });
const dive = new Garmin(diveClient);
const checks: [string, () => Promise<unknown>][] = [
  ["social profile / same account", async () => {
    const p = await dive.getUserProfile();
    if (p.profileId !== profile.profileId) throw new Error("Profile mismatch");
    return p;
  }],
  ["user settings", () => dive.getUserSettings()],
  ["activity list", () => dive.getActivities(0, 1)],
  ["workout library", () => dive.getWorkouts(0, 1)],
  ["sleep", () => dive.getSleepData(new Date())],
  ["Dive log", () => dive.getDiveLogs({ requestedPage: 0, resultsPerPage: 1 })],
  ["original token still works", () => new Garmin(normalClient).getUserProfile()],
];
for (const [label, check] of checks) {
  try {
    await check();
    console.log("PASS", label);
  } catch {
    console.log("FAIL", label, "(error details withheld)");
  }
}

if (!process.argv.includes("--yes-write-to-real-account")) {
  console.log("Read-only probe complete; no Dive data written.");
  process.exit(0);
}
if (!diveScopes.has("DIVE_API_WRITE")) throw new Error("Refusing fixture without Dive write scope.");
const name = `gcjs FAKE AUTH TEST - DELETE ${randomUUID()}`;
let fixtureId: number | undefined;
async function cleanup(id: number) {
  await normal.deleteDiveLog(id, { renumberSubsequentDives: false });
  console.log("Fixture delete completed; Dive ID:", id);
  try {
    await normal.getDiveLog(id);
  } catch (error) {
    if (error instanceof GarminHttpError && error.status === 404) {
      console.log("PASS deleted fixture detail returns 404");
      return;
    }
    throw error;
  }
  throw new Error("Deleted fixture detail still accessible.");
}
try {
  // Exercise production lazy token routing, not just the manually seeded Dive client above.
  const created = await normal.createDiveLog({
    name,
    startTime: new Date(Date.now() - 3600000).toISOString(),
    timezone: "UTC",
    diveType: "SINGLE_GAS",
    bottomTime: 60,
    profile: { maxDepth: 2, averageDepth: 1, bottomTime: 60 },
    excludedFromDLN: true,
    connectPrivacy: { typeKey: "private" },
    notes: "Synthetic authentication test, not a real dive. Safe to delete.",
  }, { renumberSubsequentDives: false });
  if (created?.id) fixtureId = created.id;
  if (!fixtureId) throw new Error("Create returned no fixture ID; cleanup discovery required.");
  console.log("Fixture created; Dive ID:", fixtureId);
  const stored = await normal.getDiveLog(fixtureId);
  if (stored?.name !== name || stored.excludedFromDLN !== true) throw new Error("Fixture read-back mismatch.");
  console.log("PASS fixture stored and excluded from dive numbering");
} finally {
  if (fixtureId) await cleanup(fixtureId);
}
