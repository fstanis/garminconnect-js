import { afterEach, describe, expect, it, vi } from "vitest";
import { GarminAuthError, GarminClient, type MfaState } from "garminconnect-js";
// eslint-disable-next-line no-restricted-imports
import { garminAuth, isDeadSession } from "../../src/http/garmin-auth.js";
import { fakeFetch, PROFILE_ROUTE, TOKENS } from "../helpers.js";

afterEach(() => vi.restoreAllMocks());

describe("garminAuth", () => {
  it("includes a Dive token after password sign-in and MFA completion", async () => {
    vi.spyOn(GarminClient.prototype, "login").mockImplementation(async function (this: GarminClient) {
      this.setTokens(TOKENS);
      return { state: "success", ...TOKENS };
    });
    vi.spyOn(GarminClient.prototype, "resumeLogin").mockImplementation(async function (this: GarminClient) {
      this.setTokens(TOKENS);
    });
    const fetchImpl = vi.fn<typeof fetch>(async () => Response.json({
      ...TOKENS.oauth2, access_token: "dive", scope: "DIVE_API_WRITE", expires_in: 86400,
    }));
    const auth = garminAuth({ fetchImpl, retries: 0 });
    const result = await auth.login("fixture", "fixture");
    expect(result).toMatchObject({ state: "success", tokens: { dive: { access_token: "dive" } } });
    expect((await auth.resume({} as MfaState, "fixture")).dive?.access_token).toBe("dive");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("does not exchange a Dive token before MFA completes", async () => {
    const state = {} as MfaState;
    vi.spyOn(GarminClient.prototype, "login").mockResolvedValue({ state: "mfa_required", mfaState: state });
    const fetchImpl = vi.fn<typeof fetch>();
    expect(await garminAuth({ fetchImpl }).login("fixture", "fixture")).toEqual({ state: "mfa_required", mfaState: state });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("prepares Dive credentials for sealed tokens and reuses them on the next OAuth refresh", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (url) => {
      expect(String(url)).toContain("/di-oauth2-service/oauth/token");
      return Response.json({
        ...TOKENS.oauth2, access_token: "dive", scope: "DIVE_API_READ DIVE_API_WRITE", expires_in: 86400,
      });
    });
    const auth = garminAuth({ fetchImpl, retries: 0 });
    const tokens = await auth.refresh(TOKENS, 60_000);
    expect(tokens.oauth2).toEqual(TOKENS.oauth2);
    expect(tokens.dive?.access_token).toBe("dive");
    const reloaded = JSON.parse(JSON.stringify(tokens)) as typeof tokens;
    expect(await auth.refresh(reloaded, 60_000)).toEqual(tokens);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("reads the profile id with the given tokens", async () => {
    const { fetchImpl } = fakeFetch(PROFILE_ROUTE);
    expect(await garminAuth({ fetchImpl, retries: 0 }).profileId(TOKENS)).toBe("1");
  });

  it("returns fresh tokens untouched when nothing is near expiry", async () => {
    const { fetchImpl, calls } = fakeFetch({});
    const tokens = { ...TOKENS, dive: { ...TOKENS.oauth2, scope: "DIVE_API_WRITE" } };
    expect(await garminAuth({ fetchImpl, retries: 0 }).refresh(tokens, 0)).toEqual(tokens);
    expect(calls).toEqual([]);
  });
});

describe("isDeadSession", () => {
  it("is true only for a 401 or a 'log in again' auth error", () => {
    expect(isDeadSession(new GarminAuthError("Not authorized for x (401)"))).toBe(true);
    expect(isDeadSession(new GarminAuthError("Refresh token expired; log in again"))).toBe(true);
    expect(isDeadSession(new GarminAuthError("Not authorized for x (403)"))).toBe(false);
    expect(isDeadSession(new Error("Not authorized for x (401)"))).toBe(false);
  });
});
