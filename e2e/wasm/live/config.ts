// Pointing the harness at a real server.

import type { ClientSettings, LoginRequest } from "@bitwarden/sdk-internal";

import type { SeederSettings } from "./seeder";

/** The server URL. Its presence is what puts the harness in live mode. */
const SERVER_URL = "BW_LIVE_SERVER_URL";
/**
 * Per-service origins, for a deployment that splits them.
 *
 * A self-hosted install serves both services under one origin, at `/api` and `/identity`, which is
 * what {@link SERVER_URL} is expanded to. A cloud-style deployment gives each service an origin of
 * its own, and `GET <server>/api/config` reports them under `environment`.
 */
const API_URL = "BW_LIVE_API_URL";
const IDENTITY_URL = "BW_LIVE_IDENTITY_URL";
/** The server's seeder API, which every test account is seeded through. */
const SEEDER_URL = "BW_LIVE_SEEDER_URL";
const SEEDER_USERNAME = "BW_LIVE_SEEDER_USERNAME";
const SEEDER_PASSWORD = "BW_LIVE_SEEDER_PASSWORD";
const EMAIL_DOMAIN = "BW_LIVE_EMAIL_DOMAIN";
const DEFAULT_EMAIL_DOMAIN = "example.com";
const DEVICE_IDENTIFIER = "BW_LIVE_DEVICE_IDENTIFIER";
const DEFAULT_DEVICE_IDENTIFIER = "sdk-internal-integration-tests";
const CLIENT_VERSION = "BW_LIVE_CLIENT_VERSION";
const DEFAULT_CLIENT_VERSION = "2026.9.0";

export interface LiveConfig {
  settings: ClientSettings;
  loginRequest: LoginRequest;
  seeder: SeederSettings;
  emailDomain: string;
}

/**
 * The live configuration, or `undefined` when {@link SERVER_URL} is unset.
 */
export function liveConfig(): LiveConfig | undefined {
  const baseUrl = process.env[SERVER_URL];
  if (baseUrl === undefined || baseUrl === "") {
    return undefined;
  }

  return requireLiveConfig();
}

export function requireLiveConfig(): LiveConfig {
  const baseUrl = trimTrailingSlash(required(SERVER_URL));
  const deviceIdentifier = process.env[DEVICE_IDENTIFIER] ?? DEFAULT_DEVICE_IDENTIFIER;

  return {
    settings: {
      apiUrl: originOr(API_URL, `${baseUrl}/api`),
      identityUrl: originOr(IDENTITY_URL, `${baseUrl}/identity`),
      deviceIdentifier,
      bitwardenClientVersion: process.env[CLIENT_VERSION] ?? DEFAULT_CLIENT_VERSION,
    },
    loginRequest: {
      clientId: "web",
      device: {
        deviceType: "SDK",
        deviceIdentifier,
        deviceName: "SDK Integration Tests",
        devicePushToken: undefined,
      },
    },
    seeder: {
      url: trimTrailingSlash(required(SEEDER_URL)),
      username: required(SEEDER_USERNAME),
      password: required(SEEDER_PASSWORD),
    },
    emailDomain: process.env[EMAIL_DOMAIN] || DEFAULT_EMAIL_DOMAIN,
  };
}

export function describeLoginFailure(error: unknown): string {
  return [
    `live login failed: ${String(error)}`,
    "a seeded account fails to log in when the server requires two-factor, a captcha, or",
    `new-device verification for device ${process.env[DEVICE_IDENTIFIER] ?? DEFAULT_DEVICE_IDENTIFIER}.`,
    "The SDK reports all three as the same unknown error, so none can be told apart here.",
  ].join(" ");
}

function originOr(name: string, fallback: string): string {
  const configured = process.env[name];

  return configured === undefined || configured === "" ? fallback : trimTrailingSlash(configured);
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(
      `${name} is not set; live mode needs ${SERVER_URL}, ${SEEDER_URL}, ${SEEDER_USERNAME} and ` +
        `${SEEDER_PASSWORD}`,
    );
  }

  return value;
}

function trimTrailingSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}
