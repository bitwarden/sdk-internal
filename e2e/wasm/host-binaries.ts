import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Native binaries the tests run next to the SDK, such as the web connector's initiator. They are
 * cargo examples built for the host by `npm run build:test-helpers`. CI builds them with the SDK and
 * sets `E2E_HOST_BINARIES_DIR`; locally they are in cargo's default output directory.
 */
const HOST_BINARIES_DIR =
  process.env.E2E_HOST_BINARIES_DIR ??
  fileURLToPath(new URL("../../target/debug/examples", import.meta.url));

/** Returns the path of a host binary, and fails if it hasn't been built. */
export function hostBinary(name: string): string {
  const path = join(HOST_BINARIES_DIR, name);
  if (!existsSync(path)) {
    throw new Error(`${path} is missing. Build it with \`npm run build:test-helpers\`.`);
  }
  return path;
}
