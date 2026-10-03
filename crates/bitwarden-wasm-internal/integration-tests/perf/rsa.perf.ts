// Performance harness: RSA-2048 through the WASM boundary.
//
//   rsa_generate_keypair ──► private key ──► rsa_extract_public_key
//                                 │                    │
//                         rsa_decrypt_data ◄── rsa_encrypt_data (OAEP-SHA1)
//
// Times the PureCrypto RSA helpers. Key generation is timed per call and varies widely (random
// prime search), so look at the median over several runs. Encrypt and decrypt are fast, so each
// run times a batch of calls.
//
// Env:
//   PERF_RSA_RUNS  timed runs per operation; key generation runs 3x  (default 7)
//   PERF_LABEL     writes perf/results/<label>-rsa.json when set

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { init_sdk, PureCrypto } from "@bitwarden/sdk-internal";

const RUNS = Number(process.env.PERF_RSA_RUNS ?? 7);
// Prime search makes key generation time vary widely, so it gets more runs.
const KEYGEN_RUNS = RUNS * 3;
const WARMUP_RUNS = 1;
const BATCH = 50;
const PAYLOAD_SIZE = 64;
const LABEL = process.env.PERF_LABEL;

const RESULTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "results");

interface Stats {
  operation: string;
  callsPerRun: number;
  runsMs: number[];
  medianMs: number;
  minMs: number;
}

const allStats: Stats[] = [];

function measure(operation: string, callsPerRun: number, runs: number, run: () => void): void {
  for (let i = 0; i < WARMUP_RUNS; i++) {
    run();
  }

  const runsMs: number[] = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    run();
    runsMs.push(performance.now() - start);
  }

  const sorted = [...runsMs].sort((a, b) => a - b);
  allStats.push({
    operation,
    callsPerRun,
    runsMs,
    medianMs: sorted[Math.floor(sorted.length / 2)],
    minMs: sorted[0],
  });
}

function report(): void {
  const rows = allStats.map(
    (s) =>
      `${s.operation.padEnd(20)} ${String(s.callsPerRun).padStart(3)} calls/run  median ${s.medianMs.toFixed(1).padStart(8)} ms` +
      `  min ${s.minMs.toFixed(1).padStart(8)} ms`,
  );
  console.log(`rsa, ${RUNS} runs (key generation ${KEYGEN_RUNS})\n${rows.join("\n")}`);

  if (!LABEL) {
    return;
  }
  mkdirSync(RESULTS_DIR, { recursive: true });
  const file = join(RESULTS_DIR, `${LABEL}-rsa.json`);
  writeFileSync(file, JSON.stringify({ label: LABEL, stats: allStats }, null, 2));
}

describe("rsa performance", () => {
  let privateKey: Uint8Array;
  let publicKey: Uint8Array;
  const payload = Uint8Array.from({ length: PAYLOAD_SIZE }, (_, i) => i);

  beforeAll(() => {
    init_sdk();
    privateKey = PureCrypto.rsa_generate_keypair();
    publicKey = PureCrypto.rsa_extract_public_key(privateKey);
  });

  afterAll(report);

  it("generates key pairs", () => {
    measure("generate_keypair", 1, KEYGEN_RUNS, () => {
      const generated = PureCrypto.rsa_generate_keypair();
      expect(generated.length).toBeGreaterThan(0);
    });
  });

  it("encrypts", () => {
    measure("encrypt", BATCH, RUNS, () => {
      for (let i = 0; i < BATCH; i++) {
        PureCrypto.rsa_encrypt_data(payload, publicKey);
      }
    });
  });

  it("decrypts", () => {
    const encrypted = PureCrypto.rsa_encrypt_data(payload, publicKey);

    measure("decrypt", BATCH, RUNS, () => {
      for (let i = 0; i < BATCH; i++) {
        // Guards against silently measuring a failing decrypt.
        expect(PureCrypto.rsa_decrypt_data(encrypted, privateKey)).toEqual(payload);
      }
    });
  });
});
