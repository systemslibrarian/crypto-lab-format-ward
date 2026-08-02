/**
 * attack.ts — a live, computed break of FF3-1 on a small domain.
 *
 * Honest scope, stated plainly on the page: the *specific* Durak–Vaudenay /
 * Beyne cryptanalysis of FF3-1's tweak schedule is a statistical attack needing
 * on the order of 2^23 (~8 million) chosen queries — hours of AES even natively,
 * far out of browser reach, so it is cited, not run. What IS browser-feasible,
 * and what those attacks reduce the cipher to on realistic field sizes, is
 * SMALL-DOMAIN CODEBOOK RECOVERY: with oracle access to FF3-1 under a fixed
 * (secret) key and tweak, an attacker who never learns the key enumerates the
 * whole domain, builds the plaintext→ciphertext table, and inverts any target
 * ciphertext. This is exactly the weakness FF3-1's own minimum-domain guard was
 * raised to a hard requirement to prevent (SP 800-38G Rev. 1, following
 * Durak–Vaudenay and Hoang–Tessaro–Trieu). Every value below is computed with
 * the real FF3-1 primitive; nothing is hardcoded.
 */

import {
  importFf3KeyFromHex,
  generateRandomKeyHex,
  hexToBytes,
  type SymbolArray,
} from "./ff1";
import { ff3_1EncryptUnchecked } from "./ff3";

const NIST_MIN_DOMAIN = 1_000_000; // SP 800-38G Rev. 1 requirement (10^6)
const BEYNE_QUERIES = 2 ** 23; // ~8.4M, Beyne CRYPTO 2021 distinguisher on N=1000

function randomTweakHex(): string {
  // 56-bit (7-byte) FF3-1 tweak.
  const bytes = crypto.getRandomValues(new Uint8Array(7));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Enumerate the i-th length-n symbol array over the given radix (odometer). */
function indexToSymbols(index: number, n: number, radix: number): SymbolArray {
  const out = new Array<number>(n).fill(0);
  let x = index;
  for (let i = n - 1; i >= 0; i -= 1) {
    out[i] = x % radix;
    x = Math.floor(x / radix);
  }
  return out;
}

const symbolsToStr = (s: SymbolArray): string => s.join("");

export interface CodebookResult {
  radix: number;
  length: number;
  domainSize: number;
  /** the secret plaintext the defender encrypted (revealed only to prove the match) */
  secret: string;
  /** ciphertext the attacker was handed */
  target: string;
  /** plaintext the attacker recovered with NO key, purely by codebook lookup */
  recovered: string | null;
  /** did the recovered plaintext equal the defender's secret? */
  recovered_ok: boolean;
  /** number of oracle encryption queries the attack spent */
  queries: number;
}

/**
 * Mount the codebook recovery. A fresh random FF3-1 key + tweak are generated
 * and kept away from the "attacker" code path; the attacker is given only the
 * radix, length, target ciphertext, and an encryption oracle. It enumerates the
 * domain until the oracle's output matches the target, recovering the secret
 * plaintext without ever seeing the key.
 */
export async function runCodebookAttack(radix: number, length: number): Promise<CodebookResult> {
  const domainSize = radix ** length;

  // ── Defender: secret key + tweak, encrypts a secret value. ──
  const keyHex = generateRandomKeyHex(16);
  const key = await importFf3KeyFromHex(keyHex);
  const tweak = hexToBytes(randomTweakHex());
  const secretIndex = Math.floor(Math.random() * domainSize);
  const secret = indexToSymbols(secretIndex, length, radix);
  const targetSymbols = await ff3_1EncryptUnchecked(key, radix, secret, tweak);
  const target = symbolsToStr(targetSymbols);

  // ── Attacker: only an encryption oracle (same key+tweak, key unknown). ──
  const oracle = (pt: SymbolArray): Promise<SymbolArray> =>
    ff3_1EncryptUnchecked(key, radix, pt, tweak);

  let recovered: string | null = null;
  let queries = 0;
  for (let idx = 0; idx < domainSize; idx += 1) {
    const guess = indexToSymbols(idx, length, radix);
    const ct = symbolsToStr(await oracle(guess));
    queries += 1;
    if (ct === target) {
      recovered = symbolsToStr(guess);
      break;
    }
  }

  return {
    radix,
    length,
    domainSize,
    secret: symbolsToStr(secret),
    target,
    recovered,
    recovered_ok: recovered !== null && recovered === symbolsToStr(secret),
    queries,
  };
}

export interface Feasibility {
  radix: number;
  length: number;
  domainSize: number;
  /** codebook recovery query cost = domain size */
  codebookQueries: number;
  /** is a full codebook browser-feasible (well under the 10^6 floor)? */
  codebookFeasible: boolean;
  /** the NIST Rev. 1 minimum domain requirement */
  nistFloor: number;
  meetsNistFloor: boolean;
  /** Beyne's FF3-1 tweak-schedule distinguisher data complexity (cited) */
  beyneQueries: number;
}

/**
 * Compute — not assert — the feasibility numbers the page otherwise only cites:
 * the codebook cost for these parameters, whether they clear the NIST floor,
 * and Beyne's 2^23 figure for context.
 */
export function feasibility(radix: number, length: number): Feasibility {
  const domainSize = radix ** length;
  return {
    radix,
    length,
    domainSize,
    codebookQueries: domainSize,
    codebookFeasible: domainSize < NIST_MIN_DOMAIN,
    nistFloor: NIST_MIN_DOMAIN,
    meetsNistFloor: domainSize >= NIST_MIN_DOMAIN,
    beyneQueries: BEYNE_QUERIES,
  };
}
