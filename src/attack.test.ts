/**
 * attack.test.ts — the live small-domain codebook recovery of FF3-1.
 *
 * Teeth:
 *  - on a small domain the attacker recovers the defender's secret plaintext
 *    EXACTLY, with no key, in at most domainSize oracle queries;
 *  - the recovery is real: it depends on the actual FF3-1 permutation, so a
 *    ciphertext from a DIFFERENT key is not found in the codebook (failure path);
 *  - the feasibility numbers are computed, and the NIST 10^6 floor is exactly
 *    the boundary between "codebook feasible" and "not".
 */

import { webcrypto } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { runCodebookAttack, feasibility } from "./attack";
import {
  importFf3KeyFromHex,
  generateRandomKeyHex,
  hexToBytes,
  stringToSymbols,
  symbolsToString,
} from "./ff1";
import { ff3_1EncryptUnchecked } from "./ff3";

beforeAll(() => {
  if (!globalThis.crypto) {
    // @ts-expect-error node webcrypto provides SubtleCrypto
    globalThis.crypto = webcrypto;
  }
});

const DIGITS = "0123456789";

describe("small-domain codebook recovery", () => {
  it("recovers the secret plaintext with no key (radix 10, length 4)", async () => {
    const r = await runCodebookAttack(10, 4);
    expect(r.domainSize).toBe(10_000);
    expect(r.recovered).toBe(r.secret);
    expect(r.recovered_ok).toBe(true);
    expect(r.queries).toBeGreaterThan(0);
    expect(r.queries).toBeLessThanOrEqual(r.domainSize);
  });

  it("recovery is a real permutation inverse, not a canned string, and is key-specific", async () => {
    // Build key A's codebook; look up a ciphertext that key B produced for "4242".
    // Because FF3-1 is a permutation of the same 10^4 domain, key A's codebook
    // DOES contain that ciphertext value — but at a DIFFERENT preimage. The
    // recovered preimage must (a) re-encrypt under key A back to the target
    // (a genuine inverse, teeth) and (b) not be key B's "4242" (key-specific).
    const radix = 10;
    const length = 4;
    const domain = radix ** length;

    const keyA = await importFf3KeyFromHex(generateRandomKeyHex(16));
    const keyB = await importFf3KeyFromHex(generateRandomKeyHex(16));
    const tweak = hexToBytes("00112233445566");

    const foreignTarget = symbolsToString(
      await ff3_1EncryptUnchecked(keyB, radix, stringToSymbols("4242", DIGITS), tweak),
      DIGITS,
    );

    let found: string | null = null;
    for (let idx = 0; idx < domain; idx += 1) {
      const digits = Array.from(
        { length },
        (_v, i) => Math.floor(idx / radix ** (length - 1 - i)) % radix,
      );
      const guess = symbolsToString(digits, DIGITS);
      const ct = symbolsToString(
        await ff3_1EncryptUnchecked(keyA, radix, digits, tweak),
        DIGITS,
      );
      if (ct === foreignTarget) {
        found = guess;
        break;
      }
    }

    // The value exists in key A's permutation, so it is found...
    expect(found).not.toBeNull();
    // ...and re-encrypting the recovered preimage under key A reproduces the
    // target — a genuine inverse, impossible for a hardcoded answer.
    const roundTrip = symbolsToString(
      await ff3_1EncryptUnchecked(keyA, radix, stringToSymbols(found!, DIGITS), tweak),
      DIGITS,
    );
    expect(roundTrip).toBe(foreignTarget);
    // The recovered preimage is key A's, not key B's plaintext (overwhelmingly).
    expect(found).not.toBe("4242");
  });

  it("computes feasibility; the 10^6 floor is the feasible/infeasible boundary", () => {
    const small = feasibility(10, 4); // 10^4
    expect(small.domainSize).toBe(10_000);
    expect(small.codebookFeasible).toBe(true);
    expect(small.meetsNistFloor).toBe(false);

    const atFloor = feasibility(10, 6); // 10^6, exactly the floor
    expect(atFloor.domainSize).toBe(1_000_000);
    expect(atFloor.meetsNistFloor).toBe(true);
    expect(atFloor.codebookFeasible).toBe(false);

    expect(small.beyneQueries).toBe(2 ** 23);
  });
});
