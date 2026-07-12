import { webcrypto } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

import {
  ff1Decrypt,
  ff1Encrypt,
  hexToBytes,
  importAesKeyFromHex,
  importFf3KeyFromHex,
  reverseHex,
  stringToSymbols,
  symbolsToString,
} from "./ff1";
import { ff3_1Decrypt, ff3_1Encrypt } from "./ff3";
import { fromDigitSymbols, toDigitSymbols } from "./formats";

// Vitest runs under Node; WebCrypto SubtleCrypto is on webcrypto, not globalThis.
beforeAll(() => {
  if (!globalThis.crypto) {
    // @ts-expect-error assign Node webcrypto to the global for SubtleCrypto access
    globalThis.crypto = webcrypto;
  }
});

const R10 = "0123456789";
const R26 = "abcdefghijklmnopqrstuvwxyz";
const R64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

async function ff1(keyHex: string, radix: number, alphabet: string, pt: string, tweakHex: string) {
  const key = await importAesKeyFromHex(keyHex);
  const ct = await ff1Encrypt(key, radix, stringToSymbols(pt, alphabet), hexToBytes(tweakHex));
  const back = await ff1Decrypt(key, radix, ct, hexToBytes(tweakHex));
  return { ct: symbolsToString(ct, alphabet), back: symbolsToString(back, alphabet) };
}

async function ff31(keyHex: string, radix: number, alphabet: string, pt: string, tweakHex: string) {
  const key = await importFf3KeyFromHex(keyHex);
  const ct = await ff3_1Encrypt(key, radix, stringToSymbols(pt, alphabet), hexToBytes(tweakHex));
  const back = await ff3_1Decrypt(key, radix, ct, hexToBytes(tweakHex));
  return { ct: symbolsToString(ct, alphabet), back: symbolsToString(back, alphabet) };
}

/**
 * FF1 known-answer tests: the nine sample vectors published by NIST alongside
 * SP 800-38G (radix 10 and radix 36; AES-128 / 192 / 256). These pin the exact
 * ciphertext, so any regression in ff1.ts fails the build.
 */
describe("FF1 NIST SP 800-38G sample vectors", () => {
  const K128 = "2b7e151628aed2a6abf7158809cf4f3c";
  const K192 = "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f";
  const K256 = "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94";
  const R36 = "0123456789abcdefghijklmnopqrstuvwxyz";
  const TW = "39383736353433323130";
  const TW36 = "3737373770717273373737";
  const PT10 = "0123456789";
  const PT36 = "0123456789abcdefghi";

  const cases: Array<[string, string, number, string, string, string, string]> = [
    ["S1 AES-128 r10 no tweak", K128, 10, R10, PT10, "", "2433477484"],
    ["S2 AES-128 r10 tweak", K128, 10, R10, PT10, TW, "6124200773"],
    ["S3 AES-128 r36 tweak", K128, 36, R36, PT36, TW36, "a9tv40mll9kdu509eum"],
    ["S4 AES-192 r10 no tweak", K192, 10, R10, PT10, "", "2830668132"],
    ["S5 AES-192 r10 tweak", K192, 10, R10, PT10, TW, "2496655549"],
    ["S6 AES-192 r36 tweak", K192, 36, R36, PT36, TW36, "xbj3kv35jrawxv32ysr"],
    ["S7 AES-256 r10 no tweak", K256, 10, R10, PT10, "", "6657667009"],
    ["S8 AES-256 r10 tweak", K256, 10, R10, PT10, TW, "1001623463"],
    ["S9 AES-256 r36 tweak", K256, 36, R36, PT36, TW36, "xs8a0azh2avyalyzuwd"],
  ];

  for (const [name, key, radix, alphabet, pt, tweak, expected] of cases) {
    it(name, async () => {
      const { ct, back } = await ff1(key, radix, alphabet, pt, tweak);
      expect(ct).toBe(expected);
      expect(back).toBe(pt);
    });
  }
});

/**
 * FF3-1 known-answer tests: NIST ACVP sample vectors (56-bit tweak). These are
 * the authoritative FF3-1 vectors and are what catch the key-reversal bug — an
 * FF3-1 implementation that does not run AES under REV(K) round-trips fine but
 * produces the wrong ciphertext for every one of these.
 */
describe("FF3-1 NIST ACVP sample vectors (56-bit tweak)", () => {
  const cases: Array<[string, string, number, string, string, string, string]> = [
    // AES-128
    ["AES-128 r10 a", "2de79d232df5585d68ce47882ae256d6", 10, R10, "3992520240", "cbd09280979564", "8901801106"],
    [
      "AES-128 r10 b",
      "01c63017111438f7fc8e24eb16c71ab5",
      10,
      R10,
      "60761757463116869318437658042297305934914824457484538562",
      "c4e822dcd09f27",
      "35637144092473838892796702739628394376915177448290847293",
    ],
    ["AES-128 r26", "718385e6542534604419e83ce387a437", 26, R26, "wfmwlrorcd", "b6f35084fa90e1", "ywowehycyd"],
    ["AES-128 r64", "aee87d0d485b3afd12bd1e0b9d03d50d", 64, R64, "ixvuuIHr0e", "5f9140601d224b", "GR90R1q838"],
    // AES-192
    ["AES-192 r10", "f62edb777a671075d47563f3a1e9ac797aa706a2d8e02fc8", 10, R10, "4406616808", "493b8451bf6716", "1807744762"],
    ["AES-192 r26", "49ccb8f62d941e5684599eca0300937b5c766d053e109777", 26, R26, "jaxlrchjjx", "0bfcf75cdc2fc1", "kjdbfqyahd"],
    // AES-256
    ["AES-256 r10", "1faa03eff55a06f8fab3f1dc57127d493e2f8f5c365540467a3a055bdbe6481d", 10, R10, "3679409436", "4d67130c030445", "1735794859"],
    ["AES-256 r26", "6187f8bde99f7daf9e3ee8a8654308e7e51d31fa88affaeb5592041c033b736b", 26, R26, "mkblaoiyfd", "5820812b3d5dd1", "ifpyiihvvq"],
  ];

  for (const [name, key, radix, alphabet, pt, tweak, expected] of cases) {
    it(name, async () => {
      const { ct, back } = await ff31(key, radix, alphabet, pt, tweak);
      expect(ct).toBe(expected);
      expect(back).toBe(pt);
    });
  }
});

/**
 * Regression guard for the specific bug this suite was written to catch:
 * FF3-1 must run AES under the byte-reversed key. importFf3KeyFromHex bakes
 * that in, so encrypting with it must match ACVP, and encrypting with the plain
 * (non-reversed) key must NOT.
 */
describe("FF3-1 key reversal is required", () => {
  const keyHex = "2de79d232df5585d68ce47882ae256d6";
  const pt = toDigitSymbols("3992520240");
  const tweak = hexToBytes("cbd09280979564");

  it("importFf3KeyFromHex reverses the key bytes", () => {
    expect(reverseHex(keyHex)).toBe("d656e22a8847ce685d58f52d239de72d");
  });

  it("reversed key matches ACVP; non-reversed key does not", async () => {
    const good = await importFf3KeyFromHex(keyHex);
    const wrong = await importAesKeyFromHex(keyHex);
    const goodCt = fromDigitSymbols(await ff3_1Encrypt(good, 10, pt, tweak));
    const wrongCt = fromDigitSymbols(await ff3_1Encrypt(wrong, 10, pt, tweak));
    expect(goodCt).toBe("8901801106");
    expect(wrongCt).not.toBe("8901801106");
  });
});

describe("round-trip properties", () => {
  it("FF1 decrypt inverts encrypt over random inputs (radix 10)", async () => {
    const key = await importAesKeyFromHex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
    const tweak = hexToBytes("00aabbccdd");
    for (let trial = 0; trial < 25; trial += 1) {
      const n = 4 + (trial % 12);
      const pt = Array.from({ length: n }, () => Math.floor(Math.random() * 10));
      const ct = await ff1Encrypt(key, 10, pt, tweak);
      const back = await ff1Decrypt(key, 10, ct, tweak);
      expect(back).toEqual(pt);
      expect(ct).toHaveLength(n); // length-preserving
    }
  });

  it("FF3-1 decrypt inverts encrypt over random inputs (radix 10)", async () => {
    const key = await importFf3KeyFromHex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
    const tweak = hexToBytes("aabbccddeeff00");
    for (let trial = 0; trial < 25; trial += 1) {
      const n = 4 + (trial % 12);
      const pt = Array.from({ length: n }, () => Math.floor(Math.random() * 10));
      const ct = await ff3_1Encrypt(key, 10, pt, tweak);
      const back = await ff3_1Decrypt(key, 10, ct, tweak);
      expect(back).toEqual(pt);
      expect(ct).toHaveLength(n);
    }
  });
});

describe("tweak sensitivity (no silent tweak collapse)", () => {
  it("FF1: flipping one tweak bit changes the ciphertext", async () => {
    const key = await importAesKeyFromHex("2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94");
    const pt = toDigitSymbols("0123456789");
    const a = fromDigitSymbols(await ff1Encrypt(key, 10, pt, hexToBytes("39383736353433323130")));
    const b = fromDigitSymbols(await ff1Encrypt(key, 10, pt, hexToBytes("39383736353433323131")));
    expect(a).not.toBe(b);
  });

  it("FF3-1: two tweaks that differ only in low nibble of byte 3 must both round-trip", async () => {
    // Bytes 3's low nibble is discarded per FF3-1 tweak split; ensure that does
    // not corrupt reversibility for either tweak.
    const key = await importFf3KeyFromHex("2de79d232df5585d68ce47882ae256d6");
    const pt = toDigitSymbols("3992520240");
    for (const tw of ["cbd09280979564", "cbd09285979564"]) {
      const ct = await ff3_1Encrypt(key, 10, pt, hexToBytes(tw));
      const back = await ff3_1Decrypt(key, 10, ct, hexToBytes(tw));
      expect(fromDigitSymbols(back)).toBe("3992520240");
    }
  });
});

describe("input validation and edge cases", () => {
  it("rejects an out-of-domain symbol (FF1)", async () => {
    const key = await importAesKeyFromHex("2b7e151628aed2a6abf7158809cf4f3c");
    await expect(ff1Encrypt(key, 10, [0, 1, 2, 10, 4, 5], new Uint8Array())).rejects.toThrow(/outside radix/);
  });

  it("rejects a too-small domain (radix^n < 100)", async () => {
    const key = await importAesKeyFromHex("2b7e151628aed2a6abf7158809cf4f3c");
    // radix 10, n=1 fails the n>=2 check; use radix 3, n=4 -> 3^4=81 < 100.
    await expect(ff1Encrypt(key, 3, [0, 1, 2, 0], new Uint8Array())).rejects.toThrow(/at least 100/);
  });

  it("domain guard does not overflow for large n (no false Infinity pass)", async () => {
    const key = await importAesKeyFromHex("2b7e151628aed2a6abf7158809cf4f3c");
    // 400 decimal digits: Math.pow(10,400) === Infinity, but BigInt is exact
    // and must accept this large-but-valid domain.
    const pt = Array.from({ length: 400 }, (_, i) => i % 10);
    const ct = await ff1Encrypt(key, 10, pt, new Uint8Array());
    expect(ct).toHaveLength(400);
  });

  it("FF3-1 rejects a tweak that is not exactly 7 bytes", async () => {
    const key = await importFf3KeyFromHex("2de79d232df5585d68ce47882ae256d6");
    await expect(ff3_1Encrypt(key, 10, toDigitSymbols("3992520240"), hexToBytes("cbd0928097"))).rejects.toThrow(
      /7 bytes/,
    );
  });
});
