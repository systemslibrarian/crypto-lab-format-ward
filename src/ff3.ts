import { SymbolArray } from "./ff1";

const ZERO_IV = new Uint8Array(16);

function ensureCrypto(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto SubtleCrypto is required.");
  }
  return globalThis.crypto.subtle;
}

function mod(a: bigint, n: bigint): bigint {
  return ((a % n) + n) % n;
}

function powBigInt(base: bigint, exp: number): bigint {
  let out = 1n;
  for (let i = 0; i < exp; i += 1) {
    out *= base;
  }
  return out;
}

function numRadix(values: SymbolArray, radix: number): bigint {
  const r = BigInt(radix);
  let out = 0n;
  for (const d of values) {
    out = out * r + BigInt(d);
  }
  return out;
}

function strRadix(value: bigint, m: number, radix: number): SymbolArray {
  const r = BigInt(radix);
  const out = new Array<number>(m).fill(0);
  let x = value;
  for (let i = m - 1; i >= 0; i -= 1) {
    out[i] = Number(x % r);
    x /= r;
  }
  return out;
}

function reverse<T>(arr: T[]): T[] {
  return arr.slice().reverse();
}

function reverseBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(Array.from(bytes).reverse());
}

function numRev(values: SymbolArray, radix: number): bigint {
  return numRadix(reverse(values), radix);
}

function strRev(value: bigint, m: number, radix: number): SymbolArray {
  return reverse(strRadix(value, m, radix));
}

function bigintToBytesBE(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let x = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) {
    out = (out << 8n) + BigInt(b);
  }
  return out;
}

function xor4(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

async function aesEncryptFirstBlock(key: CryptoKey, iv: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const subtle = ensureCrypto();
  const encrypted = await subtle.encrypt(
    { name: "AES-CBC", iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(block)
  );
  return new Uint8Array(encrypted).slice(0, 16);
}

function validateDomain(radix: number, values: SymbolArray): void {
  if (radix < 2 || radix > 65536) {
    throw new Error("Radix must be in [2, 65536].");
  }
  for (const d of values) {
    if (!Number.isInteger(d) || d < 0 || d >= radix) {
      throw new Error("Input contains symbols outside radix domain.");
    }
  }
}

function splitTweak56(
  tweak56: Uint8Array<ArrayBufferLike>
): { tl: Uint8Array; tr: Uint8Array } {
  if (tweak56.length !== 7) {
    throw new Error("FF3-1 tweak must be exactly 7 bytes (56 bits).");
  }

  const tl = new Uint8Array([tweak56[0], tweak56[1], tweak56[2], tweak56[3] & 0xf0]);
  const tr = new Uint8Array([tweak56[4], tweak56[5], tweak56[6], (tweak56[3] & 0x0f) << 4]);
  return { tl, tr };
}

function uint32be(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ]);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function ff3RoundY(
  key: CryptoKey,
  w: Uint8Array,
  i: number,
  right: SymbolArray,
  radix: number
): Promise<bigint> {
  const p = new Uint8Array(16);
  const iBytes = uint32be(i);
  p.set(xor4(w, iBytes), 0);
  p.set(bigintToBytesBE(numRev(right, radix), 12), 4);

  const revP = reverseBytes(p);
  const block = await aesEncryptFirstBlock(key, ZERO_IV, revP);
  return bytesToBigIntBE(reverseBytes(block));
}

export async function ff3_1Encrypt(
  key: CryptoKey,
  radix: number,
  plaintext: SymbolArray,
  tweak56: Uint8Array<ArrayBufferLike>
): Promise<SymbolArray> {
  validateDomain(radix, plaintext);
  const n = plaintext.length;
  if (n < 2) {
    throw new Error("FF3-1 requires at least 2 symbols.");
  }

  const { tl, tr } = splitTweak56(tweak56);
  const u = Math.ceil(n / 2);
  const v = n - u;

  let a = plaintext.slice(0, u);
  let b = plaintext.slice(u);

  for (let i = 0; i < 8; i += 1) {
    const m = i % 2 === 0 ? u : v;
    const w = i % 2 === 0 ? tr : tl;
    const y = await ff3RoundY(key, w, i, b, radix);
    const modulus = powBigInt(BigInt(radix), m);
    const c = mod(numRev(a, radix) + y, modulus);
    const cArr = strRev(c, m, radix);
    a = b;
    b = cArr;
  }

  return [...a, ...b];
}

export async function ff3_1Decrypt(
  key: CryptoKey,
  radix: number,
  ciphertext: SymbolArray,
  tweak56: Uint8Array<ArrayBufferLike>
): Promise<SymbolArray> {
  validateDomain(radix, ciphertext);
  const n = ciphertext.length;
  if (n < 2) {
    throw new Error("FF3-1 requires at least 2 symbols.");
  }

  const { tl, tr } = splitTweak56(tweak56);
  const u = Math.ceil(n / 2);
  const v = n - u;

  let a = ciphertext.slice(0, u);
  let b = ciphertext.slice(u);

  for (let i = 7; i >= 0; i -= 1) {
    const m = i % 2 === 0 ? u : v;
    const w = i % 2 === 0 ? tr : tl;
    const y = await ff3RoundY(key, w, i, a, radix);
    const modulus = powBigInt(BigInt(radix), m);
    const c = mod(numRev(b, radix) - y, modulus);
    const cArr = strRev(c, m, radix);
    b = a;
    a = cArr;
  }

  return [...a, ...b];
}
