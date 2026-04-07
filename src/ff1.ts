export type SymbolArray = number[];

const ZERO_IV = new Uint8Array(16);

function ensureCrypto(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto SubtleCrypto is required.");
  }
  return globalThis.crypto.subtle;
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error("Hex input must contain only [0-9a-f] and have even length.");
  }

  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function generateRandomKeyHex(bytes = 32): string {
  const key = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(key);
  return bytesToHex(key);
}

export function reverseHex(hex: string): string {
  const bytes = hexToBytes(hex);
  const reversed = new Uint8Array(bytes.slice().reverse());
  return bytesToHex(reversed);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export async function importAesKeyFromHex(hex: string): Promise<CryptoKey> {
  const subtle = ensureCrypto();
  const keyBytes = hexToBytes(hex);
  if (![16, 24, 32].includes(keyBytes.length)) {
    throw new Error("AES key must be 128, 192, or 256 bits.");
  }

  return subtle.importKey("raw", toArrayBuffer(keyBytes), { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
}

export async function importAes256KeyFromHex(hex: string): Promise<CryptoKey> {
  const keyBytes = hexToBytes(hex);
  if (keyBytes.length !== 32) {
    throw new Error("AES-256 key must be exactly 64 hex chars.");
  }
  return importAesKeyFromHex(hex);
}

function xorBlock(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.length;
  }
  return out;
}

function powBigInt(base: bigint, exp: number): bigint {
  let out = 1n;
  for (let i = 0; i < exp; i += 1) {
    out *= base;
  }
  return out;
}

function numRadix(symbols: SymbolArray, radix: number): bigint {
  const r = BigInt(radix);
  let out = 0n;
  for (const s of symbols) {
    out = out * r + BigInt(s);
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

function mod(a: bigint, n: bigint): bigint {
  return ((a % n) + n) % n;
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

async function aesEncryptFirstBlock(key: CryptoKey, iv: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const subtle = ensureCrypto();
  const encrypted = await subtle.encrypt({ name: "AES-CBC", iv: toArrayBuffer(iv) }, key, toArrayBuffer(block));
  return new Uint8Array(encrypted).slice(0, 16);
}

async function cbcMacNoPadding(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  if (data.length % 16 !== 0) {
    throw new Error("CBC-MAC input must be 16-byte aligned.");
  }

  let y: Uint8Array<ArrayBufferLike> = ZERO_IV;
  for (let i = 0; i < data.length; i += 16) {
    const block = data.slice(i, i + 16);
    y = await aesEncryptFirstBlock(key, y, block);
  }
  return y;
}

function buildP(radix: number, n: number, u: number, tweakLength: number): Uint8Array {
  const p = new Uint8Array(16);
  p[0] = 0x01;
  p[1] = 0x02;
  p[2] = 0x01;
  p[3] = (radix >> 16) & 0xff;
  p[4] = (radix >> 8) & 0xff;
  p[5] = radix & 0xff;
  p[6] = 0x0a;
  p[7] = u & 0xff;
  p[8] = (n >>> 24) & 0xff;
  p[9] = (n >>> 16) & 0xff;
  p[10] = (n >>> 8) & 0xff;
  p[11] = n & 0xff;
  p[12] = (tweakLength >>> 24) & 0xff;
  p[13] = (tweakLength >>> 16) & 0xff;
  p[14] = (tweakLength >>> 8) & 0xff;
  p[15] = tweakLength & 0xff;
  return p;
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

async function ff1RoundY(
  key: CryptoKey,
  radix: number,
  tweak: Uint8Array<ArrayBufferLike>,
  p: Uint8Array,
  i: number,
  b: number,
  d: number,
  right: SymbolArray
): Promise<bigint> {
  const rightNum = numRadix(right, radix);
  const rightBytes = bigintToBytesBE(rightNum, b);
  const qPadLen = (16 - ((tweak.length + 1 + b) % 16)) % 16;
  const q = new Uint8Array(tweak.length + qPadLen + 1 + b);
  q.set(tweak, 0);
  q[tweak.length + qPadLen] = i & 0xff;
  q.set(rightBytes, q.length - b);

  const r = await cbcMacNoPadding(key, concatBytes([p, q]));
  const sBlocks: Uint8Array[] = [r];

  const blocksNeeded = Math.ceil(d / 16);
  for (let j = 1; j < blocksNeeded; j += 1) {
    const jBlock = bigintToBytesBE(BigInt(j), 16);
    const x = xorBlock(r, jBlock);
    sBlocks.push(await aesEncryptFirstBlock(key, ZERO_IV, x));
  }

  const s = concatBytes(sBlocks).slice(0, d);
  return bytesToBigIntBE(s);
}

export async function ff1Encrypt(
  key: CryptoKey,
  radix: number,
  plaintext: SymbolArray,
  tweak: Uint8Array<ArrayBufferLike> = new Uint8Array()
): Promise<SymbolArray> {
  validateDomain(radix, plaintext);
  const n = plaintext.length;
  if (n < 2) {
    throw new Error("FF1 requires at least 2 symbols.");
  }

  const u = Math.floor(n / 2);
  const v = n - u;
  const b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
  const d = 4 * Math.ceil(b / 4) + 4;
  const p = buildP(radix, n, u, tweak.length);

  let a = plaintext.slice(0, u);
  let bPart = plaintext.slice(u);

  for (let i = 0; i < 10; i += 1) {
    const m = i % 2 === 0 ? u : v;
    const y = await ff1RoundY(key, radix, tweak, p, i, b, d, bPart);
    const modulus = powBigInt(BigInt(radix), m);
    const c = mod(numRadix(a, radix) + y, modulus);
    const cArr = strRadix(c, m, radix);
    a = bPart;
    bPart = cArr;
  }

  return [...a, ...bPart];
}

export async function ff1Decrypt(
  key: CryptoKey,
  radix: number,
  ciphertext: SymbolArray,
  tweak: Uint8Array<ArrayBufferLike> = new Uint8Array()
): Promise<SymbolArray> {
  validateDomain(radix, ciphertext);
  const n = ciphertext.length;
  if (n < 2) {
    throw new Error("FF1 requires at least 2 symbols.");
  }

  const u = Math.floor(n / 2);
  const v = n - u;
  const b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
  const d = 4 * Math.ceil(b / 4) + 4;
  const p = buildP(radix, n, u, tweak.length);

  let a = ciphertext.slice(0, u);
  let bPart = ciphertext.slice(u);

  for (let i = 9; i >= 0; i -= 1) {
    const m = i % 2 === 0 ? u : v;
    const y = await ff1RoundY(key, radix, tweak, p, i, b, d, a);
    const modulus = powBigInt(BigInt(radix), m);
    const c = mod(numRadix(bPart, radix) - y, modulus);
    const cArr = strRadix(c, m, radix);
    bPart = a;
    a = cArr;
  }

  return [...a, ...bPart];
}

export function stringToSymbols(input: string, alphabet: string): SymbolArray {
  const index = new Map<string, number>();
  for (let i = 0; i < alphabet.length; i += 1) {
    index.set(alphabet[i], i);
  }

  const symbols: SymbolArray = [];
  for (const ch of input) {
    const value = index.get(ch);
    if (value === undefined) {
      throw new Error(`Character '${ch}' is not present in alphabet.`);
    }
    symbols.push(value);
  }
  return symbols;
}

export function symbolsToString(symbols: SymbolArray, alphabet: string): string {
  return symbols.map((s) => alphabet[s]).join("");
}
