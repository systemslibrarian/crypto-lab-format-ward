import { ff1Encrypt, generateRandomKeyHex, importAes256KeyFromHex, stringToSymbols, symbolsToString } from './ff1';

export const ROSTER = [
  { name: 'ALICE MARIN', city: 'RIVER GLEN' },
  { name: 'MASON BIRCH', city: 'CEDAR HILL' },
  { name: 'ELENA STONE', city: 'OAK HAVEN' },
  { name: 'IVORY REED', city: 'BLUE RIDGE' },
  { name: 'NORA WILLOW', city: 'NORTH BAY' },
  { name: 'OWEN SILVER', city: 'SOUTH FORD' },
  { name: 'ARI ELM', city: 'BLUE RIDGE' },
  { name: 'LENA JUNE PARK', city: 'OAK HAVEN' },
] as const;
export type ShapeView = 'length' | 'words' | 'both';
export interface PublicRow { name: string; city: string }
export function shape(row: PublicRow, view: ShapeView): string {
  const words = (s: string) => s.split(' ').map(w => w.length).join('-');
  if (view === 'length') return `name length ${row.name.length}`;
  if (view === 'words') return `name words ${words(row.name)}`;
  return `name words ${words(row.name)}; city words ${words(row.city)}`;
}

/** Attacker receives only released ciphertext strings and an auxiliary roster.
 * No secret key, encryption oracle or per-row ground truth enters this function.
 */
export function matchFormats(released: readonly PublicRow[], auxiliary: readonly PublicRow[], view: ShapeView, padded: boolean) {
  return released.map(row => ({
    fingerprint: padded ? `opaque ${row.name.length}-character ciphertext` : shape(row, view),
    candidates: auxiliary.filter(candidate => padded || shape(candidate, view) === shape(row, view)).map(x => x.name),
  }));
}

/** Uniform prior on this explicit finite roster. This is Shannon leakage from
 * a deterministic format partition, not a claim about real populations.
 */
export function formatLeakage(roster: readonly PublicRow[], view: ShapeView, padded: boolean) {
  if (roster.length === 0) throw new Error('a nonempty auxiliary roster is required');
  const groups = new Map<string, number>();
  for (const row of roster) {
    const key = padded ? 'opaque' : shape(row, view);
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }
  let leakage = 0, unique = 0, expectedCandidates = 0;
  for (const count of groups.values()) {
    const p = count / roster.length;
    leakage -= p * Math.log2(p);
    expectedCandidates += p * count;
    if (count === 1) unique++;
  }
  return { leakage, unique, expectedCandidates, priorEntropy: Math.log2(roster.length), groups: groups.size };
}

async function encryptWords(key: CryptoKey, input: string): Promise<string> {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const letters = input.replaceAll(' ', '');
  // Encrypt all letters jointly; do not encrypt short words as tiny domains.
  const encrypted = symbolsToString(await ff1Encrypt(key, 26, stringToSymbols(letters, alphabet), crypto.getRandomValues(new Uint8Array(16))), alphabet);
  let i = 0;
  return [...input].map(c => c === ' ' ? ' ' : encrypted[i++]).join('');
}

export async function releaseSyntheticRoster(padded: boolean): Promise<PublicRow[]> {
  const key = padded ? await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt'])
    : await importAes256KeyFromHex(generateRandomKeyHex(32));
  const rows: PublicRow[] = [];
  for (const record of ROSTER) {
    if (padded) {
      const encoded = new TextEncoder().encode(JSON.stringify(record));
      if (encoded.length > 127) throw new Error('synthetic record exceeds the padded block');
      const plaintext = new Uint8Array(128);
      plaintext[0] = encoded.length;
      plaintext.set(encoded, 1);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
      const wire = new Uint8Array(iv.length + ciphertext.length);
      wire.set(iv); wire.set(ciphertext, iv.length);
      rows.push({ name: Array.from(wire, n => n.toString(16).padStart(2, '0')).join(''), city: '' });
    } else rows.push({ name: await encryptWords(key, record.name), city: await encryptWords(key, record.city) });
  }
  // Break the original roster order: matching may use only the visible shape.
  for (let i = rows.length - 1; i > 0; i--) {
    let draw: number;
    const limit = Math.floor(0x100000000 / (i + 1)) * (i + 1);
    do { draw = crypto.getRandomValues(new Uint32Array(1))[0]; } while (draw >= limit);
    const j = draw % (i + 1); [rows[i], rows[j]] = [rows[j], rows[i]];
  }
  return rows;
}
