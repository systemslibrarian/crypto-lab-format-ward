import { expect, test } from 'vitest';
import { ROSTER, formatLeakage, matchFormats, releaseSyntheticRoster, shape } from './reidentification';

test('real FF1 output preserves format classes across fresh keys and tweaks', async () => {
  const a = await releaseSyntheticRoster(false), b = await releaseSyntheticRoster(false);
  expect(a.map(x => shape(x, 'both')).sort()).toEqual(ROSTER.map(x => shape(x, 'both')).sort());
  expect(a).not.toEqual(b);
  for (const row of a) expect(row.name).toMatch(/^[A-Z]+(?: [A-Z]+)*$/);
  const matches = matchFormats(a, ROSTER, 'both', false);
  expect(matches.map(x => x.candidates.length).sort()).toEqual([1, 1, 1, 1, 1, 1, 2, 2]);
});
test('partition entropy and candidates use the declared uniform roster', () => {
  const r = formatLeakage(ROSTER, 'both', false);
  expect(r).toEqual({ leakage: 2.75, unique: 6, expectedCandidates: 1.25, priorEntropy: 3, groups: 7 });
  expect(formatLeakage(ROSTER, 'words', false).leakage).toBeLessThan(r.leakage);
  // A missing auxiliary candidate gives no match, not a fabricated identity.
  expect(matchFormats([ROSTER[7]], ROSTER.slice(0, 7), 'both', false)[0].candidates).toEqual([]);
});
test('fixed-length authenticated ciphertexts reveal no roster format distinction', async () => {
  const release = await releaseSyntheticRoster(true);
  expect(new Set(release.map(x => x.name.length))).toEqual(new Set([312]));
  expect(new Set(release.map(x => x.name)).size).toBe(8);
  expect(matchFormats(release, ROSTER, 'both', true).every(x => x.candidates.length === 8)).toBe(true);
  expect(formatLeakage(ROSTER, 'both', true)).toEqual({ leakage: 0, unique: 0, expectedCandidates: 8, priorEntropy: 3, groups: 1 });
});
