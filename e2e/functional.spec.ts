import { expect, test } from '@playwright/test';

/**
 * Functional gate for the live FF3-1 codebook-recovery exhibit. Drives the real
 * attack in the browser and asserts the computed outcome — the defender's secret
 * is recovered with no key — plus the computed feasibility numbers. This gates
 * the deploy on the break actually running, not just being described.
 */

test('codebook recovery reads out the defender secret with no key', async ({ page }) => {
  await page.goto('.');

  // Use the smaller 1,000-value domain so the attack finishes quickly.
  await page.locator('#attack-length').selectOption('3');
  await page.locator('#attack-run').click();

  const verdict = page.locator('#attack-verdict');
  await expect(verdict).toHaveAttribute('data-verdict', 'recovered', { timeout: 30_000 });
  await expect(verdict).toContainText(/BROKEN/i);

  // The recovered plaintext must equal the defender's secret (computed, not canned).
  const secret = (await page.locator('#attack-secret').textContent())?.trim();
  const recovered = (await page.locator('#attack-recovered').textContent())?.trim();
  expect(secret).toBeTruthy();
  expect(recovered).toBe(secret);

  // Queries spent are bounded by the domain size (1,000).
  const queries = Number((await page.locator('#attack-queries').textContent())?.replace(/[^0-9]/g, ''));
  expect(queries).toBeGreaterThan(0);
  expect(queries).toBeLessThanOrEqual(1000);
});

test('feasibility numbers are computed and flag sub-floor domains', async ({ page }) => {
  await page.goto('.');

  // 4-digit domain (10,000) is below the NIST 10^6 floor.
  await page.locator('#attack-length').selectOption('4');
  await expect(page.locator('#feas-codebook')).toContainText(/10,000 queries/);
  await expect(page.locator('#feas-floor')).toContainText(/NO/);
  await expect(page.locator('#feas-beyne')).toContainText(/2\^23|8,388,608/);
});
