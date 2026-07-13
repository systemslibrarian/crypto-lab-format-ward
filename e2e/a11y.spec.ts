import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST FF1/FF3-1 vectors;
 * this gates them on accessibility the same way. Scans the full page in both
 * themes with every collapsible expanded and animations neutralized so nothing
 * is scanned mid-flight.
 *
 * This lab's interactive result panels render into always-visible <output>/
 * table regions (no display:none reveal needed), and it has one <details>
 * glossary. We open every <details> and clear any inline display:none/[hidden]
 * regions defensively so their contents are always scanned.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content:
      '*, *::before, *::after { animation: none !important; transition: none !important; opacity: 1 !important; }\n' +
      'body { animation: none !important; }',
  });
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

/**
 * Several teaching regions render only after a button click (the "Start here"
 * compare, the round-walkthrough pipeline + modular column addition, and the
 * Feistel swap stage). Trigger them so their injected markup — badges, the
 * struck-through modular-wrap digits, the AES pipeline steps — is inside the
 * accessibility scan, not just the empty placeholders.
 */
async function populateDynamic(page: Page): Promise<void> {
  await page.locator('#start-run').click();
  await expect(page.locator('#start-cipher-out')).toHaveText(/\d{16}/);
  await page.locator('#rounds-run').click();
  await expect(page.locator('#round-zoom-body .pipeline')).toBeVisible();
  await page.locator('#feistel-next').click();
}

async function runSuite(page: Page): Promise<void> {
  await populateDynamic(page);
  await revealAll(page);
  await neutralizeMotion(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});
