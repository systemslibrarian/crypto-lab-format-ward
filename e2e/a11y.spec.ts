import { expect, test, type Page } from '@playwright/test';
import {
  NARROW,
  boot,
  expectBaselineNotStale,
  expectNoNewNonTextFailures,
  scan,
  settle,
} from './gate';

/**
 * WCAG regression gate.
 *
 * Deploys are already gated on the NIST FF1/FF3-1 vectors and the live
 * codebook attack by functional.spec.ts; this gates them on accessibility the
 * same way. See gate.ts for the three rules this file obeys — nothing
 * injected, content asserted before every scan, and `violations` treated as
 * one oracle among five.
 *
 * The page is scanned in both themes, in states a visitor can actually reach,
 * at a 1280px desktop viewport and at a 380px phone one. Little of the
 * interesting rendering is the first-paint one: until Trace Rounds runs there
 * is no round table, no Feistel state and no pipeline; until the codebook
 * attack runs there is no readout and no BROKEN verdict; until the Failure
 * Lab runs there are no leak rows and no avalanche diff. The previous spec
 * drove exactly three buttons, stripped `[hidden]` to expose the unrun attack
 * readout as placeholder dashes no visitor ever sees, and injected style over
 * the whole page before every scan (originally including `opacity: 1
 * !important`, so every de-emphasised rendering shipped measured at a
 * strength it never paints) — and every result and error state beyond those
 * three buttons shipped unscanned.
 */

const THEMES = ['dark', 'light'] as const;

/** Codebook recovery enumerates 1,000 real FF3-1 encryptions via WebCrypto. */
const ATTACK_TIMEOUT = 60_000;

/** Drive the round walkthrough through a real traced FF1 encryption. */
async function traceRounds(page: Page): Promise<void> {
  await page.locator('#rounds-run').click();
  await expect(page.locator('#rounds-status')).toHaveText('Done.');
  await expect(page.locator('#rounds-tbody tr')).toHaveCount(10);
  await expect(page.locator('#rounds-final')).toContainText(/Ciphertext: \d{10}/);
  await expect(page.locator('#round-zoom-body .pipeline')).toBeVisible();
}

/**
 * A state worth scanning: how to reach it from a booted page, and what has to
 * be true once you are there. The assertion is not decoration — it is what
 * stops a scan from passing over a panel that never redrew.
 */
interface State {
  label: string;
  drive: (page: Page) => Promise<void>;
}

const STATES: State[] = [
  {
    // The default mount. boot() has already asserted the async pieces of
    // first paint: the WebCrypto vector smoke check, the feasibility rows for
    // the default 4-digit domain, and the domain calculator's Rev. 1 refusal.
    label: 'first paint / vector check + feasibility + domain refusal',
    drive: async (page) => {
      await expect(page.locator('#feas-beyne')).toContainText('2^23');
      await expect(page.locator('#attack-output')).toBeHidden();
      await expect(page.locator('#start-cipher-out')).toHaveText('—');
    },
  },
  {
    // Every disclosure opened through its real <summary>: the glossary and
    // the start-here "Advanced" note. The round-table disclosure must NOT
    // exist yet — before a trace it would open onto a header-only table, a
    // focusable scroll region with nothing in it (the empty-shell rendering
    // an early gate run caught via axe's `th-has-data-cells` incomplete).
    label: 'disclosures open / glossary + advanced',
    drive: async (page) => {
      await page.locator('.glossary > summary').click();
      await expect(page.locator('.glossary dt')).toHaveCount(8);
      await page.locator('.advanced-details > summary').click();
      await expect(page.locator('.advanced-details .callout')).toBeVisible();
      await expect(page.locator('.rounds-table-details')).toBeHidden();
      await expect(page.locator('#fail-eq-tablewrap')).toBeHidden();
    },
  },
  {
    // The zero-config first encrypt, then the tweak toggled on (which
    // re-runs it): both verdict badges rendered from a computed result, and
    // the tweak-on annotation.
    label: 'start here / encrypted, then tweak toggled on',
    drive: async (page) => {
      await page.locator('#start-run').click();
      await expect(page.locator('#start-cipher-out')).toHaveText(/^\d{16}$/);
      await expect(page.locator('#start-shape-badge')).toHaveClass(/shape-ok/);
      await expect(page.locator('#start-shape-badge')).toHaveText(
        'same 16 digits, same alphabet',
      );
      await expect(page.locator('#start-luhn-badge')).toHaveClass(/shape-(ok|bad)/);
      await expect(page.locator('#start-luhn-badge')).toContainText(/Luhn/);
      await page.locator('#start-tweak-toggle').check();
      await expect(page.locator('#start-cipher-annot')).toContainText('tweak on');
      await expect(page.locator('#start-status')).toContainText('Encrypted with a tweak');
    },
  },
  {
    // The start-here refusal: malformed input, error status, and both badges
    // knocked back to their pending/danger rendering.
    label: 'start here / rejected input',
    drive: async (page) => {
      await page.locator('#start-plain').fill('123');
      await page.locator('#start-run').click();
      await expect(page.locator('#start-status')).toHaveText(
        'Enter exactly 16 digits (spaces are ignored).',
      );
      await expect(page.locator('#start-shape-badge')).toHaveClass(/shape-bad/);
      await expect(page.locator('#start-luhn-badge')).toHaveClass(/shape-bad/);
    },
  },
  {
    // All four use-case panels computed for real: PAN tokenization with Luhn
    // readouts and a round-trip, the SSN mask preserved around encrypted
    // digits, the FF1-vs-FF3-1 comparison with timings, and the custom
    // 36-symbol alphabet round-trip.
    label: 'use-case panels / all four computed',
    drive: async (page) => {
      await page.locator('#cc-run').click();
      await expect(page.locator('#cc-status')).toHaveText('Done.');
      await expect(page.locator('#cc-ff1-out')).toHaveText(/^\d{16}$/);
      await expect(page.locator('#cc-ff1-luhn')).toHaveText(/Luhn (valid|invalid)/);
      await expect(page.locator('#cc-roundtrip')).toContainText('4111111111111111');

      await page.locator('#mask-run').click();
      await expect(page.locator('#mask-status')).toHaveText('Done.');
      await expect(page.locator('#mask-mask')).toHaveText('EEE-EE-EEEE');
      await expect(page.locator('#mask-out')).toHaveText(/^\d{3}-\d{2}-\d{4}$/);
      await expect(page.locator('#mask-back')).toHaveText('123-45-6789');

      await page.locator('#cmp-run').click();
      await expect(page.locator('#cmp-status')).toHaveText('Done.');
      await expect(page.locator('#cmp-ff1-out')).toHaveText(/^\d{18}$/);
      await expect(page.locator('#cmp-ff3-out')).toHaveText(/^\d{18}$/);
      await expect(page.locator('#cmp-ff1-time')).toContainText('ms');

      await page.locator('#custom-run').click();
      await expect(page.locator('#custom-status')).toHaveText('Done.');
      await expect(page.locator('#custom-out')).toHaveText(/^[a-z0-9]{9}$/);
      await expect(page.locator('#custom-back')).toHaveText('alice2026');
      await expect(page.locator('#custom-len')).toHaveText('9');
    },
  },
  {
    // The masked panel's two refusal states, ending on the one the page
    // documents as its exhibit: a well-formed 5-digit ZIP rejected by the
    // Rev. 1 domain floor inside the FF1 implementation itself.
    label: 'mask panel / ZIP refused by the Rev. 1 domain floor',
    drive: async (page) => {
      await page.locator('#mask-format').selectOption('zip');
      await page.locator('#mask-run').click();
      await expect(page.locator('#mask-status')).toHaveText('ZIP must be exactly 5 digits.');
      await page.locator('#mask-plain').fill('90210');
      await page.locator('#mask-run').click();
      await expect(page.locator('#mask-status')).toContainText('Domain too small');
      await expect(page.locator('#mask-status')).toContainText('Draft SP 800-38G Rev. 1');
      await expect(page.locator('#mask-out')).toHaveText('-');
    },
  },
  {
    // A full traced encryption: the 10-row round table opened through its
    // real <summary>, the Feistel stage stepped so changed digits carry their
    // pulse highlight, and the round-zoom pipeline on a round whose column
    // addition actually drops digits in the modular wrap — the struck-through
    // danger rendering.
    label: 'round walkthrough / traced, stepped, wrap digits dropped',
    drive: async (page) => {
      await traceRounds(page);
      await page.locator('.rounds-table-details > summary').click();
      await expect(page.locator('#rounds-tbody tr')).toHaveCount(10);

      await page.locator('#feistel-next').click();
      await expect(page.locator('#feistel-step-label')).toHaveText('round 0 of 9 · after swap');
      expect(
        await page.locator('.feistel-half-val .digit-pulse').count(),
        'stepping must highlight the digits the round changed',
      ).toBeGreaterThan(0);

      await expect(page.locator('#round-zoom-body .pipe-step')).toHaveCount(5);
      await expect(page.locator('#round-zoom-body .pipe-aes')).toBeVisible();
      let found = false;
      for (let i = 0; i < 10 && !found; i += 1) {
        await page.locator('#round-zoom-select').selectOption(String(i));
        await expect(page.locator('#round-zoom-body .pipeline')).toBeVisible();
        found = (await page.locator('#round-zoom-body .wrap-drop').count()) > 0;
      }
      expect(found, 'some round must show digits dropped by the modular wrap').toBe(true);
    },
  },
  {
    // The Failure Lab computed end to end: four equality-leak rows with their
    // danger tags, the avalanche diff with changed symbols highlighted, and
    // the domain calculator flipped to its passing verdict and back to the
    // refusal.
    label: 'failure lab / leak rows + avalanche diff + both verdicts',
    drive: async (page) => {
      await page.locator('#fail-eq-run').click();
      await expect(page.locator('#fail-eq-status')).toContainText('ciphertext(s) repeat');
      await expect(page.locator('#fail-eq-tablewrap')).toBeVisible();
      await expect(page.locator('#fail-eq-tbody tr')).toHaveCount(5);
      await expect(page.locator('#fail-eq-tbody .leak-tag')).toHaveCount(4);

      await page.locator('#fail-av-run').click();
      await expect(page.locator('#fail-av-status')).toContainText(/\d+\/12 symbols changed/);
      expect(
        await page.locator('#fail-av-ct2 .diff').count(),
        'the avalanche readout must highlight changed symbols',
      ).toBeGreaterThan(0);

      await page.locator('#fail-dom-len').fill('9');
      await expect(page.locator('#fail-dom-out')).toContainText('Meets the Draft');
      await page.locator('#fail-dom-len').fill('4');
      await expect(page.locator('#fail-dom-out')).toContainText('REJECTED');
    },
  },
  {
    // The live break, run for real over the 1,000-value domain: the readout
    // rows populated from the actual enumeration and the BROKEN verdict in
    // its danger rendering — none of which exists at first paint.
    label: 'codebook attack / secret recovered, BROKEN verdict',
    drive: async (page) => {
      await page.locator('#attack-length').selectOption('3');
      await page.locator('#attack-run').click();
      const verdict = page.locator('#attack-verdict');
      await expect(verdict).toHaveAttribute('data-verdict', 'recovered', {
        timeout: ATTACK_TIMEOUT,
      });
      await expect(verdict).toHaveClass(/leaked/);
      await expect(verdict).toContainText('BROKEN');
      await expect(page.locator('#attack-status')).toHaveText('Done.');
      const secret = (await page.locator('#attack-secret').textContent())?.trim();
      expect(secret).toMatch(/^\d{3}$/);
      await expect(page.locator('#attack-recovered')).toHaveText(secret!);
    },
  },
  {
    // The page's own skip link is parked at `top: -100%` until focused. The
    // contrast walk deliberately skips text that paints no pixels, so the
    // only way its colours are ever measured is to focus it for real.
    label: 'in-page skip link focused',
    drive: async (page) => {
      await page.locator('.skip-link').focus();
      await expect(page.locator('.skip-link')).toBeFocused();
      await settle(page);
      const onScreen = await page
        .locator('.skip-link')
        .evaluate((el) => el.getBoundingClientRect().top >= 0);
      expect(onScreen, 'the in-page skip link must be on screen when focused').toBe(true);
    },
  },
  {
    // Same for the shared header's skip link (parked at `top: -3rem`, slides
    // in on a `transition: top .15s ease` — let it drain before reading
    // geometry).
    label: 'header skip link focused',
    drive: async (page) => {
      await page.locator('.cl-skip-link').focus();
      await expect(page.locator('.cl-skip-link')).toBeFocused();
      await settle(page);
      const onScreen = await page
        .locator('.cl-skip-link')
        .evaluate((el) => el.getBoundingClientRect().top >= 0);
      expect(onScreen, 'the header skip link must slide into view on focus').toBe(true);
    },
  },
];

for (const theme of THEMES) {
  for (const state of STATES) {
    test(`${theme} — ${state.label}`, async ({ page }) => {
      test.setTimeout(300_000);
      await boot(page, theme);
      await state.drive(page);
      await scan(page, `${theme} / ${state.label} / 1280px`);

      // Same state, phone width. Reflow (1.4.10) has no axe rule, and axe's
      // `scrollable-region-focusable` never fires on a container whose
      // content still fits — the round table and the column-addition <pre>
      // fit the desktop column and only overflow here.
      await page.setViewportSize(NARROW);
      await settle(page);
      await scan(page, `${theme} / ${state.label} / ${NARROW.width}px`);
    });
  }
}

/**
 * The third rule of the non-text baseline, and why it needs a test of its own.
 *
 * `nontext-baseline.ts` announces three rules; `expectBaselineNotStale` is the
 * third — a baselined finding that no longer appears fails, so a fixed entry
 * has to be deleted instead of lingering as a permanent exemption. It was
 * exported from `gate.ts` and never imported, so it had never run and this
 * baseline could only grow.
 *
 * It cannot be bolted onto the tests above. `nonTextSeen` is module state, so
 * the check only ever sees the states its own worker drove, and every test
 * above drives exactly ONE state. Worse, the six non-shared entries are not
 * merely state-specific, they are one-state-each AND light-theme-only, which
 * a capture pass through the gate's own path measured:
 *
 *   #start-run    2.21:1  light, 'start here / rejected input'
 *   #custom-run   2.21:1  light, 'use-case panels / all four computed'
 *   #mask-run     2.21:1  light, 'mask panel / ZIP refused'
 *   #feistel-next 2.13:1  light, 'round walkthrough'
 *   #fail-av-run  2.21:1  light, 'failure lab'
 *   #attack-run   2.21:1  light, 'codebook attack'
 *
 * They are one-state-each because `nontext.ts` skips `disabled` controls —
 * the WCAG 1.4.11 exemption for inactive components — and this lab disables
 * every run button until its panel is usable, so each is measurable only in
 * the state that enables it. They are light-only because the boundary is drawn
 * against the light surface. No single existing test can see more than one of
 * them, so wiring the ratchet into them reported six false stales in all
 * twenty-two.
 *
 * This test therefore re-walks the whole state matrix in ONE worker so the set
 * is a real union. It calls `expectNoNewNonTextFailures` rather than `scan`:
 * the twenty-two tests above already run the full WCAG gate on these states,
 * and what this one needs is the non-text audit that feeds `nonTextSeen`.
 * Both themes and both widths are walked rather than just the light desktop
 * pass the measurements above would justify, so that a future entry living in
 * dark or at 380px does not read as stale.
 */
test('non-text baseline: every baselined finding still appears somewhere', async ({ page }) => {
  test.setTimeout(600_000);
  const desktop = page.viewportSize();
  for (const theme of THEMES) {
    for (const state of STATES) {
      if (desktop) await page.setViewportSize(desktop);
      await boot(page, theme);
      await state.drive(page);
      await settle(page);
      await expectNoNewNonTextFailures(page, `${theme} / ${state.label} / 1280px`);

      await page.setViewportSize(NARROW);
      await settle(page);
      await expectNoNewNonTextFailures(page, `${theme} / ${state.label} / ${NARROW.width}px`);
    }
  }
  expectBaselineNotStale();
});
