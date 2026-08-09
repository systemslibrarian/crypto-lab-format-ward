import type { Page } from '@playwright/test';

/**
 * Composite-aware WCAG 1.4.3 contrast measurement.
 *
 * This exists because axe is not a complete contrast oracle. Two classes of
 * text never reach the `violations` array a gate asserts on:
 *
 *  - text over a background axe declines to resolve — every panel, chip and
 *    pipe-step on this page is tinted with `color-mix(... , transparent)`
 *    washes over the card surface, and the body itself is a stack of radial
 *    gradients; axe files most of it under `incomplete` and moves on;
 *  - text faded by an ancestor's `opacity` — axe reads the declared `color`,
 *    which is not the colour that lands on screen. This page's hero subtitle
 *    (`.cl-hero-sub`) paints at `opacity: .85`, and the previous gate's
 *    injected `opacity: 1 !important` measured it at a strength the page
 *    never renders.
 *
 * So: walk every element that owns text, composite the real painted result
 * (translucent colours, gradient stops and opacity groups included), and
 * compute the ratio against the surface the text is genuinely sitting on
 * rather than against white. A gradient is judged at its worst stop.
 *
 * Opacity is modelled the way the compositor actually does it: an element with
 * `opacity < 1` renders its subtree into a group, then composites the group
 * over the backdrop. That means the *text* and the *background beside it* fade
 * onto the same backdrop independently — which is why both are carried through
 * the walk as a pair rather than fading the foreground alone.
 *
 * The ancestor walk is geometry-aware, because DOM ancestry is not the same
 * thing as "painted underneath": an ancestor's own paint is applied only when
 * its border box actually intersects the text's box. A partial intersection
 * still counts, so the judgement stays worst-case. Opacity is unconditional
 * either way — an opacity group fades its whole subtree wherever that subtree
 * happens to paint.
 *
 * Two more properties of this page the helper has to respect:
 *
 *  - TEXT SCROLLED OUT OF A CLIPPING ANCESTOR PAINTS NOTHING. The round table
 *    (`min-width: 640px` inside `.table-wrap`), the comparison and equality
 *    tables, and the column-addition `<pre>` all clip their overflow; at 380px
 *    most of their content sits outside the client box: clipped, unpainted.
 *    Its rect is still to the right of every ancestor's box, so the ancestor
 *    walk would find nothing behind it and fall through to white, reporting a
 *    ratio nothing on screen has. Skip clipped text and rely on the
 *    states/widths where the same element is visible and measured for real.
 *
 *  - TEXT PARKED OFF-SCREEN PAINTS NOTHING. Both skip links — the shared
 *    header's `.cl-skip-link` (parked at `top: -3rem`) and the page's own
 *    `.skip-link` (parked at `top: -100%`) — are the WCAG-sanctioned
 *    "visually hidden until focused" idiom. Measuring the parked copy invents
 *    a failure for text that is not on screen; the focused renderings are real
 *    states and the gate scans both explicitly.
 *
 * SVG text support (ink from `fill`, backdrop from a preceding sibling shape)
 * is retained from the fleet version of this helper. This page's only SVGs are
 * the header's aria-hidden icons, which own no text, so the branch is inert
 * here — but it costs nothing and keeps the helper honest if an SVG exhibit
 * lands later.
 */

export interface ContrastFailure {
  selector: string;
  text: string;
  foreground: string;
  background: string;
  fontSize: number;
  fontWeight: number;
  required: number;
  ratio: number;
}

export async function auditContrast(page: Page): Promise<ContrastFailure[]> {
  return page.evaluate(() => {
    interface RGBA {
      r: number;
      g: number;
      b: number;
      a: number;
    }

    const TRANSPARENT: RGBA = { r: 0, g: 0, b: 0, a: 0 };
    const WHITE: RGBA = { r: 255, g: 255, b: 255, a: 1 };

    const parse = (c: string): RGBA | null => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) return null;
      const p = m[1]
        .split(/[ ,/]+/)
        .filter(Boolean)
        .map(Number);
      if (p.length < 3 || p.some((n) => Number.isNaN(n))) return null;
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    };

    /** Standard source-over compositing of a (possibly translucent) src on dst. */
    const over = (src: RGBA, dst: RGBA): RGBA => {
      const a = src.a + dst.a * (1 - src.a);
      if (a === 0) return TRANSPARENT;
      return {
        r: (src.r * src.a + dst.r * dst.a * (1 - src.a)) / a,
        g: (src.g * src.a + dst.g * dst.a * (1 - src.a)) / a,
        b: (src.b * src.a + dst.b * dst.a * (1 - src.a)) / a,
        a,
      };
    };

    const fade = (c: RGBA, o: number): RGBA => (o >= 1 ? c : { ...c, a: c.a * o });

    const luminance = (c: RGBA): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };

    const ratio = (a: RGBA, b: RGBA): number => {
      const l1 = luminance(a);
      const l2 = luminance(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };

    const gradientStops = (cs: CSSStyleDeclaration): RGBA[] | null => {
      const bi = cs.backgroundImage;
      if (!bi || bi === 'none' || !/gradient/.test(bi)) return null;
      const cols = bi.match(/rgba?\([^)]+\)/g);
      if (!cols) return null;
      const stops = cols.map(parse).filter((c): c is RGBA => c !== null && c.a > 0);
      return stops.length ? stops : null;
    };

    /**
     * Every paint this element's own box could put behind its text: the
     * background-color, plus one candidate per gradient stop layered on top of
     * it, so a gradient (the body's radial washes, the hero's surface blend)
     * is judged at its worst point rather than at an average that renders
     * nowhere.
     */
    const ownPaints = (cs: CSSStyleDeclaration): RGBA[] => {
      const color = parse(cs.backgroundColor) ?? TRANSPARENT;
      const grad = gradientStops(cs);
      if (!grad) return [color];
      return grad.map((g) => over(g, color));
    };

    /** Do two border boxes share any painted area at all? */
    const intersects = (a: DOMRect, b: DOMRect): boolean =>
      Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) > 0 &&
      Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top)) > 0;

    /** Does `a` sit entirely inside `b`? */
    const contains = (outer: DOMRect, inner: DOMRect): boolean =>
      inner.left >= outer.left - 0.5 &&
      inner.right <= outer.right + 0.5 &&
      inner.top >= outer.top - 0.5 &&
      inner.bottom <= outer.bottom + 0.5;

    /**
     * Style and geometry are memoised per element for one pass. A traced
     * round table renders seven cells per round and the codebook attack fills
     * four monospace rows; every one of them walks the same handful of
     * ancestors, and without the caches the pass re-reads the same computed
     * styles and rects over and over. Nothing mutates the DOM during the
     * pass, so the cached values cannot go stale.
     */
    const styleCache = new Map<Element, CSSStyleDeclaration>();
    const styleOf = (el: Element): CSSStyleDeclaration => {
      let cs = styleCache.get(el);
      if (!cs) {
        cs = getComputedStyle(el);
        styleCache.set(el, cs);
      }
      return cs;
    };
    const rectCache = new Map<Element, DOMRect>();
    const rectOf = (el: Element): DOMRect => {
      let r = rectCache.get(el);
      if (!r) {
        r = el.getBoundingClientRect();
        rectCache.set(el, r);
      }
      return r;
    };

    /**
     * Every container that clips its overflow, with the box it clips to.
     * An `overflow: auto` container paints only what falls inside that box.
     * Content scrolled beyond it is not dimmed or partly drawn — it is absent
     * from the frame, and asking what colour it sits on has no answer.
     */
    const clippers = Array.from(document.querySelectorAll('body *')).filter((el) => {
      const cs = styleOf(el);
      return /auto|scroll|hidden|clip/.test(cs.overflowX + ' ' + cs.overflowY);
    });

    const clippedAway = (el: Element, box: DOMRect): boolean =>
      clippers.some((c) => c !== el && c.contains(el) && !intersects(box, rectOf(c)));

    /**
     * SVG has no `background-color`: shapes paint in document order, so the
     * surface under a `<text>` is whichever earlier sibling shape lies beneath
     * it. Composite those, innermost-last, before the ancestor walk starts.
     */
    const svgUnderlay = (el: Element, box: DOMRect): RGBA => {
      let bg = TRANSPARENT;
      let sib = el.previousElementSibling;
      const stack: Element[] = [];
      while (sib) {
        stack.push(sib);
        sib = sib.previousElementSibling;
      }
      // Earliest sibling first — that is the order the compositor paints in.
      for (const s of stack.reverse()) {
        if (s.tagName === 'text' || s.tagName === 'title' || s.tagName === 'desc') continue;
        if (!contains(rectOf(s), box)) continue;
        const scs = styleOf(s);
        const fill = parse(scs.fill);
        if (!fill) continue;
        const op = parseFloat(scs.fillOpacity || '1') * parseFloat(scs.opacity || '1');
        bg = over(fade(fill, Number.isFinite(op) ? op : 1), bg);
      }
      return bg;
    };

    /**
     * Does this element's own `clip` / `clip-path` reduce it to zero area?
     *
     * `clip: rect(t, r, b, l)` applies only to absolutely positioned boxes and
     * is what the classic `.sr-only` recipe uses; `clip-path: inset(50%)` is the
     * modern spelling of the same trick. Either at zero area means the
     * compositor draws nothing, so there is no painted ink to measure — but the
     * box still has a 1x1 rect, a non-zero opacity and passes
     * `checkVisibility()`, so every other test in `isVisible` says "visible".
     * Without this the walk composites visually-hidden text against whatever
     * surface it happens to sit on and INVENTS failures: 1.15:1 for a card's
     * screen-reader-only suit name, 4.39:1 for an `.sr-only` twin of an
     * `aria-hidden` glyph. Deliberately narrow — only a ZERO-area clip
     * qualifies, so a real partial clip is still measured.
     */
    const clippedToNothing = (cs: CSSStyleDeclaration): boolean => {
      const clip = cs.clip;
      if (clip && clip !== 'auto') {
        const nums = clip.match(/-?[\d.]+/g)?.map(Number);
        if (nums && nums.length === 4) {
          // Tuple-typed: under `noUncheckedIndexedAccess` a plain destructure of
          // `number[]` yields `number | undefined` for each name, which fails
          // `tsc --noEmit` in the repos whose build typechecks the e2e tree.
          const [top, right, bottom, left] = nums as [number, number, number, number];
          if (bottom - top <= 0 || right - left <= 0) return true;
        }
      }
      const path = cs.clipPath;
      if (path && path.startsWith('inset(')) {
        const pct = path.match(/([\d.]+)%/g)?.map((v) => parseFloat(v)) ?? [];
        if (pct.length && pct.every((v) => v >= 50)) return true;
      }
      return false;
    };

    const isVisible = (el: Element): boolean => {
      const cs = styleOf(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
      if (parseFloat(cs.opacity) === 0) return false;
      // Visually hidden: a real box that paints no pixels. See above.
      if (clippedToNothing(cs)) return false;
      // Covers `content-visibility`-style hiding (a closed <details> body) that
      // the display/rect tests above miss while Chromium keeps stale geometry.
      if ((el as HTMLElement).checkVisibility?.() === false) return false;
      const r = rectOf(el);
      if (r.width <= 0 || r.height <= 0) return false;
      // Text parked off the top/left edge of the page paints no pixels — both
      // skip links until focused. The focused renderings are real states and
      // the gate scans them explicitly.
      // DOCUMENT space, not viewport space. `getBoundingClientRect()` is
      // viewport-relative, so once Playwright scrolls a control into view every
      // element ABOVE the viewport has `bottom <= 0` and this guard silently
      // dropped it from the walk. Measured on one lab: 27 of 105 text-owning
      // elements — 26% of the page — vanished from the oracle at the end of a
      // drive. A green contrast run on a page taller than the viewport could
      // not be trusted. Adding the scroll offset restores the original intent
      // (text parked off the top/left of the DOCUMENT — the "visually hidden
      // until focused" idiom) without hiding the part of the page that has
      // merely been scrolled past.
      if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) return false;
      // Scrolled out of an `overflow: auto` container — clipped, not painted.
      if (clippedAway(el, r)) return false;
      return true;
    };

    const ownText = (el: Element): string => {
      let t = '';
      for (const n of Array.from(el.childNodes)) {
        if (n.nodeType === Node.TEXT_NODE) t += n.textContent ?? '';
      }
      return t.trim();
    };

    const describe = (el: Element): string => {
      let s = el.tagName.toLowerCase();
      if (el.id) s += `#${el.id}`;
      const cls = el.getAttribute('class');
      if (cls) s += `.${cls.trim().split(/\s+/).join('.')}`;
      return s;
    };

    /**
     * WCAG 1.4.3 exempts text that is part of an *inactive* user-interface
     * component, and axe skips disabled controls for the same reason. This
     * page leans on that exemption for real: the Feistel stepper's
     * `.mini-btn:disabled { opacity: .5 }` and the round-zoom select before a
     * trace are deliberately dimmed disabled controls, which the spec does not
     * require to meet 4.5:1.
     */
    const inactive = (el: Element): boolean => {
      let n: Element | null = el;
      while (n) {
        if ((n as HTMLInputElement).disabled === true) return true;
        if (n.getAttribute('aria-disabled') === 'true') return true;
        n = n.parentElement;
      }
      return false;
    };

    const failures: unknown[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const text = ownText(el);
      if (!text) continue;
      if (!isVisible(el)) continue;
      if (inactive(el)) continue;

      const cs = styleOf(el);
      // SVG text takes its ink from `fill`, not `color`.
      const svgText = el.namespaceURI === 'http://www.w3.org/2000/svg';
      const fgRaw = parse(svgText ? cs.fill : cs.color);
      if (!fgRaw) continue;
      // `color: transparent` lays no ink down at all; there is no contrast
      // requirement on ink that is never painted.
      if (fgRaw.a === 0) continue;

      const size = parseFloat(cs.fontSize);
      const weight = parseInt(cs.fontWeight, 10) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const required = large ? 3 : 4.5;

      // Carry (text, adjacent background) as a pair up the ancestor chain,
      // painting each ancestor's own background beneath both and applying that
      // ancestor's opacity to both, exactly as the compositor would.
      const textBox = rectOf(el);
      const under = svgText ? svgUnderlay(el, textBox) : TRANSPARENT;
      let pairs: { fg: RGBA; bg: RGBA }[] = [{ fg: fgRaw, bg: under }];
      let node: Element | null = el;
      while (node) {
        const ncs = styleOf(node);
        const opacity = parseFloat(ncs.opacity);
        // An ancestor that does not overlap the text paints nothing behind it.
        const paints =
          node === el || intersects(textBox, rectOf(node)) ? ownPaints(ncs) : [TRANSPARENT];
        const next: { fg: RGBA; bg: RGBA }[] = [];
        for (const p of pairs) {
          for (const paint of paints) {
            next.push({
              fg: fade(over(p.fg, paint), opacity),
              bg: fade(over(p.bg, paint), opacity),
            });
          }
        }
        pairs = next;
        // Stop once the accumulated backdrop is fully opaque: nothing further
        // out can change the painted result.
        if (pairs.every((p) => p.bg.a >= 1)) break;
        node = node.parentElement;
      }

      let worst: { r: number; fg: RGBA; bg: RGBA } | null = null;
      for (const p of pairs) {
        const fg = over(p.fg, WHITE);
        const bg = over(p.bg, WHITE);
        const r = ratio(fg, bg);
        if (!worst || r < worst.r) worst = { r, fg, bg };
      }
      if (!worst) continue;

      // Round to 2dp before comparing so a value that is exactly on the floor
      // (e.g. 4.50) is not failed by float noise, and one just under it is not
      // rounded up into a pass.
      const rounded = Math.round(worst.r * 100) / 100;
      if (rounded >= required) continue;

      const show = (c: RGBA): string =>
        `rgb(${[c.r, c.g, c.b].map((v) => Math.round(v)).join(', ')})`;

      failures.push({
        selector: describe(el),
        text: text.slice(0, 60),
        foreground: show(worst.fg),
        background: show(worst.bg),
        fontSize: size,
        fontWeight: weight,
        required,
        ratio: rounded,
      });
    }
    return failures as never;
  });
}

/** Render failures as short strings so an assertion diff is readable. */
export function formatContrastFailures(failures: ContrastFailure[]): string[] {
  return failures.map(
    (f) =>
      `${f.ratio}:1 (needs ${f.required}:1) ${f.selector} — fg ${f.foreground} on ${f.background} — "${f.text}"`,
  );
}
