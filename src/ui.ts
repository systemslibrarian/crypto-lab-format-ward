import {
  FF1Round,
  MIN_DOMAIN_SIZE,
  bytesToHex,
  ff1Decrypt,
  ff1Encrypt,
  ff1EncryptTraced,
  generateRandomKeyHex,
  hexToBytes,
  importAes256KeyFromHex,
  importFf3KeyFromHex,
  stringToSymbols,
  symbolsToString
} from "./ff1";
import { ff3_1Decrypt, ff3_1Encrypt } from "./ff3";
import { runCodebookAttack, feasibility } from "./attack";
import {
  MaskedFormat,
  fromDigitSymbols,
  isCreditCardCandidate,
  luhnValid,
  mergeMaskedDigits,
  parseMaskedFormat,
  toDigitSymbols,
  validateCustomAlphabet
} from "./formats";

const DEFAULT_FF1_TWEAK = "39383736353433323130";
const DEFAULT_FF3_1_TWEAK = "d8e7920afa330a";

function setText(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = text;
  }
}
function getInputValue(id: string): string {
  const el = document.getElementById(id) as HTMLInputElement | null;
  if (!el) {
    throw new Error(`Missing input #${id}`);
  }
  return el.value;
}

function setInputValue(id: string, value: string): void {
  const el = document.getElementById(id) as HTMLInputElement | null;
  if (el) {
    el.value = value;
  }
}

function normalizeHex(input: string): string {
  return input.trim().toLowerCase();
}

async function parseAes256Key(id: string): Promise<CryptoKey> {
  const keyHex = normalizeHex(getInputValue(id));
  return importAes256KeyFromHex(keyHex);
}

async function parseKeyPair(id: string): Promise<{ ff1Key: CryptoKey; ff3Key: CryptoKey }> {
  const keyHex = normalizeHex(getInputValue(id));
  if (hexToBytes(keyHex).length !== 32) {
    throw new Error("AES-256 key must be exactly 64 hex chars.");
  }
  const ff1Key = await importAes256KeyFromHex(keyHex);
  // FF3-1 runs AES under the byte-reversed key (NIST SP 800-38G Rev.1).
  const ff3Key = await importFf3KeyFromHex(keyHex);
  return { ff1Key, ff3Key };
}

function disableButton(id: string): void {
  const el = document.getElementById(id) as HTMLButtonElement | null;
  if (el) el.disabled = true;
}

function enableButton(id: string): void {
  const el = document.getElementById(id) as HTMLButtonElement | null;
  if (el) el.disabled = false;
}

function parseOptionalHexTweak(hex: string): Uint8Array {
  const normalized = normalizeHex(hex);
  if (normalized.length === 0) {
    return new Uint8Array();
  }
  return hexToBytes(normalized);
}

function parseFF3_1Tweak(hex: string): Uint8Array {
  const tweak = hexToBytes(normalizeHex(hex));
  if (tweak.length !== 7) {
    throw new Error("FF3-1 tweak must be exactly 14 hex chars (56 bits).");
  }
  return tweak;
}

async function runVectorSmokeCheck(): Promise<void> {
  try {
    const ff1Key = await importAes256KeyFromHex(
      "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94"
    );
    const ff1Pt = toDigitSymbols("0123456789");
    const ff1Ct = await ff1Encrypt(ff1Key, 10, ff1Pt, hexToBytes("39383736353433323130"));
    const ff1CtStr = fromDigitSymbols(ff1Ct);

    // ACVP FF3-1 AES-128 vector (tg1/tc1). FF3-1 runs AES under the reversed key.
    const ff3Key = await importFf3KeyFromHex("2de79d232df5585d68ce47882ae256d6");
    const ff3Pt = toDigitSymbols("3992520240");
    const ff3Ct = await ff3_1Encrypt(ff3Key, 10, ff3Pt, hexToBytes("cbd09280979564"));
    const ff3CtStr = fromDigitSymbols(ff3Ct);

    const ff1Expected = "1001623463";
    const ff3Expected = "8901801106";

    const ok = ff1CtStr === ff1Expected && ff3CtStr === ff3Expected;
    if (ok) {
      setText("vector-status", "NIST smoke check passed (FF1 + FF3-1 vectors).");
      return;
    }

    setText(
      "vector-status",
      `Vector mismatch. FF1=${ff1CtStr} (exp ${ff1Expected}), FF3-1=${ff3CtStr} (exp ${ff3Expected}).`
    );
  } catch (error) {
    setText("vector-status", `Vector check failed: ${(error as Error).message}`);
  }
}

function wireKeyGenerators(): void {
  const pairs: Array<{ buttonId: string; inputId: string }> = [
    { buttonId: "cc-key-gen", inputId: "cc-key" },
    { buttonId: "mask-key-gen", inputId: "mask-key" },
    { buttonId: "cmp-key-gen", inputId: "cmp-key" },
    { buttonId: "custom-key-gen", inputId: "custom-key" },
    { buttonId: "rounds-key-gen", inputId: "rounds-key" },
    { buttonId: "fail-key-gen", inputId: "fail-key" }
  ];

  for (const pair of pairs) {
    const btn = document.getElementById(pair.buttonId) as HTMLButtonElement | null;
    btn?.addEventListener("click", () => {
      setInputValue(pair.inputId, generateRandomKeyHex(32));
    });
  }
}

// A fixed demo key + tweak for the zero-config "Start here" step. This is real
// FF1 over real AES-256 — the same primitive the panels below use — just with a
// preset key so a newcomer meets the behaviour before meeting key management.
const START_DEMO_KEY_HEX =
  "2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94";
const START_TWEAK = "39383736353433323130";

function setBadge(id: string, ok: boolean, label: string): void {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = label;
  el.classList.remove("shape-idle", "shape-ok", "shape-bad");
  el.classList.add(ok ? "shape-ok" : "shape-bad");
}

function wireStartHere(): void {
  const button = document.getElementById("start-run") as HTMLButtonElement | null;
  const run = async (): Promise<void> => {
    disableButton("start-run");
    setText("start-status", "Running…");
    try {
      const raw = getInputValue("start-plain").replace(/\s+/g, "");
      if (!/^\d{16}$/.test(raw)) {
        throw new Error("Enter exactly 16 digits (spaces are ignored).");
      }
      const key = await importAes256KeyFromHex(START_DEMO_KEY_HEX);
      const useTweak = (document.getElementById("start-tweak-toggle") as HTMLInputElement | null)?.checked;
      const tweak = useTweak ? hexToBytes(START_TWEAK) : new Uint8Array();

      const cipher = fromDigitSymbols(await ff1Encrypt(key, 10, toDigitSymbols(raw), tweak));

      setText("start-plain-out", raw);
      setText("start-cipher-out", cipher);
      setText("start-plain-annot", `${raw.length} digits · radix 10`);
      setText(
        "start-cipher-annot",
        `${cipher.length} digits · radix 10${useTweak ? " · tweak on" : ""}`
      );

      const sameShape = cipher.length === raw.length && /^\d+$/.test(cipher);
      setBadge(
        "start-shape-badge",
        sameShape,
        sameShape ? `same ${cipher.length} digits, same alphabet` : "shape changed"
      );
      const luhnOk = luhnValid(cipher);
      setBadge(
        "start-luhn-badge",
        luhnOk,
        luhnOk ? "still passes Luhn" : "fails Luhn (expected — FPE ≠ valid-PAN)"
      );
      setText(
        "start-status",
        useTweak
          ? "Encrypted with a tweak. Toggle it off and re-run: same input, different ciphertext."
          : "Same length, same character set — that is format preservation. Now toggle the tweak."
      );
    } catch (error) {
      setText("start-status", (error as Error).message);
      setBadge("start-shape-badge", false, "shape check pending");
      setBadge("start-luhn-badge", false, "Luhn pending");
    } finally {
      enableButton("start-run");
    }
  };
  button?.addEventListener("click", run);
  document.getElementById("start-tweak-toggle")?.addEventListener("change", () => {
    const out = document.getElementById("start-cipher-out");
    if (out && out.textContent && out.textContent !== "—") run();
  });
}

function wirePanel1(): void {
  const button = document.getElementById("cc-run") as HTMLButtonElement | null;
  button?.addEventListener("click", async () => {
    disableButton("cc-run");
    setText("cc-status", "Running...");
    try {
      const input = getInputValue("cc-plain").replace(/\D/g, "");
      if (!isCreditCardCandidate(input)) {
        throw new Error("Credit card input must be exactly 16 digits.");
      }

      const { ff1Key, ff3Key } = await parseKeyPair("cc-key");
      const ff1Tweak = parseOptionalHexTweak(getInputValue("cc-ff1-tweak"));
      const ff31Tweak = parseFF3_1Tweak(getInputValue("cc-ff3-tweak"));
      const symbols = toDigitSymbols(input);

      const ff1Ct = await ff1Encrypt(ff1Key, 10, symbols, ff1Tweak);
      const ff31Ct = await ff3_1Encrypt(ff3Key, 10, symbols, ff31Tweak);

      const ff1Cipher = fromDigitSymbols(ff1Ct);
      const ff31Cipher = fromDigitSymbols(ff31Ct);

      const ff1Back = fromDigitSymbols(await ff1Decrypt(ff1Key, 10, ff1Ct, ff1Tweak));
      const ff31Back = fromDigitSymbols(await ff3_1Decrypt(ff3Key, 10, ff31Ct, ff31Tweak));

      setText("cc-ff1-out", ff1Cipher);
      setText("cc-ff3-out", ff31Cipher);
      setText("cc-ff1-luhn", luhnValid(ff1Cipher) ? "Luhn valid" : "Luhn invalid");
      setText("cc-ff3-luhn", luhnValid(ff31Cipher) ? "Luhn valid" : "Luhn invalid");
      setText("cc-roundtrip", `FF1\u2009\u2192\u2009${ff1Back} | FF3-1\u2009\u2192\u2009${ff31Back}`);
      setText("cc-status", "Done.");
    } catch (error) {
      setText("cc-status", (error as Error).message);
    } finally {
      enableButton("cc-run");
    }
  });
}

function wirePanel2(): void {
  const button = document.getElementById("mask-run") as HTMLButtonElement | null;
  button?.addEventListener("click", async () => {
    disableButton("mask-run");
    setText("mask-status", "Running...");
    try {
      const format = (document.getElementById("mask-format") as HTMLSelectElement).value as MaskedFormat;
      const parsed = parseMaskedFormat(getInputValue("mask-plain"), format);
      const key = await parseAes256Key("mask-key");
      const tweak = parseOptionalHexTweak(getInputValue("mask-tweak"));
      const encryptedDigits = await ff1Encrypt(key, 10, toDigitSymbols(parsed.digits), tweak);
      const cipher = mergeMaskedDigits(parsed.normalized, parsed.digitIndexes, fromDigitSymbols(encryptedDigits));

      const decryptedDigits = await ff1Decrypt(key, 10, encryptedDigits, tweak);
      const restored = mergeMaskedDigits(parsed.normalized, parsed.digitIndexes, fromDigitSymbols(decryptedDigits));

      setText("mask-mask", parsed.mask);
      setText("mask-out", cipher);
      setText("mask-back", restored);
      setText("mask-status", "Done.");
    } catch (error) {
      setText("mask-status", (error as Error).message);
    } finally {
      enableButton("mask-run");
    }
  });
}

function wirePanel3(): void {
  const button = document.getElementById("cmp-run") as HTMLButtonElement | null;
  button?.addEventListener("click", async () => {
    disableButton("cmp-run");
    setText("cmp-status", "Running...");
    try {
      const plain = getInputValue("cmp-plain").trim();
      if (!/^\d+$/.test(plain)) {
        throw new Error("Comparison plaintext must be digits only.");
      }

      const { ff1Key, ff3Key } = await parseKeyPair("cmp-key");
      const ff1Tweak = parseOptionalHexTweak(getInputValue("cmp-ff1-tweak"));
      const ff31Tweak = parseFF3_1Tweak(getInputValue("cmp-ff3-tweak"));
      const pt = toDigitSymbols(plain);

      const ff1Start = performance.now();
      const ff1Cipher = await ff1Encrypt(ff1Key, 10, pt, ff1Tweak);
      const ff1Ms = performance.now() - ff1Start;

      const ff31Start = performance.now();
      const ff31Cipher = await ff3_1Encrypt(ff3Key, 10, pt, ff31Tweak);
      const ff31Ms = performance.now() - ff31Start;

      setText("cmp-ff1-out", fromDigitSymbols(ff1Cipher));
      setText("cmp-ff3-out", fromDigitSymbols(ff31Cipher));
      setText("cmp-ff1-time", `${ff1Ms.toFixed(2)} ms`);
      setText("cmp-ff3-time", `${ff31Ms.toFixed(2)} ms`);
      setText("cmp-status", "Done.");
    } catch (error) {
      setText("cmp-status", (error as Error).message);
    } finally {
      enableButton("cmp-run");
    }
  });
}

function wirePanel4(): void {
  const button = document.getElementById("custom-run") as HTMLButtonElement | null;
  button?.addEventListener("click", async () => {
    disableButton("custom-run");
    setText("custom-status", "Running...");
    try {
      const alphabet = getInputValue("custom-alphabet");
      validateCustomAlphabet(alphabet);

      const plain = getInputValue("custom-plain");
      const key = await parseAes256Key("custom-key");
      const tweak = parseOptionalHexTweak(getInputValue("custom-tweak"));

      const symbols = stringToSymbols(plain, alphabet);
      const cipher = await ff1Encrypt(key, alphabet.length, symbols, tweak);
      const back = await ff1Decrypt(key, alphabet.length, cipher, tweak);

      setText("custom-out", symbolsToString(cipher, alphabet));
      setText("custom-back", symbolsToString(back, alphabet));
      setText("custom-len", `${plain.length}`);
      setText("custom-status", "Done.");
    } catch (error) {
      setText("custom-status", (error as Error).message);
    } finally {
      enableButton("custom-run");
    }
  });
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function symbolsToDigits(symbols: number[]): string {
  return fromDigitSymbols(symbols);
}

function diffMarkup(a: string, b: string): string {
  const out: string[] = [];
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const ca = a[i] ?? "";
    const cb = b[i] ?? "";
    if (ca === cb) {
      out.push(escapeHtml(cb));
    } else {
      out.push(`<span class="diff">${escapeHtml(cb)}</span>`);
    }
  }
  return out.join("");
}

function countDiff(a: string, b: string): number {
  let diff = 0;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    if (a[i] !== b[i]) diff += 1;
  }
  return diff;
}

function flipTweakBit(tweak: Uint8Array, bitIndex: number): Uint8Array {
  if (tweak.length === 0) {
    return new Uint8Array([0x01]);
  }
  const out = new Uint8Array(tweak);
  const byteIndex = Math.floor(bitIndex / 8) % tweak.length;
  const bitInByte = bitIndex % 8;
  out[byteIndex] ^= 1 << bitInByte;
  return out;
}

/** Group hex into byte pairs for readability, e.g. "3f9a" -> "3f 9a". */
function groupHexBytes(hex: string): string {
  const padded = hex.length % 2 === 1 ? "0" + hex : hex;
  return (padded.match(/../g) ?? []).join(" ");
}

/**
 * Render the modular column addition (A + Y) mod r^m as an actual right-aligned
 * column sum, highlighting the leading digits dropped by the modular wrap. All
 * values are the real traced integers — nothing here is fabricated.
 */
function renderColumnAddition(round: FF1Round, radix: number): string {
  const m = round.m;
  const aDigits = symbolsToDigits(round.aBefore);
  const yStr = round.y.toString(radix);
  const sumStr = round.sumBeforeMod.toString(radix);
  const resultStr = symbolsToDigits(round.newB);
  const width = Math.max(aDigits.length, yStr.length, sumStr.length, resultStr.length);
  const pad = (str: string): string => escapeHtml(str.padStart(width, " "));
  const label = (str: string): string => str.padStart(9, " ");

  // In the pre-mod sum, the top (sumStr.length - m) digits are dropped by the modulus.
  const dropped = Math.max(0, sumStr.length - m);
  let sumMarkup = " ".repeat(width - sumStr.length);
  for (let i = 0; i < sumStr.length; i += 1) {
    const ch = escapeHtml(sumStr[i]);
    sumMarkup += i < dropped ? `<span class="wrap-drop">${ch}</span>` : ch;
  }

  const note =
    dropped > 0
      ? `The leading ${dropped} digit(s) exceed r<sup>m</sup> = ${radix}<sup>${m}</sup> and wrap around (mod), keeping the result exactly ${m} digit(s).`
      : `The sum already fits in ${m} digit(s), so the modulus changes nothing this round — but it still guarantees the half never grows.`;

  const rule = "─".repeat(width);
  return `
    <div class="col-add" role="group" aria-label="Modular column addition A plus Y">
      <pre class="col-add-grid" tabindex="0" role="region" aria-label="Column addition of A and Y in radix ${radix}">${label("A")}  ${pad(aDigits)}
${label("+ Y")}  ${pad(yStr)}
${label("")}  ${rule}
${label("= sum")}  ${sumMarkup}
${label("mod r^m")}  ${pad(resultStr)}</pre>
      <p class="hint col-add-note">${note} <span class="hint">(shown in base ${radix}; the table lists Y in hex.)</span></p>
    </div>`;
}

/** Build the visual mini-pipeline for one round: B digits -> bytes -> AES box -> Y -> column add. */
function renderRoundZoom(round: FF1Round, radix: number): string {
  const bDigits = symbolsToDigits(round.bBefore);
  const bytesHex = groupHexBytes(bytesToHex(round.internals.rightBytes));
  const macHex = groupHexBytes(bytesToHex(round.internals.macBlock));
  const sHex = groupHexBytes(bytesToHex(round.internals.sBytes));
  const yHex = round.y.toString(16);
  return `
    <ol class="pipeline" aria-label="How Y is derived in round ${round.index}">
      <li class="pipe-step">
        <span class="pipe-num">1</span>
        <div class="pipe-body">
          <span class="pipe-title">Take B, the right half</span>
          <code class="pipe-val">${escapeHtml(bDigits)}</code>
          <span class="hint">the ${round.bBefore.length}-symbol half fed to the round function</span>
        </div>
      </li>
      <li class="pipe-step">
        <span class="pipe-num">2</span>
        <div class="pipe-body">
          <span class="pipe-title">Pack it as a big-endian number, ${round.internals.rightBytes.length} byte(s)</span>
          <code class="pipe-val">${escapeHtml(bytesHex)}</code>
          <span class="hint">B read as an integer, then written across b bytes</span>
        </div>
      </li>
      <li class="pipe-step pipe-aes">
        <span class="pipe-num">3</span>
        <div class="pipe-body">
          <span class="pipe-title">AES round function (CBC-MAC over P‖Q)</span>
          <code class="pipe-val">R = ${escapeHtml(macHex)}</code>
          <span class="hint">real AES-256 keyed pseudorandom function — this is the cryptographic core</span>
        </div>
      </li>
      <li class="pipe-step">
        <span class="pipe-num">4</span>
        <div class="pipe-body">
          <span class="pipe-title">Expand R to d = ${round.internals.sBytes.length} bytes (S), read as the integer Y</span>
          <code class="pipe-val">S = ${escapeHtml(sHex)}</code>
          <code class="pipe-val">Y = 0x${escapeHtml(yHex)}</code>
        </div>
      </li>
      <li class="pipe-step">
        <span class="pipe-num">5</span>
        <div class="pipe-body">
          <span class="pipe-title">Add Y to A, wrap mod r<sup>m</sup> → the new half</span>
          ${renderColumnAddition(round, radix)}
        </div>
      </li>
    </ol>`;
}

interface RoundsState {
  traced: import("./ff1").FF1TracedResult;
  radix: number;
  step: number; // 0 = initial split, 1..10 = after round i-1
  timer: number | null;
}

function wireRoundsPanel(): void {
  const state: RoundsState = { traced: null as never, radix: 10, step: 0, timer: null };

  const feistelA = document.getElementById("feistel-a-val");
  const feistelB = document.getElementById("feistel-b-val");
  const stepLabel = document.getElementById("feistel-step-label");
  const zoomSelect = document.getElementById("round-zoom-select") as HTMLSelectElement | null;
  const zoomBody = document.getElementById("round-zoom-body");
  const prevBtn = document.getElementById("feistel-prev") as HTMLButtonElement | null;
  const nextBtn = document.getElementById("feistel-next") as HTMLButtonElement | null;
  const playBtn = document.getElementById("feistel-play") as HTMLButtonElement | null;

  function halfMarkup(prev: string, cur: string): string {
    const len = Math.max(prev.length, cur.length);
    let out = "";
    for (let i = 0; i < len; i += 1) {
      const c = cur[i] ?? "";
      out += prev[i] === c ? escapeHtml(c) : `<span class="digit-pulse">${escapeHtml(c)}</span>`;
    }
    return out;
  }

  function renderStep(): void {
    if (!state.traced) return;
    const rounds = state.traced.rounds;
    let aStr: string;
    let bStr: string;
    let prevA = "";
    let prevB = "";
    if (state.step === 0) {
      aStr = symbolsToDigits(rounds[0].aBefore);
      bStr = symbolsToDigits(rounds[0].bBefore);
      if (stepLabel) stepLabel.textContent = `initial split · A | B`;
    } else {
      const r = rounds[state.step - 1];
      aStr = symbolsToDigits(r.aAfter);
      bStr = symbolsToDigits(r.bAfter);
      prevA = symbolsToDigits(r.aBefore);
      prevB = symbolsToDigits(r.bBefore);
      if (stepLabel) stepLabel.textContent = `round ${r.index} of 9 · after swap`;
    }
    if (feistelA) feistelA.innerHTML = halfMarkup(prevA, aStr);
    if (feistelB) feistelB.innerHTML = halfMarkup(prevB, bStr);
    if (prevBtn) prevBtn.disabled = state.step === 0;
    if (nextBtn) nextBtn.disabled = state.step >= rounds.length;
  }

  function stopPlay(): void {
    if (state.timer !== null) {
      window.clearInterval(state.timer);
      state.timer = null;
    }
    if (playBtn) playBtn.textContent = "▶ Play";
  }

  prevBtn?.addEventListener("click", () => {
    stopPlay();
    if (state.step > 0) {
      state.step -= 1;
      renderStep();
    }
  });
  nextBtn?.addEventListener("click", () => {
    stopPlay();
    if (state.traced && state.step < state.traced.rounds.length) {
      state.step += 1;
      renderStep();
    }
  });
  playBtn?.addEventListener("click", () => {
    if (!state.traced) return;
    if (state.timer !== null) {
      stopPlay();
      return;
    }
    if (state.step >= state.traced.rounds.length) state.step = 0;
    playBtn.textContent = "⏸ Pause";
    state.timer = window.setInterval(() => {
      if (!state.traced || state.step >= state.traced.rounds.length) {
        stopPlay();
        return;
      }
      state.step += 1;
      renderStep();
    }, 900);
  });

  zoomSelect?.addEventListener("change", () => {
    if (!state.traced || !zoomBody) return;
    const idx = Number(zoomSelect.value);
    if (Number.isNaN(idx) || zoomSelect.value === "") {
      zoomBody.innerHTML = "";
      return;
    }
    zoomBody.innerHTML = renderRoundZoom(state.traced.rounds[idx], state.radix);
  });

  const button = document.getElementById("rounds-run") as HTMLButtonElement | null;
  button?.addEventListener("click", async () => {
    disableButton("rounds-run");
    setText("rounds-status", "Running...");
    stopPlay();
    const tbody = document.getElementById("rounds-tbody");
    if (tbody) tbody.innerHTML = "";
    try {
      const plain = getInputValue("rounds-plain").trim();
      if (!/^\d{2,}$/.test(plain)) {
        throw new Error("Round walkthrough plaintext must be at least 2 digits.");
      }
      const key = await parseAes256Key("rounds-key");
      const tweak = parseOptionalHexTweak(getInputValue("rounds-tweak"));
      const traced = await ff1EncryptTraced(key, 10, toDigitSymbols(plain), tweak);
      state.traced = traced;
      state.radix = traced.params.radix;
      state.step = 0;

      const u = traced.params.u;
      const v = traced.params.v;
      setText(
        "rounds-split",
        `n=${traced.params.n}, u=${u}, v=${v}, b=${traced.params.b}B, d=${traced.params.d}B. ` +
          `Initial A=${plain.slice(0, u)} | B=${plain.slice(u)}`
      );

      if (tbody) {
        const rows = traced.rounds.map((r: FF1Round) => {
          const yHex = r.y.toString(16);
          return `
            <tr>
              <td>${r.index}</td>
              <td>${r.m}</td>
              <td><code>${escapeHtml(symbolsToDigits(r.aBefore))}</code></td>
              <td><code>${escapeHtml(symbolsToDigits(r.bBefore))}</code></td>
              <td><code title="round-function output (added mod radix^m)">0x${escapeHtml(yHex)}</code></td>
              <td><code>${escapeHtml(symbolsToDigits(r.newB))}</code></td>
              <td><code><strong>${escapeHtml(symbolsToDigits(r.aAfter))}</strong> | <strong>${escapeHtml(symbolsToDigits(r.bAfter))}</strong></code></td>
            </tr>`;
        });
        tbody.innerHTML = rows.join("");
      }

      // Populate the round-zoom picker and default to round 0.
      if (zoomSelect) {
        zoomSelect.disabled = false;
        zoomSelect.innerHTML = traced.rounds
          .map((r) => `<option value="${r.index}">Round ${r.index} (m=${r.m})</option>`)
          .join("");
        zoomSelect.value = "0";
      }
      if (zoomBody) zoomBody.innerHTML = renderRoundZoom(traced.rounds[0], state.radix);

      if (prevBtn) prevBtn.disabled = true;
      if (nextBtn) nextBtn.disabled = false;
      if (playBtn) playBtn.disabled = false;
      renderStep();

      setText("rounds-final", `Ciphertext: ${fromDigitSymbols(traced.ciphertext)}`);
      setText("rounds-status", "Done.");
    } catch (error) {
      setText("rounds-status", (error as Error).message);
    } finally {
      enableButton("rounds-run");
    }
  });
}

function wireFailLab(): void {
  const eqBtn = document.getElementById("fail-eq-run") as HTMLButtonElement | null;
  eqBtn?.addEventListener("click", async () => {
    disableButton("fail-eq-run");
    setText("fail-eq-status", "Running...");
    const tbody = document.getElementById("fail-eq-tbody");
    if (tbody) tbody.innerHTML = "";
    try {
      const key = await parseAes256Key("fail-key");
      const tweak = parseOptionalHexTweak(getInputValue("fail-tweak"));
      const raw = getInputValue("fail-eq-list");
      const items = raw
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter((s) => s.length >= 2);
      if (items.length === 0) throw new Error("Enter at least one digit string.");

      const results: Array<{ pt: string; ct: string }> = [];
      for (const pt of items) {
        if (!/^\d+$/.test(pt)) throw new Error(`Not digits-only: ${pt}`);
        const ct = fromDigitSymbols(await ff1Encrypt(key, 10, toDigitSymbols(pt), tweak));
        results.push({ pt, ct });
      }
      const ctCounts = new Map<string, number>();
      for (const r of results) {
        ctCounts.set(r.ct, (ctCounts.get(r.ct) ?? 0) + 1);
      }
      if (tbody) {
        tbody.innerHTML = results
          .map((r) => {
            const dup = (ctCounts.get(r.ct) ?? 0) > 1;
            const cls = dup ? "leak-row" : "";
            const tag = dup ? `<span class="leak-tag">equality leak</span>` : "";
            return `<tr class="${cls}"><td><code>${escapeHtml(r.pt)}</code></td><td><code>${escapeHtml(r.ct)}</code> ${tag}</td></tr>`;
          })
          .join("");
      }
      const dupes = results.filter((r) => (ctCounts.get(r.ct) ?? 0) > 1).length;
      setText(
        "fail-eq-status",
        dupes > 0
          ? `${dupes} ciphertext(s) repeat — identical plaintexts produced identical ciphertexts. Frequency analysis is now possible on this dataset.`
          : "No duplicates in the input — try adding a repeated plaintext."
      );
    } catch (error) {
      setText("fail-eq-status", (error as Error).message);
    } finally {
      enableButton("fail-eq-run");
    }
  });

  const avBtn = document.getElementById("fail-av-run") as HTMLButtonElement | null;
  avBtn?.addEventListener("click", async () => {
    disableButton("fail-av-run");
    setText("fail-av-status", "Running...");
    try {
      const key = await parseAes256Key("fail-key");
      const tweak = parseOptionalHexTweak(getInputValue("fail-tweak"));
      if (tweak.length === 0) throw new Error("Avalanche demo needs a non-empty tweak.");
      const plain = getInputValue("fail-av-plain").trim();
      if (!/^\d{2,}$/.test(plain)) throw new Error("Plaintext must be at least 2 digits.");

      const ct1 = fromDigitSymbols(await ff1Encrypt(key, 10, toDigitSymbols(plain), tweak));
      const tweak2 = flipTweakBit(tweak, 0);
      const ct2 = fromDigitSymbols(await ff1Encrypt(key, 10, toDigitSymbols(plain), tweak2));

      const diffs = countDiff(ct1, ct2);
      const pct = ((diffs / ct1.length) * 100).toFixed(0);

      setText("fail-av-tweak1", bytesToHex(tweak));
      setText("fail-av-tweak2", bytesToHex(tweak2));
      const ct1El = document.getElementById("fail-av-ct1");
      const ct2El = document.getElementById("fail-av-ct2");
      if (ct1El) ct1El.innerHTML = `<code>${escapeHtml(ct1)}</code>`;
      if (ct2El) ct2El.innerHTML = `<code>${diffMarkup(ct1, ct2)}</code>`;
      setText(
        "fail-av-status",
        `${diffs}/${ct1.length} symbols changed (${pct}%) after flipping one tweak bit. ` +
          `Random-oracle expectation for radix 10 is 90% (1 - 1/radix), so this is the shape to expect. ` +
          `Per-record tweaks defeat cross-record equality leakage — but only if the tweak really varies per record.`
      );
    } catch (error) {
      setText("fail-av-status", (error as Error).message);
    } finally {
      enableButton("fail-av-run");
    }
  });

  const updateDomain = (): void => {
    const radix = Math.max(2, Math.min(65536, Number(getInputValue("fail-dom-radix")) || 10));
    const len = Math.max(2, Math.min(64, Number(getInputValue("fail-dom-len")) || 4));
    const size = Math.pow(radix, len);
    const bits = Math.log2(size);
    const sizeStr = size > 1e15 ? size.toExponential(2) : size.toLocaleString();
    let verdict: string;
    if (bits < 20) verdict = "Trivially brute-forceable. Treat as obfuscation, not encryption.";
    else if (bits < 40) verdict = "Vulnerable to chosen-plaintext attack with modest compute.";
    else if (bits < 60) verdict = "Adequate against casual attackers; still leaks via determinism.";
    else verdict = "Domain is large; security depends on key/tweak hygiene, not domain size.";

    // Compare against the standard's own floor with BigInt: Math.pow overflows
    // to Infinity for large len, which would silently pass anything.
    let exact = 1n;
    const radixBig = BigInt(radix);
    for (let i = 0; i < len && exact < MIN_DOMAIN_SIZE; i += 1) exact *= radixBig;
    const belowFloor = exact < MIN_DOMAIN_SIZE;
    const gate = belowFloor
      ? `REJECTED by this demo: below the Draft SP 800-38G Rev. 1 floor of ` +
        `radix^minlen >= 1,000,000. FF1/FF3-1 here will refuse these parameters. ` +
        `(The original SP 800-38G allowed 100; Rev. 1 raised it to 10^6 after ` +
        `Durak-Vaudenay and Hoang-Tessaro-Trieu showed small domains fall.)`
      : `Meets the Draft SP 800-38G Rev. 1 floor of radix^minlen >= 1,000,000. ` +
        `Clearing the floor is necessary, not sufficient — read the verdict above.`;

    setText(
      "fail-dom-out",
      `radix^length = ${radix}^${len} = ${sizeStr}  (≈ 2^${bits.toFixed(1)}). ${verdict} ${gate}`
    );
  };
  document.getElementById("fail-dom-radix")?.addEventListener("input", updateDomain);
  document.getElementById("fail-dom-len")?.addEventListener("input", updateDomain);
  updateDomain();
}

function template(): string {
  const key = generateRandomKeyHex(32);
  return `
    <a href="#main-content" class="skip-link">Skip to main content</a>
    <main id="main-content" class="shell" tabindex="-1">
      <div class="hero">
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light mode"></button>
        <header class="cl-hero">
          <div class="cl-hero-main">
            <h1 class="cl-hero-title">Format Ward</h1>
            <p class="cl-hero-sub">Format-Preserving Encryption · FF1 (NIST SP 800-38G) · FF3-1 (withdrawn)</p>
            <p class="cl-hero-desc">Encrypt a value through an AES-driven Feistel network and watch the ciphertext keep the exact length and character set of the plaintext, round by round — then see why NIST is removing half of what is on this page.</p>
          </div>
          <aside class="cl-hero-why" aria-label="Why it matters">
            <span class="cl-hero-why-label">WHY IT MATTERS</span>
            <p class="cl-hero-why-text">Legacy schemas, card fields, and databases often can't change a column's length or alphabet. FPE protects the data in place — no schema migration, no widened fields — while still behaving like real encryption.</p>
          </aside>
        </header>
        <div class="chip-row" role="list" aria-label="Primitives used">
          <span class="chip category" role="listitem">Format-Preserving Encryption</span>
          <span class="chip" role="listitem">FF1</span>
          <span class="chip" role="listitem">FF3-1</span>
          <span class="chip" role="listitem">AES-256</span>
          <span class="chip" role="listitem">Feistel Network</span>
        </div>
      </div>

      <section class="scope" aria-labelledby="scope-heading">
        <h2 id="scope-heading">Scope — FF3-1 is being withdrawn, and that is the lesson</h2>
        <p class="scope-lede">This page is <strong>not</strong> a recommendation to deploy FF3-1. NIST is removing it
        from the standard. The demo keeps FF3-1 running so you can see the construction that broke sitting next to the
        one that did not — which teaches far more about small-domain ciphers than a working example alone would.</p>

        <ol class="scope-timeline">
          <li>
            <span class="scope-when">March 2016</span>
            <strong><a href="https://csrc.nist.gov/pubs/sp/800/38/g/final" target="_blank" rel="noopener">SP 800-38G</a>
            — final, and still the only finished version.</strong>
            Specifies <strong>FF1</strong> and <strong>FF3</strong>. Requires a domain of only
            radix<sup>minlen</sup> &ge; 100, with 1,000,000 merely recommended.
          </li>
          <li>
            <span class="scope-when">2017 &ndash; 2018</span>
            <strong>The attacks land.</strong> Durak and Vaudenay break FF3 outright in
            <em>Breaking the FF3 Format-Preserving Encryption Standard Over Small Domains</em> (CRYPTO 2017):
            against a Feistel half-domain of size N, message recovery takes on the order of
            N<sup>11/6</sup> chosen plaintexts and N<sup>5</sup> time — practical at exactly the domain sizes
            FPE is reached for. Hoang, Tessaro and Trieu, <em>The Curse of Small Domains</em> (CRYPTO 2018),
            push known-plaintext message recovery against both FF1 and FF3 down to domains as small as 8 bits.
          </li>
          <li>
            <span class="scope-when">February 2019</span>
            <strong>SP 800-38G Rev. 1, initial public draft — FF3-1 is invented.</strong> NIST's answer to
            Durak&ndash;Vaudenay is to shrink FF3's tweak from 64 bits to 56 and rename the result FF3-1.
            Note what that means: <em>FF3-1 has only ever existed inside a draft.</em> It was never published
            in a final NIST standard, so "standards-compliant FF3-1" was never quite a true claim.
          </li>
          <li>
            <span class="scope-when">2021</span>
            <strong>FF3-1 falls as well.</strong> Tim Beyne, <em>Linear Cryptanalysis of FF3-1 and FEA</em>
            (CRYPTO 2021), attacks the alternating round-tweak <em>schedule</em> rather than the tweak's size.
            FF3-1 over a domain of N = 1000 can be distinguished from an ideal tweakable block cipher with
            advantage at least 1/10 using about 2<sup>23</sup> encryption queries — roughly eight million, which
            is an afternoon on a laptop. Shrinking the tweak had patched the wrong parameter.
          </li>
          <li class="scope-now">
            <span class="scope-when">3 February 2025</span>
            <strong><a href="https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd" target="_blank" rel="noopener">SP 800-38G
            Rev. 1, 2nd public draft</a> — FF3 and FF3-1 are removed.</strong>
            NIST's announcement is blunt: <q>The encryption method FF3 is no longer specified</q>, because
            <q>Beyne described a weakness in the tweak schedule that affected both FF3 and FF3-1 but not FF1</q>.
            The draft's abstract now reads <q>This recommendation specifies the FF1 method</q> — singular.
            The same draft makes radix<sup>minlen</sup> &ge; 1,000,000 a <em>requirement</em> rather than a
            recommendation, disallows building the round function from the inverse AES cipher, and disallows
            floating-point arithmetic. Comments closed 4 April 2025. Because Rev. 1 is still a draft, the 2016
            document remains the last final text — which is why FF3 is currently both "in the standard" and
            "known broken."
          </li>
        </ol>

        <h3 class="sub-h">Why small-domain encryption is hard</h3>
        <p>AES gets to be conservative: a 128-bit block, and an adversary who wants the whole codebook needs
        2<sup>128</sup> queries. Format-preserving encryption gives that up by definition — it is a permutation on
        <em>your</em> domain, not on 128-bit blocks. Encrypting a 9-digit identifier means the entire domain is
        10<sup>9</sup> values, about 30 bits. Three consequences follow, and together they are why this family keeps
        breaking:</p>
        <ul class="scope-why">
          <li><strong>The codebook is finite and often reachable.</strong> Security cannot rest on the domain being
          large, because it is not. An attacker with oracle access to a 5-digit field enumerates all 100,000 values
          and is done — no cryptanalysis required. That is why Rev. 1 promotes the 10<sup>6</sup> floor from advice
          to a rule, and why the domain calculator below refuses parameters under it.</li>
          <li><strong>Feistel rounds are weak when the halves are tiny.</strong> A Feistel network's security
          argument (Luby&ndash;Rackoff and its successors) is asymptotic in the half-width. Split a 6-digit value and
          each half carries about 10 bits, so the round function is a pseudorandom function on a 1000-element set.
          Eight or ten rounds of that does not converge on a random permutation the way ten AES rounds do on 128
          bits — a measurable distinguishing advantage survives, and measurable advantage is what
          Durak&ndash;Vaudenay and Beyne convert into recovered plaintext.</li>
          <li><strong>The tweak schedule is itself an attack surface.</strong> This is the specific thing that killed
          FF3-1, and the part most summaries miss. FF3 and FF3-1 split the tweak into two halves and use them on
          alternating rounds, XORing in only the round number. That regularity lets an attacker line up encryptions
          under <em>related</em> tweaks so that round functions coincide, and Beyne's linear cryptanalysis exploits
          exactly that. FF1 does not share the weakness: it feeds the whole tweak, the round number, and the length
          parameters into every round's PRF input, so no two rounds reuse a round function. Making the tweak shorter —
          the FF3-1 fix — never addressed the schedule at all, which is why FF3-1 bought only two years.</li>
        </ul>

        <h3 class="sub-h">So what should you actually use?</h3>
        <p>Work backwards from why FPE was reached for in the first place:</p>
        <ul class="scope-why">
          <li><strong>If you can change the schema, do that and use ordinary AEAD.</strong> AES-GCM or
          ChaCha20-Poly1305 gives confidentiality <em>and</em> integrity, which no FPE mode provides. Most production
          FPE deployments exist to avoid a column migration, not because FPE was the better primitive.</li>
          <li><strong>If you need stable tokens for joins or lookups, use a tokenization vault.</strong> Generate a
          random token, store the token-to-value mapping encrypted, hand out the token. It preserves any format you
          like, leaks nothing beyond equality, and has no cryptanalysis to track. This is what most
          "format-preserving" requirements actually want.</li>
          <li><strong>If you need determinism without a vault, use a deterministic AEAD such as AES-SIV</strong>
          (RFC 5297). It still leaks equality — inherent to determinism — but it is not a small-domain construction,
          so it inherits none of the problems above.</li>
          <li><strong>If the format genuinely cannot change, use FF1</strong>, with a domain of at least
          10<sup>6</sup> and a real per-record tweak. FF1 is the only method Rev. 1 still specifies, and no practical
          attack is known within those bounds. Do not put FF3 or FF3-1 in anything new.</li>
        </ul>
      </section>

      <section class="panel attack-lab" aria-labelledby="attack-heading">
        <h2 id="attack-heading">Live: break FF3-1 by codebook recovery</h2>
        <p class="callout">
          The timeline above <em>describes</em> the break. This runs one. A defender encrypts a
          secret value with real FF3-1 under a random key and tweak the attacker never sees; the
          attacker gets only the ciphertext and an encryption oracle (the same key + tweak, key
          unknown — exactly a tokenization API). It enumerates the whole small domain, builds the
          plaintext&rarr;ciphertext codebook, and reads off the secret. No key, no cryptanalysis.
        </p>
        <p class="hint">
          <strong>Honest scale.</strong> The <em>specific</em> Durak&ndash;Vaudenay / Beyne
          cryptanalysis of FF3-1's tweak schedule needs ~2<sup>23</sup> (≈8 million) chosen queries —
          hours of AES, out of browser reach, so it is cited, not run. Codebook recovery is what
          those attacks reduce the cipher to on realistic field sizes, and it is exactly what the
          <em>≥10<sup>6</sup></em> minimum-domain requirement exists to stop. Everything below uses
          the real FF3-1 primitive; nothing is hardcoded.
        </p>
        <div class="field">
          <label for="attack-length">Domain: number of decimal digits (radix 10)</label>
          <select id="attack-length">
            <option value="3">3 digits — 1,000 values</option>
            <option value="4" selected>4 digits — 10,000 values</option>
          </select>
        </div>
        <button id="attack-run" type="button">Run the codebook attack</button>
        <p class="status" id="attack-status" role="status" aria-live="polite">Idle.</p>
        <div id="attack-output" class="attack-output" hidden>
          <dl class="attack-rows">
            <div><dt>Defender's secret plaintext</dt><dd id="attack-secret" class="mono">—</dd></div>
            <div><dt>Ciphertext handed to attacker</dt><dd id="attack-target" class="mono">—</dd></div>
            <div><dt>Recovered by codebook (no key)</dt><dd id="attack-recovered" class="mono">—</dd></div>
            <div><dt>Oracle queries spent</dt><dd id="attack-queries" class="mono">—</dd></div>
          </dl>
          <p id="attack-verdict" role="status"></p>
        </div>
        <h3 class="sub-h">The numbers, computed for these parameters</h3>
        <dl class="attack-rows attack-feasibility">
          <div><dt>Codebook cost (queries = domain size)</dt><dd id="feas-codebook" class="mono">—</dd></div>
          <div><dt>Clears the NIST 10<sup>6</sup> floor?</dt><dd id="feas-floor" class="mono">—</dd></div>
          <div><dt>Beyne (2021) FF3-1 distinguisher (cited)</dt><dd id="feas-beyne" class="mono">—</dd></div>
        </dl>
      </section>

      <section class="why" aria-label="Glossary">
        <details class="glossary">
          <summary>Glossary — terms used on this page</summary>
          <dl>
            <dt>Radix</dt><dd>Number of distinct symbols in the alphabet (10 for decimal, 26 for lowercase letters, 36 for alphanumeric).</dd>
            <dt>Domain</dt><dd>The set of all length-N strings over the alphabet. Domain size = radix<sup>N</sup>. Small domains leak.</dd>
            <dt>Tweak</dt><dd>A public, per-context value that diversifies the output without being a secret. Same key + different tweak = different ciphertext.</dd>
            <dt>Feistel network</dt><dd>Encryption structure that splits the input into two halves (A | B), applies a keyed round function, swaps, and repeats. Reversible by design.</dd>
            <dt>Round function</dt><dd>The keyed pseudorandom function applied each round. Here: AES-CBC-MAC over a formatted block, reduced mod radix<sup>m</sup>, then added to one half.</dd>
            <dt>Rounds</dt><dd>FF1 uses 10 rounds. FF3-1 uses 8 rounds with a 56-bit tweak split into two halves.</dd>
            <dt>AES-256</dt><dd>The 256-bit-key block cipher used inside the round function. WebCrypto provides the AES primitive used here.</dd>
            <dt>Equality leak</dt><dd>Because FPE is deterministic on (key, tweak), identical plaintexts always produce identical ciphertexts — frequency analysis still works.</dd>
          </dl>
        </details>
      </section>

      <section class="refs" aria-label="References and verification status">
        <p class="warning" role="note">Security note: FF3-1 is removed from Draft SP 800-38G Rev. 1 and must not be used
        in new systems. Use FF1 (domain &ge; 10<sup>6</sup>), or better, one of the alternatives in the Scope section above.</p>
        <p>Primary sources:
          <a href="https://csrc.nist.gov/pubs/sp/800/38/g/final" target="_blank" rel="noopener">SP 800-38G (2016, final)</a> ·
          <a href="https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd" target="_blank" rel="noopener">Draft SP 800-38G Rev. 1, 2nd public draft (Feb 2025)</a> ·
          <a href="https://eprint.iacr.org/2017/521" target="_blank" rel="noopener">Durak &amp; Vaudenay, CRYPTO 2017</a> (breaks FF3) ·
          <a href="https://eprint.iacr.org/2018/556" target="_blank" rel="noopener">Hoang, Tessaro &amp; Trieu, CRYPTO 2018</a> (small domains) ·
          <a href="https://eprint.iacr.org/2021/815" target="_blank" rel="noopener">Beyne, CRYPTO 2021</a> (breaks FF3-1).
        </p>
        <p class="hint">Note on attribution: Durak&ndash;Vaudenay broke FF3, the 64-bit-tweak original. FF3-1 was created
        in response to it, so citing that paper as the reason FF3-1 is unsafe is a common but incorrect shortcut — the
        paper that broke FF3-1 itself is Beyne (2021), and it is a linear attack on the tweak schedule, not a
        differential one.</p>
        <p id="vector-status" aria-live="polite">Running NIST vector smoke checks…</p>
      </section>

      <section class="panel start-here" aria-labelledby="start-heading">
        <h2 id="start-heading">Start here — the whole idea in one encrypt</h2>
        <p class="callout">Format-Preserving Encryption keeps the <em>shape</em> of a value: a 16-digit card number encrypts to a different 16-digit number, not to random bytes. Type a card number, press Encrypt, and compare. No keys or hex to think about yet — those live in the panels below once you have the idea.</p>
        <div class="field">
          <label for="start-plain">A 16-digit number</label>
          <input id="start-plain" type="text" inputmode="numeric" pattern="[0-9 ]{16,19}" autocomplete="off" value="4111 1111 1111 1111" />
        </div>
        <div class="field toggle-field">
          <label class="toggle-label" for="start-tweak-toggle">
            <input id="start-tweak-toggle" type="checkbox" />
            <span>Add a per-record <em>tweak</em> <span class="hint">(a public label — same number, different ciphertext)</span></span>
          </label>
        </div>
        <button id="start-run" type="button">Encrypt (FF1)</button>

        <div class="fpe-compare" aria-live="polite" aria-atomic="true">
          <div class="fpe-col">
            <span class="fpe-col-label">Plaintext</span>
            <output id="start-plain-out" class="fpe-value">—</output>
            <span class="fpe-annot" id="start-plain-annot">16 digits · radix 10</span>
          </div>
          <div class="fpe-arrow" aria-hidden="true">
            <span class="fpe-arrow-glyph">→</span>
            <span class="fpe-arrow-label">FF1 / AES</span>
          </div>
          <div class="fpe-col">
            <span class="fpe-col-label">Ciphertext</span>
            <output id="start-cipher-out" class="fpe-value">—</output>
            <span class="fpe-annot" id="start-cipher-annot">press Encrypt</span>
          </div>
        </div>
        <p class="fpe-verdict" id="start-verdict">
          <span id="start-shape-badge" class="shape-badge shape-idle">shape check pending</span>
          <span id="start-luhn-badge" class="shape-badge shape-idle">Luhn pending</span>
        </p>
        <p class="status" id="start-status" role="status" aria-live="polite">Idle.</p>
        <details class="advanced-details">
          <summary>Advanced — keys, FF3-1, and tweak-hex fields</summary>
          <p class="callout">The four use-case panels below expose the full machinery: your own AES-256 key, the FF1 tweak as raw hex, and the FF3-1 variant with its fixed 14-hex-char tweak. Everything above runs the exact same FF1 primitive with a demo key and a fixed tweak so the core behaviour is what you see first.</p>
        </details>
      </section>

      <section class="grid" aria-label="Interactive panels">

        <article class="panel" aria-labelledby="panel1-heading">
          <h3 id="panel1-heading">Panel 1 — Credit Card Tokenization</h3>
          <p class="callout">Use case: PCI-DSS tokenization, payment processors, vault-less tokenization.</p>
          <div class="field">
            <label for="cc-plain">16-digit PAN</label>
            <input id="cc-plain" type="text" inputmode="numeric" pattern="[0-9 ]{16,19}" autocomplete="off" value="4111111111111111" />
          </div>
          <div class="field">
            <label for="cc-key">AES-256 Key (hex)</label>
            <div class="inline">
              <input id="cc-key" type="text" spellcheck="false" autocomplete="off" value="${key}" />
              <button id="cc-key-gen" type="button" aria-label="Generate new AES-256 key for credit card panel">Generate</button>
            </div>
          </div>
          <div class="field">
            <label for="cc-ff1-tweak">FF1 tweak (hex)</label>
            <input id="cc-ff1-tweak" type="text" spellcheck="false" autocomplete="off" value="${DEFAULT_FF1_TWEAK}" />
          </div>
          <div class="field">
            <label for="cc-ff3-tweak">FF3-1 tweak (hex, 14 chars)</label>
            <input id="cc-ff3-tweak" type="text" spellcheck="false" autocomplete="off" value="${DEFAULT_FF3_1_TWEAK}" />
          </div>
          <button id="cc-run" type="button">Encrypt + Decrypt</button>
          <div class="results" aria-live="polite" aria-atomic="true">
            <p>FF1 ciphertext: <strong><output id="cc-ff1-out">-</output></strong> (<span id="cc-ff1-luhn">-</span>)</p>
            <p>FF3-1 ciphertext: <strong><output id="cc-ff3-out">-</output></strong> (<span id="cc-ff3-luhn">-</span>)</p>
            <p>Round-trip: <output id="cc-roundtrip">-</output></p>
          </div>
          <p class="status" id="cc-status" role="status" aria-live="polite">Idle.</p>
        </article>

        <article class="panel" aria-labelledby="panel2-heading">
          <h3 id="panel2-heading">Panel 2 — SSN / Phone / Postal Code</h3>
          <p class="callout">Use case: HIPAA workflows, government records, masked analytics.</p>
          <div class="field">
            <label for="mask-format">Format</label>
            <select id="mask-format">
              <option value="ssn">SSN (XXX-XX-XXXX)</option>
              <option value="phone">US Phone (XXX-XXX-XXXX)</option>
              <option value="zip">ZIP (XXXXX) — below the Rev. 1 domain floor</option>
            </select>
          </div>
          <p class="callout">Note on the ZIP option: five decimal digits is a domain of 10<sup>5</sup> = 100,000, under the
          <strong>radix<sup>minlen</sup> &ge; 1,000,000</strong> floor that Draft SP 800-38G Rev. 1 requires. It cleared the
          original SP 800-38G bound of 100; it does not clear Rev. 1. This demo enforces Rev. 1, so the option is kept and
          <em>refuses to run</em> — that rejection is the exhibit. Encrypting a bare 5-digit postal code with FPE means an
          attacker with oracle access builds the whole codebook in 100,000 queries. The fix is a wider field, not a
          weaker bound.</p>
          <div class="field">
            <label for="mask-plain">Value</label>
            <input id="mask-plain" type="text" inputmode="text" autocomplete="off" value="123-45-6789" />
          </div>
          <div class="field">
            <label for="mask-key">AES-256 Key (hex)</label>
            <div class="inline">
              <input id="mask-key" type="text" spellcheck="false" autocomplete="off" value="${key}" />
              <button id="mask-key-gen" type="button" aria-label="Generate new AES-256 key for masked format panel">Generate</button>
            </div>
          </div>
          <div class="field">
            <label for="mask-tweak">FF1 tweak (hex)</label>
            <input id="mask-tweak" type="text" spellcheck="false" autocomplete="off" value="${DEFAULT_FF1_TWEAK}" />
          </div>
          <button id="mask-run" type="button">Encrypt + Decrypt</button>
          <div class="results" aria-live="polite" aria-atomic="true">
            <p>Format mask: <strong><output id="mask-mask">-</output></strong> <span class="hint">(E&nbsp;=&nbsp;encrypted digit)</span></p>
            <p>Ciphertext: <strong><output id="mask-out">-</output></strong></p>
            <p>Decrypted: <strong><output id="mask-back">-</output></strong></p>
          </div>
          <p class="status" id="mask-status" role="status" aria-live="polite">Idle.</p>
        </article>

        <article class="panel" aria-labelledby="panel3-heading">
          <h3 id="panel3-heading">Panel 3 — FF1 vs FF3-1 Comparison</h3>
          <p class="callout"><strong>FF1 is the only method NIST still specifies. FF3-1 is removed from Draft
          SP 800-38G Rev. 1 — it is here as a broken-construction exhibit, not as an option.</strong> Run both and
          note that they are equally convincing to look at: the output of a broken cipher is indistinguishable from
          the output of a sound one by eye. That is the point of the panel.</p>
          <p class="callout">Round structure, and why it matters: FF1 uses 10 rounds and mixes the full tweak, the
          round number, and the length parameters into every round's PRF input. FF3-1 uses 8 rounds and splits a
          56-bit tweak into two 28-bit halves used on alternating rounds, XORing in only the round index. That
          alternating schedule is the structure Beyne's linear cryptanalysis attacks.</p>
          <div class="field">
            <label for="cmp-plain">Plaintext (digits only)</label>
            <input id="cmp-plain" type="text" inputmode="numeric" autocomplete="off" value="890121234567890000" />
          </div>
          <div class="field">
            <label for="cmp-key">AES-256 Key (hex)</label>
            <div class="inline">
              <input id="cmp-key" type="text" spellcheck="false" autocomplete="off" value="${key}" />
              <button id="cmp-key-gen" type="button" aria-label="Generate new AES-256 key for comparison panel">Generate</button>
            </div>
          </div>
          <div class="field">
            <label for="cmp-ff1-tweak">FF1 tweak (hex)</label>
            <input id="cmp-ff1-tweak" type="text" spellcheck="false" autocomplete="off" value="${DEFAULT_FF1_TWEAK}" />
          </div>
          <div class="field">
            <label for="cmp-ff3-tweak">FF3-1 tweak (hex, 14 chars)</label>
            <input id="cmp-ff3-tweak" type="text" spellcheck="false" autocomplete="off" value="${DEFAULT_FF3_1_TWEAK}" />
          </div>
          <button id="cmp-run" type="button">Run Comparison</button>
          <div class="results" aria-live="polite" aria-atomic="true">
            <p>FF1 output: <strong><output id="cmp-ff1-out">-</output></strong> <span class="timing" id="cmp-ff1-time">-</span></p>
            <p>FF3-1 output: <strong><output id="cmp-ff3-out">-</output></strong> <span class="timing" id="cmp-ff3-time">-</span></p>
          </div>
          <div class="table-wrap" tabindex="0" role="region" aria-label="Security comparison table">
            <table>
              <caption class="sr-only">FF1 vs FF3-1 security comparison</caption>
              <thead>
                <tr><th scope="col">Algorithm</th><th scope="col">Status</th><th scope="col">Security note</th></tr>
              </thead>
              <tbody>
                <tr><td>FF1</td><td>Specified — the only one left</td><td>No known practical attack at radix<sup>minlen</sup> &ge; 10<sup>6</sup>. Below that floor, Hoang&ndash;Tessaro&ndash;Trieu (2018) applies to FF1 too.</td></tr>
                <tr><td>FF3</td><td>Broken; removed from Rev. 1</td><td>Message recovery in about N<sup>11/6</sup> chosen plaintexts, N<sup>5</sup> time (Durak &amp; Vaudenay, 2017).</td></tr>
                <tr><td>FF3-1</td><td>Broken; removed from Rev. 1</td><td>Linear attack on the alternating tweak schedule: N = 1000 distinguished with advantage &ge; 1/10 in about 2<sup>23</sup> queries (Beyne, 2021).</td></tr>
              </tbody>
            </table>
          </div>
          <p class="status" id="cmp-status" role="status" aria-live="polite">Idle.</p>
        </article>

        <article class="panel" aria-labelledby="panel4-heading">
          <h3 id="panel4-heading">Panel 4 — Custom Alphabet</h3>
          <p class="callout">Use case: encrypted usernames, token generation, obfuscated IDs.</p>
          <div class="field">
            <label for="custom-alphabet">Alphabet</label>
            <input id="custom-alphabet" type="text" spellcheck="false" autocomplete="off" value="abcdefghijklmnopqrstuvwxyz0123456789" />
          </div>
          <div class="field">
            <label for="custom-plain">Plaintext</label>
            <input id="custom-plain" type="text" spellcheck="false" autocomplete="off" value="alice2026" />
          </div>
          <div class="field">
            <label for="custom-key">AES-256 Key (hex)</label>
            <div class="inline">
              <input id="custom-key" type="text" spellcheck="false" autocomplete="off" value="${key}" />
              <button id="custom-key-gen" type="button" aria-label="Generate new AES-256 key for custom alphabet panel">Generate</button>
            </div>
          </div>
          <div class="field">
            <label for="custom-tweak">FF1 tweak (hex)</label>
            <input id="custom-tweak" type="text" spellcheck="false" autocomplete="off" value="${DEFAULT_FF1_TWEAK}" />
          </div>
          <button id="custom-run" type="button">Encrypt + Decrypt</button>
          <div class="results" aria-live="polite" aria-atomic="true">
            <p>Ciphertext: <strong><output id="custom-out">-</output></strong></p>
            <p>Decrypted: <strong><output id="custom-back">-</output></strong></p>
            <p>Length preserved: <strong><output id="custom-len">-</output></strong></p>
          </div>
          <p class="status" id="custom-status" role="status" aria-live="polite">Idle.</p>
        </article>

      </section>

      <section class="panel walkthrough" aria-labelledby="rounds-heading">
        <h2 id="rounds-heading">Inside FF1 — Feistel Round Walkthrough</h2>
        <p class="callout">FF1 is a 10-round Feistel network. Each round splits the plaintext into halves <strong>A | B</strong>, derives <strong>Y</strong> from <strong>B</strong> via an AES-driven round function, computes <code>(A + Y) mod radix<sup>m</sup></code>, then swaps. This panel runs a real encryption and shows the state after every round so you can watch the mixing happen.</p>
        <div class="field">
          <label for="rounds-plain">Plaintext (digits, ≥ 2)</label>
          <input id="rounds-plain" type="text" inputmode="numeric" autocomplete="off" value="0123456789" />
        </div>
        <div class="field">
          <label for="rounds-key">AES-256 Key (hex)</label>
          <div class="inline">
            <input id="rounds-key" type="text" spellcheck="false" autocomplete="off" value="2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94" />
            <button id="rounds-key-gen" type="button" aria-label="Generate new AES-256 key for round walkthrough">Generate</button>
          </div>
        </div>
        <div class="field">
          <label for="rounds-tweak">FF1 tweak (hex)</label>
          <input id="rounds-tweak" type="text" spellcheck="false" autocomplete="off" value="39383736353433323130" />
        </div>
        <button id="rounds-run" type="button">Trace Rounds</button>
        <p id="rounds-split" class="hint">Click <em>Trace Rounds</em> to populate the walkthrough.</p>
        <dl class="param-gloss" id="rounds-param-gloss" aria-label="What the split parameters mean">
          <div><dt>n</dt><dd>total length (number of symbols)</dd></div>
          <div><dt>u</dt><dd>size of the left half A</dd></div>
          <div><dt>v</dt><dd>size of the right half B</dd></div>
          <div><dt>b</dt><dd>bytes needed to hold B as a big-endian number</dd></div>
          <div><dt>d</dt><dd>length of the AES-derived keystream S (source of Y)</dd></div>
        </dl>

        <div class="feistel-stage" aria-labelledby="feistel-stage-heading">
          <h3 class="sub-h" id="feistel-stage-heading">Watch the swap</h3>
          <p class="callout">Each round replaces the right half with <code>(A + Y) mod r<sup>m</sup></code>, then the halves swap positions. Step through and watch which digits change (highlighted) and how B slides into A's place.</p>
          <div class="feistel-boxes" role="group" aria-label="Feistel half state">
            <div class="feistel-half" id="feistel-a">
              <span class="feistel-half-label">A (left)</span>
              <span class="feistel-half-val" id="feistel-a-val">—</span>
            </div>
            <span class="feistel-op" aria-hidden="true">|</span>
            <div class="feistel-half" id="feistel-b">
              <span class="feistel-half-label">B (right)</span>
              <span class="feistel-half-val" id="feistel-b-val">—</span>
            </div>
          </div>
          <div class="feistel-controls">
            <button id="feistel-prev" type="button" class="mini-btn" disabled>◀ Prev</button>
            <button id="feistel-play" type="button" class="mini-btn" disabled>▶ Play</button>
            <button id="feistel-next" type="button" class="mini-btn" disabled>Next ▶</button>
            <span class="feistel-step-label" id="feistel-step-label" role="status" aria-live="polite">round —</span>
          </div>
        </div>

        <div class="round-zoom" aria-labelledby="round-zoom-heading">
          <h3 class="sub-h" id="round-zoom-heading">Zoom into one round — where Y comes from</h3>
          <p class="callout">The table below reports Y as a big integer. Here is how that number is actually produced for a single round, step by step. Pick a round to expand:</p>
          <div class="field round-zoom-picker">
            <label for="round-zoom-select">Expand round</label>
            <select id="round-zoom-select" disabled>
              <option value="">— trace first —</option>
            </select>
          </div>
          <div id="round-zoom-body" class="round-zoom-body" aria-live="polite"></div>
        </div>

        <details class="rounds-table-details">
          <summary>Full round table (all 10 rounds)</summary>
        <div class="table-wrap" tabindex="0" role="region" aria-label="FF1 round-by-round state">
          <table class="rounds-table">
            <caption class="sr-only">FF1 Feistel rounds</caption>
            <thead>
              <tr>
                <th scope="col">i</th>
                <th scope="col">m</th>
                <th scope="col">A (left)</th>
                <th scope="col">B (round-fn input)</th>
                <th scope="col">Y (round output)</th>
                <th scope="col">new B = (A+Y) mod r<sup>m</sup></th>
                <th scope="col">After swap (A | B)</th>
              </tr>
            </thead>
            <tbody id="rounds-tbody"></tbody>
          </table>
        </div>
        </details>
        <p id="rounds-final" class="status" role="status" aria-live="polite">Ciphertext: -</p>
        <p class="status" id="rounds-status" role="status" aria-live="polite">Idle.</p>
      </section>

      <section class="panel fail-lab" aria-labelledby="fail-heading">
        <h2 id="fail-heading">Failure Lab — Why FPE Still Leaks</h2>
        <p class="callout">FPE preserves shape, not confidentiality of frequency. These three demos show <em>what</em> leaks, <em>how much</em> a tweak helps, and <em>when</em> the domain is too small to call this encryption at all.</p>

        <div class="field">
          <label for="fail-key">Shared AES-256 Key (hex)</label>
          <div class="inline">
            <input id="fail-key" type="text" spellcheck="false" autocomplete="off" />
            <button id="fail-key-gen" type="button" aria-label="Generate new AES-256 key for failure lab">Generate</button>
          </div>
        </div>
        <div class="field">
          <label for="fail-tweak">Shared FF1 tweak (hex)</label>
          <input id="fail-tweak" type="text" spellcheck="false" autocomplete="off" value="39383736353433323130" />
        </div>

        <h3 class="sub-h">1. Equality leak — same plaintext → same ciphertext</h3>
        <p class="callout">FPE is deterministic on (key, tweak). If you re-use both across a dataset, repeated values stay visibly repeated. This is why frequency-based attacks still work on FPE-protected fields.</p>
        <div class="field">
          <label for="fail-eq-list">Plaintexts (one per line, digits only)</label>
          <textarea id="fail-eq-list" rows="5" spellcheck="false" autocomplete="off">1111
2222
1111
3333
2222</textarea>
        </div>
        <button id="fail-eq-run" type="button">Encrypt all (same key + tweak)</button>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Equality leak results">
          <table>
            <thead><tr><th scope="col">Plaintext</th><th scope="col">Ciphertext</th></tr></thead>
            <tbody id="fail-eq-tbody"></tbody>
          </table>
        </div>
        <p class="status" id="fail-eq-status" role="status" aria-live="polite">Idle.</p>

        <h3 class="sub-h">2. Tweak avalanche — one flipped bit ≈ whole new output</h3>
        <p class="callout">A per-record tweak diversifies the output without needing a new key. Flip one bit of the
        tweak and almost every symbol changes — the practical fix for the equality leak above. Expect roughly
        <strong>90%</strong>, not 50%: "avalanche" is a statement about <em>bits</em>, but this readout counts
        <em>decimal symbols</em>, and a freshly randomized digit collides with the old one 1 time in 10. So the
        random-oracle expectation here is 1 &minus; 1/radix = 90%, and a result near 50% would mean something was
        wrong.</p>
        <div class="field">
          <label for="fail-av-plain">Plaintext (digits)</label>
          <input id="fail-av-plain" type="text" inputmode="numeric" autocomplete="off" value="987654321098" />
        </div>
        <button id="fail-av-run" type="button">Encrypt with T and T⊕1</button>
        <div class="results" aria-live="polite" aria-atomic="true">
          <p>Tweak A: <code><output id="fail-av-tweak1">-</output></code></p>
          <p>Ciphertext A: <span id="fail-av-ct1">-</span></p>
          <p>Tweak B: <code><output id="fail-av-tweak2">-</output></code> <span class="hint">(bit 0 flipped)</span></p>
          <p>Ciphertext B: <span id="fail-av-ct2">-</span> <span class="hint">(red = changed)</span></p>
        </div>
        <p class="status" id="fail-av-status" role="status" aria-live="polite">Idle.</p>

        <h3 class="sub-h">3. Domain calculator — when the domain is the attack surface</h3>
        <p class="callout">FPE inherits the domain it preserves. A 4-digit PIN has only 10,000 possible values — an attacker who can query the encrypt oracle once per value owns the entire codebook. This calculator shows the practical limit.</p>
        <div class="inline-fields">
          <div class="field">
            <label for="fail-dom-radix">Radix</label>
            <input id="fail-dom-radix" type="number" min="2" max="65536" value="10" />
          </div>
          <div class="field">
            <label for="fail-dom-len">Length</label>
            <input id="fail-dom-len" type="number" min="2" max="64" value="4" />
          </div>
        </div>
        <p id="fail-dom-out" class="status" role="status" aria-live="polite">-</p>
      </section>

      <nav class="links" aria-label="Related demos and resources">
        <a href="https://github.com/systemslibrarian/crypto-lab-iron-letter" target="_blank" rel="noreferrer">crypto-lab-iron-letter</a>
        <a href="https://github.com/systemslibrarian/crypto-lab-shadow-vault" target="_blank" rel="noreferrer">crypto-lab-shadow-vault</a>
        <a href="https://github.com/systemslibrarian/crypto-compare" target="_blank" rel="noreferrer">crypto-compare: Format-Preserving Encryption</a>
        <a href="https://github.com/systemslibrarian/crypto-lab-format-ward" target="_blank" rel="noreferrer">GitHub repo</a>
      </nav>

    </main>

    <footer class="shell shell-foot" role="contentinfo">
      <p class="links">Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-iron-letter/" target="_blank" rel="noreferrer">crypto-lab-iron-letter</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" target="_blank" rel="noreferrer">crypto-lab-aes-modes</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-envelope-kms/" target="_blank" rel="noreferrer">crypto-lab-envelope-kms</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-chacha20-stream/" target="_blank" rel="noreferrer">crypto-lab-chacha20-stream</a>
      </p>
      <p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p>
    </footer>
  `;
}

function renderFeasibility(length: number): void {
  const f = feasibility(10, length);
  const nf = new Intl.NumberFormat("en-US");
  setText("feas-codebook", `${nf.format(f.codebookQueries)} queries — ${f.codebookFeasible ? "browser-feasible" : "infeasible in a browser"}`);
  setText(
    "feas-floor",
    f.meetsNistFloor
      ? `yes (${nf.format(f.domainSize)} ≥ ${nf.format(f.nistFloor)})`
      : `NO — ${nf.format(f.domainSize)} is below ${nf.format(f.nistFloor)}; the standard forbids this domain`,
  );
  setText("feas-beyne", `≈ ${nf.format(f.beyneQueries)} chosen queries (2^23) — not run here`);
}

function wireCodebookAttack(): void {
  const lengthSelect = document.getElementById("attack-length") as HTMLSelectElement | null;
  const button = document.getElementById("attack-run") as HTMLButtonElement | null;
  const output = document.getElementById("attack-output");

  const currentLength = (): number => Number.parseInt(lengthSelect?.value ?? "4", 10);
  renderFeasibility(currentLength());
  lengthSelect?.addEventListener("change", () => renderFeasibility(currentLength()));

  button?.addEventListener("click", async () => {
    const length = currentLength();
    disableButton("attack-run");
    setText("attack-status", `Building the codebook over ${new Intl.NumberFormat("en-US").format(10 ** length)} values…`);
    try {
      const r = await runCodebookAttack(10, length);
      if (output) output.hidden = false;
      setText("attack-secret", r.secret);
      setText("attack-target", r.target);
      setText("attack-recovered", r.recovered ?? "(not found)");
      setText("attack-queries", new Intl.NumberFormat("en-US").format(r.queries));
      const verdict = document.getElementById("attack-verdict");
      if (verdict) {
        if (r.recovered_ok) {
          verdict.className = "attack-verdict leaked";
          verdict.setAttribute("data-verdict", "recovered");
          verdict.textContent =
            "BROKEN — the secret plaintext was recovered with no key, purely by enumerating the domain. This is why small-domain FPE is unsafe and why the 10^6 floor is a hard requirement.";
        } else {
          verdict.className = "attack-verdict";
          verdict.setAttribute("data-verdict", "failed");
          verdict.textContent = "The codebook did not resolve the target (unexpected).";
        }
      }
      setText("attack-status", "Done.");
    } catch (err) {
      setText("attack-status", `Attack error: ${(err as Error).message}`);
    } finally {
      enableButton("attack-run");
    }
  });
}

export function initUI(): void {
  const app = document.getElementById("app");
  if (!app) {
    throw new Error("Missing #app root element.");
  }

  app.innerHTML = template();
  setInputValue("fail-key", generateRandomKeyHex(32));
  wireKeyGenerators();
  wireStartHere();
  wirePanel1();
  wirePanel2();
  wirePanel3();
  wirePanel4();
  wireRoundsPanel();
  wireFailLab();
  wireCodebookAttack();
  runVectorSmokeCheck();
}
