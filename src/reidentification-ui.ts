import { ROSTER, formatLeakage, matchFormats, releaseSyntheticRoster, type ShapeView } from './reidentification';

export function mountReidentification(): void {
  const section = document.createElement('section');
  section.className = 'panel'; section.id = 'shape-leakage';
  section.innerHTML = `<h2>Format can identify a record without decrypting it</h2>
    <p>Eight invented people form an auxiliary roster. Encrypt their names and cities with real FF1, preserve spaces, then let an observer match only lengths and word shapes. The observer gets no key or encryption oracle. Rows are shuffled and each field uses a fresh tweak.</p>
    <p>Predict: will new keys or tweaks hide the shape that the application deliberately preserves?</p>
    <label for="shape-mode">Release protection</label>
    <select id="shape-mode"><option value="padded">Control: fixed-length padded AES-GCM records</option><option value="fpe">FF1 with word shape preserved</option></select>
    <label for="shape-view">Auxiliary information used for matching</label>
    <select id="shape-view"><option value="length">Name length only</option><option value="words">Name word lengths</option><option value="both">Name and city word lengths</option></select>
    <button id="shape-run" type="button">Encrypt synthetic records and match formats</button>
    <p id="shape-status" role="status" aria-live="polite">Choose a release, then run.</p>
    <div id="shape-output" hidden></div>
    <p>Scope: a format-only attack on this complete eight-record auxiliary roster, with a uniform prior. A unique candidate here is not proof of identity in an incomplete real-world roster. This does not break FF1 or recover its key. Fixed-length padding removes this format distinction; it does not certify anonymity against other metadata or side information.</p>
    <p>Source: <a href="https://eprint.iacr.org/2026/993">Boesgaard and Larsen, Format-Preserving Encryption Creates a Privacy Attack Surface for Re-Identification</a>, §3.1–3.2. The paper's real-world rates are not transferred to these invented records.</p>`;
  document.querySelector('main')!.append(section);
  const get = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
  const mode = get<HTMLSelectElement>('shape-mode'), view = get<HTMLSelectElement>('shape-view');
  const run = get<HTMLButtonElement>('shape-run'), output = get('shape-output'), status = get('shape-status');
  let generation = 0, previous = `${mode.value}/${view.value}`;
  for (const input of [mode, view]) input.addEventListener('change', () => {
    const next = `${mode.value}/${view.value}`; if (next === previous) return;
    previous = next; generation++; output.hidden = true; output.replaceChildren();
    status.textContent = 'Inputs changed. Previous result retired; run again.';
  });
  run.addEventListener('click', async () => {
    const mine = ++generation, padded = mode.value === 'padded', shapeView = view.value as ShapeView;
    run.disabled = true; output.hidden = true; output.replaceChildren(); status.textContent = 'Encrypting the synthetic roster…';
    try {
      const release = await releaseSyntheticRoster(padded);
      if (mine !== generation) return;
      const matches = matchFormats(release, ROSTER, shapeView, padded);
      const metrics = formatLeakage(ROSTER, shapeView, padded);
      const summary = document.createElement('p'); summary.id = 'shape-metrics';
      summary.textContent = `${metrics.unique} of ${ROSTER.length} records have one candidate. Average candidate count: ${metrics.expectedCandidates.toFixed(2)}. Format leakage: ${metrics.leakage.toFixed(4)} bits out of a ${metrics.priorEntropy.toFixed(4)}-bit uniform prior.`;
      const table = document.createElement('table');
      table.innerHTML = '<caption>Candidates found using only the released format</caption><thead><tr><th scope="col">Shuffled release</th><th scope="col">Visible format</th><th scope="col">Candidates</th></tr></thead>';
      const tbody = document.createElement('tbody');
      matches.forEach((match, i) => {
        const row = document.createElement('tr');
        [String(i + 1), match.fingerprint, match.candidates.join(', ') || 'No match in roster'].forEach((s, j) => {
          const cell = document.createElement(j === 0 ? 'th' : 'td'); if (j === 0) cell.setAttribute('scope', 'row'); cell.textContent = s; row.append(cell);
        }); tbody.append(row);
      }); table.append(tbody);
      const scroll = document.createElement('div'); scroll.className = 'table-scroll'; scroll.style.overflowX = 'auto'; scroll.tabIndex = 0; scroll.setAttribute('role', 'region'); scroll.setAttribute('aria-label', 'Format matching candidates'); scroll.append(table);
      const details = document.createElement('details'); const caption = document.createElement('summary'); caption.textContent = 'Inspect released ciphertexts and the synthetic auxiliary roster';
      const bytes = document.createElement('pre'); bytes.id = 'shape-bytes'; bytes.style.whiteSpace = 'pre-wrap'; bytes.style.overflowWrap = 'anywhere';
      bytes.textContent = 'Released ciphertexts (shuffled):\n' + release.map((r, i) => `${i + 1}: ${r.name}${r.city ? ' | ' + r.city : ''}`).join('\n') + '\n\nAuxiliary roster (invented):\n' + ROSTER.map(r => `${r.name} | ${r.city}`).join('\n');
      details.append(caption, bytes); output.append(summary, scroll, details); output.hidden = false;
      status.textContent = metrics.unique > 0 ? 'FORMAT LEAKAGE — some records have a unique candidate in this roster.' : 'No unique candidate under this selected format view. This is not an anonymity guarantee.';
    } catch (error) { if (mine === generation) status.textContent = `Could not compute a result: ${String(error)}`; console.error(error); }
    finally { run.disabled = false; }
  });
}
