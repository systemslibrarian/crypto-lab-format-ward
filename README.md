# crypto-lab-format-ward

`FF1 · FF3-1 · AES-256 · Feistel Network`

**[Live Demo](https://systemslibrarian.github.io/crypto-lab-format-ward/)**

## Overview

Format Ward is a browser-based crypto lab demo for format-preserving encryption (FPE) using FF1 and FF3-1 from NIST SP 800-38G.

The demo shows how sensitive values (credit cards, SSNs, phone numbers, ZIP codes, and custom-alphabet strings) can be encrypted while preserving original format constraints so legacy schema assumptions do not break.

Primary standards references:

- NIST SP 800-38G: https://csrc.nist.gov/pubs/sp/800/38/g/final
- NIST SP 800-38G Rev.1 (FF3-1): https://csrc.nist.gov/pubs/sp/800/38/g/r1/final

## What You Can Explore

1. Credit Card Tokenization panel
2. SSN / Phone / Postal format masking panel
3. FF1 vs FF3-1 side-by-side timing and output comparison
4. Custom alphabet FF1 encryption and decryption

## Primitives Used

- FF1 (NIST SP 800-38G)
- FF3-1 (NIST SP 800-38G Rev.1)
- AES via WebCrypto (`AES-CBC`) as the underlying block primitive
- Feistel round structure per standard mode definitions

## Running Locally

```bash
npm install
npm run dev
```

Build and preview:

```bash
npm run build
npm run preview
```

Run vector checks:

```bash
npm run test
```

## Security Notes

- FF1 is the preferred choice for new deployments in this demo.
- FF3-1 has known differential-attack literature and reduced margin compared to FF1.
- The FF3/FF3-1 line of analysis was highlighted by Durak & Vaudenay (2017); this demo surfaces that caveat directly in UI and documentation.
- Always treat demo code as educational and validate operational choices against your threat model and compliance requirements.

## Why This Matters

Many production systems cannot change field lengths or character constraints without expensive schema and integration rewrites.

FPE allows encryption while preserving the visible format shape, which is useful for tokenization, safe analytics, and controlled data sharing in constrained legacy environments.

## Related Demos

- crypto-compare (Format-Preserving Encryption category): https://github.com/systemslibrarian/crypto-compare
- crypto-lab landing page: https://github.com/systemslibrarian/crypto-lab
- crypto-lab-iron-letter: https://github.com/systemslibrarian/crypto-lab-iron-letter

So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31