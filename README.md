# crypto-lab-format-ward

`FF1 · FF3-1 · AES-256 · Feistel Network`

**[Live Demo](https://systemslibrarian.github.io/crypto-lab-format-ward/)**

## 1. What It Is

Format Ward is a browser demo of format-preserving encryption using FF1 and FF3-1 with WebCrypto AES-CBC rounds in a Feistel construction. It solves the problem of protecting sensitive fields while keeping the original character set and field shape, so existing schema constraints continue to work. In this codebase, encryption and decryption are shown for PAN, SSN/phone/ZIP-style formats, and custom alphabets. This is a symmetric-key model: the same secret key material is required for both encryption and decryption.

## 2. When to Use It

- Legacy databases with strict field validation: FF1/FF3-1 let you encrypt values while preserving the original format, so downstream validators and fixed-width schemas continue to accept the data.
- PAN tokenization workflows: preserving decimal length and structure helps payment pipelines that cannot immediately migrate away from format-bound interfaces.
- Masked analytics for structured identifiers: FF1 can protect only the digit positions in SSN/phone-style strings while keeping separators in place for operational readability.
- Cross-system data sharing where format compatibility is mandatory: custom-alphabet FF1 keeps agreed symbol sets and length invariant across parties.
- Do not use this when you need authenticated encryption by itself: FF1/FF3-1 preserve format but do not replace integrity/authenticity controls at the protocol layer.

## 3. Live Demo

Live GitHub Pages demo: https://systemslibrarian.github.io/crypto-lab-format-ward/

The demo supports both encrypt and decrypt flows in each panel and displays round-trip results so you can verify reversibility. You can run FF1 and FF3-1 side-by-side, compare output and timing, and inspect Luhn validity behavior on ciphertext for PAN examples. Exposed controls include plaintext/format selectors, AES-256 key generation, FF1 tweak input, FF3-1 tweak input (14 hex chars), and custom alphabet selection.

## 4. What Can Go Wrong

- FF3-1 margin assumptions: FF3-1 has published differential-cryptanalysis results relative to FF1, which is why this demo marks FF1 as the preferred default for new systems.
- Wrong tweak size for FF3-1: FF3-1 requires exactly a 56-bit tweak (14 hex chars), and using the wrong length breaks interoperability and security assumptions.
- Small-domain misuse: very small message spaces reduce effective security for format-preserving schemes because exhaustive or statistical attacks become more practical.
- Deterministic reuse patterns: reusing the same key/tweak configuration on repeated structured fields can leak equality patterns even though plaintext is hidden.
- Alphabet/radix mismatch bugs: if application characters and radix mapping are inconsistent, encryption can fail or silently produce invalid domain behavior for downstream systems.

## 5. Real-World Usage

- NIST SP 800-38G and SP 800-38G Rev.1: these standards define FF1 and FF3-1 and are the baseline references used by compliant implementations.
- PCI-oriented tokenization deployments: payment environments commonly use NIST FPE modes (especially FF1) to protect PAN data without breaking numeric format constraints.
- OpenText Voltage SecureData: this enterprise data-protection platform documents format-preserving encryption deployments for structured fields.
- Protegrity data protection platforms: Protegrity materials describe FPE usage for structured-data tokenization in regulated environments.
- Application security toolkits such as Bouncy Castle: widely used libraries include FF1/FF3-1 primitives that are integrated into production JVM systems handling structured identifiers.

## Related Demos

- crypto-compare (Format-Preserving Encryption category): https://github.com/systemslibrarian/crypto-compare
- crypto-lab landing page: https://github.com/systemslibrarian/crypto-lab
- crypto-lab-iron-letter: https://github.com/systemslibrarian/crypto-lab-iron-letter

> *"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*