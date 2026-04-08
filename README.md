# crypto-lab-format-ward

`FF1 · FF3-1 · AES-256 · Feistel Network`

**[Live Demo](https://systemslibrarian.github.io/crypto-lab-format-ward/)**

## 1. What It Is

Format Ward is a browser demo of format-preserving encryption using FF1 and FF3-1 with AES-256 rounds in a Feistel Network construction. It addresses cases where sensitive identifiers must be encrypted without changing length or allowed character set, so legacy schemas and validators can still accept the data. The demo includes encrypt and decrypt flows for PAN-like numbers, masked SSN/phone/ZIP formats, and a custom alphabet panel. This is a symmetric-key model, so the same secret key material is required to decrypt what was encrypted.

## 2. When to Use It

- Legacy structured fields with strict validators: FF1 and FF3-1 preserve radix and length so existing database and application format checks can continue working.
- PAN and other numeric tokenization workflows: the output stays numeric and fixed-width, which fits payment-adjacent interfaces that cannot accept arbitrary binary ciphertext.
- Mixed-format identifiers such as SSN/phone patterns: encrypting only digit positions keeps separators and presentation shape stable for operational tooling.
- Custom in-domain identifiers: the custom alphabet flow demonstrates FF1 over non-decimal symbol sets while preserving exact message length.
- Do not use this as your only protection where integrity is required: FF1/FF3-1 provide confidentiality for domain values but do not provide authenticity or tamper detection by themselves.

## 3. Live Demo

Live GitHub Pages demo: https://systemslibrarian.github.io/crypto-lab-format-ward/

The demo supports encrypt and decrypt flows and shows round-trip outputs so you can verify reversibility directly in the browser. You can run FF1 and FF3-1 side by side in the comparison panel, including timing output and PAN-focused Luhn checks on ciphertext results. Exposed controls include AES-256 key generation, FF1 tweak fields, FF3-1 14-hex-character tweak fields, plaintext/format selectors, and custom alphabet input.

## 4. What Can Go Wrong

- FF3-1 security margin assumptions: published differential cryptanalysis against FF3 variants is why this project labels FF1 as the preferred default where possible.
- Invalid FF3-1 tweak length: FF3-1 requires a 56-bit tweak (7 bytes or 14 hex characters), and wrong length causes incorrect operation and non-interoperable ciphertext.
- Small-domain leakage risk: small or highly structured domains can make guessing and statistical recovery materially easier for format-preserving modes.
- Deterministic equality leakage from key and tweak reuse: reusing the same key and tweak over repeated identifiers can reveal when plaintext values repeat.
- Alphabet-to-symbol mapping implementation bugs: if an input character is outside the declared alphabet or mapping is inconsistent, encryption fails or yields invalid in-domain behavior.

## 5. Real-World Usage

- NIST SP 800-38G and SP 800-38G Rev.1: these standards define FF1 and FF3-1 and are used as the normative basis for compliant format-preserving encryption implementations.
- OpenText Voltage SecureData: this platform documents deployment of NIST-style format-preserving encryption to protect structured enterprise fields.
- Protegrity data protection platform: Protegrity materials describe FPE-based protection and tokenization patterns for regulated structured data.
- Bouncy Castle cryptography library: production JVM systems use its FF1 and FF3-1 engines when implementing standards-aligned FPE in application stacks.

## Related Demos

- crypto-compare (Format-Preserving Encryption category): https://github.com/systemslibrarian/crypto-compare
- crypto-lab landing page: https://github.com/systemslibrarian/crypto-lab
- crypto-lab-iron-letter: https://github.com/systemslibrarian/crypto-lab-iron-letter

> *"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*