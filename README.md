# crypto-lab-format-ward

## What It Is

Format Ward is a browser demo of format-preserving encryption using FF1 and FF3-1 with AES-256 rounds in a Feistel Network construction. It addresses cases where sensitive identifiers must be encrypted without changing length or allowed character set, so legacy schemas and validators can still accept the data. The demo opens with a zero-config "Start here" step — one input, one Encrypt button, a live plaintext-vs-ciphertext comparison, and a tweak toggle — so the core idea (shape is preserved, the tweak diversifies) lands before any key management appears. It then includes full encrypt and decrypt flows for PAN-like numbers, masked SSN/phone/ZIP formats, and a custom alphabet panel. This is a symmetric-key model, so the same secret key material is required to decrypt what was encrypted.

## When to Use It

- Legacy structured fields with strict validators: FF1 and FF3-1 preserve radix and length so existing database and application format checks can continue working.
- PAN and other numeric tokenization workflows: the output stays numeric and fixed-width, which fits payment-adjacent interfaces that cannot accept arbitrary binary ciphertext.
- Mixed-format identifiers such as SSN/phone patterns: encrypting only digit positions keeps separators and presentation shape stable for operational tooling.
- Custom in-domain identifiers: the custom alphabet flow demonstrates FF1 over non-decimal symbol sets while preserving exact message length.
- Do not use this as your only protection where integrity is required: FF1/FF3-1 provide confidentiality for domain values but do not provide authenticity or tamper detection by themselves.
- Do NOT treat this as production tokenization — it is a browser teaching demo, not a hardened key-management or data-protection system.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-format-ward](https://systemslibrarian.github.io/crypto-lab-format-ward/)**

The demo supports encrypt and decrypt flows and shows round-trip outputs so you can verify reversibility directly in the browser. You can run FF1 and FF3-1 side by side in the comparison panel, including timing output and PAN-focused Luhn checks on ciphertext results. Exposed controls include AES-256 key generation, FF1 tweak fields, FF3-1 14-hex-character tweak fields, plaintext/format selectors, and custom alphabet input.

A progressive on-ramp and three teaching exhibits go further than the standard FPE black box:

1. **Start here — the whole idea in one encrypt**: a minimal first contact with no keys or hex. Type a 16-digit number, press Encrypt, and see the ciphertext side by side with the plaintext, annotated with length and character set ("same 16 digits, still passes Luhn"). A single tweak toggle visibly changes the output. Keys, FF3-1, and raw tweak-hex fields are deferred to a collapsed "Advanced" note and the panels below.
2. **Inside FF1 — Feistel Round Walkthrough**: traces a real encryption through all 10 rounds. Beyond the full state table, it adds (a) a plain-language gloss of the split parameters n/u/v/b/d, (b) a "Watch the swap" stage that animates the A | B halves round by round with changed digits pulsing and a step/play control, and (c) a "Zoom into one round" mini-pipeline that shows exactly how Y is produced — B's digits → packed bytes → the AES round function (CBC-MAC) → the keystream S → Y → the `(A + Y) mod r^m` addition rendered as a real column sum with the modular wrap struck through. Every value shown is the actual traced integer from the live encryption (guarded by a unit test), so the mechanism is observable, not asserted.
3. **Failure Lab — Why FPE Still Leaks**: three interactive demos that make the security caveats concrete — (a) the equality leak (same plaintext + same key + same tweak → same ciphertext, so frequency analysis still works), (b) the tweak avalanche (flipping one bit of the tweak changes roughly half the output symbols, which is the practical mitigation), and (c) a domain-size calculator that flags when the domain is too small to be called encryption at all.

An inline glossary near the top of the page defines radix, tweak, domain, Feistel network, round function, and equality leak so the jargon does not stand between the reader and the demo.

## What Can Go Wrong

- FF3-1 security margin assumptions: published differential cryptanalysis against FF3 variants is why this project labels FF1 as the preferred default where possible.
- Invalid FF3-1 tweak length: FF3-1 requires a 56-bit tweak (7 bytes or 14 hex characters), and wrong length causes incorrect operation and non-interoperable ciphertext.
- Small-domain leakage risk: small or highly structured domains can make guessing and statistical recovery materially easier for format-preserving modes.
- Deterministic equality leakage from key and tweak reuse: reusing the same key and tweak over repeated identifiers can reveal when plaintext values repeat.
- Alphabet-to-symbol mapping implementation bugs: if an input character is outside the declared alphabet or mapping is inconsistent, encryption fails or yields invalid in-domain behavior.

## Real-World Usage

- NIST SP 800-38G and SP 800-38G Rev.1: these standards define FF1 and FF3-1 and are used as the normative basis for compliant format-preserving encryption implementations.
- OpenText Voltage SecureData: this platform documents deployment of NIST-style format-preserving encryption to protect structured enterprise fields.
- Protegrity data protection platform: Protegrity materials describe FPE-based protection and tokenization patterns for regulated structured data.
- Bouncy Castle cryptography library: production JVM systems use its FF1 and FF3-1 engines when implementing standards-aligned FPE in application stacks.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-format-ward
cd crypto-lab-format-ward
npm install
npm run dev
```

## Related Demos

- [crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/) — ECIES / RSA-OAEP / AES-256-GCM, hybrid encryption for the same data-protection space.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES-GCM and AES-CBC, the authenticated-encryption modes FPE deliberately is not.
- [crypto-lab-envelope-kms](https://systemslibrarian.github.io/crypto-lab-envelope-kms/) — AES key wrap and DEK/KEK key rotation for managing the keys FPE depends on.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — ChaCha20 stream encryption and nonce-reuse pitfalls.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
