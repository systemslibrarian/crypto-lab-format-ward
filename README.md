# crypto-lab-format-ward

## What It Is

Format Ward is a browser demo of format-preserving encryption using FF1 and FF3-1 with AES-256 rounds in a Feistel Network construction. It addresses cases where sensitive identifiers must be encrypted without changing length or allowed character set, so legacy schemas and validators can still accept the data. The demo opens with a zero-config "Start here" step — one input, one Encrypt button, a live plaintext-vs-ciphertext comparison, and a tweak toggle — so the core idea (shape is preserved, the tweak diversifies) lands before any key management appears. It then includes full encrypt and decrypt flows for PAN-like numbers, masked SSN/phone/ZIP formats, and a custom alphabet panel. This is a symmetric-key model, so the same secret key material is required to decrypt what was encrypted.

**Standardization status, up front: FF3-1 is being withdrawn.** The 2nd public draft of NIST SP 800-38G Rev. 1 (3 February 2025) removes FF3 and FF3-1 entirely, leaving FF1 as the only format-preserving method NIST specifies. This demo keeps FF3-1 runnable *as an exhibit* — it is the more interesting half of the lesson, because seeing how a small-domain cipher gets broken teaches more than seeing one work. See "Standardization status" below, and the Scope section at the top of the live page.

## When to Use It

This demo is for learning what format-preserving encryption is, why it is structurally hard, and why FF3-1 did not survive. It is not a recommendation to deploy FPE.

- Understanding the small-domain problem: why a cipher whose domain is 10^6 values cannot borrow AES's security argument, and why Feistel round counts that suffice at 128 bits do not suffice at 20.
- Reading the cryptanalysis: the demo names the three papers that moved the standard (Durak-Vaudenay 2017, Hoang-Tessaro-Trieu 2018, Beyne 2021) and states what each actually claims, so the citations are checkable rather than folklore.
- Evaluating an existing FPE deployment: if you already run FF3-1 in production, the Scope section states what is now known about it and what to migrate to.
- Custom in-domain identifiers: the custom alphabet flow demonstrates FF1 over non-decimal symbol sets while preserving exact message length.
- Do NOT use FF3-1 in new systems: NIST removed it from Draft SP 800-38G Rev. 1 after Beyne's linear cryptanalysis of its tweak schedule.
- Do not use any FPE mode where integrity matters: FF1 and FF3-1 provide confidentiality for domain values but no authenticity or tamper detection. Reach for AES-GCM, a tokenization vault, or AES-SIV instead — the live page's Scope section walks through which one fits which requirement.
- Do NOT treat this as production tokenization — it is a browser teaching demo, not a hardened key-management or data-protection system.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-format-ward](https://systemslibrarian.github.io/crypto-lab-format-ward/)**

The demo supports encrypt and decrypt flows and shows round-trip outputs so you can verify reversibility directly in the browser. You can run FF1 and FF3-1 side by side in the comparison panel, including timing output and PAN-focused Luhn checks on ciphertext results. Exposed controls include AES-256 key generation, FF1 tweak fields, FF3-1 14-hex-character tweak fields, plaintext/format selectors, and custom alphabet input.

The page opens with a **Scope** section that states the standardization status before any interactive panel: a dated timeline from SP 800-38G (2016) through the 2nd public draft of Rev. 1 (February 2025) that removes FF3 and FF3-1, an explanation of *why* small-domain ciphers are hard (finite codebook, weak Feistel halves, and the tweak schedule that Beyne's attack targets), and a "what to use instead" list.

A progressive on-ramp and three teaching exhibits go further than the standard FPE black box:

1. **Start here — the whole idea in one encrypt**: a minimal first contact with no keys or hex. Type a 16-digit number, press Encrypt, and see the ciphertext side by side with the plaintext, annotated with length and character set ("same 16 digits, still passes Luhn"). A single tweak toggle visibly changes the output. Keys, FF3-1, and raw tweak-hex fields are deferred to a collapsed "Advanced" note and the panels below.
2. **Inside FF1 — Feistel Round Walkthrough**: traces a real encryption through all 10 rounds. Beyond the full state table, it adds (a) a plain-language gloss of the split parameters n/u/v/b/d, (b) a "Watch the swap" stage that animates the A | B halves round by round with changed digits pulsing and a step/play control, and (c) a "Zoom into one round" mini-pipeline that shows exactly how Y is produced — B's digits → packed bytes → the AES round function (CBC-MAC) → the keystream S → Y → the `(A + Y) mod r^m` addition rendered as a real column sum with the modular wrap struck through. Every value shown is the actual traced integer from the live encryption (guarded by a unit test), so the mechanism is observable, not asserted.
3. **Failure Lab — Why FPE Still Leaks**: three interactive demos that make the security caveats concrete — (a) the equality leak (same plaintext + same key + same tweak → same ciphertext, so frequency analysis still works), (b) the tweak avalanche (flipping one bit of the tweak changes about 90% of the output symbols — not "half": the readout counts decimal symbols, and a rerandomized digit collides with the old one 1 time in 10, so the random-oracle expectation is 1 - 1/radix), and (c) a domain-size calculator that flags when the domain is too small to be called encryption at all, showing both a practical verdict and whether the parameters clear the Draft SP 800-38G Rev. 1 floor of radix^minlen >= 1,000,000 that this demo enforces. (The Panel 2 postal-code option sits just under that floor at 10^5 and is deliberately kept as a rejection exhibit.)

An inline glossary near the top of the page defines radix, tweak, domain, Feistel network, round function, and equality leak so the jargon does not stand between the reader and the demo.

## What Can Go Wrong

- FF3-1 is broken, not merely "reduced margin": Beyne's linear cryptanalysis (CRYPTO 2021) distinguishes FF3-1 over a domain of N = 1000 from an ideal tweakable block cipher with advantage at least 1/10 using about 2^23 queries, and NIST removed the mode in response. Note the common misattribution: Durak-Vaudenay (2017) broke FF3, the 64-bit-tweak original, and FF3-1 was the *response* to that paper — citing it as the reason FF3-1 is unsafe gets the history backwards.
- Invalid FF3-1 tweak length: FF3-1 requires a 56-bit tweak (7 bytes or 14 hex characters), and wrong length causes incorrect operation and non-interoperable ciphertext.
- Small-domain leakage risk: small or highly structured domains can make guessing and statistical recovery materially easier for format-preserving modes.
- Deterministic equality leakage from key and tweak reuse: reusing the same key and tweak over repeated identifiers can reveal when plaintext values repeat.
- Alphabet-to-symbol mapping implementation bugs: if an input character is outside the declared alphabet or mapping is inconsistent, encryption fails or yields invalid in-domain behavior.

## Standardization status

| Date | Document | What it says |
|---|---|---|
| March 2016 | [SP 800-38G](https://csrc.nist.gov/pubs/sp/800/38/g/final) — **final**, still the last finished text | Specifies **FF1** and **FF3**. Domain floor only radix^minlen >= 100; 10^6 merely recommended. |
| Feb 2019 | SP 800-38G Rev. 1, initial public draft | Cuts FF3's tweak from 64 to 56 bits and renames it **FF3-1**, responding to Durak-Vaudenay. FF3-1 has therefore only ever existed inside a draft. |
| Feb 2025 | [SP 800-38G Rev. 1, 2nd public draft](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd) — **current** | **Removes FF3 and FF3-1.** NIST: "The encryption method FF3 is no longer specified", because "Beyne described a weakness in the tweak schedule that affected both FF3 and FF3-1 but not FF1." Abstract now reads "This recommendation specifies the FF1 method" — singular. Also makes radix^minlen >= 1,000,000 a *requirement*, and disallows both the inverse AES cipher function and floating-point arithmetic. Comments closed 4 April 2025. |

Because Rev. 1 is still a draft, FF3 is simultaneously "in the current standard" and "known broken" — which is exactly why this demo states the status rather than implying the standard settles it. This code enforces the Rev. 1 floor (10^6), not the retired 100.

The cryptanalysis, with what each paper actually claims:

- [Durak & Vaudenay, CRYPTO 2017](https://eprint.iacr.org/2017/521) — *Breaking the FF3 Format-Preserving Encryption Standard Over Small Domains.* Against a Feistel half-domain of size N, message recovery in about N^(11/6) chosen plaintexts and N^5 time. Breaks **FF3**.
- [Hoang, Tessaro & Trieu, CRYPTO 2018](https://eprint.iacr.org/2018/556) — *The Curse of Small Domains: New Attacks on Format-Preserving Encryption.* Known-plaintext message recovery against **both FF1 and FF3**, feasible on domains as small as 8 bits. This is the paper behind the 10^6 floor.
- [Beyne, CRYPTO 2021](https://eprint.iacr.org/2021/815) — *Linear Cryptanalysis of FF3-1 and FEA.* Attacks the alternating round-tweak schedule, not the tweak size. FF3-1 at N = 1000 is distinguishable from an ideal tweakable block cipher with advantage >= 1/10 using about 2^23 queries. Breaks **FF3-1**, and is the reason NIST removed it.

## Real-World Usage

- OpenText Voltage SecureData: this platform documents deployment of NIST-style format-preserving encryption to protect structured enterprise fields.
- Protegrity data protection platform: Protegrity materials describe FPE-based protection and tokenization patterns for regulated structured data.
- Bouncy Castle cryptography library: production JVM systems use its FF1 and FF3-1 engines when implementing standards-aligned FPE in application stacks. That FF3-1 engines remain widely shipped is the practical problem — library availability outlived the mode's standardization.

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

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
