import { SymbolArray, stringToSymbols, symbolsToString } from "./ff1";

export type MaskedFormat = "ssn" | "phone" | "zip";

export interface MaskParseResult {
  normalized: string;
  digits: string;
  digitIndexes: number[];
  mask: string;
}

const DIGITS = "0123456789";

export function digitsOnly(input: string): string {
  return input.replace(/\D/g, "");
}

export function isCreditCardCandidate(input: string): boolean {
  return /^\d{16}$/.test(digitsOnly(input));
}

export function luhnValid(cardNumber: string): boolean {
  const raw = digitsOnly(cardNumber);
  if (!/^\d+$/.test(raw)) {
    return false;
  }

  let sum = 0;
  let doubleDigit = false;
  for (let i = raw.length - 1; i >= 0; i -= 1) {
    let d = Number(raw[i]);
    if (doubleDigit) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}

export function parseMaskedFormat(input: string, format: MaskedFormat): MaskParseResult {
  const trimmed = input.trim();

  if (format === "zip") {
    if (!/^\d{5}$/.test(trimmed)) {
      throw new Error("ZIP must be exactly 5 digits.");
    }
    return {
      normalized: trimmed,
      digits: trimmed,
      digitIndexes: [0, 1, 2, 3, 4],
      mask: "EEEEE"
    };
  }

  if (format === "ssn") {
    if (!/^\d{3}-\d{2}-\d{4}$/.test(trimmed)) {
      throw new Error("SSN must be in XXX-XX-XXXX format.");
    }
  } else if (!/^\d{3}-\d{3}-\d{4}$/.test(trimmed)) {
    throw new Error("Phone must be in XXX-XXX-XXXX format.");
  }

  const chars = trimmed.split("");
  const digitIndexes: number[] = [];
  for (let i = 0; i < chars.length; i += 1) {
    if (/\d/.test(chars[i])) {
      digitIndexes.push(i);
    }
  }

  const digits = digitIndexes.map((idx) => chars[idx]).join("");
  const mask = chars
    .map((ch) => {
      if (/\d/.test(ch)) {
        return "E";
      }
      return "-";
    })
    .join("");

  return {
    normalized: trimmed,
    digits,
    digitIndexes,
    mask
  };
}

export function mergeMaskedDigits(source: string, digitIndexes: number[], encryptedDigits: string): string {
  const out = source.split("");
  for (let i = 0; i < digitIndexes.length; i += 1) {
    out[digitIndexes[i]] = encryptedDigits[i];
  }
  return out.join("");
}

export function toDigitSymbols(value: string): SymbolArray {
  return stringToSymbols(value, DIGITS);
}

export function fromDigitSymbols(value: SymbolArray): string {
  return symbolsToString(value, DIGITS);
}

export function validateCustomAlphabet(alphabet: string): void {
  if (alphabet.length < 2) {
    throw new Error("Custom alphabet must contain at least 2 symbols.");
  }
  const unique = new Set(alphabet.split(""));
  if (unique.size !== alphabet.length) {
    throw new Error("Custom alphabet cannot contain duplicate symbols.");
  }
}
