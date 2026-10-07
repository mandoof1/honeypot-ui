/*
 * Display sanitising for attacker-controlled strings.
 *
 * Everything the console prints — commands, request lines, user agents,
 * indicator values, alert titles — was typed by the person being observed.
 * React escapes markup, but it renders control characters faithfully, and
 * a terminal-minded attacker can use them against the analyst: ANSI escapes
 * that nothing strips, a carriage return that visually overwrites the start
 * of a line, a right-to-left override that reorders a command on screen, or
 * zero-width characters that make two different values look identical.
 *
 * Each such character is replaced with a visible marker rather than deleted,
 * so an analyst can see that something was there. Newlines and tabs are kept:
 * they are the structure of a transcript, not an attack on it.
 *
 * Character classes are built from code points rather than written as
 * escapes, so the file itself contains none of the characters it filters.
 */

const cp = (n) => String.fromCodePoint(n)
const range = (from, to) => `${cp(from)}-${cp(to)}`
const ESC = cp(0x1b)
const BEL = cp(0x07)

/** The APL "quad question" glyph: visibly a placeholder, never confusable with data. */
export const MARKER = cp(0x2370)

// ESC-initiated sequences: CSI (ESC [ ... final byte), OSC (ESC ] ... BEL or
// ESC \), and the two-byte forms (ESC + one character).
const ANSI = new RegExp(
  `${ESC}(?:\\[[0-?]*[ -\\/]*[@-~]|\\][^${BEL}${ESC}]*(?:${BEL}|${ESC}\\\\)?|[@-Z\\\\-_])`,
  'g',
)

// C0 controls except tab (09) and newline (0A), plus DEL. Carriage return is
// included: a bare one is the classic log-spoofing primitive.
const CONTROLS = new RegExp(`[${range(0x00, 0x08)}${range(0x0b, 0x1f)}${cp(0x7f)}]`, 'g')

// C1 controls, Unicode line/paragraph separators, zero-width characters,
// bidirectional embeddings/overrides/isolates, interlinear annotation marks
// and the byte-order mark.
const INVISIBLE = new RegExp(
  `[${range(0x80, 0x9f)}${range(0x2028, 0x2029)}${range(0x200b, 0x200f)}` +
  `${range(0x202a, 0x202e)}${range(0x2060, 0x2064)}${range(0x2066, 0x2069)}` +
  `${cp(0xfeff)}${range(0xfff9, 0xfffb)}]`,
  'g',
)

/**
 * Make an attacker-supplied string safe to put on screen.
 * Non-strings are passed through unchanged, so it can wrap any field.
 */
export function sanitizeForDisplay(value) {
  if (typeof value !== 'string') return value
  if (!value) return value
  return value
    .replace(ANSI, MARKER)
    .replace(CONTROLS, MARKER)
    .replace(INVISIBLE, MARKER)
}

/** True when sanitising would change the value — useful for a "contains hidden characters" hint. */
export function hasHiddenCharacters(value) {
  return typeof value === 'string' && sanitizeForDisplay(value) !== value
}

/** Short alias for templates. */
export const clean = sanitizeForDisplay
