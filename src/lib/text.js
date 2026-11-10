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
 * so an analyst can see that something was there.
 *
 * Two entry points, because a transcript and an indicator are different
 * things. A transcript is made of lines, so `sanitizeForDisplay` keeps
 * newlines and tabs. An address, a URL, a hash or a file name is one line by
 * definition, so `sanitizeLine` marks those too: a value copied out of the
 * console must never carry a second line into a shell or a blocklist.
 *
 * The patterns are written as code-point escapes under the `u` flag, so the
 * file itself contains none of the characters it filters and astral ranges
 * (tag characters, the variation-selector supplement) match as one character.
 */

const cp = (n) => String.fromCodePoint(n)
const esc = (n) => `\\u{${n.toString(16)}}`
const range = (from, to) => `${esc(from)}-${esc(to)}`

/** The APL "quad question" glyph: visibly a placeholder, never confusable with data. */
export const MARKER = cp(0x2370)

// ESC-initiated sequences: CSI (ESC [ ... final byte), OSC (ESC ] ... BEL or
// ESC \), and the two-byte forms (ESC + one character).
const ANSI = new RegExp(
  `${esc(0x1b)}(?:\\[[0-?]*[ -\\/]*[@-~]|\\][^${esc(0x07)}${esc(0x1b)}]*(?:${esc(0x07)}|${esc(0x1b)}\\\\)?|[@-Z\\\\-_])`,
  'gu',
)

// C0 controls except tab (09) and newline (0A), plus DEL. Carriage return is
// included: a bare one is the classic log-spoofing primitive.
const CONTROLS = new RegExp(`[${range(0x00, 0x08)}${range(0x0b, 0x1f)}${esc(0x7f)}]`, 'gu')

// Line structure. Legitimate in a transcript, never in a single-line value.
const LINE_BREAKS = new RegExp(`[${esc(0x09)}${esc(0x0a)}]`, 'gu')

// Characters that take no space, reorder their neighbours, or render blank
// while not being a space.
const INVISIBLE = new RegExp(
  '[' +
  range(0x80, 0x9f) +        // C1 controls
  esc(0xad) +                // soft hyphen
  esc(0x34f) +               // combining grapheme joiner
  esc(0x61c) +               // Arabic letter mark
  range(0x115f, 0x1160) +    // Hangul choseong and jungseong fillers
  range(0x17b4, 0x17b5) +    // Khmer inherent vowels, rendered as nothing
  range(0x180b, 0x180f) +    // Mongolian variation selectors and vowel separator
  range(0x200b, 0x200f) +    // zero-width space, joiners, direction marks
  range(0x2028, 0x202e) +    // line and paragraph separators, embeddings, overrides
  range(0x2060, 0x206f) +    // word joiner, invisible operators, isolates, deprecated formats
  esc(0x3164) +              // Hangul filler
  range(0xfe00, 0xfe0f) +    // variation selectors
  esc(0xfeff) +              // byte-order mark
  esc(0xffa0) +              // halfwidth Hangul filler
  range(0xfff9, 0xfffb) +    // interlinear annotation marks
  range(0x1bca0, 0x1bca3) +  // shorthand format controls
  range(0x1d173, 0x1d17a) +  // musical format controls
  range(0xe0000, 0xe007f) +  // tag characters
  range(0xe0100, 0xe01ef) +  // variation selectors supplement
  ']',
  'gu',
)

/**
 * Make an attacker-supplied, possibly multi-line string safe to put on
 * screen. Non-strings are passed through unchanged, so it can wrap any field.
 */
export function sanitizeForDisplay(value) {
  if (typeof value !== 'string') return value
  if (!value) return value
  return value
    .replace(ANSI, MARKER)
    .replace(CONTROLS, MARKER)
    .replace(INVISIBLE, MARKER)
}

/**
 * The same, for a value that is one line by definition: newlines and tabs are
 * marked as well. Use it for anything that can be copied or pasted.
 */
export function sanitizeLine(value) {
  if (typeof value !== 'string') return value
  if (!value) return value
  return sanitizeForDisplay(value).replace(LINE_BREAKS, MARKER)
}

/** True when sanitising would change the value — useful for a "contains hidden characters" hint. */
export function hasHiddenCharacters(value) {
  return typeof value === 'string' && sanitizeForDisplay(value) !== value
}

/** Short aliases for templates. */
export const clean = sanitizeForDisplay
export const cleanLine = sanitizeLine
