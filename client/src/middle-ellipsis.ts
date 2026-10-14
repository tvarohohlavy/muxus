/**
 * Shorten `text` to at most `max` characters by replacing its middle with an
 * ellipsis. The end is kept in full where possible, which for a path means
 * the file name and its nearest folders stay readable.
 */
export function middleEllipsis(text: string, max = 64): string {
  const chars = Array.from(text);
  if (chars.length <= max) return text;
  const tail = Math.ceil((max - 1) * 0.6);
  const head = max - 1 - tail;
  return `${chars.slice(0, head).join('')}…${chars.slice(chars.length - tail).join('')}`;
}
