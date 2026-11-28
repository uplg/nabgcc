/** Board time as minutes, seconds and tenths. */
export function boardTime(ms: number): string {
  const minutes = Math.floor(ms / 60000);
  const seconds = ((ms % 60000) / 1000).toFixed(1).padStart(4, "0");
  return `${minutes}:${seconds}`;
}

/** A count with a unit prefix: 12.3 M. */
export function count(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} G`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} k`;
  return String(Math.round(n));
}

/** Station addresses in the access points' events, as people write them. */
export function macs(text: string): string {
  return text.replace(/\[(\d+(?:, \d+){5})\]/g, (_, bytes: string) =>
    bytes
      .split(", ")
      .map((b) => Number(b).toString(16).padStart(2, "0"))
      .join(":"),
  );
}
