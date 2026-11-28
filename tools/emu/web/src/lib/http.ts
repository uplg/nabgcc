// Answers from the rabbit's web server, as the phone received them.

export interface Answer {
  status: number;
  reason: string;
  body: string;
  html: boolean;
}

export function parseAnswer(raw: string): Answer {
  const split = raw.indexOf("\r\n\r\n");
  const head = split < 0 ? raw : raw.slice(0, split);
  const body = split < 0 ? "" : raw.slice(split + 4);
  const [statusLine = "", ...fields] = head.split("\r\n");
  const [, code = "0", reason = ""] = /^HTTP\/1\.\d (\d+) ?(.*)$/.exec(statusLine) ?? [];
  const type = fields.find((f) => /^content-type:/i.test(f)) ?? "";
  return { status: Number(code), reason, body, html: type.includes("html") || /^\s*<!doctype html/i.test(body) };
}

/** The path a request line asked for. */
export function requestedPath(request: string): string {
  return request.split(" ")[1] ?? "/";
}

/** A link or form action on a page at `from`, as a path on the rabbit. */
export function resolve(target: string, from: string): string {
  const url = new URL(target, `http://rabbit${from}`);
  return url.pathname + url.search;
}
