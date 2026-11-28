// The page's side of the rabbit: the latest snapshot as reactive state,
// the logs it accumulates, and the commands, sent to the worker.

import type { PhonePage, Sound } from "./nabemu";
import type { Commands, Reply, Request, Snapshot } from "./protocol";
import EmuWorker from "./worker?worker";

const CONSOLE_LINES = 5000;
const LOG_LINES = 500;

function keep<T>(list: T[], more: T[], max: number): T[] {
  return more.length === 0 ? list : [...list, ...more].slice(-max);
}

export class Rabbit {
  // Replaced whole every time, never changed in place: no deep proxies.
  snapshot = $state.raw<Snapshot | null>(null);
  /** Whole lines printed on the serial console, and the one being printed. */
  lines = $state.raw<string[]>([]);
  partial = $state("");
  requests = $state.raw<string[]>([]);
  udp = $state.raw<string[]>([]);
  pages = $state.raw<PhonePage[]>([]);
  error = $state<string | null>(null);

  readonly #worker = new EmuWorker();
  readonly #listeners = new Set<(sounds: Sound[]) => void>();

  constructor() {
    this.#worker.onmessage = ({ data }: MessageEvent<Reply>) => {
      if (data.type === "error") this.error = data.message;
      else this.#take(data.snapshot);
    };
  }

  #take(s: Snapshot) {
    if (s.console) {
      const parts = (this.partial + s.console).split("\n");
      this.partial = parts.pop() ?? "";
      this.lines = keep(this.lines, parts, CONSOLE_LINES);
    }
    this.requests = keep(this.requests, s.server.requests, LOG_LINES);
    this.udp = keep(this.udp, s.server.udp, LOG_LINES);
    this.pages = keep(this.pages, s.pages, 50);
    if (s.sounds.length) this.#listeners.forEach((l) => l(s.sounds));
    this.snapshot = s;
  }

  /** Be told of every sound the rabbit plays. */
  onSounds(listener: (sounds: Sound[]) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  send<K extends keyof Commands>(op: K, ...args: Parameters<Commands[K]>): void {
    this.error = null;
    const message = { op, args } as Request;
    const transfer = args.filter((a) => a instanceof Int16Array).map((a) => a.buffer as ArrayBuffer);
    this.#worker.postMessage(message, transfer);
  }

  clearConsole() {
    this.lines = [];
    this.partial = "";
  }

  clearServerLog() {
    this.requests = [];
    this.udp = [];
  }

  /** Forget the phone's pages, as when it joins anew. */
  clearPages() {
    this.pages = [];
  }
}
