// What the page and the worker that runs the rabbit say to each other.

import type { AccessPoint, AccessPointSpec, PhonePage, Sample, ServerNews, Settings, Sound, Status } from "./nabemu";

/** Times real time, or as fast as the machine goes. */
export type Speed = number | "max";

/** What the server hands out, as the page describes it. */
export type Serving =
  | { kind: "nothing" }
  | { kind: "file"; name: string; bytes: Uint8Array }
  | { kind: "sample"; sample: Sample; arg: number };

export interface Snapshot {
  firmware: string;
  running: boolean;
  speed: Speed;
  /** Board time per wall time and instructions per wall second, over the last second. */
  pace: { ratio: number; ips: number };
  /** The rabbit is held behind real time: the machine cannot keep up. */
  behind: boolean;
  /** Board time at which a scripted button press ends. */
  holdUntil: number | null;
  serving: Serving;
  status: Status;
  accessPoints: AccessPoint[];
  settings: Settings | null;
  /** Since the last snapshot. */
  console: string;
  server: ServerNews;
  pages: PhonePage[];
  sounds: Sound[];
}

/** Everything the page can ask of the worker. */
export interface Commands {
  /** A new rabbit with this firmware file and these settings in its flash. */
  boot(firmware: Uint8Array, name: string, settings: Settings | null): void;
  /** A rabbit fresh from the factory with the same firmware, the world around it kept. */
  reset(keepSettings: boolean): void;
  setRunning(running: boolean): void;
  setSpeed(speed: Speed): void;
  /** Run this much board time while paused. */
  step(ms: number): void;
  powerCycle(): void;
  /** Press the button for `ms` of board time, after a power cycle if asked. */
  hold(ms: number, fromPowerOn: boolean): void;
  button(down: boolean): void;
  volume(value: number): void;
  turnEar(ear: 0 | 1, slots: number): void;
  /** Hexadecimal identifier, 16 digits, or null to take the tag away. */
  tag(uid: string | null): void;
  microphone(samples: Int16Array): void;
  addAccessPoint(ap: AccessPointSpec): void;
  removeAccessPoint(n: number): void;
  restartAccessPoint(n: number): void;
  signal(n: number, dbm: number): void;
  writeSettings(settings: Settings): void;
  eraseSettings(): void;
  serve(serving: Serving): void;
  /**
   * Restart, and flash this firmware file (null: the one running) over the
   * air at the first request, cutting the power after `cutAfter` flash
   * operations if given.
   */
  update(firmware: Uint8Array | null, cutAfter: number | null): void;
  phoneJoin(prefix: string): void;
  phoneLeave(): void;
  phoneFetch(target: string, body?: Uint8Array): void;
}

export type Request = { [K in keyof Commands]: { op: K; args: Parameters<Commands[K]> } }[keyof Commands];

export type Reply = { type: "snapshot"; snapshot: Snapshot } | { type: "error"; message: string };
