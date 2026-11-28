// Runs the rabbit away from the page, so that the page stays smooth:
// takes commands, runs board time at the chosen pace, and sends a
// snapshot of everything about thirty times a second.

import wasmUrl from "./nabemu.wasm?url";
import { Nabemu, type AccessPointSpec, type Settings, type Sound } from "./nabemu";
import type { Commands, Reply, Request, Serving, Snapshot, Speed } from "./protocol";

/** Board time run in one go, at most: the finest a scripted press can be timed. */
const SLICE_MS = 10;
/** Wall time spent running between two looks at the mailbox. */
const BUDGET_MS = 24;
const SNAPSHOT_MS = 33;

const module = WebAssembly.compileStreaming(fetch(wasmUrl));

let rabbit: Nabemu | null = null;
let firmware: { bytes: Uint8Array; name: string } = { bytes: new Uint8Array(), name: "" };
let running = false;
let speed: Speed = 1;
let behind = false;
let holdUntil: number | null = null;
/** The world around the rabbit, to put back after a reset. */
let accessPoints: AccessPointSpec[] = [];
let serving: Serving = { kind: "nothing" };

let consoleText = "";
let sounds: Sound[] = [];
const server = { requests: [] as string[], udp: [] as string[] };
let pages: Snapshot["pages"] = [];

let owedMs = 0;
let lastTick = performance.now();
let lastSnapshot = 0;
const pace = { wall: performance.now(), ms: 0, instructions: 0, ratio: 0, ips: 0 };

function reply(message: Reply) {
  postMessage(message);
}

function the(): Nabemu {
  if (!rabbit) throw new Error("no firmware loaded yet");
  return rabbit;
}

function serve(r: Nabemu, s: Serving) {
  if (s.kind === "file") r.serve(s.bytes);
  else if (s.kind === "sample") r.serveSample(s.sample, s.arg);
  else r.serve(new Uint8Array());
}

/** A rabbit with this firmware in the world as it is. */
async function make(settings: Settings | null) {
  rabbit?.free();
  rabbit = null;
  const r = await Nabemu.load(await module, firmware.bytes);
  accessPoints.forEach((ap) => r.addAccessPoint(ap));
  if (settings) r.writeSettings(settings);
  serve(r, serving);
  rabbit = r;
  holdUntil = null;
  pages = [];
  pace.ms = 0;
  pace.instructions = 0;
}

function release() {
  if (holdUntil === null) return;
  the().button(false);
  holdUntil = null;
}

/** Run up to `ms` of board time in slices, ending a scripted press on time. */
function advance(ms: number) {
  const r = the();
  let left = ms;
  while (left > 0) {
    let slice = Math.min(left, SLICE_MS);
    if (holdUntil !== null) slice = Math.max(1, Math.min(slice, holdUntil - r.status().ms));
    r.run(slice);
    left -= slice;
    if (holdUntil !== null && r.status().ms >= holdUntil) release();
  }
  collect(r);
}

function collect(r: Nabemu) {
  consoleText += r.console();
  sounds.push(...r.sounds());
  const news = r.server();
  server.requests.push(...news.requests);
  server.udp.push(...news.udp);
  pages.push(...r.phonePages());
}

function tick() {
  const now = performance.now();
  const wall = now - lastTick;
  lastTick = now;
  try {
    if (running && rabbit) runFor(now, wall);
    if (now - lastSnapshot >= SNAPSHOT_MS) snapshot(now);
  } catch (e) {
    running = false;
    reply({ type: "error", message: e instanceof Error ? e.message : String(e) });
  }
  setTimeout(tick, running ? 0 : 16);
}

function runFor(start: number, wall: number) {
  const over = () => performance.now() - start >= BUDGET_MS;
  if (speed === "max") {
    behind = false;
    while (!over()) advance(SLICE_MS);
    return;
  }
  // Owe board time for the wall time that passed; never more than a
  // quarter of a second, so that a slow machine does not spiral.
  owedMs = Math.min(owedMs + wall * speed, 250 * speed);
  while (owedMs >= 1 && !over()) {
    const ms = Math.min(Math.floor(owedMs), SLICE_MS);
    advance(ms);
    owedMs -= ms;
  }
  behind = owedMs >= SLICE_MS * 4;
}

function snapshot(now: number) {
  lastSnapshot = now;
  if (!rabbit) return;
  const status = rabbit.status();
  if (now - pace.wall >= 1000) {
    const seconds = (now - pace.wall) / 1000;
    pace.ratio = (status.ms - pace.ms) / 1000 / seconds;
    pace.ips = (status.instructions - pace.instructions) / seconds;
    Object.assign(pace, { wall: now, ms: status.ms, instructions: status.instructions });
  }
  const s: Snapshot = {
    firmware: firmware.name,
    running,
    speed,
    pace: { ratio: running ? pace.ratio : 0, ips: running ? pace.ips : 0 },
    behind: running && behind,
    holdUntil,
    serving,
    status,
    accessPoints: rabbit.accessPoints(),
    settings: rabbit.settings(),
    console: consoleText,
    server: { requests: server.requests.splice(0), udp: server.udp.splice(0) },
    pages: pages.splice(0),
    sounds,
  };
  consoleText = "";
  sounds = [];
  const buffers = s.sounds.map((p) => (p.kind === "pcm" ? p.samples.buffer : p.bytes.buffer)) as ArrayBuffer[];
  postMessage({ type: "snapshot", snapshot: s } satisfies Reply, { transfer: buffers });
}

function hex(uid: string): Uint8Array {
  return Uint8Array.from(uid.match(/../g) ?? [], (b) => parseInt(b, 16));
}

const commands: Commands = {
  async boot(bytes, name, settings) {
    firmware = { bytes, name };
    await make(settings);
  },
  async reset(keepSettings) {
    await make(keepSettings ? the().settings() : null);
  },
  setRunning(on) {
    running = on;
    owedMs = 0;
  },
  setSpeed(s) {
    speed = s;
    owedMs = 0;
  },
  step(ms) {
    advance(ms);
  },
  powerCycle() {
    release();
    the().powerCycle();
  },
  hold(ms, fromPowerOn) {
    const r = the();
    if (fromPowerOn) r.powerCycle();
    r.button(true);
    holdUntil = r.status().ms + ms;
  },
  button(down) {
    holdUntil = null;
    the().button(down);
  },
  volume: (v) => the().volume(v),
  turnEar: (ear, slots) => the().turnEar(ear, slots),
  tag: (uid) => the().tag(uid ? hex(uid) : null),
  microphone: (samples) => rabbit?.microphone(samples),
  // The world exists before any rabbit: what is set up here waits for it.
  addAccessPoint(ap) {
    accessPoints.push(ap);
    rabbit?.addAccessPoint(ap);
  },
  removeAccessPoint(n) {
    accessPoints.splice(n, 1);
    the().removeAccessPoint(n);
  },
  restartAccessPoint: (n) => the().restartAccessPoint(n),
  signal(n, dbm) {
    accessPoints[n].dbm = dbm;
    the().signal(n, dbm);
  },
  writeSettings: (s) => the().writeSettings(s),
  eraseSettings: () => the().eraseSettings(),
  serve(s) {
    serving = s;
    if (rabbit) serve(rabbit, s);
  },
  update(bytes, cutAfter) {
    // From a fresh start, so that the request comes at once.
    const r = the();
    release();
    r.powerCycle();
    r.serveUpdate(bytes ?? firmware.bytes);
    if (cutAfter !== null) r.cutPowerAfter(cutAfter);
  },
  phoneJoin(prefix) {
    pages = [];
    the().phoneJoin(prefix);
  },
  phoneLeave: () => the().phoneLeave(),
  phoneFetch: (target, body) => the().phoneFetch(target, body),
};

// One command at a time, in order, even when one waits.
let queue = Promise.resolve();
onmessage = ({ data }: MessageEvent<Request>) => {
  queue = queue.then(async () => {
    try {
      await (commands[data.op] as (...args: unknown[]) => unknown)(...data.args);
      lastSnapshot = 0;
    } catch (e) {
      reply({ type: "error", message: e instanceof Error ? e.message : String(e) });
    }
  });
};

tick();
