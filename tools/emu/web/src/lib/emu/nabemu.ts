// The emulator's WebAssembly module (tools/emu/src/web.rs), typed.
// Shared by the worker that runs the rabbit and by the tests.

/** How a network is protected, in the order the module numbers them. */
export const SECURITIES = ["open", "WEP", "WEP, shared key", "WPA", "WPA2", "WPA2/WPA3", "WPA3"] as const;
export type Security = (typeof SECURITIES)[number];
/** What the rabbit's settings can say: a WPA3 network is "WPA2" to them. */
export const SETTINGS_SECURITIES = SECURITIES.slice(0, 5) as readonly Security[];

export type Rgb = [number, number, number];

export interface Ear {
  /** Where the wheel is: twenty slots to a turn. */
  slot: number;
  /** -1 backwards, 0 stopped, 1 forwards. */
  direction: number;
  pulses: number;
}

export interface Phone {
  looksFor: string;
  link: "searching" | "authenticating" | "associating" | "associated";
  network: string | null;
  address: string | null;
  pending: number;
}

export interface Status {
  ms: number;
  instructions: number;
  skippedMs: number;
  resets: number;
  lastReset: "watchdog" | "power loss" | null;
  undefined: number;
  /** Nose, left, middle, right, bottom; each colour 0..127. */
  leds: Rgb[];
  ears: [Ear, Ear];
  button: boolean;
  volume: number;
  amplifier: boolean;
  /** Half decibels below full volume. */
  attenuation: number;
  audioBytes: number;
  tag: string | null;
  channel: number;
  /** The Wi-Fi stick took its firmware. */
  stick: boolean;
  /** Number of the access point the rabbit is joined to. */
  joined: number | null;
  lease: string | null;
  watchdog: { unfedMs: number; longestMs: number };
  flash: { erases: number; programs: number; cutArmed: boolean };
  server: { requests: number; serving: number; update: boolean };
  phone: Phone | null;
}

export interface AccessPointSpec {
  ssid: string;
  security: Security;
  /** Passphrase, or WEP key of 5 or 13 characters. */
  key: string;
  channel: number;
  dbm: number;
  hidden: boolean;
}

export interface AccessPoint {
  ssid: string;
  channel: number;
  security: Security;
  hidden: boolean;
  dbm: number;
  joined: boolean;
  events: string[];
}

export interface Settings {
  ssid: string;
  security: Security;
  key: string;
  /** Host and path the bytecode is fetched from, without http://. */
  server: string;
}

export interface ServerNews {
  requests: string[];
  udp: string[];
}

export interface PhonePage {
  request: string;
  response: string;
}

export type Sound =
  | { kind: "pcm"; rate: number; track: number; samples: Int16Array }
  | { kind: "mp3"; rate: number; track: number; bytes: Uint8Array };

/** The sample programs the server can hand out. */
export const SAMPLES = { prints: 0, restarts: 1 } as const;
export type Sample = keyof typeof SAMPLES;

type Exports = { memory: WebAssembly.Memory } & Record<`nab_${string}`, (...args: number[]) => number>;

const encoder = new TextEncoder();
const text = new TextDecoder();

export class Nabemu {
  readonly #x: Exports;
  readonly #world: number;
  readonly #console = new TextDecoder("utf-8", { fatal: false });

  private constructor(x: Exports, firmware: Uint8Array) {
    this.#x = x;
    this.#world = this.#with([firmware], (ptr, len) => x.nab_new(ptr, len));
  }

  /** A rabbit flashed with a firmware file (ELF, .sim or raw image). */
  static async load(wasm: BufferSource | WebAssembly.Module, firmware: Uint8Array): Promise<Nabemu> {
    const module = wasm instanceof WebAssembly.Module ? wasm : await WebAssembly.compile(wasm);
    const instance = await WebAssembly.instantiate(module, {});
    return new Nabemu(instance.exports as unknown as Exports, firmware);
  }

  free(): void {
    this.#x.nab_drop(this.#world);
  }

  /** Copy each argument into the module, call, free: pointers and lengths in order. */
  #with<T>(args: (Uint8Array | string)[], use: (...ptrLen: number[]) => T): T {
    const blocks = args.map((a) => (typeof a === "string" ? encoder.encode(a) : a));
    const ptrs = blocks.map((b) => {
      const ptr = this.#x.nab_alloc(b.length);
      new Uint8Array(this.#x.memory.buffer, ptr, b.length).set(b);
      return ptr;
    });
    try {
      return use(...blocks.flatMap((b, i) => [ptrs[i], b.length]));
    } finally {
      blocks.forEach((b, i) => this.#x.nab_free(ptrs[i], b.length));
    }
  }

  #call(name: string, ...args: number[]): number {
    return this.#x[`nab_${name}`](this.#world, ...args);
  }

  /** What a call handed back, copied out of the module. */
  #out(len: number): Uint8Array {
    return new Uint8Array(this.#x.memory.buffer, this.#x.nab_out(this.#world), len).slice();
  }

  #json<T>(name: string): T {
    return JSON.parse(text.decode(this.#out(this.#call(name)))) as T;
  }

  run(ms: number): void {
    this.#call("run", ms);
  }
  powerCycle(): void {
    this.#call("power_cycle");
  }
  button(down: boolean): void {
    this.#call("button", down ? 1 : 0);
  }
  /** The volume wheel, 0..255. */
  volume(value: number): void {
    this.#call("volume", value);
  }
  /** Turn an ear (0 left, 1 right) by hand, by slots of twenty to a turn. */
  turnEar(ear: 0 | 1, slots: number): void {
    this.#call("ear", ear, slots);
  }
  /** Hold a tag with this 8-byte identifier at the nose, or take it away. */
  tag(uid: Uint8Array | null): void {
    this.#with([uid ?? new Uint8Array()], (ptr, len) => this.#call("tag", ptr, len));
  }
  /** What the microphone hears, at 8000 Hz. */
  microphone(samples: Int16Array): void {
    const bytes = new Uint8Array(samples.buffer, samples.byteOffset, samples.byteLength);
    this.#with([bytes], (ptr, len) => this.#call("microphone", ptr, len));
  }

  /** Text printed by the firmware since the last call. */
  console(): string {
    const len = this.#call("console");
    return len === 0 ? "" : this.#console.decode(this.#out(len), { stream: true });
  }

  status(): Status {
    return this.#json("status");
  }

  /** Sound played since the last call, in order. */
  sounds(): Sound[] {
    const sounds: Sound[] = [];
    for (let len; (len = this.#call("audio")) > 0; ) {
      const piece = this.#out(len);
      const view = new DataView(piece.buffer);
      const rate = view.getUint32(4, true);
      const track = view.getUint32(8, true);
      const body = piece.slice(12);
      if (piece[0] === 1) sounds.push({ kind: "pcm", rate, track, samples: new Int16Array(body.buffer) });
      else if (piece[0] === 2) sounds.push({ kind: "mp3", rate, track, bytes: body });
    }
    return sounds;
  }

  addAccessPoint(ap: AccessPointSpec): number {
    return this.#with([ap.ssid, ap.key], (...p) =>
      this.#call("ap_add", ...p, SECURITIES.indexOf(ap.security), ap.channel, ap.dbm, ap.hidden ? 1 : 0),
    );
  }
  removeAccessPoint(n: number): void {
    this.#call("ap_remove", n);
  }
  restartAccessPoint(n: number): void {
    this.#call("ap_restart", n);
  }
  signal(n: number, dbm: number): void {
    this.#call("ap_signal", n, dbm);
  }
  accessPoints(): AccessPoint[] {
    return this.#json("aps");
  }

  settings(): Settings | null {
    const s = this.#json<(Omit<Settings, "security"> & { security: number }) | null>("settings");
    return s && { ...s, security: SECURITIES[s.security] };
  }
  writeSettings(s: Settings): void {
    this.#with([s.ssid, s.key], (...p) =>
      this.#with([s.server], (server, len) =>
        this.#call("settings_write", ...p, SECURITIES.indexOf(s.security), server, len),
      ),
    );
  }
  eraseSettings(): void {
    this.#call("settings_erase");
  }

  /** What the server answers to bc.jsp: a bytecode (wrapped if it needs to be), or nothing. */
  serve(bytecode: Uint8Array): void {
    this.#with([bytecode], (ptr, len) => this.#call("serve", ptr, len));
  }
  serveSample(sample: Sample, arg = 0): void {
    this.#call("serve_sample", SAMPLES[sample], arg);
  }
  /** The next bc.jsp flashes this firmware file over the running one. */
  serveUpdate(firmware: Uint8Array): void {
    this.#with([firmware], (ptr, len) => this.#call("serve_update", ptr, len));
  }
  server(): ServerNews {
    return this.#json("server");
  }

  /** A phone joins the first network whose name starts with `prefix`. */
  phoneJoin(prefix: string): void {
    this.#with([prefix], (ptr, len) => this.#call("phone_join", ptr, len));
  }
  phoneLeave(): void {
    this.#call("phone_leave");
  }
  /** A GET, or a POST when there is a body. */
  phoneFetch(target: string, body: Uint8Array = new Uint8Array()): void {
    this.#with([target, body], (...p) => this.#call("phone_fetch", ...p));
  }
  phonePages(): PhonePage[] {
    return this.#json("phone_pages");
  }

  /** Cut the power after that many more flash erases and word programs. */
  cutPowerAfter(ops: number): void {
    this.#call("cut_power_after", ops);
  }
}
