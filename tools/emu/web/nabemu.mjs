// Thin wrapper around nabemu.wasm, shared by the page and the test.

export class Rabbit {
  /** @param {WebAssembly.Instance} instance @param {Uint8Array} firmware */
  constructor(instance, firmware) {
    this.x = instance.exports;
    this.world = this.#withBytes(firmware, (ptr, len) => this.x.nab_new(ptr, len));
    this.decoder = new TextDecoder("utf-8", { fatal: false });
  }

  static async load(wasmBytes, firmware) {
    const { instance } = await WebAssembly.instantiate(wasmBytes, {});
    return new Rabbit(instance, firmware);
  }

  #withBytes(bytes, use) {
    const ptr = this.x.nab_alloc(bytes.length);
    new Uint8Array(this.x.memory.buffer, ptr, bytes.length).set(bytes);
    const result = use(ptr, bytes.length);
    this.x.nab_free(ptr, bytes.length);
    return result;
  }

  /** 0 none, 1 open, 2 WPA2, 3 WPA, 4 WEP, 5 WPA2/WPA3 transition. Restarts the rabbit. */
  network(kind) { this.x.nab_network(this.world, kind); }
  /** What the server will answer to bc.jsp. */
  bytecode(bytes) { this.#withBytes(bytes, (ptr, len) => this.x.nab_bytecode(this.world, ptr, len)); }
  run(ms) { this.x.nab_run(this.world, ms); }
  button(down) { this.x.nab_button(this.world, down ? 1 : 0); }
  volume(v) { this.x.nab_volume(this.world, v); }
  powerCycle() { this.x.nab_power_cycle(this.world); }

  /** Hold a tag with this 8-byte identifier at the nose, or null to take it away. */
  tag(uid) {
    if (uid) this.#withBytes(uid, (ptr, len) => this.x.nab_tag(this.world, ptr, len));
    else this.x.nab_tag(this.world, 0, 0);
  }
  /** What the microphone hears: an Int16Array at 8000 Hz. */
  microphone(samples) {
    const bytes = new Uint8Array(samples.buffer, samples.byteOffset, samples.byteLength);
    this.#withBytes(bytes, (ptr, len) => this.x.nab_microphone(this.world, ptr, len));
  }

  /**
   * Sound played since the last call, as pieces in order:
   * { kind: "pcm" | "mp3" | "other", rate, track, samples | bytes }.
   */
  audio() {
    const pieces = [];
    for (;;) {
      const len = this.x.nab_audio(this.world);
      if (len === 0) return pieces;
      const all = new Uint8Array(this.x.memory.buffer, this.x.nab_audio_ptr(this.world), len).slice();
      const view = new DataView(all.buffer);
      const piece = { kind: ["", "pcm", "mp3", "other"][all[0]], rate: view.getUint32(4, true), track: view.getUint32(8, true) };
      const body = all.subarray(12);
      if (piece.kind === "pcm") piece.samples = new Int16Array(body.buffer.slice(12));
      else piece.bytes = body;
      pieces.push(piece);
    }
  }

  /** Text printed by the firmware since the last call. */
  console() {
    const len = this.x.nab_console(this.world);
    if (len === 0) return "";
    const ptr = this.x.nab_console_ptr(this.world);
    return this.decoder.decode(new Uint8Array(this.x.memory.buffer, ptr, len).slice());
  }

  state() {
    const s = new Uint8Array(this.x.memory.buffer, this.x.nab_state(this.world), 32).slice();
    const view = new DataView(s.buffer);
    const leds = [];
    for (let i = 0; i < 5; i++) leds.push([s[i * 3], s[i * 3 + 1], s[i * 3 + 2]]);
    return {
      leds,                       // [nose, left, middle, right, bottom], each [r, g, b] 0..127
      ears: [s[15], s[16]],       // slots, 0..19
      earsMoving: [s[17] !== 0, s[18] !== 0],
      link: ["none", "in range", "joined"][s[19]],
      resets: s[20],
      channel: s[21],
      amplifier: s[22] !== 0,
      attenuation: s[23],      // half decibels below full volume
      ms: view.getUint32(24, true),
      audioBytes: view.getUint32(28, true),
    };
  }
}
