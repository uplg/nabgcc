// What the codec plays, through Web Audio.

import type { Sound } from "../emu/nabemu";

/** Sound scheduled further ahead than this is dropped: the rabbit runs faster than real time. */
const MAX_AHEAD_S = 2;
/** MP3 is handed to the browser about a second at a time, cut where a frame starts. */
const MP3_CHUNK = 16 * 1024;

/** The codec attenuates in half-decibel steps; the amplifier gates it all. */
export function loudness(amplifier: boolean, attenuation: number): number {
  return amplifier ? Math.pow(10, -attenuation / 40) : 0;
}

export class Speaker {
  readonly #audio: AudioContext;
  readonly #gain: GainNode;
  #playAt = 0;
  #mp3 = { track: -1, bytes: [] as number[] };

  constructor(audio: AudioContext) {
    this.#audio = audio;
    this.#gain = audio.createGain();
    this.#gain.connect(audio.destination);
  }

  set gain(value: number) {
    this.#gain.gain.setTargetAtTime(value, this.#audio.currentTime, 0.02);
  }

  async play(sounds: Sound[]) {
    for (const sound of sounds) {
      if (sound.kind === "pcm" && sound.samples.length > 0) {
        const buffer = this.#audio.createBuffer(1, sound.samples.length, sound.rate);
        const out = buffer.getChannelData(0);
        sound.samples.forEach((s, i) => (out[i] = s / 32768));
        this.#schedule(buffer);
      } else if (sound.kind === "mp3") {
        await this.#mp3Piece(sound.track, sound.bytes);
      }
    }
  }

  async #mp3Piece(track: number, bytes: Uint8Array) {
    if (track !== this.#mp3.track) this.#mp3 = { track, bytes: [] };
    const all = this.#mp3.bytes;
    all.push(...bytes);
    if (all.length < MP3_CHUNK) return;
    let cut = all.length - 4;
    while (cut > 0 && !(all[cut] === 0xff && (all[cut + 1] & 0xe0) === 0xe0)) cut--;
    if (cut === 0) return;
    const chunk = new Uint8Array(all.splice(0, cut));
    try {
      this.#schedule(await this.#audio.decodeAudioData(chunk.buffer));
    } catch {
      // Not decodable on its own: lost, as a glitch would be.
    }
  }

  #schedule(buffer: AudioBuffer) {
    const now = this.#audio.currentTime;
    this.#playAt = Math.max(this.#playAt, now + 0.05);
    if (this.#playAt - now > MAX_AHEAD_S) return;
    const source = this.#audio.createBufferSource();
    source.buffer = buffer;
    source.connect(this.#gain);
    source.start(this.#playAt);
    this.#playAt += buffer.duration;
  }

  close() {
    this.#gain.disconnect();
  }
}
