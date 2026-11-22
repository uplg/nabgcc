import { Rabbit } from "./nabemu.mjs";

const $ = (id) => document.getElementById(id);
const DEFAULT_FIRMWARE = "../../../artifacts/Nab-wpa23-gtk-r3.sim";
/** Board milliseconds run per animation frame at most, to keep the page alive. */
const MAX_STEP = 60;

const wasm = await (await fetch("nabemu.wasm")).arrayBuffer();
let rabbit = null;
let bytecode = null;
let lastFrame = performance.now();
let pendingLine = "";
let boardMs = 0, wallMs = 0;

async function start(firmware, name) {
  rabbit = await Rabbit.load(wasm, firmware);
  if (bytecode) rabbit.bytecode(bytecode);
  rabbit.volume(Number($("volume").value));
  rabbit.network(Number($("network").value));
  $("firmware-name").textContent = name;
  $("console").textContent = "";
  pendingLine = "";
  // ?warp=20000 runs that much board time at once before the first frame.
  const warp = Number(new URLSearchParams(location.search).get("warp"));
  if (warp > 0) rabbit.run(warp);
}

// ---- sound -----------------------------------------------------------

let audio = null;       // AudioContext, created on the first user gesture
let playAt = 0;         // when the next piece of sound starts
let mp3 = { track: -1, bytes: [] };

function loudness(state) {
  // The codec attenuates in half-decibel steps; the amplifier gates it all.
  return state.amplifier ? Math.pow(10, -state.attenuation / 40) : 0;
}

function schedule(buffer, gain) {
  const source = audio.createBufferSource();
  const volume = audio.createGain();
  volume.gain.value = gain;
  source.buffer = buffer;
  source.connect(volume).connect(audio.destination);
  playAt = Math.max(playAt, audio.currentTime + 0.05);
  source.start(playAt);
  playAt += buffer.duration;
}

async function play(pieces, state) {
  if (!audio || !$("speaker").checked) return;
  const gain = loudness(state);
  for (const piece of pieces) {
    if (piece.kind === "pcm" && piece.samples.length) {
      const buffer = audio.createBuffer(1, piece.samples.length, piece.rate);
      const out = buffer.getChannelData(0);
      for (let i = 0; i < out.length; i++) out[i] = piece.samples[i] / 32768;
      schedule(buffer, gain);
    } else if (piece.kind === "mp3") {
      if (piece.track !== mp3.track) mp3 = { track: piece.track, bytes: [] };
      mp3.bytes.push(...piece.bytes);
      // Decode about a second at a time, cut where a frame starts.
      if (mp3.bytes.length < 16384) continue;
      let cut = mp3.bytes.length - 4;
      while (cut > 0 && !(mp3.bytes[cut] === 0xff && (mp3.bytes[cut + 1] & 0xe0) === 0xe0)) cut--;
      if (cut === 0) continue;
      const chunk = new Uint8Array(mp3.bytes.splice(0, cut));
      try { schedule(await audio.decodeAudioData(chunk.buffer), gain); } catch { /* not decodable: skip */ }
    }
  }
}

async function listen(on) {
  if (!on) { listen.stop?.(); return; }
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const source = audio.createMediaStreamSource(stream);
  const tap = audio.createScriptProcessor(2048, 1, 1);
  let phase = 0;
  tap.onaudioprocess = (e) => {
    // Down to the 8000 Hz the rabbit records at, by picking samples.
    const input = e.inputBuffer.getChannelData(0);
    const step = audio.sampleRate / 8000;
    const out = [];
    for (; phase < input.length; phase += step) out.push(Math.max(-1, Math.min(1, input[Math.floor(phase)])) * 32767);
    phase -= input.length;
    rabbit?.microphone(Int16Array.from(out));
  };
  source.connect(tap).connect(audio.destination);
  listen.stop = () => { tap.disconnect(); source.disconnect(); stream.getTracks().forEach((t) => t.stop()); };
}

function show(text) {
  if (!text) return;
  const lines = (pendingLine + text).split("\n");
  pendingLine = lines.pop();
  const dumps = $("dumps").checked;
  const kept = lines.filter((l) => dumps || !/^[0-9a-f]{4,8} /.test(l));
  if (kept.length === 0) return;
  const out = $("console");
  const atEnd = out.scrollTop + out.clientHeight >= out.scrollHeight - 8;
  out.textContent = (out.textContent + kept.join("\n") + "\n").slice(-60000);
  if (atEnd) out.scrollTop = out.scrollHeight;
}

function paint(state) {
  state.leds.forEach(([r, g, b], i) => {
    const lit = r + g + b > 0;
    // The driver's 7-bit current setting, shown a little brighter than linear.
    const c = (v) => Math.round(255 * Math.sqrt(v / 127));
    $(`led-${i}`).style.fill = lit ? `rgb(${c(r)},${c(g)},${c(b)})` : "var(--off)";
  });
  // Twenty slots to a turn; the ears lean back as they turn.
  $("ear-left").style.transform = `rotate(${-state.ears[0] * 18}deg)`;
  $("ear-right").style.transform = `rotate(${state.ears[1] * 18}deg)`;
  $("time").textContent = (state.ms / 1000).toFixed(1) + " s";
  const where = state.channel ? `, rabbit on channel ${state.channel}` : "";
  $("link").textContent = state.link === "none" ? "no network in range" : `network ${state.link}${where}`;
  $("resets").textContent = state.resets;
  $("audio").textContent = state.amplifier ? `playing (${state.audioBytes} bytes so far)` : "silent";
}

function frame(now) {
  const elapsed = Math.min(now - lastFrame, 250);
  lastFrame = now;
  if (rabbit) {
    const step = Math.min(Math.round(elapsed), MAX_STEP);
    const before = performance.now();
    rabbit.run(step);
    wallMs = wallMs * 0.95 + (performance.now() - before);
    boardMs = boardMs * 0.95 + step;
    show(rabbit.console());
    const state = rabbit.state();
    play(rabbit.audio(), state);
    paint(state);
    const headroom = wallMs > 0 ? ` (could do ${(boardMs / wallMs).toFixed(1)}x)` : "";
    $("speed").textContent = step < elapsed - 1 ? "slower than a real rabbit" : "real time" + headroom;
  }
  requestAnimationFrame(frame);
}

$("firmware").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (file) await start(new Uint8Array(await file.arrayBuffer()), file.name);
});
$("bytecode").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  bytecode = new Uint8Array(await file.arrayBuffer());
  if (rabbit) { rabbit.bytecode(bytecode); rabbit.powerCycle(); }
});
$("network").addEventListener("change", (e) => rabbit?.network(Number(e.target.value)));
$("volume").addEventListener("input", (e) => rabbit?.volume(Number(e.target.value)));
$("power").addEventListener("click", () => rabbit?.powerCycle());
// Browsers only let a page make or record sound after a click.
$("speaker").addEventListener("change", () => { audio ??= new AudioContext(); audio.resume(); });
$("mic").addEventListener("change", async (e) => {
  audio ??= new AudioContext();
  try { await listen(e.target.checked); } catch { e.target.checked = false; }
});
const TAG = new Uint8Array([0xd0, 0x02, 0x1a, 0x03, 0x52, 0xc4, 0x66, 0x7f]);
$("tag").addEventListener("change", (e) => rabbit?.tag(e.target.checked ? TAG : null));
const head = $("head");
head.addEventListener("pointerdown", (e) => { head.setPointerCapture(e.pointerId); rabbit?.button(true); });
for (const up of ["pointerup", "pointercancel"]) head.addEventListener(up, () => rabbit?.button(false));

try {
  const response = await fetch(DEFAULT_FIRMWARE);
  if (!response.ok) throw new Error(response.statusText);
  await start(new Uint8Array(await response.arrayBuffer()), "Nab-wpa23-gtk-r3.sim (the released image)");
} catch {
  $("firmware-name").textContent = "Choose a firmware file to start.";
}
requestAnimationFrame(frame);
