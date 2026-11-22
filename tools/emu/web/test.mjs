// Runs the browser build under Node: the same module, the same wrapper.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { Rabbit } from "./nabemu.mjs";

const here = new URL(".", import.meta.url);
const wasm = readFileSync(new URL("nabemu.wasm", here));
const firmware = readFileSync(new URL("../../../artifacts/Nab-wpa23-gtk-r3.sim", here));

const rabbit = await Rabbit.load(wasm, firmware);
rabbit.network(2);

const started = performance.now();
let text = "";
rabbit.run(3000);
text += rabbit.console();
assert.deepEqual(rabbit.state().leds, Array(5).fill([126, 16, 0]), "amber while it looks for its network");
assert.equal(rabbit.state().link, "in range");

while (rabbit.state().link !== "joined") {
  assert.ok(rabbit.state().ms < 30000, "joined within 30 s:\n" + text);
  rabbit.run(100);
  text += rabbit.console();
}
rabbit.run(5000);
text += rabbit.console();
const wall = performance.now() - started;
const state = rabbit.state();

assert.match(text, /:started/);
assert.match(text, /-------------dhcp/);
assert.equal(state.resets, 0);
assert.equal(state.channel, 6);

// Setup mode: button held at power-on, released, everything blue.
rabbit.network(0);
rabbit.button(true);
rabbit.run(2000);
rabbit.button(false);
rabbit.run(8000);
assert.deepEqual(rabbit.state().leds, Array(5).fill([0, 0, 126]));
assert.match(rabbit.console(), /-------------master/);

// Factory test (button held past seven seconds), step 5: a tone.
rabbit.powerCycle();
rabbit.button(true);
rabbit.run(8000);
rabbit.button(false);
rabbit.run(500);
for (let i = 0; i < 4; i++) { rabbit.button(true); rabbit.run(200); rabbit.button(false); rabbit.run(300); }
rabbit.run(5000);
const sound = rabbit.audio();
assert.ok(sound.length > 0, "something was played");
assert.ok(sound.every((p) => p.kind === "pcm" && p.rate === 8000));
const samples = sound.flatMap((p) => Array.from(p.samples));
assert.ok(samples.length > 16000, `${samples.length} samples of tone`);
assert.ok(Math.max(...samples) > 1000 && Math.min(...samples) < -1000, "a tone, not silence");
assert.ok(rabbit.state().amplifier);
assert.deepEqual(rabbit.audio(), [], "nothing is handed over twice");

// Step 4, reached by going round: a tag at the nose turns it green.
rabbit.tag(new Uint8Array([0xd0, 0x02, 0x1a, 0x03, 0x52, 0xc4, 0x66, 0x7f]));

console.log(`ok: joined WPA2 at ${state.ms} ms of board time, ${(state.ms / wall).toFixed(1)}x real time under Node`);
