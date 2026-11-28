// The WebAssembly build, headless, under bun: the module the page runs,
// through the same wrapper. web/build.sh puts the module and the
// firmwares in place; lapin's tests are skipped when it is not built.

import { describe, expect, test } from "bun:test";
import { Nabemu, type Security, type Status } from "../src/lib/emu/nabemu";

const here = new URL("..", import.meta.url).pathname;
const wasm = await WebAssembly.compile(await Bun.file(`${here}src/lib/emu/nabemu.wasm`).arrayBuffer());
const r3 = await firmware("Nab-wpa23-gtk-r3.sim");
const lapin = await firmware("lapin-full.bin").catch(() => null);

async function firmware(name: string): Promise<Uint8Array> {
  return new Uint8Array(await Bun.file(`${here}public/firmware/${name}`).arrayBuffer());
}

const HOME = { ssid: "Terrier", key: "carotte-violette", channel: 6, dbm: -55, hidden: false };
const BLUE = Array(5).fill([0, 0, 126]);

/** A rabbit at home, set up for its network, its server printing 4242. */
async function atHome(image: Uint8Array, security: Security = "WPA2"): Promise<Nabemu> {
  const r = await Nabemu.load(wasm, image);
  r.addAccessPoint({ ...HOME, security });
  r.writeSettings({ ssid: HOME.ssid, security: "WPA2", key: HOME.key, server: "" });
  r.serveSample("prints", 4242);
  return r;
}

/** Run until `done`, for `limit` ms of board time at most; what was printed comes back. */
function until(r: Nabemu, limit: number, done: (s: Status, text: string) => boolean): string {
  let text = "";
  const end = r.status().ms + limit;
  for (let s = r.status(); !done(s, text); s = r.status()) {
    if (s.ms >= end) throw new Error(`not within ${limit} ms:\n${text.slice(-3000)}`);
    r.run(50);
    text += r.console();
  }
  return text;
}

/** The phone asks for a page and waits for the answer. */
function visit(r: Nabemu, target: string, body?: Uint8Array): string {
  r.phoneFetch(target, body);
  const pages: string[] = [];
  until(r, 60_000, () => pages.push(...r.phonePages().map((p) => p.response)) > 0);
  return pages[0];
}

/** Power on with the button held for `ms`. */
function holdingTheButton(r: Nabemu, ms: number) {
  r.powerCycle();
  r.button(true);
  r.run(ms);
  r.button(false);
}

describe("r3, the C firmware", () => {
  test("joins WPA2, takes an address and runs what the server hands out", async () => {
    const r = await atHome(r3);
    r.run(3000);
    expect(r.status().leds).toEqual(Array(5).fill([126, 16, 0]));
    const started = performance.now();
    const text = until(r, 30_000, (_, text) => text.includes("4242"));
    const s = r.status();
    expect(s.joined).toBe(0);
    expect(s.lease).toBe("192.168.1.100");
    expect(s.resets).toBe(0);
    expect(s.channel).toBe(6);
    expect(text).toMatch(/-------------dhcp/);
    expect(r.server().requests[0]).toMatch(/^GET \/vl\/bc\.jsp\?.* → 200/);
    expect(r.accessPoints()[0]).toMatchObject({ ssid: "Terrier", security: "WPA2", joined: true, dbm: -55 });
    console.log(`r3 joined at ${s.ms} ms of board time, ${(s.ms / (performance.now() - started)).toFixed(1)}x real time`);
  });

  test("set up from a phone on its own network", async () => {
    const r = await Nabemu.load(wasm, r3);
    r.addAccessPoint({ ...HOME, security: "WPA2" });
    expect(r.settings()).toBeNull();
    holdingTheButton(r, 2000);
    until(r, 10_000, (s) => s.leds.every((l, i) => l.join() === BLUE[i].join()));
    r.phoneJoin("Nabaztag");
    until(r, 30_000, (s) => s.phone?.address !== null);
    expect(r.status().phone).toMatchObject({ link: "associated", network: "Nabaztag01" });
    expect(visit(r, "/")).toContain("Save and start");
    // The form, as the page's Save button sends it.
    expect(visit(r, "/b.htm?w=-&k=Terrier&m=64&n=carotte-violette&z=1")).toMatch(/^HTTP\/1\.0 200/);
    r.phoneLeave();
    until(r, 120_000, (s) => s.joined === 0);
    expect(r.settings()).toMatchObject({ ssid: "Terrier", security: "WPA2", key: "carotte-violette" });
  });

  test("factory test: a tone from the loudspeaker, a tag, an ear turned by hand", async () => {
    const r = await Nabemu.load(wasm, r3);
    holdingTheButton(r, 8000);
    r.run(500);
    for (let i = 0; i < 4; i++) {
      r.button(true);
      r.run(200);
      r.button(false);
      r.run(300);
    }
    r.run(5000);
    const sounds = r.sounds();
    expect(sounds.length).toBeGreaterThan(0);
    const samples = sounds.flatMap((p) => (p.kind === "pcm" && p.rate === 8000 ? Array.from(p.samples) : []));
    expect(samples.length).toBeGreaterThan(16000);
    expect(Math.max(...samples)).toBeGreaterThan(1000);
    expect(Math.min(...samples)).toBeLessThan(-1000);
    expect(r.status().amplifier).toBe(true);
    expect(r.sounds()).toEqual([]);

    r.tag(Uint8Array.of(0xd0, 0x02, 0x1a, 0x03, 0x52, 0xc4, 0x66, 0x7f));
    expect(r.status().tag).toBe("d0021a0352c4667f");
    r.tag(null);
    expect(r.status().tag).toBeNull();

    const before = r.status().ears[1];
    r.turnEar(1, 3);
    expect(r.status().ears[1]).toMatchObject({ slot: (before.slot + 3) % 20, pulses: before.pulses + 3 });
  });

  test("the world around it changes under it", async () => {
    const r = await atHome(r3);
    r.addAccessPoint({ ssid: "Voisin", security: "WPA3", key: "pas-la-mienne", channel: 11, dbm: -80, hidden: true });
    r.signal(1, -40);
    expect(r.accessPoints().map((ap) => [ap.ssid, ap.security, ap.dbm, ap.hidden])).toEqual([
      ["Terrier", "WPA2", -55, false],
      ["Voisin", "WPA3", -40, true],
    ]);
    until(r, 30_000, (s) => s.joined === 0);
    r.restartAccessPoint(0);
    r.removeAccessPoint(1);
    expect(r.accessPoints()).toHaveLength(1);
    r.eraseSettings();
    expect(r.settings()).toBeNull();
    r.serve(new TextEncoder().encode("amber00000000Mind"));
    expect(r.status().server.serving).toBe(17);
  });
});

describe.skipIf(!lapin)("lapin, the Rust firmware", () => {
  test("joins a WPA3 network", async () => {
    const r = await atHome(lapin!, "WPA3");
    const text = until(r, 30_000, (_, text) => text.includes("4242"));
    expect(text).toContain("lapin");
    expect(r.status().joined).toBe(0);
  });

  test("a power cut during an update, put right from a phone on the rescue network", async () => {
    const r = await atHome(lapin!);
    r.run(500);
    r.powerCycle();
    r.serveUpdate(lapin!);
    r.cutPowerAfter(12_000);
    until(r, 60_000, (s) => s.lastReset === "power loss");
    until(r, 20_000, (_, text) => text.includes("secours: network up"));
    r.phoneJoin("Nabaztag-secours");
    until(r, 60_000, (s) => s.phone?.address !== null);
    expect(visit(r, "/")).toContain("Lapin en secours");
    expect(visit(r, "/flash", lapin!)).toContain("200 OK");
    r.phoneLeave();
    until(r, 60_000, (_, text) => text.includes("4242"));
    expect(r.status().resets).toBe(2);
  });
});
