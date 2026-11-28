<script lang="ts">
  import type { Ear, Rgb } from "../emu/nabemu";

  interface Props {
    leds: Rgb[];
    ears: [Ear, Ear];
    pressed: boolean;
    onpress: (down: boolean) => void;
  }

  let { leds, ears, pressed, onpress }: Props = $props();

  const NAMES = ["nose", "left", "middle", "right", "bottom"];

  // The driver's 7-bit current, shown a little brighter than linear.
  function colour([r, g, b]: Rgb): string | null {
    if (r + g + b === 0) return null;
    const c = (v: number) => Math.round(255 * Math.sqrt(v / 127));
    return `rgb(${c(r)} ${c(g)} ${c(b)})`;
  }

  const lit = $derived(leds.map(colour));
  const label = $derived(
    leds.map((l, i) => `${NAMES[i]} ${lit[i] ? `rgb ${l.join(" ")}` : "off"}`).join(", "),
  );

  // Keys held down repeat: only the first press counts.
  function key(e: KeyboardEvent, down: boolean) {
    if (e.key !== " " && e.key !== "Enter") return;
    e.preventDefault();
    if (!e.repeat) onpress(down);
  }

  function pointerDown(e: PointerEvent) {
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
    onpress(true);
  }
</script>

<svg viewBox="0 0 200 300" role="img" aria-label="The rabbit: {label}">
  {#each ears as ear, i (i)}
    <!-- Twenty slots to a turn; the left ear turns the other way round. -->
    <g
      class="ear"
      class:moving={ear.direction !== 0}
      style:transform="rotate({(i === 0 ? -1 : 1) * ear.slot * 18}deg)"
      style:transform-origin="{i === 0 ? 73 : 127}px 112px"
    >
      <rect x={i === 0 ? 62 : 116} y="8" width="22" height="110" rx="11" />
      <rect class="inner" x={i === 0 ? 68 : 122} y="18" width="10" height="80" rx="5" />
    </g>
  {/each}

  <g
    class="head"
    class:pressed
    role="button"
    tabindex="0"
    aria-label="Head button: press and hold"
    aria-pressed={pressed}
    onpointerdown={pointerDown}
    onpointerup={() => onpress(false)}
    onpointercancel={() => onpress(false)}
    onkeydown={(e) => key(e, true)}
    onkeyup={(e) => key(e, false)}
  >
    <path d="M40 290 C40 150 60 100 100 100 C140 100 160 150 160 290 Z" />
  </g>

  {#each [0, 1, 2, 3, 4] as i (i)}
    {@const fill = lit[i]}
    {#if i === 0}
      <circle class="led" cx="100" cy="168" r="7" style:fill style:--glow={fill} />
    {:else if i === 4}
      <ellipse class="led" cx="100" cy="284" rx="50" ry="5" style:fill style:--glow={fill} />
    {:else}
      <circle class="led" cx={48 + 26 * i} cy="222" r="10" style:fill style:--glow={fill} />
    {/if}
  {/each}
</svg>

<style>
  svg {
    display: block;
    width: 100%;
    max-width: 210px;
    margin: 0 auto;
    height: auto;
    touch-action: none;
    user-select: none;
    overflow: visible;
  }

  .ear {
    transition: transform 0.16s linear;
  }

  .ear rect {
    fill: var(--shell);
    stroke: var(--shell-line);
    stroke-width: 1.2;
  }

  .ear .inner {
    fill: color-mix(in srgb, var(--shell-line) 35%, var(--shell));
    stroke: none;
  }

  .ear.moving rect:first-child {
    stroke: var(--accent);
    stroke-width: 2;
  }

  .head {
    cursor: pointer;
    outline: none;
  }

  .head path {
    fill: var(--shell);
    stroke: var(--shell-line);
    stroke-width: 1.2;
    transition: fill 0.1s;
  }

  .head:hover path {
    fill: color-mix(in srgb, var(--shell) 92%, var(--accent));
  }

  .head.pressed path {
    fill: color-mix(in srgb, var(--shell) 80%, var(--accent));
    stroke: var(--accent);
  }

  .head:focus-visible path {
    stroke: var(--accent);
    stroke-width: 3;
  }

  .led {
    fill: var(--led-off);
    stroke: var(--shell-line);
    stroke-width: 0.6;
    pointer-events: none;
    transition: fill 0.08s linear;
    filter: drop-shadow(0 0 5px var(--glow, transparent));
  }
</style>
