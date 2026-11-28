<script lang="ts">
  import { useRabbit } from "../context";
  import type { Snapshot } from "../emu/protocol";
  import RabbitFigure from "./RabbitFigure.svelte";

  let { s }: { s: Snapshot } = $props();
  const rabbit = useRabbit();

  const status = $derived(s.status);
  const EARS = ["Left", "Right"] as const;
  const motion = (direction: number) => (direction > 0 ? "turning" : direction < 0 ? "turning back" : "still");
</script>

<section class="card" aria-labelledby="rabbit-title">
  <header>
    <h2 id="rabbit-title">Rabbit</h2>
    <span class="pill" class:ok={status.button}>{status.button ? "button down" : "button up"}</span>
  </header>

  <RabbitFigure leds={status.leds} ears={status.ears} pressed={status.button} onpress={(down) => rabbit.send("button", down)} />
  <p class="muted small center">Press and hold the head for its button (or focus it and hold Space).</p>

  <div class="row center">
    <button class="btn" onclick={() => rabbit.send("hold", 200, false)}>Click</button>
    <button class="btn" onclick={() => rabbit.send("hold", 3000, false)}>Hold 3 s</button>
  </div>

  <label class="field">
    <span>Volume wheel <output class="mono">{status.volume}</output></span>
    <input
      type="range"
      min="0"
      max="255"
      value={status.volume}
      oninput={(e) => rabbit.send("volume", e.currentTarget.valueAsNumber)}
    />
  </label>

  <div class="ears">
    {#each status.ears as ear, i (i)}
      <div class="ear">
        <span>{EARS[i]} ear</span>
        <span class="small muted">Slot {ear.slot} of 20 · {ear.pulses} pulses</span>
        <div class="row">
          <span class="pill" class:ok={ear.direction !== 0}>{motion(ear.direction)}</span>
          <button class="btn icon" aria-label="Turn the {EARS[i].toLowerCase()} ear back one slot by hand" onclick={() => rabbit.send("turnEar", i as 0 | 1, -1)}>‹</button>
          <button class="btn icon" aria-label="Turn the {EARS[i].toLowerCase()} ear on one slot by hand" onclick={() => rabbit.send("turnEar", i as 0 | 1, 1)}>›</button>
        </div>
      </div>
    {/each}
  </div>
</section>

<style>
  .center {
    text-align: center;
    justify-content: center;
  }

  .ears {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .ear .row {
    width: 100%;
    flex-wrap: nowrap;
  }

  .ear .pill {
    flex: 0 1 auto;
    margin-right: auto;
  }

  .ear {
    display: grid;
    justify-items: start;
    gap: 6px;
    padding: 10px;
    border-radius: var(--radius-sm);
    background: var(--surface-2);
  }

  output {
    color: var(--text);
    margin-left: 4px;
  }
</style>
