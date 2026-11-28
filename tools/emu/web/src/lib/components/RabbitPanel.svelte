<script lang="ts">
  import { useRabbit } from "../context";
  import type { Snapshot } from "../emu/protocol";
  import Field from "./Field.svelte";
  import Flag from "./Flag.svelte";
  import Panel from "./Panel.svelte";
  import RabbitFigure from "./RabbitFigure.svelte";

  let { s }: { s: Snapshot } = $props();
  const rabbit = useRabbit();

  const status = $derived(s.status);
  const EARS = ["Left", "Right"] as const;
  const motion = (direction: number) => (direction > 0 ? "turning" : direction < 0 ? "turning back" : "still");
</script>

<Panel name="rabbit" title="Rabbit">
  {#snippet badge()}
    <Flag on={status.button} yes="button down" no="button up" />
  {/snippet}

  <RabbitFigure leds={status.leds} ears={status.ears} pressed={status.button} onpress={(down) => rabbit.send("button", down)} />
  <p class="muted small center">Press and hold the head for its button (or focus it and hold Space).</p>

  <div class="row center">
    <button class="btn" onclick={() => rabbit.send("hold", 200, false)}>Click</button>
    <button class="btn" onclick={() => rabbit.send("hold", 3000, false)}>Hold 3 s</button>
  </div>

  <Field label="Volume wheel" reading={status.volume}>
    <input
      type="range"
      min="0"
      max="255"
      value={status.volume}
      oninput={(e) => rabbit.send("volume", e.currentTarget.valueAsNumber)}
    />
  </Field>

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
</Panel>

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
</style>
