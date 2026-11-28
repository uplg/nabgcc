<script lang="ts">
  import { useRabbit } from "../context";
  import type { Snapshot, Speed } from "../emu/protocol";

  let { s }: { s: Snapshot } = $props();
  const rabbit = useRabbit();

  const SPEEDS: { value: Speed; label: string; title: string }[] = [
    { value: 0.25, label: "¼×", title: "A quarter of real time" },
    { value: 1, label: "1×", title: "Real time" },
    { value: 4, label: "4×", title: "Four times real time" },
    { value: "max", label: "Max", title: "As fast as this machine goes" },
  ];
</script>

<div class="row">
  <button
    class="btn primary run"
    onclick={() => rabbit.send("setRunning", !s.running)}
    aria-label={s.running ? "Pause" : "Run"}
  >
    {#if s.running}
      <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="3" y="2" width="3.5" height="12" rx="1" /><rect x="9.5" y="2" width="3.5" height="12" rx="1" /></svg>
      Pause
    {:else}
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 2.5v11l9.5-5.5z" /></svg>
      Run
    {/if}
  </button>
  <button class="btn" disabled={s.running} onclick={() => rabbit.send("step", 100)} title="Run 100 ms of board time">
    Step
  </button>
  <button class="btn" onclick={() => rabbit.send("powerCycle")} title="Unplug the rabbit and plug it back in">
    Power cycle
  </button>
  <button
    class="btn"
    onclick={() => rabbit.send("reset", true)}
    title="A new rabbit: the firmware flashed afresh, the settings and the world around it kept"
  >
    Reset
  </button>
</div>

<div class="seg" role="group" aria-label="Speed">
  {#each SPEEDS as speed (speed.value)}
    <button aria-pressed={s.speed === speed.value} title={speed.title} onclick={() => rabbit.send("setSpeed", speed.value)}>
      {speed.label}
    </button>
  {/each}
</div>

<style>
  .run {
    min-width: 88px;
  }

  .run svg {
    width: 12px;
    height: 12px;
    fill: currentColor;
  }
</style>
