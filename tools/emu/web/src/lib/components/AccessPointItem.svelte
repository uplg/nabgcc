<script lang="ts">
  import { useRabbit } from "../context";
  import type { AccessPoint } from "../emu/nabemu";
  import { macs } from "../format";

  let { ap, n }: { ap: AccessPoint; n: number } = $props();
  const rabbit = useRabbit();
</script>

<li class="ap">
  <div class="top">
    <div class="name">
      <h3>{ap.ssid || "(no name)"}</h3>
      <span class="small muted">{ap.security} · channel {ap.channel}{ap.hidden ? " · hidden" : ""}</span>
    </div>
    <span class="pill" class:ok={ap.joined}>{ap.joined ? "rabbit joined" : "rabbit not joined"}</span>
  </div>

  <label class="field">
    <span>Signal <output class="mono">{ap.dbm} dBm</output></span>
    <input
      type="range"
      min="-95"
      max="-20"
      value={ap.dbm}
      onchange={(e) => rabbit.send("signal", n, e.currentTarget.valueAsNumber)}
    />
  </label>

  <div class="row">
    <button class="btn" onclick={() => rabbit.send("restartAccessPoint", n)} title="It loses power and comes back, having forgotten every station">
      Restart
    </button>
    <button class="btn danger" onclick={() => rabbit.send("removeAccessPoint", n)} title="It tells everyone to leave and goes off the air">
      Switch off
    </button>
  </div>

  <details>
    <summary class="small muted">Latest events ({ap.events.length})</summary>
    {#if ap.events.length}
      <pre class="log">{ap.events.map(macs).join("\n")}</pre>
    {:else}
      <p class="small empty">Nothing yet.</p>
    {/if}
  </details>
</li>

<style>
  .ap {
    display: grid;
    gap: 12px;
    padding: 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
  }

  .top {
    display: flex;
    justify-content: space-between;
    align-items: start;
    gap: 8px;
  }

  .name {
    display: grid;
    min-width: 0;
  }

  h3 {
    overflow-wrap: anywhere;
  }

  output {
    color: var(--text);
    margin-left: 4px;
  }

  summary {
    cursor: pointer;
  }

  details .log {
    margin-top: 8px;
  }
</style>
