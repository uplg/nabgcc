<script lang="ts">
  import type { Snapshot } from "../emu/protocol";
  import { boardTime, count } from "../format";

  let { s }: { s: Snapshot } = $props();
  const st = $derived(s.status);
  const network = $derived(st.joined === null ? null : s.accessPoints[st.joined]?.ssid);
</script>

<section class="card" aria-labelledby="state-title">
  <header>
    <h2 id="state-title">State</h2>
    {#if s.behind}
      <span class="pill warn">slower than real time</span>
    {:else}
      <span class="pill" class:ok={s.running}>{s.running ? "running" : "paused"}</span>
    {/if}
  </header>

  <dl class="kv">
    <dt>Board time</dt>
    <dd class="mono">{boardTime(st.ms)}</dd>
    <dt>Pace</dt>
    <dd>{s.running ? `${s.pace.ratio.toFixed(2)}× real time` : "—"}</dd>
    <dt>Instructions</dt>
    <dd>{s.running ? `${count(s.pace.ips)}/s` : "—"} · {count(st.instructions)} in all</dd>
    <dt>Idle time skipped</dt>
    <dd>{boardTime(st.skippedMs)}</dd>
  </dl>
  <hr />
  <dl class="kv">
    <dt>Restarts</dt>
    <dd>{st.resets}{st.lastReset ? `, last by ${st.lastReset}` : ""}</dd>
    <dt>Watchdog</dt>
    <dd>unfed {st.watchdog.unfedMs} ms · longest {st.watchdog.longestMs} ms</dd>
    {#if st.undefined > 0}
      <dt>Undefined instructions</dt>
      <dd class="bad">{st.undefined}</dd>
    {/if}
    <dt>Flash</dt>
    <dd>{st.flash.erases} erases · {st.flash.programs} words{st.flash.cutArmed ? " · power cut armed" : ""}</dd>
  </dl>
  <hr />
  <dl class="kv">
    <dt>Wi-Fi stick</dt>
    <dd>{st.stick ? `up, channel ${st.channel}` : "not started"}</dd>
    <dt>Network</dt>
    <dd>{network ? `joined ${network}` : "not joined"}</dd>
    <dt>Address</dt>
    <dd class="mono">{st.lease ?? "—"}</dd>
    <dt>Server requests</dt>
    <dd>{st.server.requests}</dd>
  </dl>
</section>

<style>
  .bad {
    color: var(--danger);
  }
</style>
