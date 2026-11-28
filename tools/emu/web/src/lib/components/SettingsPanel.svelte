<script lang="ts">
  import { onMount } from "svelte";
  import { useRabbit } from "../context";
  import { SETTINGS_SECURITIES, type AccessPoint, type Settings } from "../emu/nabemu";
  import { HOME, keyProblem, settingsFor } from "../world";

  let { settings, accessPoints }: { settings: Settings | null; accessPoints: AccessPoint[] } = $props();
  const rabbit = useRabbit();

  let form = $state<Settings>(settingsFor(HOME));
  const problem = $derived(form.ssid.length === 0 ? "the network needs a name" : keyProblem(form.security, form.key));

  function load() {
    if (settings) form = { ...settings };
  }
  onMount(load);

  function fromNetwork(ap: AccessPoint) {
    form = { ...settingsFor({ ...ap, key: form.key }), server: form.server };
  }

  function write(restart: boolean) {
    rabbit.send("writeSettings", $state.snapshot(form));
    if (restart) rabbit.send("powerCycle");
  }
</script>

<div class="stack">
  <section class="stack" aria-labelledby="saved-title">
    <h3 id="saved-title">In the rabbit's flash</h3>
    {#if settings}
      <dl class="kv saved">
        <dt>Network</dt>
        <dd>{settings.ssid}</dd>
        <dt>Security</dt>
        <dd>{settings.security}</dd>
        <dt>Key</dt>
        <dd class="mono">{settings.key || "—"}</dd>
        <dt>Server</dt>
        <dd class="mono">{settings.server}</dd>
      </dl>
    {:else}
      <p class="empty">No settings saved: the sector is blank, as on a rabbit never set up.</p>
    {/if}
    <p class="small muted">As the setup page writes them in the last sector; the firmware reads them when it starts.</p>
  </section>

  <hr />

  <form class="stack" onsubmit={(e) => (e.preventDefault(), write(true))}>
    <div class="row">
      <h3 class="grow">Write new settings</h3>
      <button type="button" class="btn quiet" disabled={!settings} onclick={load}>Copy from the flash</button>
    </div>
    <div class="fields">
      <label class="field">
        <span>Network name</span>
        <input type="text" bind:value={form.ssid} maxlength="31" list="ssids" />
        <datalist id="ssids">
          {#each accessPoints as ap, i (i)}
            <option value={ap.ssid}></option>
          {/each}
        </datalist>
      </label>
      <label class="field">
        <span>Security</span>
        <select bind:value={form.security}>
          {#each SETTINGS_SECURITIES as s (s)}
            <option value={s}>{s}</option>
          {/each}
        </select>
      </label>
      <label class="field">
        <span>Key</span>
        <input type="text" bind:value={form.key} disabled={form.security === "open"} spellcheck="false" />
      </label>
      <label class="field">
        <span>Server</span>
        <input type="text" bind:value={form.server} spellcheck="false" />
      </label>
    </div>
    {#if accessPoints.length}
      <div class="row small">
        <span class="muted">Match a network in range:</span>
        {#each accessPoints as ap, i (i)}
          <button type="button" class="btn quiet" onclick={() => fromNetwork(ap)}>{ap.ssid}</button>
        {/each}
      </div>
    {/if}
    <div class="row">
      <button class="btn primary" disabled={problem !== null}>Write and restart</button>
      <button type="button" class="btn" disabled={problem !== null} onclick={() => write(false)}>Write only</button>
      <span class="grow"></span>
      <button type="button" class="btn danger" onclick={() => rabbit.send("eraseSettings")}>Erase the settings</button>
    </div>
    {#if problem}
      <p class="small muted">{problem}</p>
    {/if}
  </form>
</div>

<style>
  .saved dd {
    text-align: left;
  }
</style>
