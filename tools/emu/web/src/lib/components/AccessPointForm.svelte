<script lang="ts">
  import { useRabbit } from "../context";
  import { SECURITIES, type AccessPointSpec } from "../emu/nabemu";
  import { keyProblem } from "../world";

  const rabbit = useRabbit();

  let ap = $state<AccessPointSpec>({
    ssid: "Voisin",
    security: "WPA3",
    key: "carotte-violette",
    channel: 11,
    dbm: -60,
    hidden: false,
  });
  const problem = $derived(ap.ssid.length === 0 ? "a network needs a name" : keyProblem(ap.security, ap.key));

  function add(e: SubmitEvent) {
    e.preventDefault();
    rabbit.send("addAccessPoint", $state.snapshot(ap));
  }
</script>

<form class="stack" onsubmit={add}>
  <h3>Add an access point</h3>
  <div class="fields">
    <label class="field">
      <span>Network name</span>
      <input type="text" bind:value={ap.ssid} maxlength="32" />
    </label>
    <label class="field">
      <span>Security</span>
      <select bind:value={ap.security}>
        {#each SECURITIES as s (s)}
          <option value={s}>{s}</option>
        {/each}
      </select>
    </label>
    <label class="field">
      <span>{ap.security.startsWith("WEP") ? "WEP key" : "Passphrase"}</span>
      <input type="text" bind:value={ap.key} disabled={ap.security === "open"} spellcheck="false" />
    </label>
    <label class="field">
      <span>Channel</span>
      <input type="number" min="1" max="13" bind:value={ap.channel} />
    </label>
    <label class="field">
      <span>Signal (dBm)</span>
      <input type="number" min="-95" max="-20" bind:value={ap.dbm} />
    </label>
    <label class="check small">
      <input type="checkbox" bind:checked={ap.hidden} />
      Hidden name
    </label>
  </div>
  <div class="row">
    <button class="btn primary" disabled={problem !== null}>Add</button>
    {#if problem}
      <span class="small muted">{problem}</span>
    {/if}
  </div>
</form>
