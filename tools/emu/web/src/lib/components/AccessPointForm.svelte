<script lang="ts">
  import { useRabbit } from "../context";
  import { SECURITIES, type AccessPointSpec } from "../emu/nabemu";
  import { keyProblem } from "../world";
  import Check from "./Check.svelte";
  import Choice from "./Choice.svelte";
  import Field from "./Field.svelte";

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
    <Field label="Network name">
      <input type="text" bind:value={ap.ssid} maxlength="32" />
    </Field>
    <Choice label="Security" options={SECURITIES} bind:value={ap.security} />
    <Field label={ap.security.startsWith("WEP") ? "WEP key" : "Passphrase"}>
      <input type="text" bind:value={ap.key} disabled={ap.security === "open"} spellcheck="false" />
    </Field>
    <Field label="Channel">
      <input type="number" min="1" max="13" bind:value={ap.channel} />
    </Field>
    <Field label="Signal (dBm)">
      <input type="number" min="-95" max="-20" bind:value={ap.dbm} />
    </Field>
    <Check small bind:checked={ap.hidden}>Hidden name</Check>
  </div>
  <div class="row">
    <button class="btn primary" disabled={problem !== null}>Add</button>
    {#if problem}
      <span class="small muted">{problem}</span>
    {/if}
  </div>
</form>
