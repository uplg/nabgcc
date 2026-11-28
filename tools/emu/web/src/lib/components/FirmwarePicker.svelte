<script lang="ts">
  import { fetchOffer, readFile, type Offer } from "../catalogue";
  import FilePick from "./FilePick.svelte";

  interface Props {
    /** The firmwares built next to the page. */
    offers: Offer[];
    /** Name of the firmware running. */
    current: string;
    onload: (bytes: Uint8Array, name: string) => void;
  }

  let { offers, current, onload }: Props = $props();

  async function choose(name: string) {
    const offer = offers.find((o) => o.name === name);
    const bytes = offer && (await fetchOffer(offer));
    if (bytes) onload(bytes, name);
  }
</script>

<div class="row">
  <select value={current} onchange={(e) => choose(e.currentTarget.value)} aria-label="Firmware">
    {#each offers as o (o.name)}
      <option value={o.name}>{o.name} — {o.about}</option>
    {/each}
    {#if current && !offers.some((o) => o.name === current)}
      <option value={current}>{current}</option>
    {/if}
  </select>
  <FilePick label="Load file…" accept=".sim,.bin,.elf" onpick={async (f) => onload(await readFile(f), f.name)} />
</div>

<style>
  select {
    width: auto;
    max-width: 20rem;
  }
</style>
