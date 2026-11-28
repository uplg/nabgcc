<script lang="ts">
  import { fetchOffer, readFile, type Offer } from "../catalogue";
  import { useRabbit } from "../context";
  import FilePick from "./FilePick.svelte";

  /** The firmwares built next to the page. */
  let { offers }: { offers: Offer[] } = $props();
  const rabbit = useRabbit();

  let cut = $state(false);
  let ops = $state(12000);

  function update(bytes: Uint8Array | null) {
    if (bytes) rabbit.send("update", bytes, cut ? ops : null);
  }
</script>

<section class="stack" aria-labelledby="update-title">
  <h3 id="update-title">Update over the air</h3>
  <p class="muted">
    The rabbit restarts; its first <code>bc.jsp</code> then brings a bytecode that writes the new image over the running
    one, after which the server goes back to what it served.
  </p>
  <label class="check">
    <input type="checkbox" bind:checked={cut} />
    Cut the power after
    <input class="ops" type="number" min="1" bind:value={ops} disabled={!cut} aria-label="Flash operations before the cut" />
    flash operations (erases and words)
  </label>
  <div class="row">
    <span class="muted small">Send</span>
    {#each offers as o (o.name)}
      <button class="btn" onclick={async () => update(await fetchOffer(o))}>{o.name}</button>
    {/each}
    <FilePick label="A firmware file…" accept=".sim,.bin" onpick={async (f) => update(await readFile(f))} />
  </div>
</section>

<style>
  .check {
    flex-wrap: wrap;
  }

  .ops {
    width: 96px;
  }
</style>
