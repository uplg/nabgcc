<script lang="ts">
  import type { AccessPoint } from "../emu/nabemu";
  import AccessPointForm from "./AccessPointForm.svelte";
  import AccessPointItem from "./AccessPointItem.svelte";

  let { accessPoints }: { accessPoints: AccessPoint[] } = $props();
</script>

<div class="stack">
  <p class="muted">
    The access points in the rabbit's range, with a wired network and the server behind them.
  </p>
  {#if accessPoints.length}
    <ul class="aps">
      {#each accessPoints as ap, n (`${n}-${ap.ssid}`)}
        <AccessPointItem {ap} {n} />
      {/each}
    </ul>
  {:else}
    <p class="empty">No network in range.</p>
  {/if}
  <hr />
  <AccessPointForm />
</div>

<style>
  .aps {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 12px;
  }
</style>
