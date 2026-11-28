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
    <ul class="tiles" style:--tile="260px">
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
