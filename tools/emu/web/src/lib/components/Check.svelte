<script lang="ts">
  import type { Snippet } from "svelte";

  /** A checkbox with what it says after it. */
  let {
    checked = $bindable(),
    small = false,
    children,
  }: { checked: boolean; small?: boolean; children: Snippet } = $props();
</script>

<label class="check" class:small>
  <input type="checkbox" bind:checked />
  {@render children()}
</label>
