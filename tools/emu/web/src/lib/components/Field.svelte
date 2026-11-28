<script lang="ts">
  import type { Snippet } from "svelte";

  /** A control with its name above it; `reading` shows its value beside the name. */
  let {
    label,
    reading,
    grow = false,
    children,
  }: { label: string; reading?: string | number; grow?: boolean; children: Snippet } = $props();
</script>

<label class="field" class:grow>
  <span>
    {label}
    {#if reading !== undefined}<output class="mono">{reading}</output>{/if}
  </span>
  {@render children()}
</label>

<style>
  output {
    color: var(--text);
    margin-left: 4px;
  }
</style>
