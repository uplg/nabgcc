<script lang="ts" generics="T extends string">
  import Field from "./Field.svelte";

  /** One of a list of words, picked from a drop-down. */
  let { label, options, value = $bindable() }: { label: string; options: readonly T[]; value: T } = $props();
</script>

<Field {label}>
  <select bind:value>
    {#each options as o (o)}
      <option value={o}>{o}</option>
    {/each}
  </select>
</Field>
