<script lang="ts">
  /** A status label, green when `on`, saying which. */
  let { on, yes, no }: { on: boolean; yes: string; no: string } = $props();
</script>

<span class="pill" class:ok={on}>{on ? yes : no}</span>
