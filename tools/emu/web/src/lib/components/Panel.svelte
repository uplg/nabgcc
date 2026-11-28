<script lang="ts">
  import type { Snippet } from "svelte";

  /** A card of the side column: its title, a badge beside it, then the body. */
  let { name, title, badge, children }: { name: string; title: string; badge: Snippet; children: Snippet } = $props();
</script>

<section class="card" aria-labelledby="{name}-title">
  <header>
    <h2 id="{name}-title">{title}</h2>
    {@render badge()}
  </header>
  {@render children()}
</section>
