<script lang="ts">
  // Lines that keep coming, newest at the bottom, followed while scrolled to the end.
  interface Props {
    title: string;
    lines: string[];
    empty: string;
  }

  let { title, lines, empty }: Props = $props();
  let box = $state<HTMLPreElement>();

  $effect.pre(() => {
    void lines.length;
    if (!box) return;
    const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 8;
    if (atEnd) queueMicrotask(() => box && (box.scrollTop = box.scrollHeight));
  });
</script>

<section class="stack" aria-label={title}>
  <h3>{title}</h3>
  {#if lines.length}
    <pre class="log" bind:this={box}>{lines.join("\n")}</pre>
  {:else}
    <p class="small empty">{empty}</p>
  {/if}
</section>
