<script lang="ts">
  import { useRabbit } from "../context";

  const rabbit = useRabbit();

  let filter = $state("");
  let dumps = $state(false);
  let follow = $state(true);
  let box = $state<HTMLPreElement>();

  // Memory dumps: an address, then bytes in hexadecimal.
  const DUMP = /^[0-9a-f]{4,8} [0-9a-f]{2} /;

  const shown = $derived.by(() => {
    const needle = filter.toLowerCase();
    const lines = [...rabbit.lines, rabbit.partial];
    return lines
      .filter((l) => (dumps || !DUMP.test(l)) && (!needle || l.toLowerCase().includes(needle)))
      .join("\n");
  });

  $effect(() => {
    void shown;
    if (follow && box) box.scrollTop = box.scrollHeight;
  });

  // Scrolling up stops following; back at the end, it follows again.
  function scrolled() {
    if (box) follow = box.scrollTop + box.clientHeight >= box.scrollHeight - 8;
  }
</script>

<section class="card" aria-labelledby="console-title">
  <header>
    <h2 id="console-title">Serial console</h2>
    <span class="small muted">{rabbit.lines.length} lines</span>
  </header>
  <div class="row">
    <input class="grow" type="search" placeholder="Filter" bind:value={filter} aria-label="Filter the console" />
    <label class="check small"><input type="checkbox" bind:checked={dumps} /> Memory dumps</label>
    <button class="btn" aria-pressed={follow} onclick={() => (follow = !follow)}>Follow</button>
    <button class="btn quiet" onclick={() => rabbit.clearConsole()}>Clear</button>
  </div>
  <pre bind:this={box} onscroll={scrolled} aria-label="What the firmware printed" aria-live="off">{shown}</pre>
</section>

<style>
  pre {
    margin: 0;
    height: 420px;
    overflow: auto;
    padding: 12px 14px;
    background: var(--console-bg);
    color: var(--console-text);
    border-radius: var(--radius-sm);
    font: 12px/1.55 var(--mono);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    resize: vertical;
  }
</style>
