<script lang="ts" generics="Id extends string">
  import type { Snippet } from "svelte";

  interface Props {
    tabs: { id: Id; label: string }[];
    selected: Id;
    label: string;
    panel: Snippet<[Id]>;
  }

  let { tabs, selected = $bindable(), label, panel }: Props = $props();

  // Arrow keys move along the tabs, as in any tab list.
  function key(e: KeyboardEvent, i: number) {
    const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    const next = (i + step + tabs.length) % tabs.length;
    selected = tabs[next].id;
    ((e.currentTarget as HTMLElement).parentElement?.children[next] as HTMLElement | undefined)?.focus();
  }
</script>

<div class="tabs" role="tablist" aria-label={label}>
  {#each tabs as tab, i (tab.id)}
    <button
      role="tab"
      id="tab-{tab.id}"
      aria-selected={selected === tab.id}
      aria-controls="panel-{tab.id}"
      tabindex={selected === tab.id ? 0 : -1}
      onclick={() => (selected = tab.id)}
      onkeydown={(e) => key(e, i)}
    >
      {tab.label}
    </button>
  {/each}
</div>
<div class="panel" role="tabpanel" id="panel-{selected}" aria-labelledby="tab-{selected}">
  {@render panel(selected)}
</div>

<style>
  .tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    scrollbar-width: none;
  }

  .tabs button {
    border: 0;
    background: none;
    padding: 8px 12px;
    font-weight: 500;
    color: var(--muted);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    white-space: nowrap;
  }

  .tabs button:hover {
    color: var(--text);
  }

  .tabs button[aria-selected="true"] {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .panel {
    padding-top: 16px;
    min-width: 0;
  }
</style>
