<script lang="ts">
  type Theme = "auto" | "light" | "dark";
  const NEXT: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
  const KEY = "nabemu-theme";

  function stored(): Theme {
    try {
      const t = localStorage.getItem(KEY);
      return t === "light" || t === "dark" ? t : "auto";
    } catch {
      return "auto";
    }
  }

  let theme = $state<Theme>(stored());

  $effect(() => {
    if (theme === "auto") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      // Not kept: fine.
    }
  });
</script>

<button class="btn quiet" onclick={() => (theme = NEXT[theme])} title="Colour scheme: {theme}" aria-label="Colour scheme: {theme}">
  <svg viewBox="0 0 16 16" aria-hidden="true">
    {#if theme === "light"}
      <circle cx="8" cy="8" r="3.2" />
      <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6L13 13M3 13l1.4-1.4M11.6 4.4L13 3" />
    {:else if theme === "dark"}
      <path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7z" />
    {:else}
      <circle cx="8" cy="8" r="6" />
      <path d="M8 2a6 6 0 0 1 0 12z" class="fill" />
    {/if}
  </svg>
  {theme}
</button>

<style>
  svg {
    width: 15px;
    height: 15px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.4;
    stroke-linecap: round;
  }

  .fill {
    fill: currentColor;
  }
</style>
