<script lang="ts">
  // A page from the rabbit, shown as the phone's browser would: links and
  // forms go back to the rabbit through the phone; the page's own scripts
  // do not run.
  import type { PhonePage } from "../emu/nabemu";
  import { parseAnswer, requestedPath, resolve } from "../http";

  interface Props {
    page: PhonePage;
    onfetch: (target: string, body?: Uint8Array) => void;
  }

  let { page, onfetch }: Props = $props();
  let raw = $state(false);

  const answer = $derived(parseAnswer(page.response));
  const path = $derived(requestedPath(page.request));

  function wire(frame: HTMLIFrameElement) {
    const doc = frame.contentDocument;
    if (!doc) return;
    doc.addEventListener("click", (e) => {
      const link = (e.target as Element).closest("a[href]");
      if (!link) return;
      e.preventDefault();
      onfetch(resolve(link.getAttribute("href") ?? "/", path));
    });
    doc.addEventListener("submit", async (e) => {
      e.preventDefault();
      const form = e.target as HTMLFormElement;
      const target = resolve(form.getAttribute("action") ?? path, path).split("?")[0];
      const data = new FormData(form, e.submitter);
      const file = [...data.values()].find((v): v is File => v instanceof File && v.size > 0);
      if (file) {
        // The file alone, as the rabbit's own upload tool sends it.
        onfetch(target, new Uint8Array(await file.arrayBuffer()));
        return;
      }
      const query = new URLSearchParams(
        [...data].filter((pair): pair is [string, string] => typeof pair[1] === "string"),
      ).toString();
      if (form.method.toLowerCase() === "post") onfetch(target, new TextEncoder().encode(query));
      else onfetch(`${target}?${query}`);
    });
  }
</script>

<div class="screen">
  <div class="bar">
    <span class="pill" class:ok={answer.status >= 200 && answer.status < 300} class:bad={answer.status >= 400}>
      {answer.status || "?"}
      {answer.reason}
    </span>
    <code class="grow url">{path}</code>
    <div class="seg" role="group" aria-label="Show the page">
      <button aria-pressed={!raw} onclick={() => (raw = false)} disabled={!answer.html}>Page</button>
      <button aria-pressed={raw || !answer.html} onclick={() => (raw = true)}>Raw</button>
    </div>
  </div>
  {#if answer.html && !raw}
    <iframe title="The rabbit's page at {path}" sandbox="allow-same-origin allow-forms" srcdoc={answer.body} onload={(e) => wire(e.currentTarget as HTMLIFrameElement)}></iframe>
  {:else}
    <pre class="log raw">{page.response}</pre>
  {/if}
</div>

<style>
  .screen {
    display: grid;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    overflow: hidden;
    background: var(--surface);
  }

  .bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
  }

  .url {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  iframe {
    width: 100%;
    height: 460px;
    border: 0;
    background: #fff;
    resize: vertical;
  }

  .raw {
    max-height: 460px;
    border-radius: 0;
  }
</style>
