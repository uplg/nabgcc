<script lang="ts">
  import { readFile } from "../catalogue";
  import { useRabbit } from "../context";
  import type { Phone } from "../emu/nabemu";
  import FilePick from "./FilePick.svelte";
  import PhoneScreen from "./PhoneScreen.svelte";

  let { phone }: { phone: Phone | null } = $props();
  const rabbit = useRabbit();

  const NETWORKS = [
    { prefix: "Nabaztag", label: "Setup network", upload: "/c", about: "the rabbit started with its button held" },
    { prefix: "Nabaztag-secours", label: "Rescue network", upload: "/flash", about: "lapin's rescue core, after a failed update" },
  ];

  let path = $state("/");
  let upload = $state("/c");
  const page = $derived(rabbit.pages.at(-1));
  const ready = $derived(phone?.address != null);

  function join(network: (typeof NETWORKS)[number]) {
    rabbit.clearPages();
    upload = network.upload;
    rabbit.send("phoneJoin", network.prefix);
  }

  function leave() {
    rabbit.clearPages();
    rabbit.send("phoneLeave");
  }

  function fetch(target: string, body?: Uint8Array) {
    path = target;
    rabbit.send("phoneFetch", target, body);
  }
</script>

<div class="stack">
  <p class="muted">
    A phone near the rabbit, for when the rabbit is the access point: it joins the network, takes an address from the
    rabbit and loads its pages.
  </p>

  <div class="row">
    {#each NETWORKS as n (n.prefix)}
      <button class="btn" onclick={() => join(n)} title="Join the first network named {n.prefix}…: {n.about}">
        Join the {n.label.toLowerCase()}
      </button>
    {/each}
    <button class="btn quiet" disabled={!phone} onclick={leave}>Leave</button>
  </div>

  {#if phone}
    <dl class="kv">
      <dt>Looking for</dt>
      <dd>{phone.looksFor}…</dd>
      <dt>Link</dt>
      <dd>
        <span class="pill" class:ok={phone.link === "associated"} class:warn={phone.link !== "associated"}>{phone.link}</span>
      </dd>
      <dt>Network</dt>
      <dd>{phone.network ?? "—"}</dd>
      <dt>Phone's address</dt>
      <dd class="mono">{phone.address ?? "waiting for the rabbit's DHCP"}</dd>
      <dt>Requests waiting</dt>
      <dd>{phone.pending}</dd>
    </dl>

    <form class="row" onsubmit={(e) => (e.preventDefault(), fetch(path))}>
      <label class="grow field">
        <span>Address on the rabbit</span>
        <input type="text" class="mono" bind:value={path} spellcheck="false" />
      </label>
      <button class="btn primary go" disabled={!ready}>Load</button>
    </form>

    <div class="row">
      <label class="field">
        <span>Upload to</span>
        <input type="text" class="mono upload" bind:value={upload} spellcheck="false" />
      </label>
      <div class="go">
        <FilePick label="Send an image…" accept=".sim,.bin" disabled={!ready} onpick={async (f) => fetch(upload, await readFile(f))} />
      </div>
    </div>

    {#if page}
      <PhoneScreen {page} onfetch={fetch} />
    {:else}
      <p class="empty">{ready ? "Load a page." : "Not on the network yet."}</p>
    {/if}
  {/if}
</div>

<style>
  .go {
    align-self: end;
  }

  .upload {
    width: 10rem;
  }

  .kv dd {
    text-align: left;
  }

  .kv {
    grid-template-columns: max-content 1fr;
  }
</style>
