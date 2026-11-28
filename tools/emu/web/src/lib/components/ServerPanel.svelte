<script lang="ts">
  import { fetchOffer, GARENNE, readFile, type Offer } from "../catalogue";
  import { useRabbit } from "../context";
  import type { Serving } from "../emu/protocol";
  import FilePick from "./FilePick.svelte";
  import Log from "./Log.svelte";
  import UpdateForm from "./UpdateForm.svelte";

  interface Props {
    serving: Serving;
    /** garenne is built next to the page. */
    garenne: boolean;
    firmwares: Offer[];
  }

  let { serving, garenne, firmwares }: Props = $props();
  const rabbit = useRabbit();

  let number = $state(4242);

  const describe = $derived.by(() => {
    switch (serving.kind) {
      case "nothing":
        return "nothing: bc.jsp is not found";
      case "file":
        return `${serving.name} (${(serving.bytes.length / 1024).toFixed(1)} KB)`;
      case "sample":
        return serving.sample === "prints" ? `a program that prints ${serving.arg}` : "a program that restarts the rabbit";
    }
  });

  function serve(s: Serving, restart = true) {
    rabbit.send("serve", s);
    if (restart) rabbit.send("powerCycle");
  }

  async function serveGarenne() {
    const bytes = await fetchOffer(GARENNE);
    if (bytes) serve({ kind: "file", name: GARENNE.name, bytes });
  }
</script>

<div class="stack">
  <section class="stack" aria-labelledby="serving-title">
    <h3 id="serving-title">What the server hands out</h3>
    <p class="muted">
      The rabbit asks for <code>bc.jsp</code> when it starts. Now serving <strong>{describe}</strong>. Choosing restarts the
      rabbit so that it asks again.
    </p>
    <div class="row">
      <button class="btn" disabled={!garenne} onclick={serveGarenne} title={garenne ? "" : "garenne is not built next to the page"}>
        garenne
      </button>
      <FilePick
        label="A bytecode file…"
        onpick={async (f) => serve({ kind: "file", name: f.name, bytes: await readFile(f) })}
      />
      <span class="join">
        <button class="btn" onclick={() => serve({ kind: "sample", sample: "prints", arg: number })}>Prints</button>
        <input type="number" bind:value={number} aria-label="Number the sample prints" />
      </span>
      <button class="btn" onclick={() => serve({ kind: "sample", sample: "restarts", arg: 0 })}>Restarts at once</button>
      <button class="btn quiet" onclick={() => serve({ kind: "nothing" })}>Nothing</button>
    </div>
  </section>

  <hr />
  <UpdateForm offers={firmwares} />
  <hr />

  <div class="logs">
    <Log title="Requests" lines={rabbit.requests} empty="No request yet." />
    <Log title="UDP from the rabbit" lines={rabbit.udp} empty="Nothing sent (garenne logs on port 9999)." />
  </div>
  <div class="row end">
    <button class="btn quiet" onclick={() => rabbit.clearServerLog()}>Clear the logs</button>
  </div>
</div>

<style>
  .join {
    display: inline-flex;
  }

  .join .btn {
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
  }

  .join input {
    width: 84px;
    border-left: 0;
    border-top-left-radius: 0;
    border-bottom-left-radius: 0;
  }

  .logs {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 12px;
  }
</style>
