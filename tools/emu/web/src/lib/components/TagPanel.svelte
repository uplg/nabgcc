<script lang="ts">
  import { useRabbit } from "../context";
  import Field from "./Field.svelte";
  import Flag from "./Flag.svelte";
  import Panel from "./Panel.svelte";

  let { tag }: { tag: string | null } = $props();
  const rabbit = useRabbit();

  let uid = $state("d0021a0352c4667f");
  const valid = $derived(/^[0-9a-f]{16}$/i.test(uid));

  function random() {
    // Starting d0, like the rabbit's own tags.
    const bytes = crypto.getRandomValues(new Uint8Array(7));
    uid = "d0" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
</script>

<Panel name="tag" title="Tag at the nose">
  {#snippet badge()}
    <Flag on={tag !== null} yes="held" no="none" />
  {/snippet}
  <Field label="Identifier (8 bytes, hexadecimal)">
    <div class="row">
      <input class="grow mono" type="text" bind:value={uid} spellcheck="false" maxlength="16" aria-invalid={!valid} />
      <button class="btn quiet" onclick={random}>Random</button>
    </div>
  </Field>
  <div class="row">
    <button class="btn primary" disabled={!valid} onclick={() => rabbit.send("tag", uid.toLowerCase())}>
      {tag ? "Hold this one instead" : "Hold it at the nose"}
    </button>
    <button class="btn" disabled={!tag} onclick={() => rabbit.send("tag", null)}>Take it away</button>
  </div>
  {#if tag}
    <p class="small muted">Held: <code>{tag}</code></p>
  {/if}
</Panel>
