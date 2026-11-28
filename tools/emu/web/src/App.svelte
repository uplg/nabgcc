<script lang="ts">
  import { onMount } from "svelte";
  import { FIRMWARES, GARENNE, fetchOffer, type Offer } from "./lib/catalogue";
  import ConsolePanel from "./lib/components/ConsolePanel.svelte";
  import FirmwarePicker from "./lib/components/FirmwarePicker.svelte";
  import PhonePanel from "./lib/components/PhonePanel.svelte";
  import RabbitPanel from "./lib/components/RabbitPanel.svelte";
  import RunControls from "./lib/components/RunControls.svelte";
  import ScenariosPanel from "./lib/components/ScenariosPanel.svelte";
  import ServerPanel from "./lib/components/ServerPanel.svelte";
  import SettingsPanel from "./lib/components/SettingsPanel.svelte";
  import SoundPanel from "./lib/components/SoundPanel.svelte";
  import StatePanel from "./lib/components/StatePanel.svelte";
  import Tabs from "./lib/components/Tabs.svelte";
  import TagPanel from "./lib/components/TagPanel.svelte";
  import ThemeToggle from "./lib/components/ThemeToggle.svelte";
  import WifiPanel from "./lib/components/WifiPanel.svelte";
  import { provideRabbit } from "./lib/context";
  import { Rabbit } from "./lib/emu/rabbit.svelte";
  import { HOME, settingsFor } from "./lib/world";

  const rabbit = provideRabbit(new Rabbit());

  let firmwares = $state<Offer[]>([]);
  let garenne = $state(false);
  let failed = $state(false);
  let tab = $state<"wifi" | "settings" | "server" | "phone" | "scenarios">("wifi");

  const TABS = [
    { id: "wifi", label: "Wi-Fi" },
    { id: "settings", label: "Settings" },
    { id: "server", label: "Server" },
    { id: "phone", label: "Phone" },
    { id: "scenarios", label: "Scenarios" },
  ] as const;

  /** Another firmware in the same rabbit: the settings carried over. */
  function load(bytes: Uint8Array, name: string) {
    const settings = rabbit.snapshot?.settings ?? settingsFor(HOME);
    rabbit.clearConsole();
    rabbit.send("boot", bytes, name, settings);
  }

  onMount(async () => {
    const found = await Promise.all(FIRMWARES.map(async (o) => [o, await fetchOffer(o)] as const));
    firmwares = found.filter(([, bytes]) => bytes).map(([o]) => o);
    const [first, bytes] = found.find(([, b]) => b) ?? [];
    const application = await fetchOffer(GARENNE);
    garenne = application !== null;
    if (!first || !bytes) {
      failed = true;
      return;
    }
    // The rabbit at home: its network, its settings, its server.
    rabbit.send("addAccessPoint", HOME);
    rabbit.send(
      "serve",
      application ? { kind: "file", name: GARENNE.name, bytes: application } : { kind: "sample", sample: "prints", arg: 4242 },
    );
    load(bytes, first.name);
    rabbit.send("setRunning", true);
  });
</script>

<header class="toolbar">
  <div class="brand">
    <h1>nabemu</h1>
    <span class="muted small">Nabaztag:tag, emulated</span>
  </div>
  {#if rabbit.snapshot}
    <FirmwarePicker offers={firmwares} current={rabbit.snapshot.firmware} onload={load} />
    <RunControls s={rabbit.snapshot} />
  {/if}
  <span class="grow"></span>
  <ThemeToggle />
</header>

{#if rabbit.error}
  <p class="banner" role="alert">{rabbit.error}</p>
{/if}

{#if rabbit.snapshot}
  {@const s = rabbit.snapshot}
  <main class="layout">
    <div class="side">
      <RabbitPanel {s} />
      <TagPanel tag={s.status.tag} />
      <SoundPanel status={s.status} />
      <StatePanel {s} />
    </div>
    <div class="work">
      <section class="card" aria-label="The world around the rabbit">
        <Tabs tabs={[...TABS]} bind:selected={tab} label="The world around the rabbit">
          {#snippet panel(id)}
            {#if id === "wifi"}
              <WifiPanel accessPoints={s.accessPoints} />
            {:else if id === "settings"}
              <SettingsPanel settings={s.settings} accessPoints={s.accessPoints} />
            {:else if id === "server"}
              <ServerPanel serving={s.serving} {garenne} {firmwares} />
            {:else if id === "phone"}
              <PhonePanel phone={s.status.phone} />
            {:else}
              <ScenariosPanel holdUntil={s.holdUntil} ms={s.status.ms} />
            {/if}
          {/snippet}
        </Tabs>
      </section>
      <ConsolePanel />
    </div>
  </main>
{:else if failed}
  <main class="message">
    <h2>No firmware next to the page</h2>
    <p class="muted">Run <code>tools/emu/web/build.sh</code>, or load a firmware file:</p>
    <FirmwarePicker offers={[]} current="" onload={load} />
  </main>
{:else}
  <main class="message"><p class="muted">Starting the rabbit…</p></main>
{/if}

<style>
  .toolbar {
    position: sticky;
    top: 0;
    z-index: 2;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px 16px;
    padding: 10px 20px;
    background: color-mix(in srgb, var(--surface) 92%, transparent);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
  }

  .brand {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }

  h1 {
    font-size: 17px;
  }

  .layout {
    display: grid;
    grid-template-columns: minmax(300px, 360px) minmax(0, 1fr);
    gap: var(--gap);
    padding: 20px;
    max-width: 1440px;
    margin: 0 auto;
    align-items: start;
  }

  .side,
  .work {
    display: grid;
    gap: var(--gap);
    min-width: 0;
  }

  .message {
    display: grid;
    gap: 12px;
    justify-items: center;
    padding: 80px 20px;
    text-align: center;
  }

  .banner {
    margin: 12px 20px 0;
    padding: 10px 14px;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--danger) 12%, var(--surface));
    color: var(--danger);
  }

  @media (max-width: 900px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
      padding: 16px;
    }

    .toolbar {
      padding: 10px 16px;
    }
  }
</style>
