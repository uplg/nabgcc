<script lang="ts">
  import { useRabbit } from "../context";

  let { holdUntil, ms }: { holdUntil: number | null; ms: number } = $props();
  const rabbit = useRabbit();

  interface Scenario {
    title: string;
    about: string;
    action: string;
    run: () => void;
  }

  const SCENARIOS: Scenario[] = [
    {
      title: "Setup mode",
      about: "Plugged in with the button held for 2 s: the rabbit turns blue and raises its own network. Then join it from the phone.",
      action: "Start in setup mode",
      run: () => rabbit.send("hold", 2000, true),
    },
    {
      title: "Factory test",
      about: "Plugged in with the button held for 8 s. Each click of the head moves to the next step: ears, tag reader, loudspeaker, microphone.",
      action: "Start the factory test",
      run: () => rabbit.send("hold", 8000, true),
    },
    {
      title: "Rescue on demand",
      about: "lapin only: the button held 20 s from power-on asks its rescue core for the \"Nabaztag-secours\" network.",
      action: "Ask for the rescue",
      run: () => rabbit.send("hold", 20000, true),
    },
    {
      title: "Power cut during an update",
      about: "The running firmware sent over the air again, and the power cut halfway through writing it. lapin comes back on its rescue network; the C firmware has no rescue core.",
      action: "Update, then cut",
      run: () => rabbit.send("update", null, 12000),
    },
    {
      title: "An application that keeps restarting",
      about: "The server hands out a program that restarts the rabbit at once, every time. lapin's rescue core takes over after a few rounds.",
      action: "Serve it",
      run: () => {
        rabbit.send("serve", { kind: "sample", sample: "restarts", arg: 0 });
        rabbit.send("powerCycle");
      },
    },
    {
      title: "Fresh from the factory",
      about: "A new rabbit with the same firmware and no settings, in the same world.",
      action: "New rabbit",
      run: () => rabbit.send("reset", false),
    },
  ];
</script>

<div class="stack">
  {#if holdUntil !== null}
    <p class="pill warn" role="status">Button held for {((holdUntil - ms) / 1000).toFixed(1)} s more</p>
  {/if}
  <ul class="scenarios">
    {#each SCENARIOS as s (s.title)}
      <li>
        <h3>{s.title}</h3>
        <p class="small muted">{s.about}</p>
        <button class="btn" onclick={s.run}>{s.action}</button>
      </li>
    {/each}
  </ul>
</div>

<style>
  .scenarios {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
  }

  li {
    display: grid;
    grid-template-rows: auto 1fr auto;
    gap: 8px;
    padding: 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }

  li .btn {
    justify-self: start;
  }

  .pill {
    justify-self: start;
  }
</style>
