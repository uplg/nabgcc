<script lang="ts">
  import { onDestroy } from "svelte";
  import { listen } from "../audio/microphone";
  import { loudness, Speaker } from "../audio/speaker";
  import { useRabbit } from "../context";
  import type { Status } from "../emu/nabemu";
  import Flag from "./Flag.svelte";
  import Panel from "./Panel.svelte";

  let { status }: { status: Status } = $props();
  const rabbit = useRabbit();

  // Browsers only let a page make or record sound after a click.
  let audio: AudioContext | null = null;
  let speaker = $state<Speaker | null>(null);
  let stopListening = $state<(() => void) | null>(null);
  let micError = $state<string | null>(null);

  function context(): AudioContext {
    audio ??= new AudioContext();
    void audio.resume();
    return audio;
  }

  function toggleSpeaker() {
    if (speaker) {
      speaker.close();
      speaker = null;
    } else {
      speaker = new Speaker(context());
    }
  }

  async function toggleMicrophone() {
    micError = null;
    if (stopListening) {
      stopListening();
      stopListening = null;
      return;
    }
    try {
      stopListening = await listen(context(), (samples) => rabbit.send("microphone", samples));
    } catch (e) {
      micError = e instanceof Error ? e.message : "the microphone is not available";
    }
  }

  $effect(() => {
    const s = speaker;
    if (!s) return;
    return rabbit.onSounds((sounds) => void s.play(sounds));
  });

  $effect(() => {
    if (speaker) speaker.gain = loudness(status.amplifier, status.attenuation);
  });

  onDestroy(() => {
    stopListening?.();
    speaker?.close();
  });
</script>

<Panel name="sound" title="Sound">
  {#snippet badge()}
    <Flag on={status.amplifier} yes="amplifier on" no="amplifier off" />
  {/snippet}
  <div class="pair">
    <button class="btn" aria-pressed={speaker !== null} onclick={toggleSpeaker} title="Play what the codec outputs on this device">
      Loudspeaker
    </button>
    <button class="btn" aria-pressed={stopListening !== null} onclick={toggleMicrophone} title="Let the rabbit hear this device's microphone">
      Microphone
    </button>
  </div>
  {#if micError}
    <p class="small bad" role="alert">Microphone: {micError}</p>
  {/if}
  <dl class="kv small">
    <dt>Codec attenuation</dt>
    <dd>{(status.attenuation / 2).toFixed(1)} dB</dd>
    <dt>Played so far</dt>
    <dd>{(status.audioBytes / 1024).toFixed(1)} KB</dd>
  </dl>
</Panel>

<style>
  .pair {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }

  .bad {
    color: var(--danger);
  }
</style>
