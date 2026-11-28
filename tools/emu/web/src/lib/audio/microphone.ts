// This device's microphone, down to the 8000 Hz the rabbit records at.

const RATE = 8000;

// A worklet that hands every block it hears to the page.
const TAP = `registerProcessor("tap", class extends AudioWorkletProcessor {
  process([input]) { if (input[0]) this.port.postMessage(input[0].slice()); return true; }
});`;
const tapped = new WeakSet<AudioContext>();

/** Start listening; the function returned stops. */
export async function listen(audio: AudioContext, hear: (samples: Int16Array) => void): Promise<() => void> {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true } });
  if (!tapped.has(audio)) {
    const url = URL.createObjectURL(new Blob([TAP], { type: "text/javascript" }));
    try {
      await audio.audioWorklet.addModule(url);
      tapped.add(audio);
    } finally {
      URL.revokeObjectURL(url);
    }
  }
  const source = audio.createMediaStreamSource(stream);
  const tap = new AudioWorkletNode(audio, "tap");
  const step = audio.sampleRate / RATE;
  let phase = 0;
  tap.port.onmessage = ({ data }: MessageEvent<Float32Array>) => {
    // Pick samples at the rabbit's rate; good enough for a voice.
    const out: number[] = [];
    for (; phase < data.length; phase += step) {
      out.push(Math.max(-1, Math.min(1, data[Math.floor(phase)])) * 32767);
    }
    phase -= data.length;
    hear(Int16Array.from(out));
  };
  source.connect(tap);
  return () => {
    tap.disconnect();
    source.disconnect();
    stream.getTracks().forEach((t) => t.stop());
  };
}
