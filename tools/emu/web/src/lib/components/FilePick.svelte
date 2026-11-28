<script lang="ts">
  // A button that opens the file chooser.
  interface Props {
    label: string;
    accept?: string;
    disabled?: boolean;
    onpick: (file: File) => void;
  }

  let { label, accept, disabled = false, onpick }: Props = $props();
  let input: HTMLInputElement;

  function picked() {
    const file = input.files?.[0];
    if (file) onpick(file);
    input.value = "";
  }
</script>

<button type="button" class="btn" {disabled} onclick={() => input.click()}>{label}</button>
<input bind:this={input} type="file" {accept} hidden onchange={picked} />
