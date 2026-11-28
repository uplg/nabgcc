// The files web/build.sh puts next to the page, when they are built.

export interface Offer {
  file: string;
  name: string;
  about: string;
}

export const FIRMWARES: Offer[] = [
  { file: "Nab-wpa23-gtk-r3.sim", name: "r3", about: "the released C firmware" },
  { file: "lapin-full.bin", name: "lapin", about: "the Rust firmware" },
];

export const GARENNE: Offer = { file: "garenne.bin", name: "garenne", about: "the rabbit's application" };

export async function fetchOffer(offer: Offer): Promise<Uint8Array | null> {
  const response = await fetch(`firmware/${offer.file}`).catch(() => null);
  return response?.ok ? new Uint8Array(await response.arrayBuffer()) : null;
}

export async function readFile(file: File): Promise<Uint8Array> {
  return new Uint8Array(await file.arrayBuffer());
}
