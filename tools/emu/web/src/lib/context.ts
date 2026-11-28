import { createContext } from "svelte";
import type { Rabbit } from "./emu/rabbit.svelte";

/** The rabbit the page drives, for every component under the app. */
export const [useRabbit, provideRabbit] = createContext<Rabbit>();
