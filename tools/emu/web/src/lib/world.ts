// The world a rabbit starts in on this page, and what makes a key valid.

import type { AccessPointSpec, Security, Settings } from "./emu/nabemu";

export const HOME: AccessPointSpec = {
  ssid: "Terrier",
  security: "WPA2",
  key: "carotte-violette",
  channel: 6,
  dbm: -55,
  hidden: false,
};

/** Settings for a network, as the setup page would save them. */
export function settingsFor(ap: AccessPointSpec): Settings {
  // A WPA3 network is "WPA2" to the settings: the firmware finds out.
  const security = ap.security.startsWith("WPA2") || ap.security === "WPA3" ? "WPA2" : ap.security;
  return { ssid: ap.ssid, security, key: ap.key, server: "r.nabaztag.com/vl" };
}

/** Why a key does not suit a network, or null. */
export function keyProblem(security: Security, key: string): string | null {
  if (security === "open") return null;
  if (security.startsWith("WEP")) {
    return [5, 13].includes(key.length) ? null : "a WEP key has 5 or 13 characters";
  }
  return key.length >= 8 && key.length <= 63 ? null : "a passphrase has 8 to 63 characters";
}
