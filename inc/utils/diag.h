/**
 * @file diag.h
 * @brief Off-board diagnostics: console ring + WPA2/3 association probe
 *
 * Everything here is compiled in only with -DDIAG_RING. The rabbit has no
 * reachable serial port once assembled, and connecting the JTAG rig keeps the
 * WiFi module from booting, so diagnostics travel over the air instead.
 */
#ifndef _DIAG_H_
#define _DIAG_H_

#include <stdint.h>

/* 16K: DEBUG_WIFI narrates every beacon heard during the scan, which can
 * easily exceed 4K before the association attempt even starts. */
#define DIAG_RING_SIZE 16384

/* The ring and the TX scratch buffer live in otherwise-unused external RAM
 * (0xD0000000..0xD0007FFF; the hcd pool starts at 0xD0008000, the VM heap at
 * 0xD0010000) because IntRAM is too small for them. ExtRAM contents survive
 * resets, but diag_ring_len lives in IntRAM .bss (zeroed at boot) so stale
 * bytes past the counter are never read. */
#define diag_ring ((volatile uint8_t *)0xD0000000)
#define DIAG_PKT_ADDR 0xD0004000

extern volatile uint32_t diag_ring_len;

/**
 * @brief Try to associate with the target network, logging everything
 *
 * Runs before the VM boots, so the VM's own (working) association from the
 * config sector is what the rabbit ends up on either way.
 */
void diag_probe_target(void);

/**
 * @brief Ship the console ring to DIAG_HOST_IP:DIAG_HOST_PORT over UDP
 *
 * Sent as broadcast-MAC datagrams so no ARP is needed. Call from the main
 * loop; no-op unless associated, self-limits to one ship every 4 s, 15 max.
 */
void diag_ship_ring(void);

/**
 * @brief Become an open AP named "NabDiag" and ship the ring over it
 *
 * Depends on the radio alone — no Freebox, no hotspot, no DHCP, no VM, no
 * HTTP server. Join the AP from a machine running scripts/diag-listen.py.
 * Returns after DIAG_AP_MS so the rabbit still boots normally afterwards.
 */
void diag_export_via_ap(void);

/*
 * RX/EAPOL counters (-DDIAG_COUNTERS, independent of DIAG_RING): the
 * instrument for the deafness campaign. TX survives the wedge, so a small
 * broadcast UDP datagram every few seconds carries the counters out even
 * once nothing comes in any more. Beacons are unencrypted management
 * frames: if they keep counting while encrypted data stops, the fault is a
 * key, not the radio.
 */

/* Event classes for diag_count_eapol(). */
#define DIAG_EAPOL_M1      0  /* pairwise 1/4 */
#define DIAG_EAPOL_M3      1  /* pairwise 3/4 */
#define DIAG_EAPOL_GROUP   2  /* group key message 1 (every rekey) */
#define DIAG_EAPOL_DROP    3  /* validation or dispatch drop */
#define DIAG_EAPOL_MICFAIL 4  /* MIC (or ANonce) check failed in a handler */
#define DIAG_EAPOL_GTKOK   5  /* GTK unwrapped and installed (E2 fix) */
#define DIAG_EAPOL_GTKFAIL 6  /* GTK present but unwrap/parse/install failed */
#define DIAG_EAPOL_NEVENTS 7

#ifdef DIAG_COUNTERS
/**
 * @brief Count one received frame; IRQ context, increments only
 *
 * @param [in] rxd_   PRXD_STRUC of the frame (as void* to keep this header
 *                    free of driver types)
 * @param [in] dot11  Start of the 802.11 header, right after the RXD
 */
void diag_count_rx(const void *rxd_, const uint8_t *dot11);

/** @brief Count one EAPOL event (DIAG_EAPOL_*); IRQ context */
void diag_count_eapol(uint8_t ev);

/**
 * @brief Broadcast the counters as one ASCII UDP datagram on DIAG_PORT
 *
 * Call from the main loop; no-op unless associated, self-limits to one
 * datagram every 2 s. Reads SEC_CSR0/1/2 from the RT2573 each time.
 */
void diag_ship_counters(void);

#define DIAG_EAPOL_EV(ev) diag_count_eapol(ev)
#else
#define DIAG_EAPOL_EV(ev) ((void)0)
#endif /* DIAG_COUNTERS */

#endif /* _DIAG_H_ */
