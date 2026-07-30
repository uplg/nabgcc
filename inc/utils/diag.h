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

#endif /* _DIAG_H_ */
