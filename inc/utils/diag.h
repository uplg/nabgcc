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

#define DIAG_RING_SIZE 4096

extern volatile uint32_t diag_ring_len;
extern volatile uint8_t  diag_ring[DIAG_RING_SIZE];

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
 * Sent as broadcast-MAC / unicast-IP datagrams so no ARP is needed. Call once
 * the VM's association is up. Safe to call repeatedly; it only fires once.
 */
void diag_ship_ring(void);

#endif /* _DIAG_H_ */
