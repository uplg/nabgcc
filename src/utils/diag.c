/**
 * @file diag.c
 * @brief Off-board diagnostics: WPA2/3 association probe + UDP ring export
 *
 * The rabbit has no reachable serial port once assembled and connecting the
 * JTAG rig keeps the RT2573 core from booting, so the whole diagnostic loop
 * happens over the air:
 *  1. diag_probe_target(): before the VM boots, natively scan+associate with
 *     the network under investigation (DIAG_SSID, hardcoded PMK), letting
 *     DEBUG_WIFI narrate every step into diag_ring via putch_uart.
 *  2. The VM then boots normally and joins the known-good network from the
 *     config sector.
 *  3. diag_ship_ring(): once that association is up, broadcast the ring as
 *     UDP datagrams on port DIAG_PORT (broadcast MAC, so no ARP needed).
 *
 * Compiled in only with -DDIAG_RING (probe + ring export) and/or
 * -DDIAG_COUNTERS (RX/EAPOL counters for the deafness campaign).
 */
#if defined(DIAG_RING) || defined(DIAG_COUNTERS)

#include <stdio.h>
#include <string.h>

#include "ml674061.h"
#include "common.h"
#include "utils/debug.h"
#include "utils/delay.h"
#include "hal/led.h"
#include "hal/uart.h"
#include "usb/hcdmem.h"
#include "usb/hcd.h"
#include "usb/usbh.h"
#include "usb/rt2501usb.h"
#include "usb/rt2501usb_io.h"
#include "net/ieee80211.h"
#include "net/eapol.h"
#include "vm/vlog.h"
#include "utils/diag.h"

#define DIAG_PORT 9999

static uint16_t diag_ip_checksum(const uint8_t *hdr, uint32_t len)
{
  uint32_t sum = 0;
  uint32_t i;
  for(i = 0; i+1 < len; i += 2)
    sum += (hdr[i] << 8) | hdr[i+1];
  while(sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t)~sum;
}

#ifdef DIAG_RING

#define DIAG_SSID "Freebox-664E25"
#define DIAG_AP_SSID "NabDiag"
#define DIAG_AP_CHANNEL 6
#define DIAG_CHUNK 1024
#define DIAG_MAX_SHIPS 4000
/* How long the rabbit stays its own AP shipping the ring before it gives up
 * and boots the VM normally. */
#define DIAG_AP_MS 240000

/* PMK = PBKDF2-SHA1("blabliblou", "Freebox-664E25", 4096, 32).
 * Note the 0x00 at offset 19: this is the network the strcpy bug ate. */
static const uint8_t diag_pmk[32] = {
  0xed, 0x7c, 0x31, 0x7f, 0x1b, 0x5b, 0x61, 0x8e,
  0xc3, 0x81, 0x99, 0x91, 0xa1, 0xef, 0x56, 0x1e,
  0x80, 0x0b, 0x5d, 0x00, 0xa0, 0xc5, 0x57, 0x4a,
  0xa4, 0x82, 0x9c, 0xa2, 0x74, 0xb6, 0x57, 0x29
};

static char diag_buf[128];

/* Blink colour, so the LEDs narrate the phase: blue = waiting for the dongle,
 * white = scanning, red = association attempt, green = shipping the ring. */
static uint32_t diag_led_color = RGB_BLUE;

static volatile uint8_t diag_scan_found;
static volatile uint8_t diag_scan_count;
static struct rt2501_scan_result diag_scan_match;

/* Runs in IRQ context (URB completion path): copy and get out. */
static void diag_scan_cb(struct rt2501_scan_result *r, void *userparam)
{
  diag_scan_count++;
  if(strcmp((char*)r->ssid, DIAG_SSID) == 0) {
    memcpy(&diag_scan_match, r, sizeof(diag_scan_match));
    diag_scan_found = 1;
  }
}

/* The VM owns the LEDs, but it has not booted yet during the probe: drive
 * them here so the rabbit visibly says "working" instead of looking dead
 * through a minute of silent diagnostics. */
static void diag_led(uint32_t color)
{
  uint8_t i;
  /* set_led() indexes LEDs 0..4; the LED_RGB_* constants are the encoded
   * form set_led_rgb() wants, not indices. */
  for(i = 0; i < 5; i++)
    set_led(i, color);
}

/* Same pump as the main loop, minus the VM: keep USB + 802.11 alive. */
static void diag_pump(uint32_t ms)
{
  uint32_t t0 = counter_timer;
  uint32_t last_timer = counter_timer;
  uint32_t last_blink = counter_timer;
  uint8_t on = 0;

  while((counter_timer - t0) < ms) {
    struct rt2501buffer *r;
    CLR_WDT;
    usbhost_events();
    while((r = rt2501_receive())) {
      disable_ohci_irq();
      hcd_free(r);
      enable_ohci_irq();
    }
    if((counter_timer - last_timer) >= 100) {
      last_timer = counter_timer;
      rt2501_timer();
    }
    if((counter_timer - last_blink) >= 500) {
      last_blink = counter_timer;
      on = !on;
      diag_led(on ? diag_led_color : RGB_BLACK);
    }
  }
}

static const char *diag_state_name(int32_t s)
{
  switch(s) {
    case IEEE80211_S_IDLE:  return "IDLE";
    case IEEE80211_S_SCAN:  return "SCAN";
    case IEEE80211_S_AUTH:  return "AUTH";
    case IEEE80211_S_ASSOC: return "ASSOC";
    case IEEE80211_S_EAPOL: return "EAPOL";
    case IEEE80211_S_RUN:   return "RUN";
    default:                return "?";
  }
}

/* Follow one association attempt to its conclusion (RUN, back to IDLE, or
 * budget exhausted), logging every state transition with a timestamp. */
static int32_t diag_watch_assoc(uint32_t budget_ms)
{
  uint32_t t0 = counter_timer;
  int32_t last = ieee80211_state;

  while((counter_timer - t0) < budget_ms) {
    diag_pump(50);
    if(ieee80211_state != last) {
      sprintf(diag_buf, "DIAG: state %s -> %s at +%lums"EOL,
              diag_state_name(last), diag_state_name(ieee80211_state),
              (unsigned long)(counter_timer - t0));
      consolestr(diag_buf);
      last = ieee80211_state;
    }
    if(ieee80211_state == IEEE80211_S_RUN) return 1;
    /* Left IDLE at auth time; back means the attempt is over. */
    if(ieee80211_state == IEEE80211_S_IDLE) return 0;
  }
  sprintf(diag_buf, "DIAG: attempt timed out in state %s"EOL,
          diag_state_name(ieee80211_state));
  consolestr(diag_buf);
  return 0;
}

void diag_probe_target(void)
{
  uint32_t t0;
  uint8_t scan_try, auth_try;
  uint8_t scanned = 0;
  uint8_t enc;

  consolestr(EOL"DIAG: probe of \""DIAG_SSID"\" ("__DATE__" "__TIME__")"EOL);

  /* Wait for the RT2573 to enumerate (factory timing: ~200 ms). */
  t0 = counter_timer;
  while((rt2501_state() == RT2501_S_BROKEN) && ((counter_timer - t0) < 20000))
    diag_pump(100);
  if(rt2501_state() == RT2501_S_BROKEN) {
    consolestr("DIAG: dongle never came up, aborting probe"EOL);
    return;
  }
  sprintf(diag_buf, "DIAG: dongle up at +%lums"EOL,
          (unsigned long)(counter_timer - t0));
  consolestr(diag_buf);

  diag_led_color = RGB_WHITE;
  for(scan_try = 0; scan_try < 2 && !diag_scan_found; scan_try++) {
    diag_scan_count = 0;
    rt2501_scan((const uint8_t*)DIAG_SSID, diag_scan_cb, NULL);
    diag_pump(500);
    scanned = diag_scan_count;
  }

  /* Start the log over here. A scan logs every beacon of every neighbouring
   * network, which would fill the ring long before the association verdict —
   * the one line we are after — is even printed. Outside the scan state the
   * 802.11 code is quiet, so what follows is the association attempt alone. */
  diag_ring_len = 0;
  sprintf(diag_buf,
          EOL"DIAG: === association phase === (%d scan results, target %sfound)"EOL,
          scanned, diag_scan_found ? "" : "NOT ");
  consolestr(diag_buf);

  if(!diag_scan_found) {
    consolestr("DIAG: target absent, probe over"EOL);
    return;
  }

  sprintf(diag_buf,
          "DIAG: bssid %02x:%02x:%02x:%02x:%02x:%02x ch %d rssi %d rates 0x%04x enc 0x%02x"EOL,
          diag_scan_match.bssid[0], diag_scan_match.bssid[1],
          diag_scan_match.bssid[2], diag_scan_match.bssid[3],
          diag_scan_match.bssid[4], diag_scan_match.bssid[5],
          diag_scan_match.channel, diag_scan_match.rssi,
          diag_scan_match.rateset, diag_scan_match.encryption);
  consolestr(diag_buf);

  diag_led_color = RGB_RED;
  for(auth_try = 0; auth_try < 3; auth_try++) {
    /* First attempt: exactly what the VM would pass (the parsed scan
     * verdict). If the parser said UNSUPPORTED (or found nothing), force
     * plain WPA2/CCMP instead so we still get to see the AP's reaction. */
    enc = diag_scan_match.encryption;
    if(auth_try > 0 || (enc & 0xF0) == 0xF0 || (enc & 0xF0) == 0)
      enc = IEEE80211_CRYPT_WPA2
            | (IEEE80211_CIPHER_CCMP << 1)   /* group CCMP */
            | (IEEE80211_CIPHER_CCMP >> 1);  /* pairwise CCMP */

    sprintf(diag_buf, "DIAG: auth attempt %d, enc 0x%02x"EOL, auth_try+1, enc);
    consolestr(diag_buf);

    rt2501_auth((const uint8_t*)DIAG_SSID,
                diag_scan_match.mac, diag_scan_match.bssid,
                diag_scan_match.channel, diag_scan_match.rateset,
                IEEE80211_AUTH_OPEN, enc, diag_pmk);

    if(diag_watch_assoc(30000)) {
      consolestr("DIAG: SUCCESS, association + EAPOL complete"EOL);
      break;
    }
  }

  if(ieee80211_state != IEEE80211_S_RUN) {
    disable_ohci_irq();
    ieee80211_state = IEEE80211_S_IDLE;
    enable_ohci_irq();
  }
  sprintf(diag_buf, "DIAG: probe over, state %s, ring %lu bytes"EOL,
          diag_state_name(ieee80211_state), (unsigned long)diag_ring_len);
  consolestr(diag_buf);
}

/* LLC/SNAP + IPv4 + UDP + 16-byte diag header + chunk, broadcast MAC.
 * Scratch buffer in ExtRAM (IntRAM is full); fully rewritten before each
 * send, so stale contents are harmless. */
#define diag_pkt ((uint8_t *)DIAG_PKT_ADDR)

static int32_t diag_ship_chunk(uint32_t offset, uint32_t clen, uint32_t total,
                               uint8_t seq, uint8_t nchunks, const uint8_t *dst_ip,
                               const uint8_t *dst_mac)
{
  static const uint8_t bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t *ip  = diag_pkt+8;
  uint8_t *udp = diag_pkt+28;
  uint8_t *hdr = diag_pkt+36;
  uint16_t ip_len  = 20+8+16+clen;
  uint16_t udp_len = 8+16+clen;
  uint16_t csum;
  uint32_t i;

  /* LLC/SNAP, EtherType IPv4 */
  memcpy(diag_pkt, "\xaa\xaa\x03\x00\x00\x00\x08\x00", 8);

  ip[0] = 0x45; ip[1] = 0;
  ip[2] = ip_len >> 8; ip[3] = ip_len & 0xff;
  ip[4] = 0; ip[5] = seq;             /* identification */
  ip[6] = 0; ip[7] = 0;               /* no fragmentation */
  ip[8] = 64; ip[9] = 17;             /* TTL, UDP */
  ip[10] = 0; ip[11] = 0;             /* checksum, computed below */
  ip[12] = 169; ip[13] = 254; ip[14] = 187; ip[15] = 1;  /* link-local src */
  memcpy(ip+16, dst_ip, 4);
  csum = diag_ip_checksum(ip, 20);
  ip[10] = csum >> 8; ip[11] = csum & 0xff;

  udp[0] = DIAG_PORT >> 8; udp[1] = DIAG_PORT & 0xff;  /* sport */
  udp[2] = DIAG_PORT >> 8; udp[3] = DIAG_PORT & 0xff;  /* dport */
  udp[4] = udp_len >> 8; udp[5] = udp_len & 0xff;
  udp[6] = 0; udp[7] = 0;             /* checksum optional over IPv4 */

  memcpy(hdr, "NDG1", 4);
  hdr[4] = seq; hdr[5] = nchunks;
  hdr[6] = offset & 0xff; hdr[7] = (offset >> 8) & 0xff;
  hdr[8] = clen & 0xff; hdr[9] = (clen >> 8) & 0xff;
  hdr[10] = total & 0xff;         hdr[11] = (total >> 8) & 0xff;
  hdr[12] = (total >> 16) & 0xff; hdr[13] = (total >> 24) & 0xff;
  hdr[14] = 0; hdr[15] = 0;

  for(i = 0; i < clen; i++)
    hdr[16+i] = diag_ring[offset+i];

  return rt2501_send(diag_pkt, 8+ip_len, dst_mac ? dst_mac : bcast_mac, 1, 0);
}

void diag_ship_ring(void)
{
  static const uint8_t ip_limited[4] = {255,255,255,255};
  /* The Mac running scripts/diag-listen.py: unicast survives AP setups that
   * filter client-to-client broadcast (and gets L2 ACKs + retries). */
  static const uint8_t mac_ip[4] = {10,143,57,51};
  static const uint8_t mac_mac[6] = {0xba,0x1e,0x82,0x0b,0xfa,0xd4};
  static uint32_t rounds;
  static uint32_t last_send;
  static uint32_t total;
  static uint8_t seq, nchunks;
  uint32_t offset, clen;
  uint8_t unicast;

  if(ieee80211_state != IEEE80211_S_RUN) return;
  if(rounds >= DIAG_MAX_SHIPS) return;
  if((counter_timer - last_send) < 200) return;
  last_send = counter_timer;

  if(nchunks == 0 || seq >= nchunks) {
    if(nchunks != 0)
      rounds++;
    /* (Re)snapshot the ring for the next round. */
    total = diag_ring_len;
    if(total > DIAG_RING_SIZE) total = DIAG_RING_SIZE;
    if(total == 0) return;
    nchunks = (total + DIAG_CHUNK - 1) / DIAG_CHUNK;
    seq = 0;
  }

  /* One chunk per call (~200 ms apart): a couple of ms of work each time,
   * instead of a multi-second burst that starves the VM and the watchdog. */
  offset = (uint32_t)seq * DIAG_CHUNK;
  clen = total - offset;
  if(clen > DIAG_CHUNK) clen = DIAG_CHUNK;
  /* On our own AP the Mac uses a per-SSID private MAC we cannot know, so
   * unicast is only useful on the shared network. */
  unicast = (ieee80211_mode != IEEE80211_M_MASTER) && (rounds & 1);
  if(diag_ship_chunk(offset, clen, total, seq, nchunks,
                     unicast ? mac_ip : ip_limited,
                     unicast ? mac_mac : NULL))
    seq++;
}

void diag_export_via_ap(void)
{
  uint32_t t0;

  if(rt2501_state() == RT2501_S_BROKEN)
    consolestr("DIAG: driver reports no dongle, trying to export anyway"EOL);

  /* Become an open AP and ship the ring over it. This depends on nothing but
   * the radio: no Freebox, no hotspot, no DHCP, no VM, no HTTP server — the
   * chain that has broken every export attempt so far. */
  sprintf(diag_buf, "DIAG: exporting ring (%lu bytes) as AP \""DIAG_AP_SSID"\""EOL,
          (unsigned long)diag_ring_len);
  consolestr(diag_buf);

  rt2501_setmode(IEEE80211_M_MASTER, (const uint8_t*)DIAG_AP_SSID,
                 DIAG_AP_CHANNEL);

  diag_led_color = RGB_GREEN;
  t0 = counter_timer;
  while((counter_timer - t0) < DIAG_AP_MS) {
    diag_pump(150);
    diag_ship_ring();
  }

  consolestr("DIAG: export window over, booting normally"EOL);
  rt2501_setmode(IEEE80211_M_MANAGED, NULL, 0);
  diag_led(RGB_BLACK);
}

#endif /* DIAG_RING */

#ifdef DIAG_COUNTERS

/*
 * The deafness discriminator. Everything is counted at the lowest layer we
 * can reach (the RXD the RT2573 prepends to every frame), so a wedge that
 * starves ieee80211_input still shows up here — or provably does not.
 */

#define DIAG_CNT_PERIOD_MS 2000

static volatile uint32_t cnt_rx_total;    /* complete frames, any state    */
static volatile uint32_t cnt_rx_crc;      /* CRC error set by the hardware */
static volatile uint32_t cnt_beacon;      /* beacons, any BSS              */
static volatile uint32_t cnt_beacon_bss;  /* beacons the ASIC tagged MyBss */
static volatile uint32_t cnt_data_enc_ok; /* encrypted data, decrypted OK  */
static volatile uint32_t cnt_data_plain;  /* unencrypted data frames       */
static volatile uint32_t cnt_ciph_err[4]; /* CipherErr: -, ICV, MIC, KEY   */
static volatile uint32_t cnt_eapol[DIAG_EAPOL_NEVENTS];
static volatile uint32_t cnt_eapol_last_ms; /* counter_timer, last event   */

/* IRQ context (URB completion): increments only. */
void diag_count_rx(const void *rxd_, const uint8_t *dot11)
{
  const RXD_STRUC *rxd = (const RXD_STRUC *)rxd_;
  uint8_t type;

  cnt_rx_total++;
  if(rxd->Crc) {
    cnt_rx_crc++;
    return;                     /* the header bytes are not trustworthy */
  }
  if(rxd->CipherAlg != RT2501_CIPHER_NONE)
    cnt_ciph_err[rxd->CipherErr & 3]++;

  type = dot11[0] & IEEE80211_FC0_TYPE_MASK;
  if(type == IEEE80211_FC0_TYPE_MGT) {
    if((dot11[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_BEACON) {
      cnt_beacon++;
      if(rxd->MyBss)
        cnt_beacon_bss++;
    }
  } else if(type == IEEE80211_FC0_TYPE_DATA) {
    if(rxd->CipherAlg == RT2501_CIPHER_NONE)
      cnt_data_plain++;
    else if(rxd->CipherErr == 0)
      cnt_data_enc_ok++;
  }
}

void diag_count_eapol(uint8_t ev)
{
  if(ev < DIAG_EAPOL_NEVENTS)
    cnt_eapol[ev]++;
  cnt_eapol_last_ms = counter_timer;
}

/* One ASCII line, LLC/SNAP + IPv4 + UDP, broadcast MAC on DIAG_PORT: no
 * ARP, no peer state, nothing the wedge can take away from the TX side.
 * Scratch in ExtRAM (.extbss, never zeroed at boot): fully rewritten
 * before each send, so stale contents are harmless. */
static uint8_t diag_cnt_pkt[320] __attribute__((section(".extbss")));

void diag_ship_counters(void)
{
  static uint32_t last_send;
  static uint32_t seq;
  static const uint8_t bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t *ip  = diag_cnt_pkt+8;
  uint8_t *udp = diag_cnt_pkt+28;
  char *payload = (char *)diag_cnt_pkt+36;
  uint32_t csr0, csr1, csr2;
  uint16_t plen, ip_len, udp_len;
  uint16_t csum;

  if(ieee80211_state != IEEE80211_S_RUN) return;
  if(ieee80211_mode != IEEE80211_M_MANAGED) return;
  if((counter_timer - last_send) < DIAG_CNT_PERIOD_MS) return;
  last_send = counter_timer;

  /* Key-table state straight from the RT2573: CSR0 = shared key valid
   * bits, CSR1 = shared key ciphers, CSR2 = pairwise key valid bitmap.
   * Control transfers from the main loop, same as rt2501_calibrate(). */
  csr0 = rt2501_read(rt2501_dev, RT2501_SEC_CSR0);
  csr1 = rt2501_read(rt2501_dev, RT2501_SEC_CSR1);
  csr2 = rt2501_read(rt2501_dev, RT2501_SEC_CSR2);

  /* bld identifies the image on the wire: no more guessing which build
   * is in flash (the whole first night was lost to exactly that). */
  plen = (uint16_t)sprintf(payload,
    "NDC1 bld=" __TIME__ " seq=%lu up=%lu bcn=%lu/%lu denc=%lu dpl=%lu "
    "cerr=%lu/%lu/%lu crc=%lu rx=%lu "
    "e14=%lu e34=%lu eg=%lu edr=%lu emic=%lu gok=%lu gko=%lu eage=%ld "
    "es=%d is=%ld csr0=%08lx csr1=%08lx csr2=%08lx",
    (unsigned long)seq++,
    (unsigned long)counter_timer,
    (unsigned long)cnt_beacon, (unsigned long)cnt_beacon_bss,
    (unsigned long)cnt_data_enc_ok, (unsigned long)cnt_data_plain,
    (unsigned long)cnt_ciph_err[1], (unsigned long)cnt_ciph_err[2],
    (unsigned long)cnt_ciph_err[3],
    (unsigned long)cnt_rx_crc, (unsigned long)cnt_rx_total,
    (unsigned long)cnt_eapol[DIAG_EAPOL_M1],
    (unsigned long)cnt_eapol[DIAG_EAPOL_M3],
    (unsigned long)cnt_eapol[DIAG_EAPOL_GROUP],
    (unsigned long)cnt_eapol[DIAG_EAPOL_DROP],
    (unsigned long)cnt_eapol[DIAG_EAPOL_MICFAIL],
    (unsigned long)cnt_eapol[DIAG_EAPOL_GTKOK],
    (unsigned long)cnt_eapol[DIAG_EAPOL_GTKFAIL],
    cnt_eapol_last_ms ? (long)(counter_timer - cnt_eapol_last_ms) : -1L,
    (int)eapol_state, (long)ieee80211_state,
    (unsigned long)csr0, (unsigned long)csr1, (unsigned long)csr2);

  ip_len  = 20+8+plen;
  udp_len = 8+plen;

  memcpy(diag_cnt_pkt, "\xaa\xaa\x03\x00\x00\x00\x08\x00", 8);

  ip[0] = 0x45; ip[1] = 0;
  ip[2] = ip_len >> 8; ip[3] = ip_len & 0xff;
  ip[4] = 0; ip[5] = seq & 0xff;      /* identification */
  ip[6] = 0; ip[7] = 0;               /* no fragmentation */
  ip[8] = 64; ip[9] = 17;             /* TTL, UDP */
  ip[10] = 0; ip[11] = 0;             /* checksum, computed below */
  ip[12] = 169; ip[13] = 254; ip[14] = 187; ip[15] = 1;  /* link-local src */
  ip[16] = 255; ip[17] = 255; ip[18] = 255; ip[19] = 255;
  csum = diag_ip_checksum(ip, 20);
  ip[10] = csum >> 8; ip[11] = csum & 0xff;

  udp[0] = DIAG_PORT >> 8; udp[1] = DIAG_PORT & 0xff;  /* sport */
  udp[2] = DIAG_PORT >> 8; udp[3] = DIAG_PORT & 0xff;  /* dport */
  udp[4] = udp_len >> 8; udp[5] = udp_len & 0xff;
  udp[6] = 0; udp[7] = 0;             /* checksum optional over IPv4 */

  rt2501_send(diag_cnt_pkt, 8+ip_len, bcast_mac, 1, 0);
}

#endif /* DIAG_COUNTERS */

#endif /* DIAG_RING || DIAG_COUNTERS */
