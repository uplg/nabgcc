/* The board under the C firmware's virtual machine, built for the
 * machine that runs the tests: every hardware function the machine
 * calls goes to the Rust world of the tests (rs_* below), the same
 * world the Rust machine runs against. */
#include <stdint.h>
#include <string.h>

#include "vm/vmem.h"
#include "vm/vloader.h"
#include "vm/vinterp.h"
#include "vm/vlog.h"
#include "vm/vnet.h"
#include "vm/vaudio.h"
#include "net/ieee80211.h"
#include "usb/rt2501usb.h"
#include "hal/audio.h"

/* The Rust side. */
extern void rs_console(const uint8_t *p, uint32_t n);
extern uint32_t rs_time_ms(void);
extern uint32_t rs_time_s(void);
extern void rs_led(uint32_t led, uint32_t color);
extern void rs_motor(uint32_t motor, uint32_t run); /* 0 stop, 1 forward, 2 reverse */
extern uint32_t rs_motor_position(uint32_t motor);
extern uint32_t rs_button(void);
extern uint32_t rs_adc(void);
extern int32_t rs_rfid_first(uint8_t *id);
extern int32_t rs_rfid_count(void);
extern void rs_rfid_nth(int32_t i, uint8_t *id);
extern int32_t rs_rfid_read(const uint8_t *id, int32_t block, uint8_t *data);
extern int32_t rs_rfid_write(const uint8_t *id, int32_t block, const uint8_t *data);
extern int32_t rs_i2c_read(uint32_t address, uint8_t *data, uint32_t n);
extern int32_t rs_i2c_write(uint32_t address, const uint8_t *data, uint32_t n);
extern void rs_settings_read(uint32_t offset, uint8_t *data, uint32_t n);
extern void rs_settings_write(uint32_t offset, const uint8_t *data, uint32_t n);
extern void rs_flash_firmware(const uint8_t *data, int32_t n);
extern void rs_reboot(void);
extern uint32_t rs_codec_read(uint32_t reg);
extern void rs_codec_write(uint32_t reg, uint32_t value);
extern int32_t rs_codec_ready(void);
extern uint32_t rs_codec_feed(const uint8_t *data, uint32_t n);
extern void rs_amplifier(int32_t on);
extern int32_t rs_net_state(void);
extern int32_t rs_net_send(const uint8_t *frame, uint32_t n, const uint8_t *dest, int32_t low_rate);
extern void rs_net_mac(uint8_t *mac);
extern void rs_net_set_mode(int32_t mode, const uint8_t *ssid, uint32_t ssid_len, int32_t has_ssid, uint32_t channel);
extern int32_t rs_net_scan(const uint8_t *ssid, uint32_t ssid_len, int32_t has_ssid);
extern void rs_net_scan_result(int32_t i, uint8_t *ssid, uint8_t *mac, uint8_t *bssid, int32_t *rssi,
                               uint32_t *channel, uint32_t *rateset, uint32_t *encryption);
extern void rs_net_auth(const uint8_t *ssid, uint32_t ssid_len, int32_t has_ssid, const uint8_t *mac,
                        const uint8_t *bssid, uint32_t channel, uint32_t rateset, uint32_t authmode,
                        uint32_t encryption, const uint8_t *key, uint32_t key_len, int32_t has_key);
extern void rs_net_pmk(const uint8_t *ssid, uint32_t ssid_len, const uint8_t *key, uint32_t key_len, uint8_t *pmk);
extern int32_t rs_net_rssi(void);
extern int32_t rs_net_pending(void);
extern void rs_net_take(uint8_t *data, uint8_t *mac);
extern void rs_usb_events(void);
extern void rs_net_timer(void);

int32_t _vmem_heap[VMEM_LENGTH];
volatile uint32_t counter_timer, counter_timer_s;
uint8_t rt2501_mac[IEEE80211_ADDR_LEN];
PDEVINFO rt2501_dev;

/* The time only moves in the Rust world; the machine reads it from
 * these two words, as it reads the board's timer. */
static void sync(void)
{
  counter_timer = rs_time_ms();
  counter_timer_s = rs_time_s();
}

void __disable_interrupt(void) {}
void __enable_interrupt(void) {}

void putst_uart(uint8_t *str) { rs_console(str, strlen((char *)str)); sync(); }
void putbin_uart(uint8_t *str, uint32_t len) { rs_console(str, len); sync(); }
void putch_uart(uint8_t c) { rs_console(&c, 1); }
void putint_uart(int32_t v)
{
  char buf[16];
  int n = 15;
  uint32_t u = v < 0 ? 0u - (uint32_t)v : (uint32_t)v;
  buf[n] = 0;
  do { buf[--n] = '0' + u % 10; u /= 10; } while (u);
  if (v < 0) buf[--n] = '-';
  putst_uart((uint8_t *)buf + n);
}
void puthx_uart(uint32_t v)
{
  static const char hex[] = "0123456789abcdef";
  char buf[12];
  int n = 11, started = 0, i;
  buf[0] = '0'; buf[1] = 'x'; n = 2;
  for (i = 7; i >= 0; i--)
  {
    uint32_t d = (v >> (4 * i)) & 15;
    if (d || started || i == 0) { started = 1; buf[n++] = hex[d]; }
  }
  buf[n] = 0;
  putst_uart((uint8_t *)buf);
}
void dump(uint8_t *src, int32_t len) { (void)src; (void)len; }

void set_led(uint8_t led, uint32_t color) { rs_led(led, color); sync(); }
void run_motor(uint8_t number, uint8_t speed, uint8_t rotation)
{
  (void)speed;
  rs_motor(number, rotation == 1 ? 2 : 1);
  sync();
}
void stop_motor(uint8_t number) { rs_motor(number, 0); sync(); }
uint16_t get_motor_position(uint8_t number) { uint16_t v = rs_motor_position(number); sync(); return v; }
uint8_t push_button_value(void) { uint8_t v = rs_button(); sync(); return v; }
uint8_t get_adc_value(void) { uint8_t v = rs_adc(); sync(); return v; }

static uint8_t rfid_id[8];
static uint8_t rfid_nth_id[8];
uint8_t *get_rfid_first_device(void)
{
  int32_t found = rs_rfid_first(rfid_id);
  sync();
  return found ? rfid_id : NULL;
}
int32_t check_rfid_n(void) { int32_t n = rs_rfid_count(); sync(); return n; }
uint8_t *get_nth_rfid(int32_t i) { rs_rfid_nth(i, rfid_nth_id); sync(); return rfid_nth_id; }
int32_t rfid_read(uint8_t *id, int32_t bloc, uint8_t *data) { int32_t r = rs_rfid_read(id, bloc, data); sync(); return r; }
int32_t rfid_write(uint8_t *id, int32_t bloc, uint8_t *data) { int32_t r = rs_rfid_write(id, bloc, data); sync(); return r; }

/* The C reads into a null pointer here; the test world gets a buffer
 * of its own, and the Rust machine returns what the device said, so
 * the scenarios do not use this native. */
static uint8_t i2c_buffer[256];
uint8_t read_i2c(uint8_t addr_i2c, uint8_t *data, uint8_t nb_byte)
{
  (void)data;
  int32_t r = rs_i2c_read(addr_i2c, i2c_buffer, nb_byte);
  sync();
  return r;
}
uint8_t write_i2c(uint8_t addr_i2c, uint8_t *data, uint8_t nb_byte)
{
  int32_t r = rs_i2c_write(addr_i2c, data, nb_byte);
  sync();
  return r;
}

void read_uc_flash(uint32_t address, uint8_t *data, uint32_t nb_byte) { rs_settings_read(address, data, nb_byte); sync(); }
void write_uc_flash(uint32_t address, uint8_t *data, uint32_t nb_byte, uint8_t *temp)
{
  (void)temp;
  rs_settings_write(address, data, nb_byte);
  sync();
}
/* Neither comes back: the board resets. Here the run stops. */
#include <setjmp.h>
static jmp_buf on_reset;
void flash_uc(uint8_t *data, int32_t nb_byte, uint8_t *temp) { (void)temp; rs_flash_firmware(data, nb_byte); longjmp(on_reset, 1); }
void reset_uc(void) { rs_reboot(); longjmp(on_reset, 1); }

uint16_t vlsi_read_sci(uint8_t reg) { uint16_t v = rs_codec_read(reg); sync(); return v; }
void vlsi_write_sci(uint8_t reg, uint16_t val) { rs_codec_write(reg, val); sync(); }
uint8_t vlsi_fifo_ready(void) { uint8_t v = rs_codec_ready(); sync(); return v; }
uint32_t vlsi_feed_sdi(uint8_t *data, uint32_t len) { uint32_t v = rs_codec_feed(data, len); sync(); return v; }
void vlsi_ampli(uint8_t on) { rs_amplifier(on); sync(); }
/* play_check's byte to the codec: chip select, one byte, release. */
void shim_sdi_byte(uint8_t v) { rs_codec_feed(&v, 1); sync(); }

int32_t rt2501_state(void) { int32_t v = rs_net_state(); sync(); return v; }
int32_t rt2501_rssi_average(void) { int32_t v = rs_net_rssi(); sync(); return v; }
int32_t rt2501_send(const uint8_t *frame, uint32_t length, const uint8_t *dest_mac, int32_t lowrate, int32_t mayblock)
{
  (void)mayblock;
  int32_t v = rs_net_send(frame, length, dest_mac, lowrate);
  sync();
  return v;
}
void rt2501_setmode(int32_t mode, const uint8_t *ssid, uint8_t channel)
{
  rs_net_set_mode(mode, ssid, ssid ? strlen((const char *)ssid) : 0, ssid != NULL, channel);
  sync();
}
void rt2501_scan(const uint8_t *ssid, rt2501_scan_callback callback, void *userparam)
{
  int32_t n = rs_net_scan(ssid, ssid ? strlen((const char *)ssid) : 0, ssid != NULL);
  int32_t i;
  sync();
  for (i = 0; i < n; i++)
  {
    struct rt2501_scan_result r;
    int32_t rssi;
    uint32_t channel, rateset, encryption;
    memset(&r, 0, sizeof r);
    rs_net_scan_result(i, r.ssid, r.mac, r.bssid, &rssi, &channel, &rateset, &encryption);
    r.rssi = rssi;
    r.channel = channel;
    r.rateset = rateset;
    r.encryption = encryption;
    callback(&r, userparam);
  }
}
void rt2501_auth(const uint8_t *ssid, const uint8_t *mac, const uint8_t *bssid, uint8_t channel,
                 uint16_t rateset, uint8_t authmode, uint8_t encryption, const uint8_t *key)
{
  /* The key is a string of the machine: its length is in its header. */
  uint32_t key_len = key ? (uint32_t)(((const int32_t *)key)[-3] >> 8) : 0;
  rs_net_auth(ssid, ssid ? strlen((const char *)ssid) : 0, ssid != NULL, mac, bssid, channel, rateset,
              authmode, encryption, key, key_len, key != NULL);
  sync();
}
void mypassword_to_pmk(const uint8_t *password, uint8_t *ssid, int32_t ssidlength, uint8_t *pmk)
{
  rs_net_pmk(ssid, ssidlength, password, strlen((const char *)password), pmk);
  sync();
}

/* Where the C machine was when it touched memory the host does not
 * have: on the rabbit that read or write lands somewhere in its RAM. */
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
extern int32_t _currentop;
static void on_fault(int sig, siginfo_t *info, void *ctx)
{
  (void)ctx;
  fprintf(stderr, "C machine: signal %d at %p (heap %p..%p), op %d, stack %d, heap index %d\n", sig,
          info->si_addr, (void *)_vmem_heap, (void *)(_vmem_heap + VMEM_LENGTH), _currentop, _vmem_stack,
          _vmem_heapindex);
  _exit(70);
}

/* The firmware's main, minus the hardware. */
void cvm_reset(void);
void cvm_boot(const uint8_t *bytecode)
{
  static uint8_t alt[65536];
  stack_t ss;
  struct sigaction sa;
  ss.ss_sp = alt;
  ss.ss_size = sizeof alt;
  ss.ss_flags = 0;
  sigaltstack(&ss, NULL);
  memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = on_fault;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  cvm_reset();
  if (setjmp(on_reset)) return;
  rs_net_mac(rt2501_mac);
  sync();
  vmemInit(0);
  loaderInit((uint8_t *)bytecode);
  VPUSH(INTTOVAL(0));
  interpGo();
  (void)VPULL();
}

static uint8_t frame[4096];
static uint8_t counttimer;

void cvm_loop_once(void)
{
  uint32_t t;
  if (setjmp(on_reset)) return;
  VPUSH(VCALLSTACKGET(_sys_start, SYS_CBLOOP));
  if (VSTACKGET(0) != NIL)
    interpGo();
  (void)VPULL();
  sync();
  t = counter_timer;
  do
  {
    int32_t len;
    play_check(0);
    rec_check();
    rs_usb_events();
    sync();
    while ((counter_timer - t < 1000) && ((len = rs_net_pending()) >= 0))
    {
      uint8_t mac[6];
      sync();
      if (len > (int32_t)sizeof frame) len = sizeof frame;
      rs_net_take(frame, mac);
      sync();
      netCb(frame, len, mac);
      play_check(0);
      rec_check();
    }
    sync();
  } while (counter_timer - t < 50);
  counttimer = (counttimer + 1) & 3;
  if (!counttimer)
  {
    rs_net_timer();
    sync();
  }
}

uint32_t cvm_heap_address(void) { return (uint32_t)(uintptr_t)_vmem_heap; }
int32_t *cvm_heap(void) { return _vmem_heap; }
uint8_t *cvm_fifo(void) { return audioFifoPlay; }
int32_t cvm_stack(void) { return _vmem_stack; }
int32_t cvm_heapindex(void) { return _vmem_heapindex; }
int32_t cvm_start(void) { return _vmem_start; }
int32_t cvm_broken(void) { return _vmem_broken; }

/* The machine's own state, back to what a fresh board has. */
extern int32_t rndval, play_w, play_r, valtrytofeed, _currentop, nscan;
extern uint8_t play_state, rec_state;
void cvm_reset(void)
{
  memset(_vmem_heap, 0, sizeof _vmem_heap);
  memset(audioFifoPlay, 0, AUDIO_FIFOPLAY);
  rndval = 0;
  play_w = play_r = 0;
  play_state = rec_state = 0;
  valtrytofeed = 2048;
  _currentop = -1;
  counttimer = 0;
}
