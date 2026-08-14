/*
 * RAM-resident flash-programming stub for the Nabaztag V2 (OKI ML67Q4051).
 *
 * Replaces the lost RedoX `ml67q40xx` OpenOCD flash driver: a stock OpenOCD
 * (>= 0.12) loads this stub into internal RAM over JTAG, fills a 4 KB buffer
 * with one flash sector's worth of data, sets the parameter block, and runs
 * the stub. The stub erases the target sector and programs it using the same
 * JEDEC SPD command sequences as the firmware's own self-update code
 * (vendor/nabgcc/src/utils/mem.c), then parks in an infinite loop with a
 * status word the host polls.
 *
 * Memory map (IntRAM, 16 KB @ 0x10000000):
 *   0x10000000  stub code (this file, entry point first)
 *   0x10000FE0  parameter block: [0]=status [1]=flash dst addr [2]=byte count
 *   0x10001000  4 KB data buffer (one flash sector)
 *   0x10003FF0  initial stack pointer (grows down)
 *
 * Status values:
 *   0xB0B0B0B0  busy (host sets this before resume)
 *   0xD00ED00E  done, sector programmed
 *   0xBAD0BAD0  bad parameters (unaligned dst, out of range, or > 4 KB —
 *               includes any attempt to touch the config sector at 0x1F000)
 *   0xBADE7A5E  erase timed out
 *   0xBAD00075  program timed out
 *
 * Built with build-stub.sh (arm-none-eabi-gcc in Docker). Driven by
 * flash-jtag.tcl.
 */

#define FLACON (*(volatile unsigned char *)0xB7000100)
#define TBGCON (*(volatile unsigned char *)0xB7E00004)

#define FLASH_BASE 0x08000000u
#define CONFIG_SECTOR_OFF 0x1F000u /* sector 31: WiFi conf, serial — never erase */
#define SECTOR_SIZE 4096u

#define SPD_UNLOCK1 (*(volatile unsigned char *)(FLASH_BASE + 0x15554))
#define SPD_UNLOCK2 (*(volatile unsigned char *)(FLASH_BASE + 0x0AAA8))

#define PARAMS ((volatile unsigned int *)0x10000FE0)
#define BUF ((volatile unsigned char *)0x10001000)

#define ST_BUSY 0xB0B0B0B0u
#define ST_DONE 0xD00ED00Eu
#define ST_BAD_PARAMS 0xBAD0BAD0u
#define ST_ERASE_TIMEOUT 0xBADE7A5Eu
#define ST_PROG_TIMEOUT 0xBAD00075u

#define NOPS() __asm__ volatile("nop\n\tnop\n\tnop")

void stub_main(void);

__attribute__((naked, section(".text.entry"))) void _start(void)
{
  __asm__ volatile("ldr sp, =0x10003FF0\n\t"
                   "bl stub_main\n\t"
                   "1: b 1b");
}

/* mem.c waits for (FLACON & 0x0E) == 0x02: command done, no error bits. */
static int wait_flash_ready(void)
{
  unsigned long t;
  for (t = 0; t < 40000000UL; t++) {
    if ((FLACON & 0x0E) == 0x02)
      return 1;
  }
  return 0;
}

static void park(unsigned int status)
{
  PARAMS[0] = status;
  for (;;)
    ;
}

void stub_main(void)
{
  unsigned int dst = PARAMS[1];
  unsigned int n = PARAMS[2];
  volatile unsigned char *out = (volatile unsigned char *)dst;
  unsigned int i;

  if (dst < FLASH_BASE || (dst & (SECTOR_SIZE - 1)) != 0 || n == 0 ||
      n > SECTOR_SIZE || (dst - FLASH_BASE) + n > CONFIG_SECTOR_OFF)
    park(ST_BAD_PARAMS);

  /* Stop the watchdog clock, as mem.c does before touching flash. */
  TBGCON |= 0x80;
  NOPS();

  /* Erase the sector (SPD sequence + sector address, command 0x30). */
  FLACON = 0x03;
  NOPS();
  SPD_UNLOCK1 = 0xAA;
  SPD_UNLOCK2 = 0x55;
  SPD_UNLOCK1 = 0x80;
  SPD_UNLOCK1 = 0xAA;
  SPD_UNLOCK2 = 0x55;
  *out = 0x30;
  NOPS();
  if (!wait_flash_ready())
    park(ST_ERASE_TIMEOUT);

  /* Program 4 bytes at a time (SPD command 0xA0), skipping all-0xFF groups. */
  for (i = 0; i < n; i += 4) {
    unsigned char b0 = BUF[i];
    unsigned char b1 = (i + 1 < n) ? BUF[i + 1] : 0xFF;
    unsigned char b2 = (i + 2 < n) ? BUF[i + 2] : 0xFF;
    unsigned char b3 = (i + 3 < n) ? BUF[i + 3] : 0xFF;

    if (b0 == 0xFF && b1 == 0xFF && b2 == 0xFF && b3 == 0xFF)
      continue;

    FLACON = 0x03;
    NOPS();
    SPD_UNLOCK1 = 0xAA;
    SPD_UNLOCK2 = 0x55;
    SPD_UNLOCK1 = 0xA0;
    out[i] = b0;
    out[i + 1] = b1;
    out[i + 2] = b2;
    out[i + 3] = b3;
    NOPS();
    if (!wait_flash_ready())
      park(ST_PROG_TIMEOUT);
  }

  /* Re-prohibit flash programming. */
  FLACON = 0x02;
  NOPS();

  park(ST_DONE);
}
