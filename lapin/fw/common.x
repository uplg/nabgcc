/* What the application (link.x) and the rescue core (rescue.x) lay out
   the same way: the internal RAM, its first four words shared between
   the two and left alone (src/boot.rs), and the external RAM. */
MEMORY
{
  RAM   (rw)  : ORIGIN = 0x10000010, LENGTH = 16K - 16
  /* External static RAM, 1 MB: big buffers, later the bytecode's heap. */
  XRAM  (rw)  : ORIGIN = 0xD0000000, LENGTH = 1024K
}

/* Stacks grow down from the top of the internal RAM: 1 KB for
   interrupts, then up to 12 KB for the program (measured at most 6.9 KB
   in the emulator, tools/emu/tests/limits.rs). The data must end below
   both, with room to spare. */
__stack_top = 0x10004000;
__irq_stack_size = 0x400;

SECTIONS
{
  .data : ALIGN(4)
  {
    __data_start = .;
    /* First: the flash routines, copied again before every use. */
    __ramcode_start = .;
    *(.data.ramcode .data.ramcode.*)
    . = ALIGN(4);
    __ramcode_end = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > RAM AT > FLASH
  __data_load = LOADADDR(.data);
  __ramcode_load = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4)
  {
    __bss_start = .;
    *(.bss .bss.*)
    . = ALIGN(4);
    __bss_end = .;
  } > RAM

  /* Never initialised: what lives here is scratch space. */
  .xram (NOLOAD) : ALIGN(4)
  {
    *(.xram .xram.*)
  } > XRAM

  /* The bytecode's memory, where the C firmware put it: its address
     shows in the collector's reports. */
  .vmem 0xD0010000 (NOLOAD) : ALIGN(4)
  {
    *(.vmem .vmem.*)
  } > XRAM

  ASSERT(__bss_end <= __stack_top - __irq_stack_size - 12K - 2K,
         "the internal RAM's data leaves too little room for the stacks")

  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
}
