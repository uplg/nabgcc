/* The rescue core (src/bin/rescue.rs, src/boot.rs): the first 20 KB of
   the flash, the processor's vectors at their head. The internal RAM
   is laid out as the application's (link.x), its first four words
   shared and left alone. */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 20K
  RAM   (rw)  : ORIGIN = 0x10000010, LENGTH = 16K - 16
  /* External static RAM, 1 MB: big buffers, later the bytecode's heap. */
  XRAM  (rw)  : ORIGIN = 0xD0000000, LENGTH = 1024K
}

ENTRY(_start)

/* Stacks grow down from the top of the internal RAM: 1 KB for
   interrupts, then up to 12 KB for the program (measured at most 6.9 KB
   in the emulator, tools/emu/tests/limits.rs). The data must end below
   both, with room to spare. */
__stack_top = 0x10004000;
__irq_stack_size = 0x400;

SECTIONS
{
  .text :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH

  .data : ALIGN(4)
  {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > RAM AT > FLASH
  __data_load = LOADADDR(.data);

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

  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.app_header) }
}
