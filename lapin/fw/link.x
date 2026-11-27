/* Memory of the ML67Q4051 as the rabbit's board uses it. The last
   4 KB sector of the flash holds the settings and is not ours. */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 124K
  RAM   (rw)  : ORIGIN = 0x10000000, LENGTH = 16K
  /* External static RAM, 1 MB: big buffers, later the bytecode's heap. */
  XRAM  (rw)  : ORIGIN = 0xD0000000, LENGTH = 1024K
}

ENTRY(_start)

/* Stacks grow down from the top of the internal RAM: 1 KB for
   interrupts, the rest of the top 5 KB for the program. */
__stack_top = ORIGIN(RAM) + LENGTH(RAM);
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

  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
}
