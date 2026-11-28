/* The rescue core (src/bin/rescue.rs, src/boot.rs): the first 20 KB of
   the flash, the processor's vectors at their head. The RAM is laid
   out as the application's (common.x). */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 20K
}

ENTRY(_start)

SECTIONS
{
  .text :
  {
    KEEP(*(.vectors))
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH

  /* The application's header, which start.rs brings along. */
  /DISCARD/ : { *(.app_header) }
}

INCLUDE common.x
