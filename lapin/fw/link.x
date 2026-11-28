/* Memory of the ML67Q4051 as the rabbit's board uses it, for the
   application (see src/boot.rs): the first 20 KB of the flash are the
   rescue core's (rescue.x), the last 4 KB sector holds the settings.
   The RAM is laid out as the rescue core's (common.x). */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08005000, LENGTH = 104K
}

ENTRY(reset)

SECTIONS
{
  .text :
  {
    KEEP(*(.app_header))
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH
}

INCLUDE common.x
