/* Linker script for the Nabaztag JTAG flash stub: everything in IntRAM,
 * entry point at the very first byte (0x10000000) so the host can simply
 * `resume 0x10000000`. No .data/.bss — the stub uses only fixed addresses
 * and the stack. */
ENTRY(_start)
SECTIONS
{
  . = 0x10000000;
  .text : {
    *(.text.entry)
    *(.text*)
    *(.rodata*)
  }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
