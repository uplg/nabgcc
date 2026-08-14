# Flash a Nabaztag V2 (ML67Q4051) over JTAG using the RAM stub — no custom
# OpenOCD flash driver required. Works with stock OpenOCD >= 0.12.
#
# Preparation (on the Pi, in this directory):
#   split -b 4096 -d -a 3 firmware.bin chunk_        # 4 KB sector chunks
#
# Backup then flash:
#   sudo openocd -f nabaztag-pi1.cfg -f flash-jtag.tcl \
#     -c "init; backup_flash bricked-backup.bin; flash_rabbit firmware.bin; shutdown"
#
# Or interactively: sudo openocd -f nabaztag-pi1.cfg, then from
# `telnet localhost 4444`: backup_flash ... / flash_rabbit ...

set STUB_ADDR   0x10000000
set PARAM_ADDR  0x10000FE0
set BUF_ADDR    0x10001000
set ST_BUSY     0xB0B0B0B0
set ST_DONE     0xD00ED00E
set FLASH_BASE  0x08000000
set MAX_IMAGE   0x1F000   ;# sectors 0-30 only; sector 31 (config) is protected

proc backup_flash {outfile} {
    reset halt
    echo "Dumping 128 KB of flash to $outfile (takes a few minutes)..."
    dump_image $outfile 0x08000000 0x20000
    echo "Backup done: $outfile"
}

proc flash_rabbit {binfile} {
    global STUB_ADDR PARAM_ADDR BUF_ADDR ST_BUSY ST_DONE FLASH_BASE MAX_IMAGE

    set size [file size $binfile]
    if {$size > $MAX_IMAGE} {
        error "image is $size bytes, max is $MAX_IMAGE (config sector protected)"
    }

    set chunks [lsort [glob chunk_*]]
    set expected [expr {($size + 4095) / 4096}]
    if {[llength $chunks] != $expected} {
        error "found [llength $chunks] chunk_* files, expected $expected.\
               Run: split -b 4096 -d -a 3 $binfile chunk_"
    }

    reset halt
    echo "Loading stub..."
    load_image stub.bin $STUB_ADDR bin

    set off 0
    foreach f $chunks {
        set csize [file size $f]
        set dst [expr {$FLASH_BASE + $off}]
        echo [format "Sector %2d: %s (%d bytes) -> 0x%08X" \
                  [expr {$off / 4096}] $f $csize $dst]

        load_image $f $BUF_ADDR bin
        mww $PARAM_ADDR $ST_BUSY
        mww [expr {$PARAM_ADDR + 4}] $dst
        mww [expr {$PARAM_ADDR + 8}] $csize
        reg cpsr 0x000000d3
        resume $STUB_ADDR

        set st $ST_BUSY
        for {set t 0} {$t < 100} {incr t} {
            sleep 100
            halt
            set st [read_memory $PARAM_ADDR 32 1]
            if {$st != $ST_BUSY} { break }
            resume
        }
        if {[format 0x%08X $st] ne [format 0x%08X $ST_DONE]} {
            error [format "sector at 0x%08X failed, stub status 0x%08X" $dst $st]
        }
        incr off 4096
    }

    echo "All sectors written. Verifying..."
    verify_image $binfile $FLASH_BASE bin
    echo "Verify OK — arming tripwire flag and resetting the rabbit."
    # DIAG tripwire (init.s): 0x10003EC0 must be 0 after a real reset so the
    # first pass through address 0 is recognized as a legitimate boot.
    mww 0x10003EC0 0
    mww 0x10003EC4 0
    reset run
}
