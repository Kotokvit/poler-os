ENTRY(_start)

SECTIONS {
    . = 1M;

    /* Multiboot header — must be 8-byte aligned and in first 8KB of image */
    .rodata.boot : ALIGN(8) {
        KEEP(*(.rodata.boot))
    }

    .text.boot : ALIGN(4K) {
        KEEP(*(.text.boot))
    }

    .text : ALIGN(4K) {
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
