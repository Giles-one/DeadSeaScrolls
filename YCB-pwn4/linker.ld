PHDRS
{
    text PT_LOAD FLAGS(7);  /* 7 = Read + Write + Execute */
}

SECTIONS
{
    . = 0x800000;
    .text : 
    {
        *(.text)
        *(.data)
        *(.bss)
    } : text
}