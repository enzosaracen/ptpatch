ENTRY(_start)
SECTIONS
{
    . = 0x13370000;
    .text :
    {
        *(.text)
    }
}
