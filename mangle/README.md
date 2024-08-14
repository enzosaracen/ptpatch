# mangling
we use a few types of mangling to make memory corruption vulns harder to exploit and to obfuscate our patches

1. variable relocation
randomly relocate variables in memory. this is done both through ELF relocs but also pattern matching against certain instructions 

2. code relocation
randomly chunk code blocks, rearrange them, and add instructions to chain them together to imitate original control flow

3. SMC layering
on top of code relocations, pack code blocks using state dependent SMC, separate from the external ptpacker which adds additional layers of obfuscation and compression

4. ELF header
corrupt and overlap the binary's ELF header to the extent that Linux will allow
