# ptpatch
`ptpatch` is a dynamic binary patching tool for Linux that uses ptrace to inject arbitrarily complex modifications to the behavior of a binary at runtime. This is accomplished through a tracing stub with user-defined hooks that can control the tracee's registers/memory, triggered at specific breakpoints or conditions. Only x86-64 binaries are currently supported.

## Installation
Run `./install.sh`. `cargo` and `gcc` are required.

## Usage
The `ptpatch` CLI processes one or more patch files and generates a tracing stub that can run an arbitrary executable with the patches applied.

```
ptpatch [options] [patch_files ...]
```

The file `stub.gen.c` will be generated and automatically compiled to `stub.out`.

```
./stub.out /path/to/exe [args ...]
```

The `--embed` option passed to `ptpatch` followed by a file argument will embed the specified binary directly into `stub.out`. `stub.out` will then run the embedded binary without needing to specify it as an argument. This method avoids the need for an `execve` syscall by emulating its behavior in-process, similar to how UPX operates (but without applying compression).

## Format
Patch files are written in a specific format that combines C code with special markers to define hooks. Code written for patches is compiled using Linux's [nolibc](https://elixir.bootlin.com/linux/v6.10.9/source/tools/include/nolibc) to minimize stub size, so certain libc features may not be available. The structure of a patch file is outlined as follows.

1. **Globals**: Declarations of global variables or functions accessible by all hooks

 ```c
 int break_cnt;
 long saved_rdx;
 ```

2. **Delimiter**: A line containing only `%%` separates the global declarations from the hooks

 ```c
 %%
 ```

3. **Hooks**: Enclosed by `<@` and `@>` with a specified breakpoint

 ```c
 <@ breakpoint
     // hook code
 @>
 ```

The different breakpoint types are defined as follows:

- **Address-based**: use a C expression that evaluates to an address
    ```c
    <@ base+0x1234
        // code to execute each time we hit base+0x1234
    @>
    ```
    `base` is a predefined variable representing the executable's base address (useful for PIE executables)

- **Pre-syscall**: executes before the entry of a certain syscall (specified by name or number, comma separated list for multiple syscalls)
    ```c
    <@ pre-syscall write, read, 96
      // modify syscall arguments
    @>
    ```

- **Post-syscall**: executes after the completion of a certain syscall
    ```c
    <@ post-syscall write, read, 96
      // inspect or modify return values
    @>
    ```

The code within each hook has access to the following predefined variables and functions.

- `pid`: pid of the tracee

- `regs`: struct `user_regs_struct` representing the current register state, modifications will be applied to the tracee after the hook

- `mem_write(char *addr, char *buf, int n)`: write `n` bytes from `buf` to the tracee's memory at `addr`

- `mem_read(char *addr, char *buf, int n)`: read `n` bytes from the tracee's memory at `addr` into `buf`

**Example**
```c
// global variables
int break_cnt;
long saved_rdx;

%%

// hook at a specific address
<@ base+0x1151
    printf("Hit breakpoint at base+0x1151 %d times\n", break_cnt++);
@>

<@ pre-syscall write
    // modify the buffer being written
    mem_write((char *)regs.rsi, "intercepted!\n", 13);
    saved_rdx = regs.rdx;
    regs.rdx = 13; // update the number of bytes to write
@>

<@ post-syscall write
    // restore the original number of bytes written
    regs.rax = saved_rdx;
@>
```
