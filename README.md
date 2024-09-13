# ptpatch
`ptpatch` is a dynamic binary patching tool for Linux that uses ptrace to inject arbitrarily complex modifications to the behavior of a binary at runtime. This is accomplished through a tracing stub with user-defined hooks that can control the tracee's registers/memory, triggered at specific breakpoints or conditions. Only x86-64 binaries are currently supported.

## Installation
Run `./build.sh` in the project's root directory. The `./ptpatch` symlink should now point to the CLI binary (located at `./cli/target/release/ptpatch`). `cargo`+`rustc` and `gcc` are required.

## Usage
The `ptpatch` CLI processes one or more patch files and generates a tracing stub that can be used to run a target executable with the patches applied.

```
ptpatch [options] [patch_files ...]
```

The file `stub.gen.c` will be generated and automatically compiled to `stub.out`

```
./stub.out /path/to/exe [args ...]
```

The `--embed` option with a file argument causes `stub.out` to contain a single binary such that executing `stub.out` will always run the embedded binary and apply patches. This method avoids the need for an execve syscall by mimicking its behavior in-process, similar to how UPX operates (but without compression).


## Format
Patch files are written in a specific format that combines C code with special markers to define hooks. Code written for patches is compiled using Linux's [nolibc](https://elixir.bootlin.com/linux/v6.10.9/source/tools/include/nolibc) to minimize stub size, so certain libc features may not be available. The structure of a patch file is outlined as follows.

1. **Globals**: Declarations of global variables or functions accessible by all hooks

 ```c
 int break_cnt = 0;
 long saved_rdx = 0;
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

- **Pre-syscall**: code to execute before the entry of a certain syscall (specified by name or number)
    ```c
    <@ pre-syscall write
      // modify syscall arguments
    @>
    ```

- **Post-syscall**: code to execute after the completion of a certain syscall
    ```c
    <@ post-syscall write
      // inspect or modify return values
    @>
    ```

The code within each hook has access to the following predefined variables and functions

- `pid`: pid of the tracee

- `regs`: struct `user_regs_struct` representing the current register state, modifications will be applied to the tracee after the hook

- `mem_write(char *addr, char *buf, int n)`: write `n` bytes from `buf` to the tracee's memory at `addr`

- `mem_read(char *addr, char *buf, int n)`: read `n` bytes from the tracee's memory at `addr` into `buf`

**Example**
```c
// Global variables
int break_cnt = 0;
long saved_rdx = 0;

%%

// Hook at a specific address
<@ base+0x1151
    break_cnt++;
    printf("Hit breakpoint at base+0x1151 %d times\n", break_cnt);
@>

<@ pre-syscall write
    // Intercept and modify the buffer being written
    mem_write((char *)regs.rsi, "intercepted!\n", 13);
    saved_rdx = regs.rdx;
    regs.rdx = 13; // Update the number of bytes to write
@>

<@ post-syscall write
    // Restore the original number of bytes written
    regs.rax = saved_rdx;
@>
```
