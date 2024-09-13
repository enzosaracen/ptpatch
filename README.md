# ptpatch
`ptpatch` is a dynamic binary patching tool for Linux that uses ptrace to modify the behavior of binaries at runtime, allowing for the injection of arbitrarily complex logic. This is accomplished through a tracing stub with user-defined hooks that can control the tracee's registers/memory, triggered at specific breakpoints or conditions. Only x86-64 binaries are currently supported.

## Installation
Run `./build.sh` in the project's root directory. The `./ptpatch` symlink should now point to the CLI binary (located at `./cli/target/release/ptpatch`). `cargo`+`rustc` and `gcc` are required.

## Usage
`ptpatch` CLI takes a list of file path arguments. Each file should be in the patch file format described below. These patches will be grouped to generate a `stub.gen.c` that's automatically compiled to a `stub.out` executable. You can apply the patches to any executable by running `./stub.out exe args...`

Alternatively, the stub can embed a single binary file using the `--embed` flag followed by a path to that binary. Running the embedded `stub.out` will execute the stub with that binary directly, passing through all arguments. This avoids an `execve` call by mimicking its behavior in-process, similar to how UPX works (although no compression is applied during the embedding).

## Format

Patch files are written in a specific format that combines C code with special markers to define hooks. Code written for patches is compiled using Linux's [nolibc](https://elixir.bootlin.com/linux/v6.10.9/source/tools/include/nolibc) to minimize stub size, so certain libc features may not be available. The structure of patch files is outlined as follows.

1. **Globals**: Declarations of global variables or functions accessible by all hooks.

 ```c
 int break_cnt = 0;
 long saved_rdx = 0;
 ```

2. **Delimiter**: A line containing only `%%` separates the global declarations from the hooks.

 ```c
 %%
 ```

3. **Hooks**: Enclosed by `<@` and `@>` with a specified breakpoint or condition.

 ```c
 <@ breakpoint
     // hook code
 @>
 ```

The different breakpoint types are defined as follows:

- **Address-based**: use a C expression that evaluates to an address.
    ```c
    <@ base+0x1234
        // code to be executed each time we hit base+0x1234
    @>
    ```
    `base` is a predefined variable representing the executable's base address (useful for PIE executables).

- **Pre-syscall**: code to execute before the entry of a certain syscall (specified by name or number).
    ```c
    <@ pre-syscall write
      // modify syscall arguments
    @>
    ```

- **Post-syscall**: code to execute after the completion of a certain syscall.
    ```c
    <@ post-syscall write
      // inspect or modify return values
    @>
    ```

The code within each hook has access to the following predefined variables and functions.

- `regs`: struct `user_regs_struct` representing the current register state. Modifications will be applied to the tracee once the hook returns.

- `pid`: pid of the tracee.

- `mem_write(char *addr, char *buf, int n)`: write `n` bytes from `buf` to the tracee's memory at `addr`.

- `mem_read(char *addr, char *buf, int n)`: read `n` bytes from the tracee's memory at `addr` into `buf`.

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
