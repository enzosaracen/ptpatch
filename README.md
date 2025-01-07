# ptpatch
`ptpatch` is a tool for patching Linux executables with a ptracing stub to inspect and modify behavior at runtime. Patches are defined by a series of hook functions written in C with full control over the process's registers/memory, triggered at specific breakpoints or conditions. Only x86-64 binaries are currently supported.

## Installation
Run `./install.sh`. `cargo` and `gcc` are required.

## Usage
The `ptpatch` CLI accepts one or more patch file arguments in the [custom format described below](#format).
```
ptpatch [options] [patch_files ...]
```
A `stub.gen.c` file will be generated and automatically compiled to `stub.out`.
By default, `stub.out` will be isolated, meaning it can be run with any executable by specifying its path as the first argument.
```
./stub.out /path/to/exe [args_for_exe ...]
```
The `--embed` or `-e` option to `ptpatch` takes a single executable file argument and embeds its contents into `stub.out`,
causing `stub.out` to always run that executable.
The size of stubs and thus overhead of embedding is usually below 0x2800 bytes.

See some [example uses of ptpatch here.](examples)

## Format
Patch files combine C code with special markers to define a series of hook functions. Code written in patch files is compiled with Linux's [nolibc](https://lwn.net/Articles/920158/) to minimize stub size, so certain libc features may not be available. The structure of a patch file is outlined as follows.

1. **globals**: global variable/function declarations accessible by all hooks

 ```c
 int break_cnt;
 long saved_rdx;
 ```

2. **delimiter**: line containing only `%%` to indicate end of globals

 ```c
 %%
 ```

3. **hooks**: C code enclosed by `<@` and `@>` with a specified breakpoint on the same line after `<@`

 ```c
 <@ breakpoint
     // code
 @>
 ```

The code within each hook has access to the following predefined variables and functions.

- `pid`: pid of the tracee
- `regs`: struct `user_regs_struct` representing the current register state, modifications will be applied to the tracee after the hook returns
- `int mem_write(char *addr, char *buf, int n)`: write `n` bytes from `buf` to the tracee's memory at `addr`, return `0` on success
- `int mem_read(char *addr, char *buf, int n)`: read `n` bytes from the tracee's memory at `addr` into `buf`, return `0` on success

The different breakpoint types are defined as follows.

- **address-based**: executes whenever PC reaches the address, specified by a C expression
    ```c
    <@ base+0x1234
        // code to execute each time we hit base+0x1234
    @>
    ```
    `base` is a predefined variable representing the executable's base address (useful for PIE)

- **pre-syscall**: executes before the entry of a certain syscall, specified by name or number, comma separated list for multiple syscalls
    ```c
    <@ pre-syscall write, read, 96
      // modify syscall arguments
    @>
    ```

- **post-syscall**: executes after the completion of a certain syscall
    ```c
    <@ post-syscall write, read, 96
      // inspect or modify return values
    @>
    ```
- **fork**: executes when a tracee triggers a fork, vfork, or clone. the new child pid will be stored in a local variable `child`. setting the local variable `should_trace` to `0` will prevent the child from being traced. `regs` for the parent is available to modify as usual, but `child_regs` is also available for registers of the new child. `mem_write` and `mem_read` will operate on the parent by default, but can be switched to the child by setting the global variable `cur_pid` to the child's pid. caution: if using address breakpoints and you stop tracing the child, hitting those traps in the child will cause a crash as there is no tracer to handle them. this can be fixed by resetting breakpoints on detach, but it's not yet implemented
    ```c
    <@ fork
      // inspect or modify state, decide whether to trace child
      if (regs.r15 == 0x42 || child == 69420)
          should_trace = 0;
      else
          child_regs.r15 = 0x100;
    @>
    ```
- **status**: executes when the tracer receives an unhandled status (anything besides a trap from a breakpoint or syscall) from one of it's tracees. the status is available within the local variable `status`. the local variable `should_exit` can be set to `1` to cause the tracer to exit after the handler returns, or `-1` to force the tracer to not exit. otherwise, whether the tracer exits depends on the rules for exiting defined in the `Exiting` section below. `regs` will try to be gathered for inspecting/modifying, however, it is likely this will fail due to the process having exited, so before accessing `regs`, check the local variable `is_regs` which will be set to `1` if `regs` is usable
    ```c
    <@ status
        // inspect or modify state, decide whether to exit the tracer based on status
        if (WIFEXITED(status))
            should_exit = 1;
    @>
    ```

**Exiting**

The tracer will exit upon receiving an unhandled status in which the status handler hook returns a `1`, or, as long as the status handler return value is not `-1`, if the process's pid equals the global variable `focus_pid`. `focus_pid` is set to the original process's pid by default, so children exiting will not cause the tracer to exit. `focus_pid` can be changed from within a hook function. If `focus_pid` is set to `-1`, an unhandled status from any process will cause the tracer to exit. Additionally, the global variable `exit_now` can be set to `1` from within a hook to immediately exit the tracer. There is currently no support to set muliple different pids as focuses, but this logic can be implemented within the custom status handler.

**Example**
```c
// global variables
int break_cnt;
long saved_rdx;

%%

// hook at a specific address
<@ base+0x1168
    if (break_cnt > 69)
        return;
    printf("hit breakpoint %d times\n", break_cnt++);
@>

<@ pre-syscall write
    // modify the buffer being written
    mem_write((char*)regs.rsi, "intercepted!\n", 13);
    saved_rdx = regs.rdx;
    regs.rdx = 13; // update the number of bytes to write
@>

<@ post-syscall write
    // restore the original number of bytes written
    regs.rax = saved_rdx;
@>
```

[More examples here.](examples)

## Notes
When the stub runs with a dynamically linked program, it waits until the linker has transfered
control to the program's entry point before applying hooks.
During this process, it needs to be able to read maps from procfs to determine
the programs's base address (since we start at linker code and extracting base from memory would require nontrivial parsing of the stack).

## TODO
- Avoid memory leaks with collisions in the syscall entry pid hash table after processes exit
