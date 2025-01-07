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
```
ptpatch patch.ptp -e exe
./stub.out [args_for_exe ...]
```

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
- `mem_write` and `mem_read` will operate on the process that triggered the hook by default, but can be switched to an arbitrary process by temporarily setting the global variable `cur_pid`. `cur_pid` should be restored to `pid` before the hook exits

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
- **fork**: executes when a tracee triggers a fork, vfork, or clone. the new child pid will be stored in a local variable `child`. setting the local variable `should_trace` to `0` will prevent the child from being traced. `regs` for the parent is available to modify as usual, but `child_regs` is also available for registers of the new child.  caution: if using address breakpoints and you stop tracing the child, hitting those traps in the child will cause a crash as there is no tracer to handle them. this can be fixed by resetting breakpoints on detach, but it's not yet implemented
    ```c
    <@ fork
        // inspect or modify state, decide whether to trace child
        if (regs.r15 == 0x42 || child == 69420)
            should_trace = 0;
        else
            child_regs.r15 = 0x100;
    @>
    ```
- **status**: executes when the tracer receives an unhandled status (anything besides a trap from a breakpoint or syscall). the status is available within the local variable `status`. `regs` will try to be gathered for inspecting/modifying, however, it is likely this will fail due to the process having exited, so before accessing `regs`, check the local variable `is_regs` which will be set to `1` if `regs` is usable. the `should_detach` global will be set to the value of `!is_regs` by default, meaning unless overridden, the tracer will detach from the tracee that triggered the status if regs is not accessible
    ```c
    <@ status
        // inspect or modify state, decide whether to exit the tracer based on status
        if (WIFEXITED(status)) {
            exit_now = 1;
            return;
        }
        if (is_regs)
            printf("rip = %p\n", regs.rip);
        should_detach = 0;
    @>
    ```

**Exiting**

The tracer will exit if the global variable `exit_now` is ever set to `1` from within a hook, or if a tracee with pid equal to the global variable `focus_pid` is detached. `focus_pid` is initially the first pid but can be modified within hooks.

**Detaching**

To detach from a tracee, set the global variable `should_detach` to `1` from within a hook. The tracee which triggered the hook will be detached after the hook returns.

**Pausing**

The execution of a tracee can be paused/unpaused by passing its pid to the following functions, accessible within hooks:
```c
void pid_pause(int pid);
void pid_unpause(int pid);
```
The following function returns `1` if the pid is paused and `0` otherwise.
```c
int pid_is_paused(int pid);
```
Pausing a tracee prevents it from resuming after its next breakpoint until `pid_unpause` is called, but the associated hook will still run. Pausing will not issue an interrupt and thus only takes effect after the next breakpoint. If a hook initiated from pid `A` pauses pid `A`, pid `A` will not continue execution after the hook.

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
- Maybe find a better way to differentiate syscall entry/exit and pausing, global pid table can cause memory leaks if processes don't properly detach
