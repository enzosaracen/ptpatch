# ptpatch
`ptpatch` is a tool for patching Linux executables with a ptracing stub to inspect and modify behavior at runtime. Patches are defined by a series of hook functions written in C with full control over traced processes' registers/memory, triggered at specific breakpoints or conditions. Only x86-64 binaries are currently supported.

## Installation
Run `./install.sh`. `cargo` and `gcc` are required.

## Usage
The `ptpatch` CLI accepts one or more patch file arguments in the [custom format described below](#format).
```
ptpatch [options] [patch_files ...]
```
A `stub.gen.c` file will be generated and automatically compiled to `stub.out`.
By default, `stub.out` will be generic, meaning it can be run with any executable by specifying its path as the first argument.
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
Patch files combine C code with special markers to define a series of hook functions. These hooks are executed each time a process being traced (tracee) triggers the hook's associated breakpoint condition. There will always be a single tracer process responsible for detecting and running hooks. There will initially be a single tracee corresponding to the first process spawned by the executable, but additional tracees may be added or dropped as this tracee spawns children. Code written in patch files is compiled with Linux's [nolibc](https://lwn.net/Articles/920158/) to minimize stub size, so certain libc features may not be available. The structure of a patch file is outlined as follows.

1. **globals**: global variable/function declarations accessible by all hooks

 ```c
 int break_cnt;
 long saved_rdx;
 ```

2. **delimiter**: line containing only `%%` to indicate end of globals

 ```c
 %%
 ```

3. **hooks**: C code enclosed by `<@` and `@>` with a specified breakpoint on the same line after `<@`, a patch file can contain any number of hooks

 ```c
 <@ breakpoint
     // code
 @>
 ```
The different breakpoint formats [are described later in this section.](##breakpoints)

## Hooks
The code within each hook is executed whenever a tracee triggers the breakpoint condition. The tracee which triggered a hook will be referred to as the current tracee. Multiple hooks with overlapping breakpoint conditions are not allowed. Hook code should be treated as code within a C function returning `void`, so `return;` can be used to exit a hook early. Hook code has access to a variety of predefined variables/functions described in the following sections. Hooks with certain breakpoint types may have access to additional variables which are described [in the breakpoints section.](##breakpoints)

### Variables
- **`int pid`**
    - PID of the current tracee.

- **`struct user_regs_struct regs`**
    - Register state of the current tracee, modifications will be applied to the tracee after the hook returns.

- **`int exit_now`**
    - If set to a non-zero value, the tracer will exit immediately after the hook returns.

- **`int should_detach`**
    - If set to a non-zero value, the tracer will detach from the current tracee after the hook returns. `should_detach` is set to `0` by default, with the exception of `status` breakpoints, [more details in this section.](###status))

- **`int focus_pid`**
    - The tracer will exit if a tracee with PID equal to `focus_pid` is detached. `focus_pid` is set to the first tracee's PID by default. This is a global variable that is persistent across hooks.

### Functions
#### Pausing
The functions below interface pause management.
Most ptrace operations require the tracee to be in a stopped state.
While the current tracee is always stopped, operations on other tracees from within a hook require explicit pausing.
Pausing does not issue interrupts and thus only takes effect after the tracee's next breakpoint, at which point the hook will execute, but the tracee will not be resumed. Note that a pause cannot take effect within the hook that scheduled it, although unpausing works immediately.
- **`int pid_pause(int pid)`**
    - Schedule a pause for tracee with PID equal to `pid`, return `0` on success.
- **`int pid_unpause(int pid)`**
    - Immediately unpause tracee with PID equal to `pid`, return `0` on success.
- **`int pid_is_paused(int pid)`**
    - For tracee with PID equal to `pid`, return `1` if paused, `0` if unpaused, or `-1` on error.
- **`int pid_exists(int pid)`**
    - If there exists a tracee with PID equal to `pid`, return `1`, else `0`.
#### Memory
The functions below interface memory transfer between tracer and tracee.
- **`int mem_write(char *addr, char *buf, int n)`**
    - Write `n` bytes from `buf` (in the tracer's memory) to the current tracee's memory at `addr`, return `0` on success.
- **`int mem_read(char *addr, char *buf, int n)`**
    - Read `n` bytes from the current tracee's memory at `addr` into `buf` (in the tracer's memory), return `0` on success.
- **`int pid_mem_write(int pid, char *addr, char *buf, int n)`**
    - Perform `mem_write` on a paused tracee with PID equal to `pid`.
- **`int pid_mem_read(int pid, char *addr, char *buf, int n)`**
    - Perform `mem_read` on a paused tracee with PID equal to `pid`.
#### Injection
The functions below interface syscall injection into tracees. Injected syscalls are executed immediately and will not trigger any hooks. Register state will be saved and restored before function return. The return value is the syscall return value, and any injection failure will exit the tracer. As an exception, `pid_inject_syscall` will return `-1` if the passed PID does not correspond to a valid paused tracee. This is indistinguishable from a normal syscall return value, so ensure `pid_is_paused(pid) == 1` to guarantee a syscall actually occurred.
- **`long inject_syscall(long nr, long a1, long a2, long a3, long a4, long a5, long a6)`**
    - Execute a syscall in the current tracee with syscall number `nr` and arguments `a1` through `a6`, return the syscall return value.
- **`long pid_inject_syscall(int pid, long nr, long a1, long a2, long a3, long a4, long a5, long a6)`**
    - Perform `inject_syscall` on a paused tracee with PID equal to `pid`.

## Breakpoints
The different breakpoint types are defined as follows.

### Address-based
Executes whenever PC reaches the address, specified by a C expression.
```c
<@ base+0x1234
    // code to execute each time we hit base+0x1234
@>
```
`base` is a predefined variable representing the executable's base address (useful for PIEs).

### Pre-syscall
Executes before the entry of a certain syscall, specified by name or number, comma separated list for multiple syscalls.
```c
<@ pre-syscall write, read, 96
    // modify syscall arguments
@>
```

### Post-syscall
Executes after the completion of a certain syscall.
```c
<@ post-syscall write, read, 96
    // inspect or modify return values
@>
```

### Fork
Executes when a tracee triggers a fork, vfork, or clone.
Three new variables are introduced:
- **`int child`**
    - PID of the spawned child, while the usual `pid` variable stores the parent's PID
- **`int should_trace`**
    - If set to `0`, the child will be immediately detached from the tracer. Set to `1` by default.
- **`struct user_regs_struct child_regs`**
    - Register state of the child, while the usual `regs` variable stores the parent's regsiters. Modifications to both will be applied.
Caution: If using address breakpoints and you stop tracing the child, hitting those traps in the child will cause a crash as there is no tracer to handle them. This can be fixed by resetting breakpoints on detach, but it's not yet implemented.
```c
<@ fork
    // inspect or modify state, decide whether to trace child
    if (regs.r15 == 0x42 || child == 69420)
        should_trace = 0;
    else
        child_regs.r15 = 0x100;
@>
```

### Status
Executes when the tracer receives an unhandled status (anything besides a trap from a breakpoint or syscall).
Two new variables are introduced: 
- **`int status`** 
    - Status set by `waitpid`.
- **`int is_regs`**
    - Set to `1` if the `regs` variable is usable, `0` otherwise. Any attempt to access `regs` should be prefaced by checking `is_regs`.

`is_regs` is required due to exit statuses being sent after execution state has been destructed. `should_detach` is set to `!is_regs` to help clean up exited tracees, but it can be overridden as usual.
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

## Example
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
- Eliminate all trap instructions when detaching from a child that is not in an exited state.
- Add arbitrary shellcode injection, make injection safer by starting at beginning of page containing PC to give most runway.
