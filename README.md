# ptpatch
`ptpatch` is a tool for patching Linux binaries at runtime using ptrace, allowing patches to contain arbitrarily complex logic. This is accomplished through a tracing stub with user-defined hooks that can control the tracee's registers/memory, triggered at specific breakpoints or conditions. Only x86_64 binaries are currently supported.

## Installation
Run `./build.sh` in the project's root directory. The `./ptpatch` symlink should now point to the CLI binary (located at `./cli/target/release/ptpatch`).

## Usage
`ptpatch` CLI takes a list of file path arguments. Each file should be in the patch file format described below. These patches will be grouped to generate a `stub.gen.c` which will be automatically compiled to a `stub.out` executable. You can apply the patches to any executable by running `./stub.out exe args...`.

Alternatively, the stub can embed a single binary file using the `--embed` flag followed by a path to that binary. Running the embedded `stub.out` will execute the stub with that binary directly, passing through all arguments. This avoids an `execve` call by mimicking its behavior in-process, similar to how UPX works (although no compression is applied during the embedding).

## Format
A descriptive example of the patch file format is shown below.
Warning: all C code written for patches is compiled using Linux's [nolibc](https://elixir.bootlin.com/linux/v6.10.9/source/tools/include/nolibc) to minimize stub size, so certain usual libc features may not available (although most are).
```c
// globals/arbitrary C code accessible by all hooks go at the top
// of the file before a delimiting line containing "%%".
// be careful of clobbering predefined convenience variables/functions,
// which are viewable in stub.gen.c

int break_cnt = 0;
long saved_rdx = 0;

// following the "%%", a series of hooks are defined in the format:
// <@ `breakpoint`
//     // C code
// @>

// `breakpoint` is usually interpreted as an arbitrary
// C expression that evaluates to an address in the binary to break on,
// unless `breakpoint` matches the following special cases:
//      - starts with `pre-syscall` or `post-syscall`,
//        followed by a syscall name or number

// the predefined variable `base` contains the exe base address for
// PIE executables, which will be necessary to specify valid breakpoints

%%

<@ base+0x1234
    // predefined variables/functions available in hooks:

    // - `regs` defines current register state,
    //      - of type `struct user_regs_struct`
    //      - any modifications will be committed
    //        after the hook finishes

    // - `int mem_write(char *addr, char *buf, int n)`
    //      - writes `n` bytes from `buf` to `addr` in the
    //        tracee's memory

    // - `int mem_read(char *addr, char *buf, int n)`
    //      - reads `n` bytes from `addr` into `buf` from
    //        the tracee's memory
    
    break_cnt++;
    printf("hit base+0x1234 %d times\n", break_cnt);
@>

<@ pre-syscall write
    // pre-syscall hooks will be run before the syscall is entered
    
    mem_write(regs.rsi, "intercepted!\n", 13);
    saved_rdx = regs.rdx;
    regs.rdx = 13;
@>

<@ post-syscall write
    // post-syscall hooks will be run after the syscall is entered

    // we do this to appease libc's write, thinking it wrote
    // as many bytes as it originally requested
    regs.rax = saved_rdx;
@>
```

