# ptpatch
`ptpatch` is a tool for patching Linux binaries at runtime using ptrace, allowing patches to contain arbitrarily complex logic. This is accomplished through a tracing stub with user-defined hooks that can control the tracee's registers/memory, triggered at specific breakpoints or conditions.

## Installation
Run `./build.sh` in the project's root directory. The `./ptpatch` symlink should now point to the CLI binary (located at `./cli/target/release/ptpatch`).

## Usage
`ptpatch` takes a list of file path arguments. Each file should be in the `ptpatch` patch file format described below. The patches from each file will be grouped together into a `stub.gen.c` which will be compiled into a `stub.out` executable. You can apply the patches to any executable by running `./stub.out exe args...`. Alternatively, the stub can embed a single binary file using the `--embed` flag followed by a path to that binary. Running the embedded `stub.out` will execute the specified binary directly, passing through all arguments. This avoids an `execve` call by performing an in-process `execve` similar to how UPX works, however, no compression is applied durign the embedding.

## Format
A descriptive example of the patch file format is shown below.
```
// globals/arbitrary C code accessible by all hooks goes before
// the delimiting line containing "%%".
// be careful of clobbering predefined convenience variables/functions,
// which are viewable in stub.gen.c

int break_cnt = 0;
long saved_rdx = 0;

// following the "%%", a series of hooks are defined in the format:
// <@ `breakpoint`
//     // C code goes here
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
    // arbitrary C code to be run for this hook goes here
    
    // predefined variables/functions:

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

<@ pre-sys write
    // pre-sys hooks will be run before the syscall is entered
    
    mem_write(regs.rsi, "intercepted!\n", 13);
    saved_rdx = regs.rdx;
    regs.rdx = 13;
@>

<@ post-sys write
    // post-sys hooks will be run after the syscall is entered

    // we do this to appease libc's write, thinking it wrote
    // as many bytes as it originally requested
    regs.rax = saved_rdx;
@>
```
