# Simple Flag Checker
This was a [reversing challenge from AlpacaHack Round 4](https://alpacahack.com/ctfs/round-4/challenges/simple-flag-checker).

We are given an x64 ELF that implements a flag checker. Decompilation of the important logic is shown below.

```c
fgets(&buf, 0x32, stdin)
__builtin_memset(&state, 0, 0x24)
int64_t i = 0
int32_t correct = 1
do
    update(&state, *(&buf + i))
    correct &= (memcmp(&state, (i << 4) + &table, 0x10) == 0)
    i += 1
while (i != 0x31)

if (correct == 0)
    puts("Wrong...")
```

For each of the 0x31 characters sent in the input buffer, some persistent memory at `state` is updated by `update` using our character. After each update, the state is compared with some predefined bytes in `table`, and if they ever compare as not equal, `correct` will be set to false meaning our flag is wrong. The `update` function itself is difficult to reverse, but because only one character is checked at a time, we can brute force byte by byte.

The high-level logic for performing the bruteforce is as follows:
    0) save the current `state` in some external memory
    1) set *(&buf + i) to the byte we are testing before `update` is called
    2) if the memcmp returns 0, we found the correct character, let the loop advance and repeat this process
    3) else, roll back `state` to the saved version, jump back to before the `update` call, and repeat the process with a new character

There are likely a variety of ways to implement this, but I chose to use my tool `ptpatch` which lets you patch a binary with a stub that uses ptrace to modify the original binary's behavior at runtime. Further description of this tool and its code can be found here: [github.com/enzosaracen/ptpatch](https://github.com/enzosaracen/ptpatch).

We can define a ptpatch patch file that will modify the `checker` binary to solve itself as it runs.
The contents of the, patch file, `patch.ptp` is provided below with comments.

```c
int bf_byte = 1;
int flag_pos = 0;
char flag[0x100];
char saved_buf[0x10];

%%

// index in $rbx
// input[index] byte in $rsi
// checked buffer with 0x10 bytes in $rbp
// target value in $base+0x4020+i*0x10

// so we bruteforce with all possible byte values
// until memcmp($rbp, $base+0x4020+i*0x10) == 0
// repeat 49 times for the full flag
// make sure to backtrack the state in $rbp

// after byte is set in $rsi
<@ base+0x1a0d
	mem_write(regs.rbp, saved_buf, 0x10);
	if (bf_byte > 255) {
		puts("something went wrong, bf_byte exceeded 255");
		exit(1);
	}
	regs.rsi = bf_byte++;
@>

// after update is called (checked buffer generated)
<@ base+0x1a18
	char buf[0x10], target[0x10];
	mem_read(base+0x4020+regs.rbx*0x10, target, 0x10);
	mem_read(regs.rbp, buf, 0x10);
	// need to try again, so reset pc to before the call
	if (memcmp(buf, target, 0x10) != 0) {
		regs.rip = base+0x1a08;
		return;
	}
	printf("found valid byte: '%c' at pos: %d\n", bf_byte-1, flag_pos);
	flag[flag_pos] = bf_byte-1;
	printf("flag so far: %s\n", flag);
	mem_read(regs.rbp, saved_buf, 0x10);
	flag_pos += 1;
	bf_byte = 0;
@>
```

We can then run `ptpatch patch.ptp -e checker`.
A file `stub.out` will be generated, which is the `checker` binary embedded with the ptracing stub.
Simply running it and pressing enter to get past the fgets will cause the flag to be printed out.

```
➜  ./stub.out
flag?
found valid byte: 'A' at pos: 0
flag so far: A
found valid byte: 'l' at pos: 1
flag so far: Al
found valid byte: 'p' at pos: 2
flag so far: Alp

(snip)

found valid byte: 'k' at pos: 47
flag so far: Alpaca{h4sh_4lgor1thm_1s_b4s3d_0n_MD5_4nd_keccak
found valid byte: '}' at pos: 48
flag so far: Alpaca{h4sh_4lgor1thm_1s_b4s3d_0n_MD5_4nd_keccak}
Correct! Your flag is:
```
