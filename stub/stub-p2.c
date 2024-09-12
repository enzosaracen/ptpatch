
char procbuf[22] = "/proc////////////maps";

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	unsigned long entry = 0;
	if (INIT_AFTER_ENTRY) {
		int fd = open(argv[1], O_RDONLY);
		lseek(fd, 24, SEEK_SET);
		read(fd, &entry, 8);
		close(fd);
	}

	pid_t pid = fork();
	if (!pid) {
		ptrace_traceme();
		execve(argv[1], &argv[1], 0);
		exit(1);
	}

	int status;
	waitpid(pid, 0, 0);
	if (INIT_AFTER_ENTRY) {
		if (ptrace_testtext(pid, (void*)entry) < 0) {
			// we must be dynamic, easiest way to find base is through proc.
			// unfortunately nolibc doesn't contain any sprintf functions
			int i = 15;
			for(int v = pid; v > 0; v /= 10)
				procbuf[i--] = '0' + v%10;
			int fd = open(procbuf, O_RDONLY);
			char buf[13];
			// assume first address in maps is exe base,
			// don't know of any cases for dyn where this isn't true
			read(fd, buf, 12);
			close(fd);
			buf[12] = 0;
			base = strtoul(buf, 0, 0x10);
			entry += base;
		}
		long orig = ptrace_peektext(pid, (void*)entry);
		ptrace_poketext(pid, (void*)entry, (orig&~0xff)|0xcc);
		ptrace_cont(pid);
		waitpid(pid, &status, 0);
		if (!(WIFSTOPPED(status) && WEXITSTATUS(status) == SIGTRAP))
			exit(1);
	}

	#ifdef HOOK_SYSCALLS
		#define RESUME ptrace_syscall
	#else
		#define RESUME ptrace_cont
	#endif

