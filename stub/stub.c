#include <sys/user.h>
#include <sys/personality.h>

#define INIT_AFTER_ENTRY 1

#define PTRACE_O_TRACESYSGOOD   0x01
#define PTRACE_O_TRACEFORK      0x02
#define PTRACE_O_TRACEVFORK     0x04
#define PTRACE_O_TRACECLONE     0x08
#define PTRACE_O_TRACEEXEC      0x10
#define PTRACE_O_TRACEVFORKDONE 0x20
#define PTRACE_O_TRACEEXIT      0x40
#define PTRACE_O_TRACESECCOMP   0x80
#define PTRACE_EVENT_FORK	1
#define PTRACE_EVENT_VFORK	2
#define PTRACE_EVENT_CLONE	3
#define PTRACE_EVENT_EXEC	4
#define PTRACE_EVENT_VFORK_DONE	5
#define PTRACE_EVENT_EXIT	6
#define PTRACE_EVENT_SECCOMP	7
#define PTRACE_EVENT_STOP	128

enum __ptrace_request
{
	PTRACE_TRACEME = 0,
	PTRACE_PEEKTEXT = 1,
	PTRACE_PEEKDATA = 2,
	PTRACE_PEEKUSER = 3,
	PTRACE_POKETEXT = 4,
	PTRACE_POKEDATA = 5,
	PTRACE_POKEUSER = 6,
	PTRACE_CONT = 7,
	PTRACE_KILL = 8,
	PTRACE_SINGLESTEP = 9,
	PTRACE_GETREGS = 12,
	PTRACE_SETREGS = 13,
	PTRACE_GETFPREGS = 14,
	PTRACE_SETFPREGS = 15,
	PTRACE_ATTACH = 16,
	PTRACE_DETACH = 17,
	PTRACE_GETFPXREGS = 18,
	PTRACE_SETFPXREGS = 19,
	PTRACE_SYSCALL = 24,
	PTRACE_GET_THREAD_AREA = 25,
	PTRACE_SET_THREAD_AREA = 26,
	PTRACE_ARCH_PRCTL = 30,
	PTRACE_SYSEMU = 31,
	PTRACE_SYSEMU_SINGLESTEP = 32,
	PTRACE_SINGLEBLOCK = 33,
	PTRACE_SETOPTIONS = 0x4200,
	PTRACE_GETEVENTMSG = 0x4201,
	PTRACE_GETSIGINFO = 0x4202,
	PTRACE_SETSIGINFO = 0x4203,
	PTRACE_GETREGSET = 0x4204,
	PTRACE_SETREGSET = 0x4205,
	PTRACE_SEIZE = 0x4206,
	PTRACE_INTERRUPT = 0x4207,
	PTRACE_LISTEN = 0x4208,
	PTRACE_PEEKSIGINFO = 0x4209,
	PTRACE_GETSIGMASK = 0x420a,
	PTRACE_SETSIGMASK = 0x420b,
	PTRACE_SECCOMP_GET_FILTER = 0x420c,
	PTRACE_SECCOMP_GET_METADATA = 0x420d,
	PTRACE_GET_SYSCALL_INFO = 0x420e,
	PTRACE_GET_RSEQ_CONFIGURATION = 0x420f
};

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)
{
	return syscall(__NR_ptrace, request, pid, addr, data);
}

long ptrace_peektext(pid_t pid, void *addr)
{
	long data;
	if (ptrace(PTRACE_PEEKTEXT, pid, addr, &data) < 0) {
		puts("peektext error");
		exit(1);
	}
	return data;
}

int ptrace_testtext(pid_t pid, void *addr)
{
	long data;
	return ptrace(PTRACE_PEEKTEXT, pid, addr, &data);
}

void ptrace_poketext(pid_t pid, void *addr, long data)
{
	if (ptrace(PTRACE_POKETEXT, pid, addr, (void*)data) < 0) {
		puts("poketext error");
		exit(1);
	}
}

void ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, pid, 0, regs) < 0) {
		puts("getregs error");
		exit(1);
	}
}

void ptrace_setregs(pid_t pid, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0) {
		puts("setregs error");
		exit(1);
	}
}

void ptrace_cont(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
		puts("cont error");
		exit(1);
	}
}

void ptrace_syscall(pid_t pid)
{
	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
		puts("syscall error");
		exit(1);
	}
}

void ptrace_traceme(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
		puts("traceme error");
		exit(1);
	}
}

void ptrace_singlestep(pid_t pid)
{
	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
		puts("singlestep error");
		exit(1);
	}
}

void ptrace_setoptions(pid_t pid, long data)
{
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void*)data) < 0) {
		puts("setoptions error");
		exit(1);
	}
}

struct Breakpoint {
	int idx;
	pid_t pid;
	void *addr;
	void (*hook)(pid_t, void *);
	long orig;
};

#define MAX_BKPTS 64

int bkpt_cnt;
struct Breakpoint bkpt_tab[MAX_BKPTS];

int bkpt_add(pid_t pid, void *addr, void (*hook)(pid_t, void *))
{
	if (bkpt_cnt >= MAX_BKPTS)
		return -1;
	for (int i = 0; i < bkpt_cnt; i++)
		if (bkpt_tab[i].addr == addr) {
			puts("duplicate breakpoint error");
			exit(1);
		}
	bkpt_tab[bkpt_cnt].pid = pid;
	bkpt_tab[bkpt_cnt].addr = addr;
	bkpt_tab[bkpt_cnt].hook = hook;
	bkpt_tab[bkpt_cnt].idx = bkpt_cnt;
	return bkpt_cnt++;
}

void bkpt_insert(struct Breakpoint *bkpt)
{
	bkpt->orig = ptrace_peektext(bkpt->pid, bkpt->addr);
	ptrace_poketext(bkpt->pid, bkpt->addr, (bkpt->orig&~0xff)|0xcc);
}

int bkpt_handle(pid_t pid)
{
	struct user_regs_struct regs;
	ptrace_getregs(pid, &regs);
	void *rip = (void*)(regs.rip-1);
	int idx = -1;
	for (int i = 0; i < bkpt_cnt; i++)
		if (bkpt_tab[i].addr == rip)
			idx = i;
	if (idx < 0)
		return -1;
	struct Breakpoint *bkpt = &bkpt_tab[idx];
	ptrace_poketext(pid, rip, bkpt->orig);
	regs.rip -= 1;
	if (bkpt_tab[idx].hook)
		bkpt_tab[idx].hook(pid, &regs);
	ptrace_setregs(pid, &regs);
	ptrace_singlestep(pid);
	waitpid(pid, 0, 0);
	ptrace_poketext(bkpt->pid, bkpt->addr, (bkpt->orig&~0xff)|0xcc);
	return 0;
}

#define MAX_SYSNR 500

void (*presys_hooks[MAX_SYSNR])(pid_t, void *);
void (*postsys_hooks[MAX_SYSNR])(pid_t, void *);

#define MAX_ENTRY 1024
struct Htab {
	int pid;
	int entry;
	struct Htab *next;
} entry_table[MAX_ENTRY];

int entry_lookup(int pid)
{
	struct Htab *p = &entry_table[pid % MAX_ENTRY];
	for(;;) {
		if (p->pid == pid) {
			int ret = p->entry;
			p->entry = !p->entry;
			return ret;
		}
		if (!p->next)
			break;
		p = p->next;
	}
	p->next = malloc(sizeof(struct Htab));
	p->next->pid = pid;
	p->next->entry = 1;
	p->next->next = 0;
	return 0;
}

void sys_handle(pid_t pid)
{
	struct user_regs_struct regs;
	ptrace_getregs(pid, &regs);
	int nr = regs.orig_rax;
	if (nr >= 0 && nr < MAX_SYSNR) {
		if (entry_lookup(pid)) {
			if (postsys_hooks[nr]) 
				postsys_hooks[nr](pid, &regs);
		} else if (presys_hooks[nr])
			presys_hooks[nr](pid, &regs);
	}
	ptrace_setregs(pid, &regs);
}

int cur_pid, focus_pid, exit_now;
unsigned long base;

int mem_write(char *addr, char *buf, int n)
{
	while (n >= 8) {
		if (ptrace(PTRACE_POKETEXT, cur_pid, addr, (void*)*(long*)buf) < 0)
			return -1;
		buf += 8;
		addr += 8;
		n -= 8;
	}
	if (n > 0) {
		long mask = (1UL<<(n*8))-1;
		long partial;
		if (ptrace(PTRACE_PEEKTEXT, cur_pid, addr, &partial) < 0)
			return -1;
		partial &= ~mask;
		partial |= *(long*)buf & mask;
		if (ptrace(PTRACE_POKETEXT, cur_pid, addr, (void*)partial) < 0)
			return -1;
	}
	return 0;
}

int mem_read(char *addr, char *buf, int n)
{
	long v;
	while (n >= 8) {
		if (ptrace(PTRACE_PEEKTEXT, cur_pid, addr, &v) < 0)
			return -1;
		*(long*)buf = v;
		buf += 8;
		addr += 8;
		n -= 8;
	}
	if (n > 0) {
		if (ptrace(PTRACE_PEEKTEXT, cur_pid, addr, &v) < 0)
			return -1;
		memcpy(buf, &v, n);
	}
	return 0;
}

int fork_handle(int pid, int child, int *ret, void *arg1, void *arg2);
int status_handle(int pid, int status, int *ret, void *arg, int is_regs);

int fork_handle_wrapper(int pid, int child)
{
	int should_trace = 1;
	struct user_regs_struct regs, child_regs;
	ptrace_getregs(pid, &regs);
	ptrace_getregs(child, &child_regs);
	fork_handle(pid, child, &should_trace, &regs, &child_regs);
	ptrace_setregs(pid, &regs);
	ptrace_setregs(child, &child_regs);
	return should_trace;
}

int status_handle_wrapper(int pid, int status)
{
	int should_exit = 0;
	struct user_regs_struct regs;
	int is_regs = ptrace(PTRACE_GETREGS, pid, 0, &regs) >= 0;
	status_handle(pid, status, &should_exit, &regs, is_regs);
	if (is_regs)
		ptrace_setregs(pid, &regs);
	return should_exit;
}

// add hooks here

char procbuf[22] = "/proc////////////maps";

int main(int argc, char **argv, char **envp)
{
	unsigned long entry = 0;

	#ifndef EMBED_EXECUTABLE	
		if (argc < 2)
			return 1;

		if (INIT_AFTER_ENTRY) {
			int fd = open(argv[1], O_RDONLY);
			lseek(fd, 24, SEEK_SET);
			read(fd, &entry, 8);
			close(fd);
		}

		pid_t pid = fork();
		if (!pid) {
			ptrace_traceme();
			execve(argv[1], &argv[1], envp);
			exit(1);
		}
	#else
		extern char _binary_embed_gen_tmp_start[];
		extern char _binary_embed_gen_tmp_end[];
		int fd = memfd_create("embed", 0);
		write(fd, _binary_embed_gen_tmp_start,
			(unsigned long)&_binary_embed_gen_tmp_end-(unsigned long)&_binary_embed_gen_tmp_start);

		if (INIT_AFTER_ENTRY)
			entry = *(unsigned long*)((char*)(_binary_embed_gen_tmp_start)+24);

		pid_t pid = fork();
		if (!pid) {
			ptrace_traceme();
			syscall(322, fd, "", argv, envp, 0x1000);
			exit(1);
		}
	#endif

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

	int flags = PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE;
	#ifdef HOOK_SYSCALLS
		#define RESUME ptrace_syscall
		flags |= PTRACE_O_TRACESYSGOOD;
	#else
		#define RESUME ptrace_cont
	#endif
	ptrace_setoptions(pid, flags);

	// add breakpoints here

	for (int i = 0; i < bkpt_cnt; i++)
		bkpt_insert(&bkpt_tab[i]);
	
	focus_pid = pid;
	RESUME(pid);
	while (!exit_now) {
		int this_pid = waitpid(-1, &status, 0);
		if (WIFSTOPPED(status)) {
			switch(WEXITSTATUS(status)) {
			case SIGTRAP:
				switch (status >> 16) {
				case PTRACE_EVENT_FORK:
				case PTRACE_EVENT_VFORK:
				case PTRACE_EVENT_CLONE:
					int child;
					ptrace(PTRACE_GETEVENTMSG, this_pid, 0, &child);
					struct user_regs_struct regs;
					while (ptrace(PTRACE_GETREGS, child, 0, &regs) < 0);
					cur_pid = pid;
					if (fork_handle_wrapper(pid, child))
						ptrace_setoptions(child, flags);
					else
						ptrace(PTRACE_DETACH, child, 0, 0);
					RESUME(child);
					break;
				default:
					bkpt_handle(this_pid);
				}
				break;
			case SIGTRAP|0x80:
				sys_handle(this_pid);
				break;
			default:
				goto handle_unknown;
			}
		} else  {
		handle_unknown:
			int ret = status_handle_wrapper(this_pid, status);
			if (ret != -1 && (ret == 1 || this_pid == focus_pid || focus_pid == -1))
				break;
		}
		RESUME(this_pid);
	}
	return 0;
}
