#include <sys/user.h>

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

#define err(s) { \
	printf("%s:%d: error: %s\n",  __FILE__, __LINE__, s); \
	exit(1); \
}

long ptrace(enum __ptrace_request request, int pid, void *addr, void *data)
{
	return syscall(__NR_ptrace, request, pid, addr, data);
}

long ptrace_peektext(int pid, void *addr)
{
	long data;
	if (ptrace(PTRACE_PEEKTEXT, pid, addr, &data) < 0)
		err("peektext");
	return data;
}

int ptrace_testtext(int pid, void *addr)
{
	long data;
	return ptrace(PTRACE_PEEKTEXT, pid, addr, &data);
}

void ptrace_poketext(int pid, void *addr, long data)
{
	if (ptrace(PTRACE_POKETEXT, pid, addr, (void*)data) < 0)
		err("poketext");
}

void ptrace_getregs(int pid, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, pid, 0, regs) < 0)
		err("getregs");
}

void ptrace_setregs(int pid, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0)
		err("setregs");
}

void ptrace_cont(int pid)
{
	if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
		err("cont");
}

void ptrace_syscall(int pid)
{
	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
		err("syscall");
}

void ptrace_traceme(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
		err("traceme");
}

void ptrace_singlestep(int pid)
{
	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
		err("singlestep");
}

void ptrace_setoptions(int pid, long data)
{
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void*)data) < 0)
		err("setoptions");
}

#ifdef HOOK_SYSCALLS
#define RESUME ptrace_syscall
#else
#define RESUME ptrace_cont
#endif

int cur_pid, focus_pid, exit_now, should_detach;
unsigned long base;

struct Breakpoint {
	int idx;
	int pid;
	void *addr;
	void (*hook)(int, void *);
	long orig;
};

#define MAX_BKPTS 64
int bkpt_cnt;
struct Breakpoint bkpt_tab[MAX_BKPTS];

int bkpt_add(int pid, void *addr, void (*hook)(int, void *))
{
	if (bkpt_cnt >= MAX_BKPTS)
		return -1;
	for (int i = 0; i < bkpt_cnt; i++)
		if (bkpt_tab[i].addr == addr)
			err("duplicate breakpoint");
	bkpt_tab[bkpt_cnt].pid = pid;
	bkpt_tab[bkpt_cnt].addr = addr;
	bkpt_tab[bkpt_cnt].hook = hook;
	bkpt_tab[bkpt_cnt].idx = bkpt_cnt;
	return bkpt_cnt++;
}

void bkpt_insert(struct Breakpoint *bkpt)
{
	bkpt->orig = ptrace_peektext(bkpt->pid, bkpt->addr);
	ptrace_poketext(bkpt->pid, bkpt->addr, (bkpt->orig & ~0xff)|0xcc);
}

int bkpt_handle(int pid)
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
	ptrace_poketext(bkpt->pid, bkpt->addr, (bkpt->orig & ~0xff)|0xcc);
	return 0;
}

#define MAX_SYSNR 1024
void (*presys_hooks[MAX_SYSNR])(int, void *);
void (*postsys_hooks[MAX_SYSNR])(int, void *);

#define MAX_PIDTAB 1024
struct pidtab {
	int pid;
	int val;
	struct pidtab *next;
} entry_tab[MAX_PIDTAB], pause_tab[MAX_PIDTAB];

enum pidtab_op {
	PIDTAB_TOGGLE,
	PIDTAB_SET,
	PIDTAB_EXISTS,
	PIDTAB_NOP,
};

int pidtab_lookup(struct pidtab *tab, int pid, enum pidtab_op op, int val)
{
	struct pidtab *p = &tab[pid % MAX_PIDTAB];
	for(;;) {
		if (p->pid == pid) {
			if (op == PIDTAB_EXISTS)
				return 1;
			int ret = p->val;
			if (op == PIDTAB_TOGGLE)
				p->val = !p->val;
			else if (op == PIDTAB_SET)
				p->val = val;
			return ret;
		}
		if (!p->next)
			break;
		p = p->next;
	}
	if (op == PIDTAB_EXISTS)
		return 0;
	p->next = malloc(sizeof(struct pidtab));
	p->next->pid = pid;
	p->next->val = val;
	p->next->next = 0;
	return 0;
}

void pidtab_delete(struct pidtab *tab, int pid)
{
	struct pidtab *p = &tab[pid % MAX_PIDTAB], *prev = 0;
    if (p->pid == pid) {
        if (p->next) {
            struct pidtab *tmp = p->next;
            *p = *tmp;
            free(tmp);
        } else
            p->pid = 0;
        return;
    }
    while (p) {
        if (p->pid == pid) {
            if (prev)
                prev->next = p->next;
            free(p);
            return;
        }
        prev = p;
        p = p->next;
    }
}

void pid_pause(int pid)
{
	pidtab_lookup(pause_tab, pid, PIDTAB_SET, 1);
}

void pid_unpause(int pid)
{
	if (pidtab_lookup(pause_tab, pid, PIDTAB_SET, 0) && pid != cur_pid)
		RESUME(pid);
}

int pid_is_paused(int pid)
{
	return pidtab_lookup(pause_tab, pid, PIDTAB_NOP, 0);
}

int pid_exists(int pid)
{
	return pidtab_lookup(pause_tab, pid, PIDTAB_EXISTS, 0);
}

void pid_add(int pid)
{
	pidtab_lookup(pause_tab, pid, PIDTAB_SET, 0);
}

void ptrace_detach(int pid)
{
	printf("detach: %d\n", pid);
	ptrace(PTRACE_DETACH, pid, 0, 0);
	pidtab_delete(entry_tab, pid);
	pidtab_delete(pause_tab, pid);
}

void sys_handle(int pid)
{
	struct user_regs_struct regs;
	ptrace_getregs(pid, &regs);
	int nr = regs.orig_rax;
	if (nr >= 0 && nr < MAX_SYSNR) {
		if (pidtab_lookup(entry_tab, pid, PIDTAB_TOGGLE, 1)) {
			if (postsys_hooks[nr]) 
				postsys_hooks[nr](pid, &regs);
		} else if (presys_hooks[nr])
			presys_hooks[nr](pid, &regs);
	}
	ptrace_setregs(pid, &regs);
}

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

// add hooks here

#ifndef STATUS_HANDLER
	void status_handle(int pid, int status, void *arg, int is_regs) {};
#endif
#ifndef HOOK_FORKS
	void fork_handle(int pid, int child, int *ret, void *arg1, void *arg2) {};
#endif

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

void status_handle_wrapper(int pid, int status)
{
	struct user_regs_struct regs;
	int is_regs = !WIFEXITED(status) && ptrace(PTRACE_GETREGS, pid, 0, &regs) >= 0;
	should_detach = !is_regs;
	status_handle(pid, status, &regs, is_regs);
	if (is_regs)
		ptrace_setregs(pid, &regs);
}

int main(int argc, char **argv, char **envp)
{
	#define INIT_AFTER_ENTRY
	unsigned long entry = 0;

	#ifndef EMBED_EXECUTABLE	
		if (argc < 2)
			return 1;
		#ifdef INIT_AFTER_ENTRY
			int fd = open(argv[1], O_RDONLY);
			lseek(fd, 24, SEEK_SET);
			read(fd, &entry, 8);
			close(fd);
		#endif
		int pid = fork();
		if (!pid) {
			ptrace_traceme();
			execve(argv[1], &argv[1], envp);
			exit(1);
		}
	#else
		extern char _binary_embed_gen_tmp_start[];
		extern char _binary_embed_gen_tmp_end[];
		int fd = memfd_create("", 0);
		write(fd, _binary_embed_gen_tmp_start,
			(unsigned long)&_binary_embed_gen_tmp_end-(unsigned long)&_binary_embed_gen_tmp_start);

		#ifdef INIT_AFTER_ENTRY
			entry = *(unsigned long*)((char*)(_binary_embed_gen_tmp_start)+24);
		#endif

		int pid = fork();
		if (!pid) {
			ptrace_traceme();
			syscall(322, fd, "", argv, envp, 0x1000);
			exit(1);
		}
	#endif

	int status;
	waitpid(pid, 0, 0);
	#ifdef INIT_AFTER_ENTRY
		if (ptrace_testtext(pid, (void*)entry) < 0) {
			char procbuf[] = "/proc////////////maps";
			int i = 15;
			for(int v = pid; v > 0; v /= 10)
				procbuf[i--] = '0' + v%10;
			int fd = open(procbuf, O_RDONLY);
			char buf[13];
			read(fd, buf, 12);
			close(fd);
			buf[12] = 0;
			base = strtoul(buf, 0, 0x10);
			entry += base;
		}
		long orig = ptrace_peektext(pid, (void*)entry);
		ptrace_poketext(pid, (void*)entry, (orig & ~0xff)|0xcc);
		ptrace_cont(pid);
		waitpid(pid, &status, 0);
		if (!(WIFSTOPPED(status) && WEXITSTATUS(status) == SIGTRAP))
			exit(1);
	#endif

	int flags = 0;
	#ifdef HOOK_FORKS
		flags |= PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE;
	#endif
	#ifdef HOOK_SYSCALLS
		flags |= PTRACE_O_TRACESYSGOOD;
	#endif
	ptrace_setoptions(pid, flags);

	// add breakpoints here

	for (int i = 0; i < bkpt_cnt; i++)
		bkpt_insert(&bkpt_tab[i]);

	focus_pid = pid;
	RESUME(pid);
	pid_add(pid);
	while (!exit_now) {
		cur_pid = waitpid(-1, &status, 0);
		if (cur_pid == -1)
			break;
		if (!pid_exists(cur_pid))
			continue;
		should_detach = 0;
		if (WIFSTOPPED(status)) {
			switch(WEXITSTATUS(status)) {
			case SIGTRAP:
				switch (status >> 16) {
				case PTRACE_EVENT_FORK:
				case PTRACE_EVENT_VFORK:
				case PTRACE_EVENT_CLONE:
					int child = -1;
					ptrace(PTRACE_GETEVENTMSG, cur_pid, 0, &child);
					if (child == -1)
						err("geteventmsg");
					pid_add(child);
					struct user_regs_struct regs;
					while (ptrace(PTRACE_GETREGS, child, 0, &regs) < 0);
					if (fork_handle_wrapper(pid, child)) {
						ptrace_setoptions(child, flags);
						if (!pid_is_paused(child))
							RESUME(child);
					} else
						ptrace_detach(child);
					break;
				default:
					bkpt_handle(cur_pid);
				}
				break;
			case SIGTRAP|0x80:
				sys_handle(cur_pid);
				break;
			default:
				goto handle_unknown;
			}
		} else {
		handle_unknown:
			#ifdef STATUS_HANDLER
				status_handle_wrapper(cur_pid, status);
			#else
				struct user_regs_struct regs;
				should_detach = WIFEXITED(status) || ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0;
			#endif
		}
		if (should_detach) {
			if (cur_pid == focus_pid)
				break;
			ptrace_detach(cur_pid);
		} else if (!pid_is_paused(cur_pid))
			RESUME(cur_pid);
	}
	return 0;
}
