#include <sys/user.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdlib.h>

struct Breakpoint {
	int idx;
	pid_t pid;
	void *addr;
	void (*hook)(pid_t, void *);
	long orig;
};

int bkpt_add(pid_t pid, void *addr, void (*hook)(pid_t, void *));
void bkpt_insert(struct Breakpoint *bkpt);
void bkpt_handle(pid_t pid);

#define MAX_BKPTS 64

int bkpt_cnt;
struct Breakpoint bkpt_tab[MAX_BKPTS];

long ptrace_peektext(pid_t pid, void *addr);
void ptrace_poketext(pid_t pid, void *addr, long data);
void ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
void ptrace_setregs(pid_t pid, struct user_regs_struct *regs);
void ptrace_cont(pid_t pid);
void ptrace_traceme(void);

long ptrace_peektext(pid_t pid, void *addr)
{
	return ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
}

void ptrace_poketext(pid_t pid, void *addr, long data)
{
	if (ptrace(PTRACE_POKETEXT, pid, addr, data) < 0)
		exit(1);
}

void ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, pid, 0, regs) < 0)
		exit(1);
}

void ptrace_setregs(pid_t pid, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_SETREGS, pid, 0, regs) < 0)
		exit(1);
}

void ptrace_cont(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
		exit(1);
}

void ptrace_traceme(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
		exit(1);
}

int bkpt_add(pid_t pid, void *addr, void (*hook)(pid_t, void *))
{
	if (bkpt_cnt >= MAX_BKPTS)
		return -1;
	bkpt_tab[bkpt_cnt].pid = pid;
	bkpt_tab[bkpt_cnt].addr = addr;
	bkpt_tab[bkpt_cnt].hook = hook;
	bkpt_tab[bkpt_cnt].idx = bkpt_cnt;
	return bkpt_cnt++;
}

void bkpt_insert(struct Breakpoint *bkpt)
{
	bkpt->orig = ptrace_peektext(bkpt->pid, bkpt->addr);
	// we need some way to look up the hook function,
	// so also write the breakpoint index after the int3
	ptrace_poketext(bkpt->pid, bkpt->addr,
		(bkpt->orig&~0xffffffffff)|0xcc|((long)bkpt->idx<<8));
}

void bkpt_handle(pid_t pid)
{
	struct user_regs_struct regs;
	ptrace_getregs(pid, &regs);
	void *rip = (void*)(regs.rip-1);
	int idx = ptrace_peektext(pid, (void*)regs.rip);
	if (idx < 0 || idx > MAX_BKPTS || bkpt_tab[idx].addr != rip)
		return;
	ptrace_poketext(pid, rip, bkpt_tab[idx].orig);
	regs.rip -= 1;
	if (bkpt_tab[idx].hook)
		bkpt_tab[idx].hook(pid, &regs);
	ptrace_setregs(pid, &regs);
	ptrace_cont(pid);
}

void hook(pid_t pid, void *arg)
{
	struct user_regs_struct *regs = arg;
	printf("rip: %p\nrsp: %p\n", regs->rip, regs->rsp);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	int pers = personality(0xffffffff);
    personality(pers | ADDR_NO_RANDOMIZE);

	pid_t pid = fork();
	if (!pid) {
		ptrace_traceme();
		execve(argv[1], &argv[1], 0);
		perror("execve");
		exit(1);
	}

	int status;
	waitpid(pid, &status, 0);

	int idx = bkpt_add(pid, (void*)0x401787, hook);
	bkpt_insert(&bkpt_tab[idx]);

	ptrace_cont(pid);

	for(;;) {
		waitpid(pid, &status, 0);
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
			bkpt_handle(pid);
		} else  {
			break;
		}
	}
	return 0;
}
