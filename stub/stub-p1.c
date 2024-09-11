#include <sys/user.h>
#include <sys/personality.h>
enum __ptrace_request{PTRACE_TRACEME=0,PTRACE_PEEKTEXT=1,PTRACE_PEEKDATA=2,PTRACE_PEEKUSER=3,PTRACE_POKETEXT=4,PTRACE_POKEDATA=5,PTRACE_POKEUSER=6,PTRACE_CONT=7,PTRACE_KILL=8,PTRACE_SINGLESTEP=9,PTRACE_GETREGS=12,PTRACE_SETREGS=13,PTRACE_GETFPREGS=14,PTRACE_SETFPREGS=15,PTRACE_ATTACH=16,PTRACE_DETACH=17,PTRACE_GETFPXREGS=18,PTRACE_SETFPXREGS=19,PTRACE_SYSCALL=24,PTRACE_GET_THREAD_AREA=25,PTRACE_SET_THREAD_AREA=26,PTRACE_ARCH_PRCTL=30,PTRACE_SYSEMU=31,PTRACE_SYSEMU_SINGLESTEP=32,PTRACE_SINGLEBLOCK=33,PTRACE_SETOPTIONS=0x4200,PTRACE_GETEVENTMSG=0x4201,PTRACE_GETSIGINFO=0x4202,PTRACE_SETSIGINFO=0x4203,PTRACE_GETREGSET=0x4204,PTRACE_SETREGSET=0x4205,PTRACE_SEIZE=0x4206,PTRACE_INTERRUPT=0x4207,PTRACE_LISTEN=0x4208,PTRACE_PEEKSIGINFO=0x4209,PTRACE_GETSIGMASK=0x420a,PTRACE_SETSIGMASK=0x420b,PTRACE_SECCOMP_GET_FILTER=0x420c,PTRACE_SECCOMP_GET_METADATA=0x420d,PTRACE_GET_SYSCALL_INFO=0x420e,PTRACE_GET_RSEQ_CONFIGURATION=0x420f};
long ptrace(enum __ptrace_request r, pid_t p, void*a, void*d){return syscall(__NR_ptrace,r,p,a,d);}
long ptrace_peektext(pid_t p,void*a){long d;if(ptrace(PTRACE_PEEKTEXT,p,a,&d)<0)exit(1);return d;}
int ptrace_testtext(pid_t p,void*a){long d;return ptrace(PTRACE_PEEKTEXT,p,a,&d);}
void ptrace_poketext(pid_t p,void*a,long d){if(ptrace(PTRACE_POKETEXT,p,a,(void*)d)<0)exit(1);}
void ptrace_getregs(pid_t p,struct user_regs_struct*r){if(ptrace(PTRACE_GETREGS,p,0,r)<0)exit(1);}
void ptrace_setregs(pid_t p,struct user_regs_struct*r){if(ptrace(PTRACE_SETREGS,p,0,r)<0)exit(1);}
void ptrace_cont(pid_t p){if(ptrace(PTRACE_CONT,p,0,0)<0)exit(1);}
void ptrace_traceme(void){if(ptrace(PTRACE_TRACEME,0,0,0)<0)exit(1);}
void ptrace_singlestep(pid_t p){if(ptrace(PTRACE_SINGLESTEP,p,0,0)<0)exit(1);}

#define INIT_AFTER_ENTRY 1

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
		if (bkpt_tab[i].addr == addr)
			exit(1);
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

void bkpt_handle(pid_t pid)
{
	struct user_regs_struct regs;
	ptrace_getregs(pid, &regs);
	void *rip = (void*)(regs.rip-1);
	int idx = -1;
	for (int i = 0; i < bkpt_cnt; i++)
		if (bkpt_tab[i].addr == rip)
			idx = i;
	if (idx < 0)
		return;
	struct Breakpoint *bkpt = &bkpt_tab[idx];
	ptrace_poketext(pid, rip, bkpt->orig);
	regs.rip -= 1;
	if (bkpt_tab[idx].hook)
		bkpt_tab[idx].hook(pid, &regs);
	ptrace_setregs(pid, &regs);
	int status;
	ptrace_singlestep(pid);
	waitpid(pid, &status, 0);
	ptrace_poketext(bkpt->pid, bkpt->addr, (bkpt->orig&~0xff)|0xcc);
	ptrace_cont(pid);
}

int cur_pid = 0;
unsigned long base = 0;

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
