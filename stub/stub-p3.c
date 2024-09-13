
	for (int i = 0; i < bkpt_cnt; i++)
		bkpt_insert(&bkpt_tab[i]);

	RESUME(pid);
	for(;;) {
		waitpid(pid, &status, 0);
		int is_syscall = status & 0x8000;
		status = status & ~0x8000;
		if (WIFSTOPPED(status) && WEXITSTATUS(status) == SIGTRAP) {
			if (is_syscall)
				sys_handle(pid);
			else
				bkpt_handle(pid);
			RESUME(pid);
		} else  {
			break;
		}
	}
	return 0;
}
