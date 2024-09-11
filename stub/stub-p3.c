	for (int i = 0; i < bkpt_cnt; i++)
		bkpt_insert(&bkpt_tab[i]);

	ptrace_cont(pid);
	for(;;) {
		waitpid(pid, &status, 0);
		if (WIFSTOPPED(status) && WEXITSTATUS(status) == SIGTRAP) {
			bkpt_handle(pid);
		} else  {
			break;
		}
	}
	return 0;
}
