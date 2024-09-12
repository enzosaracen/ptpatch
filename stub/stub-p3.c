
	for (int i = 0; i < bkpt_cnt; i++)
		bkpt_insert(&bkpt_tab[i]);

	RESUME(pid);
	for(;;) {
		waitpid(pid, &status, 0);
		if (WIFSTOPPED(status) && WEXITSTATUS(status) == SIGTRAP) {
			if (bkpt_handle(pid) < 0)
				sys_handle(pid);
			RESUME(pid);
		} else  {
			break;
		}
	}
	return 0;
}
