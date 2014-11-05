/*
 * lemem.c - Utility to run a program while limiting its memory usage
 *
 * Copyright (C) 2013 -  2014	Andrew Clayton <andrew@digital-domain.net>
 *
 * Licensed under the GNU General Public License Version 2
 * See COPYING
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <linux/limits.h>

#define MEM_CGROUP_MNT_PT	"/sys/fs/cgroup/memory"

static volatile sig_atomic_t child_reaped;
static pid_t child_pid;

static void cleanup(const char *cgrp_path)
{
	FILE *fp;
	char fpath[PATH_MAX];

	/* Clear the cgroups memory usage */
	snprintf(fpath, PATH_MAX, "%s/memory.force_empty", cgrp_path);
	fp = fopen(fpath, "w");
	fprintf(fp, "0\n");
	fclose(fp);
	rmdir(cgrp_path);
}

/*
 * Upon receiving an INT or TERM signal, terminate the child.
 */
static void terminate(int signo)
{
	kill(child_pid, SIGTERM);
}

/*
 * Upon receiving a SIGCHLD, reap the childs pid and set the child_reaped
 * flag.
 */
static void reaper(int signo)
{
	int status;

	waitpid(child_pid, &status, WNOHANG);
	child_reaped = 1;
}

int main(int argc, char *argv[])
{
	int msize;
	pid_t pid;
	char cgpath[PATH_MAX];
	const char *prog;
	struct sigaction sa;

	if (argc < 3) {
		printf("Usage: lemem <memory limit in MB> <program> [args ...]"
				"\n");
		exit(EXIT_FAILURE);
	}

	if (geteuid() != 0) {
		printf("Needs root privileges to run. e.g setuid\n");
		exit(EXIT_FAILURE);
	}

	msize = atoi(argv[1]);
	prog = argv[2];

	/* Setup a signal handler for SIGINT & SIGTERM */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = terminate;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/*
	 * Setup a signal handler for SIGCHLD to handle child
	 * process terminations.
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = reaper;
	sa.sa_flags = 0;
	sigaction(SIGCHLD, &sa, NULL);

	pid = child_pid = fork();
	if (pid == 0) { /* Child */
		int err;
		char fpath[PATH_MAX];
		pid_t cpid = getpid();
		FILE *fp;

		snprintf(cgpath, PATH_MAX, "%s/%s-%d", MEM_CGROUP_MNT_PT,
				basename(prog), cpid);
		err = mkdir(cgpath, 0777);
		if (err) {
			perror("mkdir");
			_exit(EXIT_FAILURE);
		}

		/* Place the child's pid into its tasks file */
		snprintf(fpath, PATH_MAX, "%s/tasks", cgpath);
		fp = fopen(fpath, "a");
		fprintf(fp, "%d\n", cpid);
		fclose(fp);

		/* Set the requested memory limit (in bytes) */
		snprintf(fpath, PATH_MAX, "%s/memory.limit_in_bytes", cgpath);
		fp = fopen(fpath, "w");
		fprintf(fp, "%lu\n", (unsigned long)msize * 1024*1024);
		fclose(fp);

		/* Set back to the users Real GID */
		err = setgid(getgid());
		if (err) {
			perror("setgid");
			goto cleanup_exit;
		}
		/* Set back to the users Real UID */
		err = setuid(getuid());
		if (err) {
			perror("setuid");
			goto cleanup_exit;
		}

		err = execvp(prog, argv + 2);
		if (err)
			perror("execvp");
cleanup_exit:
		cleanup(cgpath);
		_exit(EXIT_FAILURE);
	} else if (pid > 0) {
		/*
		 * We also need to set the path for the child processes
		 * cgroup in the parent process as that is where the
		 * directory will be removed from.
		 */
		snprintf(cgpath, PATH_MAX, "%s/%s-%d", MEM_CGROUP_MNT_PT,
				basename(prog), child_pid);
	}

	for (;;) {
		pause();
		if (child_reaped) {
			cleanup(cgpath);
			break;
		}
	}

	exit(EXIT_SUCCESS);
}
