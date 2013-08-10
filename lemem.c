/*
 * lemem.c - Utility to run a program while limiting its memory usage
 *
 * Copyright (C) 2013		Andrew Clayton <andrew@digital-domain.net>
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
#include <linux/limits.h>

#define MEM_CGROUP_MNT_PT	"/sys/fs/cgroup/memory"

int main(int argc, char *argv[])
{
	int msize;
	int status;
	int ret;
	pid_t pid;
	char cgpath[PATH_MAX];
	char fpath[PATH_MAX];
	const char *prog;
	const char *sprog;
	FILE *fp;

	if (argc < 3) {
		printf("Usage: lemem <memory limit in MB> <program> [args ...]"
				"\n");
		exit(EXIT_FAILURE);
	}

	msize = atoi(argv[1]);
	prog = argv[2];
	sprog = basename(prog);

	snprintf(cgpath, PATH_MAX, "%s/%s", MEM_CGROUP_MNT_PT, sprog);
	ret = mkdir(cgpath, 0777);
	if (ret != 0) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid == 0) { /* Child */
		/* Place the child's pid into its tasks file */
		snprintf(fpath, PATH_MAX, "%s/%s/tasks", MEM_CGROUP_MNT_PT,
				sprog);
		fp = fopen(fpath, "a");
		fprintf(fp, "%d\n", getpid());
		fclose(fp);

		/* Set the requested memory limit (in bytes) */
		snprintf(fpath, PATH_MAX, "%s/%s/memory.limit_in_bytes",
				MEM_CGROUP_MNT_PT, sprog);
		fp = fopen(fpath, "w");
		fprintf(fp, "%lu\n", (unsigned long)msize * 1024*1024);
		fclose(fp);

		/* Set back to the users Real GID */
		ret = setgid(getgid());
		if (ret != 0) {
			perror("setgid");
			exit(EXIT_FAILURE);
		}
		/* Set back to the users Real UID */
		ret = setuid(getuid());
		if (ret != 0) {
			perror("setuid");
			exit(EXIT_FAILURE);
		}

		execvp(prog, argv + 2);
	}

	wait(&status);
	/* Clear the cgroups memory usage */
	snprintf(fpath, PATH_MAX, "%s/%s/memory.force_empty",
			MEM_CGROUP_MNT_PT, sprog);
	fp = fopen(fpath, "w");
	fprintf(fp, "0\n");
	fclose(fp);
	rmdir(cgpath);

	exit(EXIT_SUCCESS);
}
