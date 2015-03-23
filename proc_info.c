/**
 * create a caching layer in front of /proc/<pid>/psinfo
 *
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: March 22, 2015
 * License: CDDL
 */

#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "proc_info.h"

static struct proc_info *l;

/**
 * get a pointer to a psinfo struct for a given pid
 *
 * this function will cache them so they can be retrieved
 * quickly caller should not call free() on any items returned
 */
struct proc_info *proc_info_get(int pid) {
	struct proc_info *temp;

	// username of the pid
	char *name = NULL;

	// check cache
	for (temp = l; temp; temp = temp->next)
		if (temp->psinfo->pr_pid == pid)
			return temp;

	// cache miss, allocate space
	struct psinfo *info = (struct psinfo *)malloc(sizeof *info);
	struct proc_info *nl = (struct proc_info *)malloc(sizeof *nl);
	if (!info || !nl) {
		perror("malloc");
		exit(1);
	}

	// read psinfo
	char fname[PATH_MAX];
	snprintf(fname, sizeof (fname), "/proc/%d/psinfo", pid);
	int fd = open(fname, O_RDONLY);
	if (fd < 0 || read(fd, info, sizeof *info) != sizeof *info)
		goto error;
	close(fd);
	fd = -1;

	// read pwd with getpwuid
	struct passwd *pwd = getpwuid(info->pr_uid);
	if (pwd) {
		int len = strlen(pwd->pw_name);
		name = (char *)malloc(len * sizeof(char) + 1);
		if (!name) {
			perror("malloc");
			exit(1);
		}
		strcpy(name, pwd->pw_name);
	}

	// add to cache
	nl->next = NULL;
	nl->psinfo = info;
	nl->name = name;

	if (!l) {
		l = nl;
	} else {
		for (temp = l; temp->next; temp = temp->next);
		temp->next = nl;
	}

	return nl;

error:
	if (fd >= 0)
		close(fd);
	free(info);
	free(nl);
	if (name)
		free(name);
	return NULL;
}
