/**
 * Provides a caching layer in front of /proc/<pid>/psinfo
 * and getpwuid()->pw_name with the key as the pid
 *
 * Listing sockets in sockstat.c will not be sorted by pid,
 * so calling open/read/close for every socket in a process
 * can be annoying if the process has a lot of sockets open.
 * This library provides `proc_info_get` which will return
 * a reference to the struct below that has the `psinfo`
 * struct and a pointer to the username of the uid that is
 * running the process
 *
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: March 22, 2015
 * License: CDDL
 */

#include <procfs.h>
#include <pwd.h>

struct proc_info {
	struct psinfo *psinfo;
	char *name;
	struct proc_info *next;
};

/**
 * Example
 *
 * struct proc_info info = proc_info_get(12345)
 * if (info) {
 *         // info->psinfo guaranteed to be set
 *         printf("args = %s\n", info->psinfo->pr_psargs);
 *         // info->name could be NULL if getpwuid() failed
 *         if (info->name)
 *                 printf("username = %s\n", info->name);
 * }
 */
struct proc_info *proc_info_get(int pid);
