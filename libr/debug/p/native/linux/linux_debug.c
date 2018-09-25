/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_userconf.h>

#if DEBUGGER
#include <r_debug.h>
#include <r_asm.h>
#include <r_reg.h>
#include <r_lib.h>
#include <r_anal.h>
#include <signal.h>
#include <sys/uio.h>
#include <errno.h>
#include "linux_debug.h"
#include "../procfs.h"

#include <sys/syscall.h>
#include <unistd.h>

char *linux_reg_profile (RDebug *dbg) {
#if __arm__
#include "reg/linux-arm.h"
#elif __arm64__ || __aarch64__
#include "reg/linux-arm64.h"
#elif __MIPS__ || __mips__
	if ((dbg->bits & R_SYS_BITS_32) && (dbg->bp->endian == 1)) {
#include "reg/linux-mips.h"
	} else {
#include "reg/linux-mips64.h"
	}
#elif (__i386__ || __x86_64__)
	if (dbg->bits & R_SYS_BITS_32) {
#if __x86_64__
#include "reg/linux-x64-32.h"
#else
#include "reg/linux-x86.h"
#endif
	} else {
#include "reg/linux-x64.h"
	}
#elif __powerpc__
	if (dbg->bits & R_SYS_BITS_32) {
#include "reg/linux-ppc.h"
	} else {
#include "reg/linux-ppc64.h"
	}
#else
#error "Unsupported Linux CPU"
#endif
}

static void linux_detach_all (RDebug *dbg);
static char *read_link (int pid, const char *file);
static int linux_attach_single_pid (RDebug *dbg, int ptid);
static void linux_attach_all (RDebug *dbg);
static void linux_remove_thread (RDebug *dbg, int pid);
static void linux_add_and_attach_new_thread (RDebug *dbg, int tid);
static int linux_stop_process(int pid);

int linux_handle_signals (RDebug *dbg) {
	siginfo_t siginfo = {0};
	int ret = ptrace (PTRACE_GETSIGINFO, dbg->pid, 0, &siginfo);
	if (ret == -1) {
		/* ESRCH means the process already went away :-/ */
		if (errno == ESRCH) {
			dbg->reason.type = R_DEBUG_REASON_DEAD;
			return true;
		}
		r_sys_perror ("ptrace GETSIGINFO");
		return false;
	}

	if (siginfo.si_signo > 0) {
		//siginfo_t newsiginfo = {0};
		//ptrace (PTRACE_SETSIGINFO, dbg->pid, 0, &siginfo);
		dbg->reason.type = R_DEBUG_REASON_SIGNAL;
		dbg->reason.signum = siginfo.si_signo;
		dbg->stopaddr = (ut64)siginfo.si_addr;
		//dbg->errno = siginfo.si_errno;
		// siginfo.si_code -> HWBKPT, USER, KERNEL or WHAT
#warning DO MORE RDEBUGREASON HERE
		switch (dbg->reason.signum) {
			case SIGTRAP:
			{
				if (dbg->glob_libs || dbg->glob_unlibs) {
					ut64 pc_addr = r_debug_reg_get (dbg, "PC");
					RBreakpointItem *b = r_bp_get_at (dbg->bp, pc_addr - dbg->bpsize);
					if (b && b->internal) {
						char *p = strstr (b->data, "dbg.");
						if (p) {
							if (r_str_startswith (p, "dbg.libs")) {
								const char *name;
								if (strstr (b->data, "sym.imp.dlopen")) {
									name = r_reg_get_name (dbg->reg, R_REG_NAME_A0);
								} else {
									name = r_reg_get_name (dbg->reg, R_REG_NAME_A1);
								}
								b->data = r_str_appendf (b->data, ";ps@r:%s", name);
								dbg->reason.type = R_DEBUG_REASON_NEW_LIB;
							} else if (r_str_startswith (p, "dbg.unlibs")) {
								dbg->reason.type = R_DEBUG_REASON_EXIT_LIB;
							}
						}
					}
				}
				if (dbg->reason.type != R_DEBUG_REASON_NEW_LIB &&
					dbg->reason.type != R_DEBUG_REASON_EXIT_LIB) {
					dbg->reason.bp_addr = (ut64)(size_t)siginfo.si_addr;
					dbg->reason.type = R_DEBUG_REASON_BREAKPOINT;
				}
			}
				break;
			case SIGABRT: // 6 / SIGIOT // SIGABRT
				dbg->reason.type = R_DEBUG_REASON_ABORT;
				break;
			case SIGSEGV:
				dbg->reason.type = R_DEBUG_REASON_SEGFAULT;
				break;
			case SIGCHLD:
				dbg->reason.type = R_DEBUG_REASON_SIGNAL;
			default:
				break;
		}
		if (dbg->reason.signum != SIGTRAP) {
			eprintf ("[+] SIGNAL %d errno=%d addr=0x%08"PFMT64x
				" code=%d ret=%d\n",
				siginfo.si_signo, siginfo.si_errno,
				(ut64)(size_t)siginfo.si_addr, siginfo.si_code, ret);
		}
		return true;
	}
	return false;
}

#if __ANDROID__
#undef PT_GETEVENTMSG
#define PT_GETEVENTMSG
#endif

#ifdef PT_GETEVENTMSG
/*
 * Handle PTRACE_EVENT_*
 *
 * Returns R_DEBUG_REASON_*
 *
 * If it's not something we handled, we return ..._UNKNOWN to
 * tell the caller to keep trying to figure out what to do.
 *
 * If something went horribly wrong, we return ..._ERROR;
 *
 * NOTE: This API was added in Linux 2.5.46
 */
RDebugReasonType linux_ptrace_event (RDebug *dbg, int pid, int status) {
	ut32 pt_evt;
#if __powerpc64__ || __arm64__ || __aarch64__ || __x86_64__
	ut64 data;
#else
	ut32 data;
#endif
	/* we only handle stops with SIGTRAP here */
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		return R_DEBUG_REASON_UNKNOWN;
	}

	pt_evt = status >> 16;
	switch (pt_evt) {
	case 0:
		/* NOTE: this case is handled by linux_handle_signals */
		break;
	case PTRACE_EVENT_CLONE:
		if (dbg->trace_clone) {
			if (ptrace (PTRACE_GETEVENTMSG, pid, 0, &data) == -1) {
				r_sys_perror ("ptrace GETEVENTMSG");
				return R_DEBUG_REASON_ERROR;
			}
		//	eprintf ("PTRACE_EVENT_CLONE new_thread=%"PFMT64d"\n", (ut64)data);
			linux_add_and_attach_new_thread (dbg, (int)data);
			return R_DEBUG_REASON_NEW_TID;
		}
		break;
	case PTRACE_EVENT_FORK:
		if (dbg->trace_forks) {
			if (ptrace (PTRACE_GETEVENTMSG, pid, 0, &data) == -1) {
				r_sys_perror ("ptrace GETEVENTMSG");
				return R_DEBUG_REASON_ERROR;
			}

		//	eprintf ("PTRACE_EVENT_FORK new_pid=%"PFMT64d"\n", (ut64)data);
			dbg->forked_pid = data;
			// TODO: more handling here?
			/* we have a new process that we are already tracing */
			return R_DEBUG_REASON_NEW_PID;
		}
		break;
	case PTRACE_EVENT_EXIT:
		if (ptrace (PTRACE_GETEVENTMSG, pid, 0, &data) == -1) {
			r_sys_perror ("ptrace GETEVENTMSG");
			return R_DEBUG_REASON_ERROR;
		}
		//eprintf ("PTRACE_EVENT_EXIT pid=%d, status=0x%"PFMT64x"\n", pid, (ut64)data);
		return pid != dbg->pid ? R_DEBUG_REASON_EXIT_TID : R_DEBUG_REASON_EXIT_PID;
	default:
		eprintf ("Unknown PTRACE_EVENT encountered: %d\n", pt_evt);
		break;
	}
	return R_DEBUG_REASON_UNKNOWN;
}
#endif

int linux_step(RDebug *dbg) {
	int ret = false;
	ut64 addr = r_debug_reg_get (dbg, "PC");
	ret = ptrace (PTRACE_SINGLESTEP, dbg->pid, (void*)(size_t)addr, 0);
	//XXX(jjd): why?? //linux_handle_signals (dbg);
	if (ret == -1) {
		perror ("native-singlestep");
		ret = false;
	} else {
		ret = true;
	}
	return ret;
}

bool linux_set_options(RDebug *dbg, int pid) {
	int traceflags = 0;
	if (dbg->trace_forks) {
		traceflags |= PTRACE_O_TRACEFORK;
		traceflags |= PTRACE_O_TRACEVFORK;
		traceflags |= PTRACE_O_TRACEVFORKDONE;
	}
	if (dbg->trace_clone) {
		traceflags |= PTRACE_O_TRACECLONE;
	}
	if (dbg->trace_execs) {
		traceflags |= PTRACE_O_TRACEEXEC;
	}
	if (dbg->trace_aftersyscall) {
		traceflags |= PTRACE_O_TRACEEXIT;
	}
	/* SIGTRAP | 0x80 on signal handler .. not supported on all archs */
	traceflags |= PTRACE_O_TRACESYSGOOD;
	if (ptrace (PTRACE_SETOPTIONS, pid, 0, traceflags) == -1) {
		return false;
	}
	return true;
}

static void linux_detach_all (RDebug *dbg) {
	RList *th_list = dbg->threads;
	if (th_list) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (th_list, it, th) {
			if (th->pid != dbg->main_pid) {
				if (ptrace (PTRACE_DETACH, th->pid, NULL, NULL) == -1) {
					perror ("PTRACE_DETACH");
				}
			}
		}
	}

	// Detaching from main proc
	if (ptrace (PTRACE_DETACH, dbg->main_pid, NULL, NULL) == -1) {
		perror ("PTRACE_DETACH");
	}
}

static void linux_remove_thread (RDebug *dbg, int pid) {
	RList *th_list = dbg->threads;

	if (th_list) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (th_list, it, th) {
			if (th->pid == pid) {
				r_list_delete_data (th_list, th);
				dbg->n_threads--;
			}
		}
	}
}

void linux_attach_new_process (RDebug *dbg) {
	linux_detach_all (dbg);

	if (dbg->threads) {
		r_list_free (dbg->threads);
		dbg->threads = NULL;
	}
	int stopped = linux_stop_process (dbg->forked_pid);
	if (!stopped) {
		eprintf ("Could not stop pid (%d)\n", dbg->forked_pid);
	}
	linux_attach (dbg, dbg->forked_pid);
	r_debug_select (dbg, dbg->forked_pid, dbg->forked_pid);
}

RDebugReasonType linux_dbg_wait(RDebug *dbg, int my_pid) {
	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;
	int pid = (dbg->continue_all_threads && dbg->n_threads) ? -1 : dbg->main_pid;
	int status, flags = __WALL;

	if (pid == -1) {
		flags |= WNOHANG;
	}
repeat:
	for (;;) {
		int ret = waitpid (pid, &status, flags);
		if (ret < 0) {
			perror ("waitpid");
			break;
		} else if (!ret) {
			flags &= ~WNOHANG;
		} else {
			int pid = ret;
			reason = linux_ptrace_event (dbg, pid, status);

			if (reason == R_DEBUG_REASON_EXIT_TID) {
				ptrace (PTRACE_CONT, pid, NULL, 0);
				goto repeat;
			}

			if (reason != R_DEBUG_REASON_UNKNOWN) {
				break;
			}

			if (WIFEXITED (status)) {
				eprintf ("child exited with status %d\n", WEXITSTATUS (status));
				if (pid == dbg->main_pid) {
					reason = R_DEBUG_REASON_DEAD;
				} else {
					reason = R_DEBUG_REASON_EXIT_TID;
					linux_remove_thread (dbg, pid);
				}
			} else if (WIFSIGNALED (status)) {
				eprintf ("child received signal %d\n", WTERMSIG (status));
				reason = R_DEBUG_REASON_SIGNAL;
			} else if (WIFSTOPPED (status)) {
				if (WSTOPSIG (status) != SIGTRAP &&
					WSTOPSIG (status) != SIGSTOP) {
					eprintf ("child stopped with signal %d\n", WSTOPSIG (status));
					reason = R_DEBUG_REASON_DEAD;
				}
				if (!linux_handle_signals (dbg)) {
					eprintf ("can't handle signals\n");
					return R_DEBUG_REASON_ERROR;
				}
				reason = dbg->reason.type;
#ifdef WIFCONTINUED
			} else if (WIFCONTINUED (status)) {
				eprintf ("child continued...\n");
				reason = R_DEBUG_REASON_NONE;
#endif
			} else if (status == 1) {
				eprintf ("EEK DEAD DEBUGEE!\n");
				reason = R_DEBUG_REASON_DEAD;
			} else if (status == 0) {
				eprintf ("STATUS=0?!?!?!?\n");
				reason = R_DEBUG_REASON_DEAD;
			} else {
				if (ret != pid) {
					reason = R_DEBUG_REASON_NEW_PID;
				} else {
					eprintf ("CRAP. returning from wait without knowing why...\n");
				}
			}
			if (reason != R_DEBUG_REASON_UNKNOWN) {
				break;
			}
		}
	}
	return reason;
}

int match_pid(const void *pid_o, const void *th_o) {
	int pid = *(int *)pid_o;
	RDebug *th = (RDebug *)th_o;
	return pid == th->pid;
}

static void linux_add_and_attach_new_thread(RDebug *dbg, int tid) {
	int uid = getuid(); // XXX
	char info[1024] = {0};
	RDebugPid *tid_info;

	if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
		tid_info = fill_pid_info (info, NULL, tid);
	} else {
		tid_info = r_debug_pid_new ("new_path", tid, uid, 's', 0);
	}
	(void) linux_attach (dbg, tid);
	r_list_append (dbg->threads, tid_info);
	dbg->tid = tid;
	dbg->n_threads++;
}

static int linux_stop_process(int pid) {
	int status;
	int ret = syscall (__NR_tkill, pid, SIGSTOP);
	if (ret != -1) {
		ret = waitpid (pid, &status, __WALL);
	}
	return ret == pid;
}

static int linux_attach_single_pid(RDebug *dbg, int ptid) {
	int ret = 0;
	linux_set_options (dbg, ptid);
	ret = ptrace (PTRACE_ATTACH, ptid, NULL, NULL);
	return ret;
}

static RList *get_pid_thread_list (RDebug *dbg, int main_pid) {
	RList *list = r_list_new ();
	if (list) {
		list = linux_thread_list (main_pid, list);
		dbg->main_pid = main_pid;
	}
	return list;
}

static void linux_attach_all (RDebug *dbg) {
	int ret = linux_attach_single_pid (dbg, dbg->main_pid);
	if (ret != -1) {
		perror ("ptrace (PT_ATTACH)");
	}

	RList *list = dbg->threads;
	if (list) {
		RDebugPid *th;
		RListIter *it;
		r_list_foreach (list, it, th) {
			if (th->pid && th->pid != dbg->main_pid) {
				ret = linux_attach_single_pid (dbg, th->pid);
				if (ret == -1) {
					eprintf ("PID %d\n", th->pid);
					perror ("ptrace (PT_ATTACH)");
				}
			}
		}
	}
}

int linux_attach(RDebug *dbg, int pid) {
	// First time we run: We try to attach to all "possible" threads and to the main pid
	if (!dbg->threads) {
		dbg->threads = get_pid_thread_list (dbg, pid);
		linux_attach_all (dbg);
	} else {
		// This means we did a first run, so we probably attached to all possible threads already.
		// So check if the requested thread is being traced already. If yes: skip
		if (dbg->threads && !r_list_find (dbg->threads, &pid, &match_pid)) {
			goto out;
		}
		int ret = linux_attach_single_pid (dbg, pid);
		if (ret == -1) {
			// ignore perror ("ptrace (PT_ATTACH)");
		}
	}
out:
	return pid;
}

static char *read_link(int pid, const char *file) {
	char path[1024] = {0};
	char buf[1024] = {0};

	snprintf (path, sizeof (path), "/proc/%d/%s", pid, file);
	int ret = readlink (path, buf, sizeof (buf));
	if (ret > 0) {
		buf[sizeof (buf) - 1] = '\0';
		return strdup (buf);
	}
	return NULL;
}

RDebugInfo *linux_info(RDebug *dbg, const char *arg) {
	char proc_buff[1024];
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}

	RList *th_list;
	bool list_alloc = false;
	if (dbg->threads) {
		th_list = dbg->threads;
	} else {
		th_list = r_list_new ();
		list_alloc = true;
		if (th_list) {
			th_list = linux_thread_list (dbg->pid, th_list);
		}
	}
	RDebugPid *th;
	RListIter *it;
	bool found = false;
	r_list_foreach (th_list, it, th) {
		if (th->pid == dbg->pid) {
			found = true;
			break;
		}
	}
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->uid = found ? th->uid : -1;
	rdi->gid = found ? th->gid : -1;
	rdi->cwd = read_link (rdi->pid, "cwd");
	rdi->exe = read_link (rdi->pid, "exe");
	snprintf (proc_buff, sizeof (proc_buff),
				"/proc/%d/cmdline", rdi->pid);
	rdi->cmdline = r_file_slurp (proc_buff, NULL);
	snprintf (proc_buff, sizeof (proc_buff),
				"/proc/%d/stack", rdi->pid);
	rdi->kernel_stack = r_file_slurp (proc_buff, NULL);
	rdi->status = found ? th->status : R_DBG_PROC_STOP;
	if (list_alloc) {
		r_list_free (th_list);
	}
	return rdi;
}

RDebugPid *fill_pid_info(const char *info, const char *path, int tid) {
	RDebugPid *pid_info = R_NEW0 (RDebugPid);
	if (!pid_info) {
		return NULL;
	}
	char *ptr = strstr (info, "State:");
	if (ptr) {
		switch (*(ptr + 7)) {
		case 'R':
			pid_info->status = R_DBG_PROC_RUN;
			break;
		case 'S':
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		case 'T':
		case 't':
			pid_info->status = R_DBG_PROC_STOP;
			break;
		case 'Z':
			pid_info->status = R_DBG_PROC_ZOMBIE;
			break;
		case 'X':
			pid_info->status = R_DBG_PROC_DEAD;
			break;
		default:
			pid_info->status = R_DBG_PROC_SLEEP;
			break;
		}
	}
	ptr = strstr (info, "Uid:");
	if (ptr) {
		pid_info->uid = atoi (ptr + 5);
	}
	ptr = strstr (info, "Gid:");
	if (ptr) {
		pid_info->gid = atoi (ptr + 5);
	}
	pid_info->pid = tid;
	pid_info->path = path ? strdup (path) : NULL;
	pid_info->runnable = true;
	pid_info->pc = 0;
	return pid_info;
}

RList *linux_thread_list(int pid, RList *list) {
	int i, thid = 0;
	char *ptr, buf[1024];

	if (!pid) {
		r_list_free (list);
		return NULL;
	}

	list->free = (RListFree)&r_debug_pid_free;
	/* if this process has a task directory, use that */
	snprintf (buf, sizeof (buf), "/proc/%d/task", pid);
	if (r_file_is_directory (buf)) {
		struct dirent *de;
		DIR *dh = opendir (buf);
		while ((de = readdir (dh))) {
			if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) {
				continue;
			}
			int tid = atoi (de->d_name);
			char info[1024];
			int uid = 0;
			if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
				ptr = strstr (info, "Uid:");
				if (ptr) {
					uid = atoi (ptr + 4);
				}
				ptr = strstr (info, "Tgid:");
				if (ptr) {
					int tgid = atoi (ptr + 5);
					if (tgid != pid) {
						// If we want to attach to just one thread, don't attach to the parent
						continue;
					}
                                }
			}

			if (procfs_pid_slurp (tid, "comm", buf, sizeof (buf)) == -1) {
				/* fall back to auto-id */
				snprintf (buf, sizeof (buf), "thread_%d %s", thid++, pid == tid ? "(current)" : NULL);
				buf[sizeof (buf) - 1] = 0;
			}

			RDebugPid *pid_info;
			if (!procfs_pid_slurp (tid, "status", info, sizeof (info))) {
				// Get information about pid (status, pc, etc.)
				pid_info = fill_pid_info (info, buf, tid);
			} else {
				pid_info = r_debug_pid_new (buf, tid, uid, 's', 0);
			}
			r_list_append (list, pid_info);
		}
		closedir (dh);
	} else {
		/* LOL! linux hides threads from /proc, but they are accessible!! HAHAHA */
#undef MAXPID
#define MAXPID 99999
		/* otherwise, brute force the pids */
		for (i = pid; i < MAXPID; i++) { // XXX
			if (procfs_pid_slurp (i, "status", buf, sizeof(buf)) == -1) {
				continue;
			}
			int uid = 0;
			/* look for a thread group id */
			ptr = strstr (buf, "Uid:");
			if (ptr) {
				uid = atoi (ptr + 4);
			}
			ptr = strstr (buf, "Tgid:");
			if (ptr) {
				int tgid = atoi (ptr + 5);

				/* if it is not in our thread group, we don't want it */
				if (tgid != pid) {
					continue;
				}

				if (procfs_pid_slurp (i, "comm", buf, sizeof(buf)) == -1) {
					/* fall back to auto-id */
					snprintf (buf, sizeof(buf), "thread_%d", thid++);
				}
				r_list_append (list, r_debug_pid_new (buf, i, uid, 's', 0));
			}
		}
	}
	return list;
}

#define PRINT_FPU(fpregs) \
	eprintf ("cwd = 0x%04x  ; control   ", (fpregs).cwd);\
	eprintf ("swd = 0x%04x  ; status\n", (fpregs).swd);\
	eprintf ("ftw = 0x%04x              ", (fpregs).ftw);\
	eprintf ("fop = 0x%04x\n", (fpregs).fop);\
	eprintf ("rip = 0x%016"PFMT64x"  ", (ut64)(fpregs).rip);\
	eprintf ("rdp = 0x%016"PFMT64x"\n", (ut64)(fpregs).rdp);\
	eprintf ("mxcsr = 0x%08x        ", (fpregs).mxcsr);\
	eprintf ("mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)\

#define PRINT_FPU_NOXMM(fpregs) \
	eprintf ("cwd = 0x%04lx  ; control   ", (fpregs).cwd);\
	eprintf ("swd = 0x%04lx  ; status\n", (fpregs).swd);\
	eprintf ("twd = 0x%04lx              ", (fpregs).twd);\
	eprintf ("fip = 0x%04lx          \n", (fpregs).fip);\
	eprintf ("fcs = 0x%04lx              ", (fpregs).fcs);\
	eprintf ("foo = 0x%04lx          \n", (fpregs).foo);\
	eprintf ("fos = 0x%04lx              ", (fpregs).fos)

void print_fpu (void *f, int r){
#if __x86_64__ || __i386__
	int i;
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct*)f;
#if __x86_64__
#if !__ANDROID__
	eprintf ("---- x86-64 ----\n");
	PRINT_FPU (fpregs);
	eprintf ("size = 0x%08x\n", (ut32)sizeof (fpregs));
	for (i = 0; i < 16; i++) {
		ut32 *a = (ut32*)&fpregs.xmm_space;
		a = a + (i * 4);
		eprintf ("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0], (int)a[1],
			(int)a[2], (int)a[3] );
		if (i < 8) {
			ut64 *b = (ut64*)&fpregs.st_space[i * 4];
			ut32 *c = (ut32*)&fpregs.st_space;
			float *f = (float *)&fpregs.st_space;
			double *d = (double *)&fpregs.st_space[i*4];
			c = c + (i * 4);
			f = f + (i * 4);
			eprintf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (%08x)  |\
				%0.3f (%08x) \n", i, *d, *b,
				(float)f[0], c[0], (float)f[1], c[1]);
		} else {
			eprintf ("\n");
		}
	}
#else
	PRINT_FPU (fpregs);
	for (i = 0;i < 8; i++) {
		ut64 *b = (ut64 *)&fpregs.st_space[i*4];
		ut32 *c = (ut32*)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		eprintf ("st%d =%0.3lg (0x%016"PFMT64x") | %0.3f (%08x)  | \
			%0.3f (%08x) \n", i,
			(double)*((double*)&fpregs.st_space[i*4]), *b, (float) f[0],
			c[0], (float) f[1], c[1]);
	}
#endif	// !__ANDROID__
#elif __i386__
	if (!r) {
#if !__ANDROID__
		struct user_fpxregs_struct fpxregs = *(struct user_fpxregs_struct*)f;
		eprintf ("---- x86-32 ----\n");
		eprintf ("cwd = 0x%04x  ; control   ", fpxregs.cwd);
		eprintf ("swd = 0x%04x  ; status\n", fpxregs.swd);
		eprintf ("twd = 0x%04x ", fpxregs.twd);
		eprintf ("fop = 0x%04x\n", fpxregs.fop);
		eprintf ("fip = 0x%08x\n", fpxregs.fip);
		eprintf ("fcs = 0x%08x\n", fpxregs.fcs);
		eprintf ("foo = 0x%08x\n", fpxregs.foo);
		eprintf ("fos = 0x%08x\n", fpxregs.fos);
		eprintf ("mxcsr = 0x%08x\n", fpxregs.mxcsr);
		for(i = 0; i < 8; i++) {
			ut32 *a = (ut32*)(&fpxregs.xmm_space);
			ut64 *b = (ut64 *)(&fpxregs.st_space[i * 4]);
			ut32 *c = (ut32*)&fpxregs.st_space;
			float *f = (float *)&fpxregs.st_space;
			a = a + (i * 4);
			c = c + (i * 4);
			f = f + (i * 4);
			eprintf ("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0],
				(int)a[1], (int)a[2], (int)a[3] );
			eprintf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x) |\
				%0.3f (0x%08x)\n", i,
				(double)*((double*)(&fpxregs.st_space[i*4])), b[0],
				f[0], c[0], f[1], c[1]);
		}
#endif // !__ANDROID__
	} else {
		eprintf ("---- x86-32-noxmm ----\n");
		PRINT_FPU_NOXMM (fpregs);
		for(i = 0; i < 8; i++) {
			ut64 *b = (ut64 *)(&fpregs.st_space[i*4]);
			double *d = (double*)b;
			ut32 *c = (ut32*)&fpregs.st_space;
			float *f = (float *)&fpregs.st_space;
			c = c + (i * 4);
			f = f + (i * 4);
			eprintf ("st%d = %0.3lg (0x%016"PFMT64x") | %0.3f (0x%08x)  | \
				%0.3f (0x%08x)\n", i, d[0], b[0], f[0], c[0], f[1], c[1]);
		}
	}
#endif
#else
#warning print_fpu not implemented for this platform
#endif
}

int linux_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	bool showfpu = false;
	int pid = dbg->pid;
	int ret;
	if (type < -1) {
		showfpu = true;
		type = -type;
	}
	switch (type) {
	case R_REG_TYPE_DRX:
#if __POWERPC__
		// no drx for powerpc
		return false;
#elif __i386__ || __x86_64__
#if !__ANDROID__
	{
		int i;
		for (i = 0; i < 8; i++) { //DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			long ret = ptrace (PTRACE_PEEKUSER, pid,
					r_offsetof (struct user, u_debugreg[i]), 0);
			if ((i+1) * sizeof (ret) > size) {
				eprintf ("linux_reg_get: Buffer too small %d\n", size);
				break;
			}
			memcpy (buf + (i * sizeof (ret)), &ret, sizeof (ret));
		}
		struct user a;
		return sizeof (a.u_debugreg);
	}
#else
	#warning Android X86 does not support DRX
#endif
#endif
		return true;
		break;
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_MMX:
	case R_REG_TYPE_XMM:
#if __POWERPC__
		return false;
#elif __x86_64__ || __i386__
		{
		int ret1 = 0;
		struct user_fpregs_struct fpregs;
		if (type == R_REG_TYPE_FPU) {
#if __x86_64__
#if !__ANDROID__
			ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) {
				print_fpu ((void *)&fpregs, 0);
			}
			if (ret1 != 0) {
				return false;
			}
			if (sizeof (fpregs) < size) {
				size = sizeof (fpregs);
			}
			memcpy (buf, &fpregs, size);
			return sizeof(fpregs);
#else
			ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) print_fpu ((void *)&fpregs, 0);
			if (ret1 != 0) return false;
			if (sizeof(fpregs) < size) size = sizeof(fpregs);
			memcpy (buf, &fpregs, size);
			return sizeof(fpregs);
#endif // !__ANDROID__
#elif __i386__
#if !__ANDROID__
			struct user_fpxregs_struct fpxregs;
			ret1 = ptrace (PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret1 == 0) {
				if (showfpu) print_fpu ((void *)&fpxregs, ret1);
				if (sizeof(fpxregs) < size) size = sizeof(fpxregs);
				memcpy (buf, &fpxregs, size);
				return sizeof(fpxregs);
			} else {
				ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (showfpu) print_fpu ((void *)&fpregs, ret1);
				if (ret1 != 0) return false;
				if (sizeof(fpregs) < size) size = sizeof(fpregs);
				memcpy (buf, &fpregs, size);
				return sizeof(fpregs);
			}
#else
			ret1 = ptrace (PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (showfpu) print_fpu ((void *)&fpregs, 1);
			if (ret1 != 0) return false;
			if (sizeof (fpregs) < size) size = sizeof(fpregs);
			memcpy (buf, &fpregs, size);
			return sizeof(fpregs);
#endif // !__ANDROID__
#endif // __i386__
		}
		}
#else
	#warning getfpregs not implemented for this platform
#endif
		break;
	case R_REG_TYPE_SEG:
	case R_REG_TYPE_FLG:
	case R_REG_TYPE_GPR:
		{
			R_DEBUG_REG_T regs;
			memset (&regs, 0, sizeof (regs));
			memset (buf, 0, size);
#if __arm64__ || __aarch64__
			{
			struct iovec io = {
				.iov_base = &regs,
				.iov_len = sizeof (regs)
			};
			ret = ptrace (PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
			}
#elif __BSD__ && __POWERPC__ || __sparc__
			ret = ptrace (PTRACE_GETREGS, pid, &regs, NULL);
#else
			/* linux -{arm/x86/x86_64} */
			ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
#endif
			/*
			 * if perror here says 'no such process' and the
			 * process exists still.. is because there's a missing call
			 * to 'wait'. and the process is not yet available to accept
			 * more ptrace queries.
			 */
			if (ret != 0) {
				return false;
			}
			if (sizeof (regs) < size) {
				size = sizeof (regs);
			}
			memcpy (buf, &regs, size);
			return sizeof (regs);
		}
		break;
	}
	return true;

}

int linux_reg_write (RDebug *dbg, int type, const ut8 *buf, int size) {
	if (type == R_REG_TYPE_DRX) {
#if !__ANDROID__ && (__i386__ || __x86_64__)
		int i;
		long *val = (long*)buf;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			if (ptrace (PTRACE_POKEUSER, dbg->pid, r_offsetof (
					struct user, u_debugreg[i]), val[i])) {
				eprintf ("ptrace error for dr %d\n", i);
				r_sys_perror ("ptrace POKEUSER");
			}
		}
		return sizeof (R_DEBUG_REG_T);
#else
		return false;
#endif
	}
	if (type == R_REG_TYPE_GPR) {
#if __arm64__ || __aarch64__
		struct iovec io = {
			.iov_base = buf,
			.iov_len = sizeof (R_DEBUG_REG_T)
		};
		int ret = ptrace (PTRACE_SETREGSET, dbg->pid, NT_PRSTATUS, &io);
#elif __POWERPC__ || __sparc__
		int ret = ptrace (PTRACE_SETREGS, dbg->pid, buf, NULL);
#else
		int ret = ptrace (PTRACE_SETREGS, dbg->pid, 0, (void*)buf);
#endif
#if DEAD_CODE
		if (size > sizeof (R_DEBUG_REG_T)) {
			size = sizeof (R_DEBUG_REG_T);
		}
#endif
		return (ret != 0) ? false : true;
	}
	return false;
}

RList *linux_desc_list (int pid) {
	RList *ret = NULL;
	char path[512], file[512], buf[512];
	struct dirent *de;
	RDebugDesc *desc;
	int type, perm;
	int len, len2;
	struct stat st;
	DIR *dd = NULL;

	snprintf (path, sizeof (path), "/proc/%i/fd/", pid);
	if (!(dd = opendir (path))) {
		r_sys_perror ("opendir /proc/x/fd");
		return NULL;
	}
	ret = r_list_new ();
	if (!ret) {
		closedir (dd);
		return NULL;
	}
	ret->free = (RListFree)r_debug_desc_free;
	while ((de = (struct dirent *)readdir(dd))) {
		if (de->d_name[0] == '.') {
			continue;
		}
		len = strlen (path);
		len2 = strlen (de->d_name);
		if (len + len2 + 1 >= sizeof(file)) {
			r_list_free (ret);
			closedir (dd);
			eprintf ("Filename is too long");
			return NULL;
		}
		memcpy (file, path, len);
		memcpy (file + len, de->d_name, len2 + 1);
		memset (buf, 0, sizeof(buf));
		readlink (file, buf, sizeof (buf) - 1);
		buf[sizeof (buf)-1] = 0;
		type = perm = 0;
		if (stat (file, &st) != -1) {
			type  = st.st_mode & S_IFIFO  ? 'P':
#ifdef S_IFSOCK
				st.st_mode & S_IFSOCK ? 'S':
#endif
				st.st_mode & S_IFCHR  ? 'C':'-';
		}
		if (lstat(path, &st) != -1) {
			if (st.st_mode & S_IRUSR) {
				perm |= R_PERM_R;
			}
			if (st.st_mode & S_IWUSR) {
				perm |= R_PERM_W;
			}
		}
		//TODO: Offset
		desc = r_debug_desc_new (atoi (de->d_name), buf, perm, type, 0);
		if (!desc) {
			break;
		}
		r_list_append (ret, desc);
	}
	closedir (dd);
	return ret;
}

#endif
