/* radare2 - LGPL - Copyright 2015-2018 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"
#if __WINDOWS__
#include <windows.h>
#endif
#ifdef _MSC_VER
#include <process.h>
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len);
static int lang_pipe_file(RLang *lang, const char *file) {
	return lang_pipe_run (lang, file, -1);
}

#if __WINDOWS__
static HANDLE  myCreateChildProcess(const char * szCmdline) {
	PROCESS_INFORMATION piProcInfo = {0};
	STARTUPINFO siStartInfo = {0};
	BOOL bSuccess = FALSE;
	siStartInfo.cb = sizeof (STARTUPINFO);
	LPTSTR cmdline_ = r_sys_conv_utf8_to_utf16 (szCmdline);
	bSuccess = CreateProcess (NULL, cmdline_, NULL, NULL,
		TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
	free (cmdline_);
	//CloseHandle (piProcInfo.hProcess);
	//CloseHandle (piProcInfo.hThread);
	return bSuccess? piProcInfo.hProcess: NULL;
}

static BOOL bStopPipeLoop = FALSE;
static HANDLE hPipeInOut = NULL;
static HANDLE hproc = NULL;
#define PIPE_BUF_SIZE 4096

static DWORD WINAPI WaitForProcThread(LPVOID lParam) {
	WaitForSingleObject(hproc, INFINITE);
	bStopPipeLoop = TRUE;
	return 0;
}
static void lang_pipe_run_win(RLang *lang) {
	CHAR buf[PIPE_BUF_SIZE];
	BOOL bSuccess = FALSE;
	int i, res = 0;
	DWORD dwRead, dwWritten;
	r_cons_break_push (NULL, NULL);
	res = ConnectNamedPipe (hPipeInOut, NULL);
	if (!res) {
		eprintf ("ConnectNamedPipe failed\n");
		return;
	}
	do {
		if (r_cons_is_breaked ()) {
			TerminateProcess(hproc,0);
			break;
		}
		memset (buf, 0, PIPE_BUF_SIZE);
		bSuccess = ReadFile (hPipeInOut, buf, PIPE_BUF_SIZE, &dwRead, NULL);
		if (bStopPipeLoop) {
			break;
		}
		if (bSuccess && dwRead > 0) {
			buf[sizeof (buf)-1] = 0;
			char *res = lang->cmd_str ((RCore*)lang->user, buf);
			if (res) {
				int res_len = strlen (res) + 1;
				for (i = 0; i < res_len; i++) {
					memset (buf, 0, PIPE_BUF_SIZE);
					dwWritten = 0;
					int writelen=res_len - i;
					int rc = WriteFile (hPipeInOut, res + i, writelen>PIPE_BUF_SIZE?PIPE_BUF_SIZE:writelen, &dwWritten, 0);
					if (bStopPipeLoop) {
						free (res);
						break;
					}
					if (!rc) {
						eprintf ("WriteFile: failed 0x%x\n", (int)GetLastError());
					}
					if (dwWritten > 0) {
						i += dwWritten - 1;
					} else {
						/* send null termination // chop */
						eprintf ("w32-lang-pipe: 0x%x\n", (ut32)GetLastError ());
						//WriteFile (hPipeInOut, "", 1, &dwWritten, NULL);
						//break;
					}
				}
				free (res);
			} else {
				WriteFile (hPipeInOut, "", 1, &dwWritten, NULL);
			}
		}
	} while (!bStopPipeLoop);
	r_cons_break_pop ();
}
#else
static void env(const char *s, int f) {
	char *a = r_str_newf ("%d", f);
	r_sys_setenv (s, a);
//	eprintf ("%s %s\n", s, a);
	free (a);
}
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len) {
#if __UNIX__
	int safe_in = dup (0);
	int child, ret;
	int input[2];
	int output[2];

	pipe (input);
	pipe (output);

	env ("R2PIPE_IN", input[0]);
	env ("R2PIPE_OUT", output[1]);

	child = r_sys_fork ();
	if (child == -1) {
		/* error */
		perror ("pipe run");
	} else if (!child) {
		/* children */
		r_sandbox_system (code, 1);
		write (input[1], "", 1);
		close (input[0]);
		close (input[1]);
		close (output[0]);
		close (output[1]);
		exit (0);
		return false;
	} else {
		/* parent */
		char *res, buf[1024];
		/* Close pipe ends not required in the parent */
		close (output[1]);
		close (input[0]);
		r_cons_break_push (NULL, NULL);
		for (;;) {
			if (r_cons_is_breaked ()) {
				break;
			}
			memset (buf, 0, sizeof (buf));
			void *bed = r_cons_sleep_begin ();
			ret = read (output[0], buf, sizeof (buf) - 1);
			r_cons_sleep_end (bed);
			if (ret < 1 || !buf[0]) {
				break;
			}
			buf[sizeof (buf) - 1] = 0;
			res = lang->cmd_str ((RCore*)lang->user, buf);
			//eprintf ("%d %s\n", ret, buf);
			if (res) {
				write (input[1], res, strlen (res) + 1);
				free (res);
			} else {
				eprintf ("r_lang_pipe: NULL reply for (%s)\n", buf);
				write (input[1], "", 1); // NULL byte
			}
		}
		r_cons_break_pop ();
		/* workaround to avoid stdin closed */
		if (safe_in != -1) {
			close (safe_in);
		}
		safe_in = open (ttyname(0), O_RDONLY);
		if (safe_in != -1) {
			dup2 (safe_in, 0);
		} else {
			eprintf ("Cannot open ttyname(0) %s\n", ttyname(0));
		}
	}

	close (input[0]);
	close (input[1]);
	close (output[0]);
	close (output[1]);
	if (safe_in != -1) {
		close (safe_in);
	}
	waitpid (child, NULL, WNOHANG);
	return true;
#else
#if __WINDOWS__
	char *r2pipe_var = r_str_newf ("R2PIPE_IN%x", _getpid ());
	char *r2pipe_paz = r_str_newf ("\\\\.\\pipe\\%s", r2pipe_var);
	LPTSTR r2pipe_var_ = r_sys_conv_utf8_to_utf16 (r2pipe_var);
	LPTSTR r2pipe_paz_ = r_sys_conv_utf8_to_utf16 (r2pipe_paz);

	SetEnvironmentVariable (TEXT ("R2PIPE_PATH"), r2pipe_var_);
	hPipeInOut = CreateNamedPipe (r2pipe_paz_,
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
			PIPE_BUF_SIZE,
			PIPE_BUF_SIZE,
			0, NULL);
	hproc = myCreateChildProcess (code);
	if (hproc) {
		/* a separate thread is created that sets bStopPipeLoop once hproc terminates. */
		bStopPipeLoop = FALSE;
		CloseHandle (CreateThread (NULL, 0, WaitForProcThread, NULL, 0, NULL));
		/* lang_pipe_run_win has to run in the command thread to prevent deadlock. */
		lang_pipe_run_win (lang);
		DeleteFile (r2pipe_paz_);
		CloseHandle (hPipeInOut);
	}
	free (r2pipe_var);
	free (r2pipe_paz);
	free (r2pipe_var_);
	free (r2pipe_paz_);
	return hproc != NULL;
#endif
#endif
}

static RLangPlugin r_lang_plugin_pipe = {
	.name = "pipe",
	.ext = "pipe",
	.license = "LGPL",
	.desc = "Use #!pipe node script.js",
	.run = lang_pipe_run,
	.run_file = (void*)lang_pipe_file,
};
