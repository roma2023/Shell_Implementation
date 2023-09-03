/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Raman Saparkhan <rsaparkh@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);
void BFG_helper(struct cmdline_tokens token, sigset_t prev_all);
bool builtin_command(struct cmdline_tokens token, sigset_t prev_all);
void unix_error(const char *msg);
void IO_error_handling(char *file, int open_return);
void IO_redirection(struct cmdline_tokens token);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

// ---------------------------- Global variables ------------------------------
/**
 * @brief Global variable for handling critical sections in signal handlers.
 *
 * saved_errno is a volatile sig_atomic_t used to save and restore the errno
 * variable during signal handling. Its volatile qualifier ensures atomic
 * access, preventing data corruption in concurrent signal handling scenarios.
 *
 * @see sigint_handler, sigtstp_handler, sigchld_handler
 */
volatile sig_atomic_t saved_errno;

//-------------------------------  MAIN  --------------------------------------
/**
 * @brief Main function of the Tiny Shell (tsh).
 *
 * This function serves as the entry point for the Tiny Shell program. It is
 * responsible for initializing the shell, setting up signal handlers,
 * processing command-line arguments, and entering the read/eval loop to
 * interact with the user and execute commands.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of strings containing the command-line arguments.
 *
 * @return The function never returns in the normal execution flow. If there
 *         are any errors, the function will exit with a non-zero status code.
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}
//--------------------------- HELPER FUNCTIONS --------------------------------

/**
 * @brief Background or Foreground (BFG) command helper function.
 *
 * Resumes a job specified by PID or %jid, sending a SIGCONT signal to allow it
 * to continue execution. If the command is a foreground command (BUILTIN_FG),
 * it sets the job state to FG and waits until the job completes or is stopped
 * by a signal from the child. If the command is a background command
 * (BUILTIN_BG), it sets the job state to BG and prints information about the
 * background job.
 *
 * @param token    Parsed command-line tokens (command and arguments).
 * @param prev_all The previous signal mask before calling this function.
 * @return None.
 */
void BFG_helper(struct cmdline_tokens token, sigset_t prev_all) {
    pid_t pid;
    jid_t jid;
    // Case 1: No argument given
    if (token.argv[1] == NULL) {
        sio_printf("%s command requires PID or %sjobid argument\n",
                   token.argv[0], "%");
        return;
    }
    // Case 2: PID or JID given

    // Checking for PID
    else if (isdigit(token.argv[1][0])) {
        pid = atoi(token.argv[1]);
        jid = job_from_pid(pid);
        if (!jid) {
            sio_printf("%s: No such process\n", token.argv[1]);
            return;
        }
    }
    // Checking for JID
    else if (token.argv[1][0] == '%') {
        jid = atoi(&(token.argv[1][1]));
        if (!(job_exists(jid))) {
            sio_printf("%s: No such job\n", token.argv[1]);
            return;
        }
        pid = job_get_pid(jid);
    }
    // Case 3: Improper format of argument
    else {
        sio_printf("%s: argument must be a PID or %sjobid\n", token.argv[0],
                   "%");
        return;
    }

    // So, now resume job by sending it a SIGCONT signal
    if (kill(-pid, SIGCONT) < 0)
        unix_error("SIGCOUNT ERROR\n");

    if (token.builtin == BUILTIN_FG) {
        // change state to FG
        job_set_state(jid, FG);

        // Run till signal from Child
        while (fg_job())
            sigsuspend(&prev_all);

    }
    // change state to BG
    else {
        job_set_state(jid, BG);
        sio_printf("[%d] (%d) %s \n", job_from_pid(pid), pid,
                   job_get_cmdline(jid));
    }
    return;
}

/**
 * @brief Execute built-in shell commands and indicate a non-built-in command.
 *
 * Executes the built-in shell command specified by the `token` argument.
 * For built-in commands (QUIT, JOBS, BG, FG), it calls the corresponding helper
 * function or exits the shell in the case of QUIT. For non-built-in commands,
 * it returns `true` to indicate that the command is not a built-in command.
 *
 * @param token    Parsed command-line tokens (command and arguments).
 * @param prev_all The previous signal mask before calling this function.
 * @return False if the command is a built-in command, True if it is not.
 */

bool builtin_command(struct cmdline_tokens token, sigset_t prev_all) {
    switch (token.builtin) {
    case BUILTIN_QUIT:
        exit(0);
    case BUILTIN_JOBS:
        return false;
    case BUILTIN_BG:
        // resumes job by sending it a SIGCONT signal
        BFG_helper(token, prev_all);
        return false;
    case BUILTIN_FG:
        // resumes job by sending it a SIGCONT signal
        BFG_helper(token, prev_all);
        return false;
    case BUILTIN_NONE:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Print a Unix-style error message and terminate the program.
 *
 * Prints an error message to the standard error stream (`stderr`) in
 * Unix-style, including the provided error message `msg` and the corresponding
 * error string obtained from `strerror(errno)`. It then terminates the program
 * with an exit status of 1.
 *
 * @param msg The custom error message to display.
 */
void unix_error(const char *msg) { /* Unix-style error */
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

void IO_error_handling(char *file, int open_return) {
    if (open_return < 0) {
        if (errno == EACCES) {
            // Permission denied error
            sio_printf("%s: Permission denied\n", file);
            exit(0);
        } else {
            sio_printf("%s: No such file or directory\n", file);
            exit(0);
        }
    }
}
/**
 * @brief Handle input and output redirection.
 *
 * `IO_redirection` function handles the input and output redirection for a
 * command, as specified by the `token` argument. It opens and redirects the
 * specified input and output files, if provided, using the `dup2` system call.
 *
 * @param token The `cmdline_tokens` structure containing the command-line
 * tokens. It holds information about the input and output files.
 *
 * @see struct cmdline_tokens
 */
void IO_redirection(struct cmdline_tokens token) {
    // Check infile
    if (token.infile) {
        int infd = open(token.infile, O_RDONLY, 0);
        IO_error_handling(token.infile, infd);
        dup2(infd, STDIN_FILENO);
        close(infd);
    } // Check outfile
    if (token.outfile) {
        int outfd = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC,
                         S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        IO_error_handling(token.outfile, outfd);
        dup2(outfd, STDOUT_FILENO);
        close(outfd);
    }
}

/**
 * @brief Evaluate the command line and execute the specified command.
 *
 * The `eval` function parses the input `cmdline` to extract the command and
 * arguments, and then determines whether the command is a built-in command
 * (e.g., quit, jobs) or an external command to be executed by forking a child
 * process. It also handles I/O redirection for input and output if specified in
 * the command line.
 *
 * @param cmdline The input command line to evaluate and execute.
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // printf("\n WE ARE IN EVAL \n");
    // char *argv[MAXARGS]; /* Argument list execve() */
    pid_t pid; /* Process id */
    bool bg;   /* true if its background job*/

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        // parseline error
        return;
    }

    bg =
        (parse_result ==
         PARSELINE_BG); // Determine if the command should run in the background
    if (token.argv[0] == NULL) {
        return; /* Ignore empty lines */
    }
    /* Block signals before fork() */
    sigset_t mask_all, prev_all;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

    if (builtin_command(token, prev_all)) {
        pid = fork();
        if (pid < 0) {
            unix_error("fork failed");
        }
        if (pid == 0) {                                /* Child runs user job */
            sigprocmask(SIG_SETMASK, &prev_all, NULL); // Restore signal mask
            setpgid(0, 0); // Put the child in a new process group to avoid
                           // signal conflicts

            /* Set up I/O redirection */
            IO_redirection(token);

            /* Exec the command */
            execve(token.argv[0], token.argv, environ);
            // If we get here, execve failed.

            sio_printf("%s: %s\n", token.argv[0], strerror(errno));
            exit(127);
        }
        /* Parent waits for foreground job to terminate */
        /* Parent process */
        else {
            if (!bg) {
                add_job(
                    pid, FG,
                    cmdline); // Add the process to the job list as foreground

                while (fg_job()) {
                    sigsuspend(&prev_all);
                }

                sigprocmask(SIG_SETMASK, &prev_all,
                            NULL); // Restore signal mask
            } else {
                // Background job is launched
                add_job(
                    pid, BG,
                    cmdline); // Add the process to the job list as background
                sio_printf("[%d] (%d) %s \n", job_from_pid(pid), pid, cmdline);
                sigprocmask(SIG_SETMASK, &prev_all,
                            NULL); // Restore signal mask
                return;
            }
        }
    } else if (token.builtin == BUILTIN_JOBS) {
        // Check if the output is redirected
        if (token.outfile != NULL) {
            int output_fd = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC,
                                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (output_fd < 0) {
                if (errno == EACCES) {
                    // Permission denied error
                    sio_printf("%s: Permission denied\n", token.outfile);
                    sigprocmask(SIG_SETMASK, &prev_all,
                                NULL); // Restore signal mask
                    return;
                } else {
                    sio_printf("%s: No such file or directory\n",
                               token.outfile);
                    sigprocmask(SIG_SETMASK, &prev_all,
                                NULL); // Restore signal mask
                    return;
                }
            }
            list_jobs(output_fd);
            close(output_fd);
        } else {
            list_jobs(STDOUT_FILENO);
        }
        sigprocmask(SIG_SETMASK, &prev_all, NULL); // Restore signal mask

    } else if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {
        sigprocmask(SIG_SETMASK, &prev_all, NULL); // Restore signal mask
    }

    return;

    // TODO: Implement commands here.
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Signal handler for the SIGCHLD signal, which is sent to the parent
 * process when a child process terminates or is stopped.
 *
 * The `sigchld_handler` function handles the SIGCHLD signal and processes
 * information about terminated or stopped child processes. It updates the job
 * state in the job list accordingly and removes completed jobs from the list.
 * The function also restores the signal mask to its previous state to prevent
 * signal race conditions.
 *
 * @param sig The signal number (should be SIGCHLD).
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_mask;
    pid_t pid;
    int status;
    // Create a signal mask with all signals blocked
    sigfillset(&mask_all);

    // Save the current signal mask
    sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    // sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        if (WIFSTOPPED(status)) { // Child process was stopped (Ctrl+Z)
            job_set_state(job_from_pid(pid),
                          ST); // Set job state to ST (Stopped)
            sio_printf("Job [%d] (%d) stopped by signal %d\n",
                       job_from_pid(pid), pid, WSTOPSIG(status));
        } else if (WIFSIGNALED(status)) { // Child process terminated by a
                                          // signal (Ctrl + C)
            jid_t jid = job_from_pid(pid);
            delete_job(jid); // Remove job from the job list
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
        } else if (WIFEXITED(status)) { // Child process terminated normally
            jid_t jid = job_from_pid(pid);
            delete_job(jid); // Remove job from the job list
        }
    }

    // Restore the original signal mask
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);

    errno = olderrno;
}

/**
 * @brief Signal handler for the SIGINT signal (Ctrl+C), which is sent to the
 * parent process when the user presses Ctrl+C.
 *
 * The `sigint_handler` function handles the SIGINT signal and sends the SIGINT
 * signal to the current foreground job (if there is any). It uses the `fg_job`
 * function to get the job ID of the foreground job and then sends the SIGINT
 * signal to the process group of the job. The function restores the signal mask
 * to its previous state to prevent signal race conditions.
 *
 * @param sig The signal number (should be SIGINT).
 */

void sigint_handler(int sig) {

    int olderrno = errno;

    sigset_t mask_all, prev_mask;

    // Create a signal mask with all signals blocked
    sigfillset(&mask_all);

    // Save the current signal mask
    sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);

    jid_t jid = fg_job(); // Get the job ID of the current foreground job
    if (jid != 0) {
        /* Send SIGINT to the foreground job */
        pid_t pid = job_get_pid(jid);
        if (kill(-pid, SIGINT) < 0) {
            unix_error("kill error");
        }
    }
    // Restore the original signal mask
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);

    errno = olderrno;
}

/**
 * @brief Signal handler for the SIGTSTP signal (Ctrl+Z), which is sent to the
 * parent process when the user presses Ctrl+Z.
 *
 * The `sigtstp_handler` function handles the SIGTSTP signal and sends the
 * SIGTSTP signal to the current foreground job (if there is any). It uses the
 * `fg_job` function to get the job ID of the foreground job and then sends the
 * SIGTSTP signal to the process group of the job. The function restores the
 * signal mask to its previous state to prevent signal race conditions.
 *
 * @param sig The signal number (should be SIGTSTP).
 */
void sigtstp_handler(int sig) {

    int olderrno = errno;

    sigset_t mask_all, prev_mask;

    // Create a signal mask with all signals blocked
    sigfillset(&mask_all);

    // Save the current signal mask
    sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);

    jid_t jid = fg_job(); // Get the job ID of the current foreground job

    if (jid != 0) {
        /* Send SIGTSTP to the foreground job */
        pid_t pid = job_get_pid(jid);
        if (kill(-pid, SIGTSTP) < 0) {
            unix_error("kill error");
        }
    }

    // Restore the original signal mask
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);

    errno = olderrno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
