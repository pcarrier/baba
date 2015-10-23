#include <errno.h>
#include <iostream>
#include <signal.h>
#include <spawn.h>
#include <stdexcept>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"

/**
 * Higher than the highest signal number.
 * Widespread in libcs but not in POSIX, see Austin 741
 */
#ifndef NSIG
#define NSIG 65
#endif

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#else
/*
 * Our very own signalfd wrapper.
 * We still requires recent kernel headers (2.6.22+)
 */

#include <sys/syscall.h>
int signalfd(int fd, const sigset_t * sigs, int flags)
{
    return syscall(__NR_signalfd4, fd, sigs, NSIG / 8, flags);
}

struct signalfd_siginfo {
    uint32_t ssi_signo;
    int32_t ssi_errno;
    int32_t ssi_code;
    uint32_t ssi_pid;
    uint32_t ssi_uid;
    int32_t ssi_fd;
    uint32_t ssi_tid;
    uint32_t ssi_band;
    uint32_t ssi_overrun;
    uint32_t ssi_trapno;
    int32_t ssi_status;
    int32_t ssi_int;
    uint64_t ssi_ptr;
    uint64_t ssi_utime;
    uint64_t ssi_stime;
    uint64_t ssi_addr;
    uint16_t ssi_addr_lsb;
    uint8_t pad[128 - 12 * 4 - 4 * 8 - 2];
};
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#else
#endif

/**
 * Exception wrapping a description and errno.
 * Presents them in user-friendly fashion.
 * Don't use this unless you know the exception will be displayed:
 * its representation is generated eagerly.
 */
class syserror:public std::exception {
    std::string msg_;

 public:
    const char *what() const throw()
    {
        return msg_.c_str();
    }
    syserror(std::string header)
        : msg_(header + ": " + strerror(errno))
    {
    }
    ~syserror() throw()
    {
    }
};

/**
 * Find the absolute path of an executable, looking up the
 * PATH environment variable if needed.
 * Efficient for absolute paths.
 * Like sh, we skip matches we can't execute.
 */
std::string path_for(std::string name) throw()
{
    if (!access(name.c_str(), X_OK))
        return name;

    const char *cpath = getenv("PATH");
    if (cpath == NULL)
        throw std::runtime_error("no PATH");

    const std::string path(cpath);

    size_t left = 0, right = path.find_first_of(':');

    while (right != std::string::npos) {
        const std::string candidate =
            path.substr(left, right - left) + '/' + name;
        if (!access(candidate.c_str(), X_OK))
            return candidate;
        left = right + 1;
        right = path.find_first_of(':', left);
    }

    throw std::invalid_argument("no such executable: " + name);
}

enum LogLevel {
    CRITICAL = 0,
    VERBOSE = 1,
    TRACE = 2
};

enum TargetType {
    NONE,  // Intercepted signals will be ignored altogether
    CHILD, // Forward to the first child
    GROUP  // Forward to the process group (we always create our own)
};

enum ExitStatus {
    CHILD_STATUS,  // Exit status of the first child
    FAILURE_COUNT  // Number of children (not descendants!) that failed
};

class Runner {
    const pid_t pid_;        // PID of the current process
    pid_t first_child_pid_;  // PID of the first child
    std::string path_;       // Path of the executable for the first child
    int first_child_status_; // Status code of the first child if it exited, or 0
    sigset_t mask_;          // Signals managed by signalfd(2)
    int sfd_;                // File descriptor used for signalfd(2)
    LogLevel log_level_;
    bool failed_count_;      // Number of children (not descendants!) that failed so far
    TargetType signal_fwd_;  // Which process(es) do we forward signals to?
    TargetType track_fails_; // Which process(es) do we track the failure of?
    ExitStatus exit_status_; // What do we want to exit with?

 public:
     /**
      * Parses options, sets everything up, spawns the child.
      * Should be quickly followed by run() to deal with events.
      */
     Runner(int argc, char **argv, char **envp):pid_(getpid()),
        failed_count_(0),
        log_level_(CRITICAL),
        signal_fwd_(GROUP),
        track_fails_(CHILD), first_child_status_(0), exit_status_(CHILD_STATUS) {
        int c;
        while ((c = getopt(argc, argv, "t:f:l:e:")) != -1)
            switch (c) {
            case 'l':
                switch (*optarg) {
                case 'T':
                    log_level_ = TRACE;
                    break;
                case 'V':
                    log_level_ = VERBOSE;
                     break;
                case 'C':
                    log_level_ = CRITICAL;
                    break;
                default:
                    throw std::runtime_error("invalid signal target");
                } break;
            case 'f':
                switch (*optarg) {
                case 'G':
                    signal_fwd_ = GROUP;
                    break;
                case 'C':
                    signal_fwd_ = CHILD;
                    break;
                case 'N':
                    signal_fwd_ = NONE;
                    break;
                default:
                    throw std::runtime_error("invalid log level");
                }
                break;
            case 't':
                switch (*optarg) {
                case 'G':
                    track_fails_ = GROUP;
                    break;
                case 'C':
                    track_fails_ = CHILD;
                    break;
                case 'N':
                    track_fails_ = NONE;
                    break;
                default:
                    throw std::runtime_error("invalid tracking target");
                }
                break;
            case 'e':
                switch (*optarg) {
                case 'c':
                    exit_status_ = CHILD_STATUS;
                    break;
                case 'f':
                    exit_status_ = FAILURE_COUNT;
                    break;
                default:
                    throw std::runtime_error("invalid exit status choice");
                }
                break;
            case '?':
                throw std::runtime_error("invalid usage");
            default:
                abort();
            }

        if (optind == argc) {
            // No command provided!?
            throw std::runtime_error("usage: baba [-option ...] cmd [arg ...]");
        }

        // Look up what to spawn
        path_ = path_for(std::string(argv[optind]));

        // Create our little universe
        setpgrp();
        // We want daemons to reattach to us, not init(1).
        if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0) != 0) {
            throw syserror("becoming subreaper");
        }

        // We should have everything we can intercept here.
        // In practice we skipped real-time signals, maybe others.
        sigemptyset(&mask_);
        sigaddset(&mask_, SIGALRM);
        sigaddset(&mask_, SIGHUP);
        sigaddset(&mask_, SIGINT);
        sigaddset(&mask_, SIGQUIT);
        sigaddset(&mask_, SIGTERM);
        sigaddset(&mask_, SIGTSTP);
        sigaddset(&mask_, SIGTTIN);
        sigaddset(&mask_, SIGTTOU);
        sigaddset(&mask_, SIGUSR1);
        sigaddset(&mask_, SIGUSR2);
        sigaddset(&mask_, SIGWINCH);
        sigaddset(&mask_, SIGCHLD);

        if (sigprocmask(SIG_BLOCK, &mask_, NULL)) {
            throw syserror("sigprocmask");
        }

        // Making sure we reliably receive signals
        // and forward them to our process group (depending on options)
        // but not run in an infinite loop is a hard problem.
        // Note that by "reliably" we really mean as reliably as we possibly can:
        // the guarantees for signals are... loosely defined.
        // signalfd(2) helps.
        sfd_ = signalfd(-1, &mask_, 0);

        if (sfd_ < 0) {
            throw syserror("signalfd");
        }

        posix_spawnattr_t attrs;
        if (posix_spawnattr_init(&attrs)) {
            throw syserror("posix_spawnattr_init");
        }

        // What we spawn should have reasonable signal handling.
        // TODO: the pedantic solution would be to set it
        //       to what we inherited in the first place.
        if (posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETSIGMASK)) {
            throw syserror("posix_spawnattr_setflags");
        }

        // Spawn our first child
        if (posix_spawn(&first_child_pid_, path_.c_str(), NULL, &attrs,
                argv + optind, envp)) {
            throw syserror("spawn");
        }
    }

    /**
     * Main loop, returns our exit status once we're out of children.
     */
    int run() {
        for (;;) {
            struct signalfd_siginfo info;
            if (read(sfd_, &info, sizeof(struct signalfd_siginfo))
                != sizeof(struct signalfd_siginfo)) {
                throw std::runtime_error("partial signalfd read (OS bug!)");
            }

            if (info.ssi_signo == SIGCHLD) {
                // One or more children (not descendants!) finished.
                pid_t pid;
                int stat;
                while ((pid = waitpid(0, &stat, WNOHANG)) >= 0) {
                    bool exited = WIFEXITED(stat);
                    int status = WEXITSTATUS(stat);
                    bool is_first_child = pid == first_child_pid_;
                    bool tracked = (track_fails_ == GROUP ||
                        (track_fails_ == CHILD && is_first_child));
                    if (!exited || status) {
                        if (is_first_child)
                            first_child_status_ = status;
                        if (tracked)
                            failed_count_++;
                        if (log_level_ >= VERBOSE) {
                            if (exited) {
                                std::cerr
                                    << pid
                                    << " exited with status "
                                    << status
                                    << std::endl;
                            }
                            else {
                                std::cerr
                                    << pid
                                    << " terminated early"
                                    << std::endl;
                            }
                        }
                    } else if (log_level_ == TRACE)
                        std::cerr << pid <<
                            " successfully exited" <<
                            std::endl;
                }
                if (errno == ECHILD)
                    // We're all out of children
                    return _finished();
                throw syserror("waitpid");
            }

            _forward_signal(info.ssi_signo);
        }
    }

 private:
    int _finished() {
        close(sfd_);
        if (exit_status_ == CHILD_STATUS)
            return first_child_status_;
        else
            return failed_count_ > 127 ? 127 : failed_count_;
    }

    void _forward_signal(int sig) {
        switch (signal_fwd_) {
        case NONE:
            break;
        case CHILD:
            if (kill(first_child_pid_, sig) < 0 && errno != ESRCH)
                throw syserror("kill child");
            break;
        case GROUP:
            sigdelset(&mask_, sig);
            if (signalfd(sfd_, &mask_, 0) < 0)
                throw syserror("signalfd off");

            if (kill(0, sig) < 0)
                throw syserror("kill group");

            sigset_t waited_for;
            int received;
            sigemptyset(&waited_for);
            sigaddset(&waited_for, sig);
            sigwait(&waited_for, &received);

            sigaddset(&mask_, sig);
            if (signalfd(sfd_, &mask_, 0) < 0)
                throw syserror("signalfd on");
            break;
        }
    }
};

int main(int argc, char **argv, char **envp)
{
    try {
        return Runner(argc, argv, envp).run();
    }
    catch(const std::exception & e) {
        std::cerr << "baba: " << e.what() << std::endl;
        return 1;
    }
}
