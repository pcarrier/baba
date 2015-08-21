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

#ifndef NSIG
#define NSIG 65
#endif

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#else
#include <sys/syscall.h>
int signalfd(int fd, const sigset_t *sigs, int flags)
{
        return syscall(__NR_signalfd4, fd, sigs, NSIG/8, flags);
}
struct signalfd_siginfo {
        uint32_t  ssi_signo;
        int32_t   ssi_errno;
        int32_t   ssi_code;
        uint32_t  ssi_pid;
        uint32_t  ssi_uid;
        int32_t   ssi_fd;
        uint32_t  ssi_tid;
        uint32_t  ssi_band;
        uint32_t  ssi_overrun;
        uint32_t  ssi_trapno;
        int32_t   ssi_status;
        int32_t   ssi_int;
        uint64_t  ssi_ptr;
        uint64_t  ssi_utime;
        uint64_t  ssi_stime;
        uint64_t  ssi_addr;
        uint16_t  ssi_addr_lsb;
        uint8_t   pad[128-12*4-4*8-2];
};
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#else
#endif

class syserror:public std::exception {
    std::string msg_;

public:
    const char *what() const throw() {
        return msg_.c_str();
    }
    syserror(std::string header) :
        msg_(header + ": " + strerror(errno))
    {
    }
    ~syserror() throw()
    {
    }
};

std::string path_for(std::string name)
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
    NONE,
    CHILD,
    GROUP
};

enum ExitStatus {
    CHILD_STATUS,
    FAILURE_COUNT
};

class Runner {
    const pid_t pid_;
    std::string path_;
    pid_t child_pid_;
    int child_status_code_;
    sigset_t mask_;
    int sfd_;
    LogLevel log_level_;
    bool failed_count_;
    TargetType signal_forwarding_;
    TargetType failure_tracking_;
    ExitStatus exit_status_;

public:
    Runner(int argc, char **argv, char **envp) :
        pid_(getpid()),
        failed_count_(0),
        log_level_(CRITICAL),
        signal_forwarding_(GROUP),
        failure_tracking_(CHILD),
        child_status_code_(0),
        exit_status_(CHILD_STATUS)
    {
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
                    throw std::runtime_error("invalid signal forwarding target");
                }
                break;
            case 'f':
                switch (*optarg) {
                case 'G':
                    signal_forwarding_ = GROUP;
                    break;
                case 'C':
                    signal_forwarding_ = CHILD;
                    break;
                case 'N':
                    signal_forwarding_ = NONE;
                    break;
                default:
                    throw std::runtime_error("invalid log level");
                }
                break;
            case 't':
                switch (*optarg) {
                case 'G':
                    failure_tracking_ = GROUP;
                    break;
                case 'C':
                    failure_tracking_ = CHILD;
                    break;
                case 'N':
                    failure_tracking_ = NONE;
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
            throw std::runtime_error("usage: baba [-options ...] cmd [args ...]");
        }

        path_ = path_for(std::string(argv[optind]));

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

        setpgrp();
        if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0) != 0)
            throw syserror("becoming subreaper");
        if (sigprocmask(SIG_BLOCK, &mask_, NULL))
            throw syserror("sigprocmask");
        sfd_ = signalfd(-1, &mask_, 0);
        if (sfd_ < 0)
            throw syserror("signalfd");
        posix_spawnattr_t attrs;
        if (posix_spawnattr_init(&attrs))
            throw syserror("posix_spawnattr_init");
        if (posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETSIGMASK))
            throw syserror("posix_spawnattr_setflags");
        if (posix_spawn(&child_pid_, path_.c_str(), NULL, &attrs,
                        argv + optind, envp))
            throw syserror("spawn");
    }

    int run() {
        for (;;) {
            struct signalfd_siginfo info;
            if (read(sfd_, &info, sizeof(struct signalfd_siginfo)) !=
                    sizeof(struct signalfd_siginfo))
                throw std::runtime_error("partial signalfd read");

            if (info.ssi_signo == SIGCHLD) {
                pid_t pid;
                int stat;
                while ((pid = waitpid(0, &stat, WNOHANG)) >= 0) {
                    bool exited = WIFEXITED(stat);
                    int status = WEXITSTATUS(stat);
                    bool is_child = pid == child_pid_;
                    bool tracked = (failure_tracking_ == GROUP ||
                                    (failure_tracking_ == CHILD && is_child));
                    if (!exited || status) {
                        if (is_child)
                            child_status_code_ = status;
                        if (tracked)
                            failed_count_++;
                        if (log_level_ >= VERBOSE) {
                            if (exited)
                                std::cerr << pid << " exited with status " << status << std::endl;
                            else
                                std::cerr << pid << " terminated early" << std::endl;
                        }
                    } else if (log_level_ == TRACE)
                        std::cerr << pid << " successfully exited" << std::endl;
                }
                if (errno == ECHILD)
                    return finished();
                throw syserror("waitpid");
            }

            forward_signal(info.ssi_signo);
        }
    }

private:
    int finished() {
        close(sfd_);
        if (exit_status_ == CHILD_STATUS)
            return child_status_code_;
        else
            return failed_count_ > 127 ? 127 : failed_count_;
    }

    void forward_signal(int sig) {
        switch (signal_forwarding_) {
        case NONE:
            break;
        case CHILD:
            if (kill(child_pid_, sig) < 0 && errno != ESRCH)
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
    if (argc < 2) {
        return 1;
    }

    try {
        return Runner(argc, argv, envp).run();
    } catch(const std::exception & e) {
        std::cerr << "baba: " << e.what() << std::endl;
        return 1;
    }
}

