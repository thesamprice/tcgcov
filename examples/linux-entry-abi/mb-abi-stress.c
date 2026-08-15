/*
 * mb-abi-stress: exercise every entry.S path that the MicroBlaze
 * argument-save-area fix (the "GCC 15 regression" v5 kernel patch) touches,
 * so a tcgcov run can confirm each patched reserve site actually executed.
 *
 * Design cribbed from the register-integrity idea of RTEMS spcontext01 and
 * the syscall/signal-state selftests other arches ship (x86 sigreturn,
 * arm64 fp-stress): fill state, cross a kernel boundary, check nothing
 * leaked -- but here the point is coverage of the boundary code, not the
 * check. Each stanza is annotated with the entry.S callee it drives.
 *
 * Runs to "MB-ABI-STRESS DONE"; children that deliberately fault are
 * expected to die and are reaped.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/types.h>

static volatile sig_atomic_t alarms;

/* do_notify_resume: a signal handler runs on the return-to-user path. The
   handler does real work so its own frame is non-trivial. */
static void on_alarm(int sig)
{
    (void)sig;
    alarms++;
}

/* schedule_tail + bra r12 dispatch + do_page_fault(data): a fresh child's
   first return to userspace is schedule_tail; then it faults in its pages
   and makes syscalls. */
static void drive_fork_and_faults(void)
{
    for (int i = 0; i < 8; i++) {
        pid_t p = fork();
        if (p == 0) {
            /* demand-fault a fresh mapping (do_page_fault, data) */
            char *m = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            volatile char s = 0;
            for (size_t k = 0; k < 64 * 1024; k += 4096) {
                m[k] = (char)k;              /* write fault */
                s += m[k];                   /* read */
            }
            (void)s;
            _exit(0);
        }
    }
    for (int i = 0; i < 8; i++) {
        wait(NULL);
    }
}

/* do_page_fault(instruction): jump through a pointer into an unmapped page.
   Fatal (SIGSEGV) in the child, which is the point. */
static void drive_instr_fault(void)
{
    pid_t p = fork();
    if (p == 0) {
        void (*bad)(void) = (void (*)(void))0x4;
        bad();
        _exit(0);
    }
    waitpid(p, NULL, 0);
}

/* full_exception: a privileged instruction from user mode traps to the
   general exception vector. mts to rmsr is privileged; SIGILL follows. */
static void drive_privileged_insn(void)
{
    pid_t p = fork();
    if (p == 0) {
        __asm__ __volatile__("mts rmsr, r0" ::: "memory");
        _exit(0);
    }
    waitpid(p, NULL, 0);
}

/* do_syscall_trace_enter / do_syscall_trace_leave (and, via single-step,
   the dbtrap sw_exception path): a tracer PTRACE_SYSCALLs and single-steps
   a child through some syscalls. */
static void drive_ptrace(void)
{
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        for (int i = 0; i < 4; i++) {
            getpid();
            getppid();
        }
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);          /* initial SIGSTOP */

    /* a few PTRACE_SYSCALL stops (syscall_trace_enter/leave) ... */
    for (int i = 0; i < 8; i++) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) < 0) break;
        if (waitpid(child, &status, 0) < 0 || WIFEXITED(status)) return;
    }
    /* ... then single-step a few instructions (dbtrap/sw_exception) ... */
    for (int i = 0; i < 8; i++) {
        if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) break;
        if (waitpid(child, &status, 0) < 0 || WIFEXITED(status)) return;
    }
    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, 0);
}

/* sw_exception (dbtrap): execute a software-breakpoint instruction. On
   MicroBlaze `brki r16, 0x18` vectors to the debug trap; the child takes
   SIGTRAP. PTRACE_SINGLESTEP is not implemented on this arch, so this is
   the reachable trigger for the dbtrap reserve site. */
static void drive_swbreak(void)
{
    pid_t p = fork();
    if (p == 0) {
        __asm__ __volatile__("brki r16, 0x18" ::: "r16", "memory");
        _exit(0);
    }
    waitpid(p, NULL, 0);
}

/* do_IRQ: a busy loop under a periodic timer guarantees device interrupts
   land while user code runs; do_notify_resume then delivers SIGALRM from
   the interrupt-return path. */
static void drive_irq_and_signals(void)
{
    struct sigaction sa = { .sa_handler = on_alarm };
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = { {0, 2000}, {0, 2000} };  /* 2 ms */
    setitimer(ITIMER_REAL, &it, NULL);

    volatile unsigned long x = 0;
    while (alarms < 20) {
        for (int i = 0; i < 100000; i++) x += i;
    }
    struct itimerval off = { {0, 0}, {0, 0} };
    setitimer(ITIMER_REAL, &off, NULL);
}

int main(void)
{
    printf("MB-ABI-STRESS START\n");
    fflush(stdout);

    drive_fork_and_faults();
    printf(" fork/faults done\n"); fflush(stdout);

    drive_instr_fault();
    drive_privileged_insn();
    printf(" fault stanzas done\n"); fflush(stdout);

    drive_ptrace();
    printf(" ptrace done\n"); fflush(stdout);

    drive_swbreak();
    printf(" swbreak done\n"); fflush(stdout);

    drive_irq_and_signals();
    printf(" irq/signals done (%d alarms)\n", (int)alarms); fflush(stdout);

    printf("MB-ABI-STRESS DONE\n");
    fflush(stdout);
    return 0;
}
