/*
 * mb-abi-stress: exercise every entry.S path that the MicroBlaze
 * argument-save-area fix (the "GCC 15 regression" v5 kernel patch) touches,
 * and assert the bug is absent.
 *
 * Two roles:
 *  1. COVERAGE -- each drive_* stanza crosses a kernel boundary through a
 *     specific entry.S callee, so a tcgcov run confirms every patched
 *     reserve site executed (design lineage: RTEMS spcontext01's
 *     register-integrity idea, the x86/arm64 signal+syscall selftests).
 *  2. CANARY -- a positive pass/fail assertion that the saved user stack
 *     pointer survives a syscall. The bug spills a kernel-entry callee's
 *     first argument to caller_sp+4, which on an unpatched kernel is PT_R1
 *     (the saved user SP) -- so a syscall silently rewrites the user's SP
 *     to a syscall-argument value (init died getting AT_FDCWD as its SP).
 *     sp_checked_syscall() measures r1 immediately before and after the
 *     trap in one asm block; a mismatch is the bug, caught deterministically
 *     rather than waiting for the delayed crash.
 *
 * Exit status and markers: "CANARY PASS" + exit 0 iff every checked syscall
 * preserved SP; "CANARY FAIL" + exit 1 on any mismatch. A harness keys on
 * those, so a kernel that reintroduces the bug turns the test red.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>

static volatile sig_atomic_t alarms;
static int canary_failed;

/*
 * A raw MicroBlaze syscall (nr in r12, args r5.., trap `brki r14, 8`,
 * return in r3) that captures the stack pointer r1 immediately before and
 * after the trap. On a correct kernel the two are identical. On the buggy
 * kernel the syscall's PT_R1 is overwritten by the handler's spilled first
 * argument, so the return path restores a corrupted SP and sp_after differs
 * -- the exact fault, observed in one instruction pair with no reliance on
 * a subsequent crash. The distinctive first argument makes a corrupted SP
 * unmistakable and mirrors the original AT_FDCWD failure.
 */
static long sp_checked_syscall(long nr, long a1, long a2, long a3)
{
    register long r12 __asm__("r12") = nr;
    register long r5  __asm__("r5")  = a1;
    register long r6  __asm__("r6")  = a2;
    register long r7  __asm__("r7")  = a3;
    register long r3  __asm__("r3");
    unsigned long sp_before, sp_after;

    __asm__ __volatile__(
        "addk %0, r1, r0\n\t"      /* sp_before = r1 */
        "brki r14, 0x8\n\t"        /* syscall trap */
        "addk %1, r1, r0\n\t"      /* sp_after  = r1 */
        : "=&r"(sp_before), "=&r"(sp_after), "+r"(r3)
        : "r"(r12), "r"(r5), "r"(r6), "r"(r7)
        : "r14", "r4", "memory");

    if (sp_before != sp_after) {
        /* async-signal-safe report path is not needed; we are in normal
           context. Print raw values so a failure is self-describing. */
        fprintf(stderr,
                "CANARY FAIL: syscall %ld corrupted SP: "
                "0x%lx -> 0x%lx (arg1 was 0x%lx)\n",
                nr, sp_before, sp_after, (unsigned long)a1);
        canary_failed = 1;
    }
    return r3;
}

/* The canary proper: many syscalls through the vulnerable dispatch, each
   carrying a distinctive first argument, each SP-checked. getpid takes no
   args so it also spills nothing; a syscall with a large first arg (here
   an lseek on an invalid fd, and access() with a high pointer) is what
   makes a spilling handler overwrite PT_R1 with that value. */
static void canary_syscall_storm(void)
{
    const long AT_FDCWD = -100;                 /* the original poison value */
    for (int i = 0; i < 20000; i++) {
        sp_checked_syscall(SYS_getpid, 0, 0, 0);
        sp_checked_syscall(SYS_getppid, 0, 0, 0);
        /* faccessat(AT_FDCWD, "x", F_OK, 0): first arg is AT_FDCWD */
        sp_checked_syscall(SYS_faccessat, AT_FDCWD,
                           (long)"/nonexistent", 0);
        if (canary_failed) return;
    }
}

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

    /* Canary first: it is the pass/fail assertion and the most direct
       reproduction of the bug. On an unpatched GCC-15 kernel SP is
       corrupted here (or the process has already died getting a bad SP). */
    canary_syscall_storm();
    printf(" canary storm done (failed=%d)\n", canary_failed);
    fflush(stdout);

    /* Coverage stanzas: drive the remaining entry.S sites. */
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

    if (canary_failed) {
        printf("CANARY FAIL\n");
        fflush(stdout);
        return 1;
    }
    printf("CANARY PASS\n");
    printf("MB-ABI-STRESS DONE\n");
    fflush(stdout);
    return 0;
}
