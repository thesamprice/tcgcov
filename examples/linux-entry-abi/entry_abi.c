// SPDX-License-Identifier: GPL-2.0
/*
 * MicroBlaze kernel-entry ABI regression test.
 *
 * The MicroBlaze ABI has the caller reserve stack space for register
 * arguments and lets the callee spill its incoming argument registers
 * there, at [caller_sp + 4, caller_sp + 28).  When arch/microblaze
 * assembly calls C with r1 still pointing at saved state, that spill area
 * aliases live data -- and at the syscall dispatch it aliases pt_regs + 4,
 * i.e. PT_R1, the saved user stack pointer.  A syscall handler that spills
 * its first argument then silently overwrites the user SP, which the return
 * path restores; userspace resumes with a corrupted stack pointer.  (This
 * is how a GCC 15 codegen change turned a latent bug fatal: init died with
 * AT_FDCWD as its stack pointer.)
 *
 * This test asserts the property that must hold: a syscall does not change
 * the user stack pointer.  It reads r1 immediately before and after the
 * trap; on a fixed kernel they are identical, on a regressed kernel they
 * differ (when the process does not simply crash first).
 */
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../kselftest.h"

#if defined(__microblaze__)

/*
 * Raw syscall (nr in r12, args in r5.., trap "brki r14, 8", return in r3)
 * that captures r1 -- the stack pointer -- immediately before and after the
 * trap in one asm block, so the compiler cannot interpose stack motion.
 */
static long sp_checked_syscall(long nr, long a1, long a2, long a3,
			       unsigned long *sp_before, unsigned long *sp_after)
{
	register long r12 __asm__("r12") = nr;
	register long r5  __asm__("r5")  = a1;
	register long r6  __asm__("r6")  = a2;
	register long r7  __asm__("r7")  = a3;
	register long r3  __asm__("r3");
	unsigned long before, after;

	__asm__ __volatile__(
		"addk %0, r1, r0\n\t"
		"brki r14, 0x8\n\t"
		"addk %1, r1, r0\n\t"
		: "=&r"(before), "=&r"(after), "+r"(r3)
		: "r"(r12), "r"(r5), "r"(r6), "r"(r7)
		: "r14", "r4", "memory");

	*sp_before = before;
	*sp_after = after;
	return r3;
}

/*
 * Drive the syscall dispatch many times, each carrying a distinctive first
 * argument (AT_FDCWD, the value that originally poisoned init's SP), so a
 * handler that spills its first argument makes a corrupted SP unmistakable.
 */
static void test_sp_preserved_across_syscall(void)
{
	const long AT_FDCWD = -100;
	unsigned long before, after;
	int corrupt = 0;
	long i;

	for (i = 0; i < 50000; i++) {
		sp_checked_syscall(__NR_getpid, 0, 0, 0, &before, &after);
		if (before != after) {
			corrupt = 1;
			break;
		}
		sp_checked_syscall(__NR_faccessat, AT_FDCWD,
				   (long)"/nonexistent", 0, &before, &after);
		if (before != after) {
			corrupt = 1;
			break;
		}
	}

	if (corrupt)
		ksft_test_result_fail(
			"syscall corrupted the user stack pointer: "
			"0x%lx -> 0x%lx after %ld iterations\n",
			before, after, i);
	else
		ksft_test_result_pass(
			"user stack pointer preserved across %ld syscalls\n",
			i * 2);
}

int main(void)
{
	ksft_print_header();
	ksft_set_plan(1);

	test_sp_preserved_across_syscall();

	ksft_finished();
}

#else

int main(void)
{
	ksft_print_header();
	ksft_set_plan(1);
	ksft_test_result_skip("not a MicroBlaze build\n");
	ksft_finished();
}

#endif
