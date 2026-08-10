/*
 * Branch-coverage fixture with deliberately known outcomes.
 *
 * Every conditional in this file has a documented, hand-checkable result, so
 * the coverage report can be verified rather than merely inspected. See
 * README.md in this directory for the expected output.
 *
 * Build freestanding for a bare-metal target, run under QEMU with the tcgcov
 * plugin, then run the pipeline. Edge recording is on by default, and
 * execution counts are always on. Compile at -O0: at -O1 and above
 * the compiler inlines these and constant-folds every condition away, leaving
 * nothing to measure.
 */

volatile int sink;

/* Both outcomes are exercised: called with 9 and with 1. */
static int taken_both(int x)
{
    if (x > 5) { sink = 1; return 1; }
    else       { sink = 2; return 2; }
}

/* Only one outcome: called with 1, so the condition is never true. */
static int taken_one(int x)
{
    if (x > 1000) { sink = 3; return 3; }
    return 4;
}

/* Never called at all: the branch is never evaluated. */
static int never_called(int x)
{
    if (x) { sink = 5; return 5; }
    return 6;
}

int main(void)
{
    taken_both(9);                      /* condition true  */
    taken_both(1);                      /* condition false */
    taken_one(1);                       /* condition false only */

    if (sink == 12345) {                /* never true: sink is 2 here */
        never_called(1);
    }

    /* Board-specific epilogue. Replace both addresses for your machine:
     * the first signals success on the UART, the second asks the emulator to
     * shut down cleanly. A clean exit matters -- the plugin writes its
     * artifact from an atexit callback, so a SIGKILLed QEMU produces no .cov
     * file at all. */
    *(volatile char *)0x84000004 = 'P';
    *(volatile unsigned *)0xFF000000 = 0;

    for (;;) { }
}
