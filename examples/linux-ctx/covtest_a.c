/* Tier-3 demo, binary A: linked at the SAME base as binary B, so their
   addresses collide by construction and only the address-space context can
   tell their coverage apart.  Each binary carries a "beacon" function in a
   .beacon section placed at a per-binary address -- the one deliberate
   VA-range difference, which is what lets the host join ctx -> binary
   (`tcgcov contexts --elf`) without guest-side help. */
#include <unistd.h>

__attribute__((section(".beacon"), noinline))
int beacon_a(void)
{
    return 0xA;
}

static int accumulate(int n)
{
    int sum = 0;
    for (int i = 0; i < n; i++)
        sum += i * i;
    return sum;
}

static int taken_branch(int v)
{
    if (v > 10)
        return v * 2;      /* covered */
    return v - 1;          /* not covered with v=32 */
}

int main(void)
{
    int r = beacon_a();
    /* one long-lived process: one address-space context, alive while B runs */
    for (int it = 0; it < 10; it++) {
        r += accumulate(8) + taken_branch(32);
        sleep(1);
    }
    static char msg[] = "cov-a: done\n";
    write(1, msg, sizeof(msg) - 1);
    return r & 1;
}
