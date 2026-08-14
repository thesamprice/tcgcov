/* Tier-3 demo, binary B: same -Ttext-segment as A, entirely different code.
   Its loop runs 13 times where A's runs 8, and its branch takes the arm A's
   never does -- so a report that mixes the two up is visibly wrong, not
   subtly wrong. */
#include <unistd.h>

__attribute__((section(".beacon"), noinline))
int beacon_b(void)
{
    return 0xB;
}

static int collect(int n)
{
    int p = 1;
    for (int i = 1; i <= n; i++)
        p = (p * i) & 0xffff;
    return p;
}

static int low_branch(int v)
{
    if (v > 10)
        return v * 2;      /* not covered with v=5 */
    return v - 1;          /* covered */
}

int main(void)
{
    int r = beacon_b();
    for (int it = 0; it < 10; it++) {
        r += collect(13) + low_branch(5);
        sleep(1);
    }
    static char msg[] = "cov-b: done\n";
    write(1, msg, sizeof(msg) - 1);
    return r & 1;
}
