/* Tier-2 demo: distinct coverage shape -- a taken branch, an untaken branch,
   a loop, and a function that is never called. */
#include <unistd.h>

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

static int never_called(int v)
{
    return v ^ 0xdead;     /* deliberately uncovered */
}

int main(void)
{
    int r = accumulate(8) + taken_branch(32);
    if (r < 0)
        r = never_called(r);   /* untaken guard */
    static char msg[] = "covtest: done\n";
    write(1, msg, sizeof(msg) - 1);
    return r & 1;
}
