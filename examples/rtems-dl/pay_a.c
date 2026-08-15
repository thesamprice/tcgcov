/* Reuse-fixture payload A: the LARGER object, loaded first -- its freed
   allocation must be able to swallow B. Distinct shape from B: loop of 7,
   plus padding functions (one called, one deliberately uncovered). */
#include <stdio.h>

int pay_entry( int n );

static int spin( int n )
{
  int s = 0;
  for ( int i = 0; i < n; i++ ) {
    s += i * 3;
  }
  return s;
}

static int pad_called( int v )
{
  return v * 5 + 1;
}

static int pad_uncovered( int v )
{
  return v ^ 0x5a5a;      /* never called: must report uncovered */
}

int pay_entry( int n )
{
  int r = spin( 7 ) + pad_called( n );
  if ( n < 0 ) {
    r = pad_uncovered( r );
  }
  printf( "pay_a: entry(%d) -> %d\n", n, r );
  return r;
}
