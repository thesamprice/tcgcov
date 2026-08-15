/* Reuse-fixture payload B: structurally IDENTICAL to pay_a.c -- same
   functions, same statement shapes, so -O0 emits the same section sizes
   and the loader's first-fit allocator reuses A's freed block exactly
   (the dl09 behavior, but with a different object). Only the constants
   differ: loop of 11 (A: 7), multiplier 9 (A: 5), mask 0x3c3c (A:
   0x5a5a) -- so the same address carries different counts and a
   different source file per generation. */
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
  return v * 9 + 1;
}

static int pad_uncovered( int v )
{
  return v ^ 0x3c3c;      /* never called: must report uncovered */
}

int pay_entry( int n )
{
  int r = spin( 11 ) + pad_called( n );
  if ( n < 0 ) {
    r = pad_uncovered( r );
  }
  printf( "pay_b: entry(%d) -> %d\n", n, r );
  return r;
}
