/* Stage R1 / cross-object-reuse fixture.
 *
 * Loads payload A, calls it, dumps the per-section map (rtl-map-dump),
 * closes A, loads the smaller payload B -- which the allocator places in
 * A's freed block -- calls it, dumps again, exits. Run under the tcgcov
 * plugin's rtl mode, this produces the different-object address-reuse
 * case the stock dl tests never generate.
 *
 * License: BSD-2-Clause.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include <rtems.h>
#include <rtems/imfs.h>

#include "rtl-map-dump.h"

#include "payload-tar.h"

typedef int ( *pay_entry_t )( int );

static int run_one( const char* path, const char* tag )
{
  void*       handle;
  pay_entry_t entry;
  int         r;

  handle = dlopen( path, RTLD_NOW | RTLD_GLOBAL );
  if ( handle == NULL ) {
    printf( "FIXTURE-FAIL dlopen %s: %s\n", path, dlerror() );
    return 1;
  }
  entry = (pay_entry_t) dlsym( handle, "pay_entry" );
  if ( entry == NULL ) {
    printf( "FIXTURE-FAIL dlsym %s\n", path );
    return 1;
  }
  r = entry( 3 );
  printf( "FIXTURE %s returned %d\n", tag, r );
  rtl_map_dump( tag );
  if ( dlclose( handle ) != 0 ) {
    printf( "FIXTURE-FAIL dlclose %s\n", path );
    return 1;
  }
  return 0;
}

static rtems_task Init( rtems_task_argument arg )
{
  int rc;

  (void) arg;

  printf( "*** BEGIN OF TEST tcgcov reuse fixture ***\n" );

  rc = rtems_tarfs_load( "/", (void*) payload_tar,
                         (size_t) payload_tar_size );
  if ( rc != 0 ) {
    printf( "FIXTURE-FAIL untar: %d\n", rc );
    exit( 1 );
  }

  rc  = run_one( "/pay_a.o", "A-LOADED" );
  rc += run_one( "/pay_b.o", "B-LOADED" );

  printf( "*** END OF TEST tcgcov reuse fixture ***\n" );
  exit( rc );
}

#define CONFIGURE_APPLICATION_NEEDS_CLOCK_DRIVER
#define CONFIGURE_APPLICATION_NEEDS_SIMPLE_CONSOLE_DRIVER

#define CONFIGURE_MAXIMUM_FILE_DESCRIPTORS 4

#define CONFIGURE_MAXIMUM_TASKS 1

#define CONFIGURE_MAXIMUM_SEMAPHORES 1

#define CONFIGURE_RTEMS_INIT_TASKS_TABLE

#define CONFIGURE_INIT_TASK_STACK_SIZE \
  ( CONFIGURE_MINIMUM_TASK_STACK_SIZE + ( 8U * 1024U ) )

#define CONFIGURE_INIT_TASK_ATTRIBUTES RTEMS_FLOATING_POINT

#define CONFIGURE_INIT

#include <rtems/confdefs.h>
