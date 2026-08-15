/*
 * Stage R1: dump every loaded object's per-section RUNTIME placement.
 *
 * Application-side code using only the public RTL API -- no RTEMS
 * modification. This is the ground truth the link_map cannot give (it
 * carries only the four aggregate region bases): rtems_rtl_obj_sect.base
 * is each section's real address, alignment gaps included.
 *
 * Output, between BEGIN/END markers for the harness to cut:
 *   RTLMAP <tag> OBJ <oname> SEC <name> <base> <size> <EXEC|->
 *
 * License: BSD-2-Clause, to match the RTEMS code it accompanies.
 */
#include <stdio.h>

#include <rtems/rtl/rtl.h>
#include <rtems/rtl/rtl-obj.h>

#include "rtl-map-dump.h"

void rtl_map_dump( const char* tag )
{
  rtems_chain_control* objects;
  rtems_chain_node*    onode;

  rtems_rtl_lock();
  objects = rtems_rtl_objects_unprotected();
  printf( "RTLMAP %s BEGIN\n", tag );
  for ( onode = rtems_chain_first( objects );
        !rtems_chain_is_tail( objects, onode );
        onode = rtems_chain_next( onode ) ) {
    rtems_rtl_obj*    obj = (rtems_rtl_obj*) onode;
    rtems_chain_node* snode;

    for ( snode = rtems_chain_first( &obj->sections );
          !rtems_chain_is_tail( &obj->sections, snode );
          snode = rtems_chain_next( snode ) ) {
      rtems_rtl_obj_sect* sect = (rtems_rtl_obj_sect*) snode;

      if ( sect->base != NULL && sect->size != 0 ) {
        printf( "RTLMAP %s OBJ %s SEC %s %p %zu %s\n", tag,
                rtems_rtl_obj_oname( obj ) != NULL ?
                  rtems_rtl_obj_oname( obj ) : "(base)",
                sect->name, sect->base, sect->size,
                ( sect->flags &
                  ( RTEMS_RTL_OBJ_SECT_TEXT | RTEMS_RTL_OBJ_SECT_EXEC ) )
                  != 0 ? "EXEC" : "-" );
      }
    }
  }
  printf( "RTLMAP %s END\n", tag );
  rtems_rtl_unlock();
}
