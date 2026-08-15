# R2 hook validation: order of per-object load/unload hook hits, with the
# constructor-run flag read AT the load hook (must be clear: hook precedes
# ctors). $a0 is the rtems_rtl_obj* argument (riscv32 ilp32).
set pagination off
set confirm off
target remote :1234
break rtems_rtl_debugger_load
break rtems_rtl_debugger_unload
commands 1
  silent
  printf "HOOK LOAD obj=%s ctor_run=%d\n", ((rtems_rtl_obj*)$a0)->oname, (((rtems_rtl_obj*)$a0)->flags >> 5) & 1
  continue
end
commands 2
  silent
  printf "HOOK UNLOAD obj=%s\n", ((rtems_rtl_obj*)$a0)->oname
  continue
end
continue
