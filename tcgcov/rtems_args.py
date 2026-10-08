"""Print the -plugin options for RTEMS loader mode, read from the base image.

    qemu-system-riscv32 ... \
        -plugin libtcgcov.so,out=run.cov,mode=tb,edges=on,$(tcgcov rtems-args dl09.exe)

resolves `_rtld_debug_state` and `_rtld_debug` (and the optional
`rtems_rtl_debugger_load` hook, when the image has it) from the ELF's symbol
table, adds `flush_at=` at `_Terminate` so the artifact is written as RTEMS
starts shutting down (a BSP whose shutdown crashes QEMU still leaves one),
and adds `elf=` so the artifact names its base image. This is the step
GDB does for itself when it finds `_r_debug`; without it, every run needs an
`nm` and two hand-copied addresses.
"""

from .rtl import add_args_arguments as add_arguments, run_args as run  # noqa
