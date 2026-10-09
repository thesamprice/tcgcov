/* tests/test_dwarf_reloc: entry() is kept; dropped() is never referenced, so
 * --gc-sections discards its code while its debug info stays, relocated to 0. */
int dropped(int v)
{
  return v * 7 + 1;
}

int entry(int v)
{
  return v + 3;
}
