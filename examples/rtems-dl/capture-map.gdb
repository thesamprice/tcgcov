# Capture the RTL module map at the post-load RT_CONSISTENT notification.
# _rtld_debug_state() is called: RT_ADD (pre-load), RT_CONSISTENT (post-load,
# linkmap populated), RT_DELETE, RT_CONSISTENT (post-unload). Stop at hit 2.
set pagination off
set confirm off
target remote :1234
tbreak _rtld_debug_state
continue
tbreak _rtld_debug_state
continue
printf "RSTATE %d\n", _rtld_debug.r_state
set $lm = _rtld_debug.r_map
while $lm != 0
  printf "OBJ %s\n", $lm->name
  printf "BASE text %p const %p data %p bss %p\n", $lm->sec_addr[0], $lm->sec_addr[1], $lm->sec_addr[4], $lm->sec_addr[5]
  set $i = 0
  while $i < $lm->sec_num
    printf "SEC %s off %u size %u rap %u\n", $lm->sec_detail[$i].name, $lm->sec_detail[$i].offset, $lm->sec_detail[$i].size, $lm->sec_detail[$i].rap_id
    set $i = $i + 1
  end
  set $lm = $lm->l_next
end
printf "MAP-DONE\n"
detach
quit
