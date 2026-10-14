rule demo_c2_like_elf {
  meta: description = "Demo: ELF importing ptrace+connect+dup2 and containing a TEST-NET address"
  strings: $ip = "198.51.100.7" ascii  $a = "ptrace" ascii  $b = "connect" ascii  $c = "dup2" ascii
  condition: uint32(0) == 0x464c457f and $ip and all of ($a,$b,$c)
}
rule demo_electron_exec_bridge {
  meta: description = "Demo: JS exposing ipcMain.handle with exec"
  strings: $h = "ipcMain.handle" ascii  $e = "child_process" ascii  $x = "exec(" ascii
  condition: all of them
}
