rule Lab01_01_exe {
   meta:
      description = "It may like Lab01-01.exe"
      author = "zhouyanlin"
      date = "2022-10-12"
   strings:
      $mz = {4D 5A}
      $s1 = "kernel32.dll" fullword ascii nocase
      $s2 = "MSVCRT.dll" fullword ascii nocase
      $s3 = ".exe" fullword ascii nocase
      $s4 = "WARNING_THIS_WILL_DESTROY_YOUR_MACHINE" fullword ascii nocase
      $s5 = "Lab01-01.dll" fullword ascii nocase
      $s6 = "C:\\Windows\\System32\\Kernel32.dll" fullword ascii nocase
      $s7 = "C:\\Windows\\System32\\Kerne132.dll" fullword ascii nocase
      $s8 = "C:\\*" fullword ascii nocase
   condition:
      all of them
}

rule Lab01_01_dll {
   meta:
      description = "It may like Lab01-01.dll"
      author = "zhouyanlin"
      date = "2022-10-12"
   strings:
      $mz = {4D 5A}
      $s1 = "kernel32.dll" fullword ascii nocase
      $s2 = "MSVCRT.dll" fullword ascii nocase
      $s3 = "WS2_32.dll" fullword ascii nocase
      $s4 = "exec" fullword ascii nocase
      $s5 = "sleep" fullword ascii nocase
      $s6 = "hello" fullword ascii nocase
      $s7 = "127.26.152.13" fullword ascii nocase
      $s8 = "SADFHUHF" fullword ascii nocase
   condition:
      all of them
}

rule Lab01_02_exe_unpack {
   meta:
      description = "It may like Lab01-02-unpack.exe"
      author = "zhouyanlin"
      date = "2022-10-12"
   strings:
      $mz = {4D 5A}
      $s1 = "kernel32.dll" fullword ascii nocase
      $s2 = "MSVCRT.dll" fullword ascii nocase
      $s3 = "ADVAPI32.dll" fullword ascii nocase
      $s4 = "WININET.dll" fullword ascii nocase
      $s5 = "MalService" fullword ascii nocase
      $s6 = "HGL345" fullword ascii nocase
      $s7 = "http://www.malwareanalysisbook.com" fullword ascii nocase
      $s8 = "Internet Explorer 8.0" fullword ascii nocase
   condition:
      all of them
}

rule Lab01_03_exe_unpacked {
   meta:
      description = "It may like Lab01-03-unpacked.exe"
      author = "zhouyanlin"
      date = "2022-10-12"
   strings:
      $mz = {4D 5A}
      $s1 = "kernel32.dll" fullword ascii nocase
      $s2 = "MSVCRT.dll" fullword ascii nocase
      $s3 = "LoadLibraryA" fullword ascii nocase
      $s4 = "GetProcAddress" fullword ascii nocase
      $s5 = "OLEAUT32.dll" fullword ascii nocase
      $s6 = "ole32.dll" fullword ascii nocase
   condition:
      all of them
}

rule Lab01_04_exe {
   meta:
      description = "It may like Lab01-04.exe"
      author = "zhouyanlin"
      date = "2022-10-12"
   strings:
      $mz = {4D 5A}
      $s1 = "kernel32.dll" fullword ascii nocase
      $s2 = "MSVCRT.dll" fullword ascii nocase
      $s3 = "ADVAPI32.dll" fullword ascii nocase
      $s4 = "SeDebugPrivilege" fullword ascii nocase
      $s5 = "sfc_os.dll" fullword ascii nocase
      $s6 = "\\system32\\wupdmgr.exe" fullword ascii nocase
      $s7 = "%s%s" fullword ascii nocase
      $s8 = "#101" fullword ascii nocase
      $s9 = "EnumProcessModules" fullword ascii nocase
      $s11 = "psapi.dll" fullword ascii nocase
      $s12 = "GetModuleBaseNameA" fullword ascii nocase
      $s13 = "EnumProcesses" fullword ascii nocase
      $s14 = "\\winup.exe" fullword ascii nocase
   condition:
      all of them
}