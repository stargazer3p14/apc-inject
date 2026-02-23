@rem cl apc-inject.c
@rem cl /DEMBEDDED_SHELLCODE=1 apc-inject.c /Feapc-inject-embedded-shellcode.exe
@rem cl apc-inject-demo.c /Feapc-inject-demo.exe
@rem cl main.c /Feapc-inject-pname-win32.exe
@rem copy /y apc-inject-pname-win32.exe c:\share
cl apc-inject-demo-pname.c /Feapc-inject-demo-pname.exe
