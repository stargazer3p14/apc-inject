del *.obj *.exe *.bin *.txt cyrus-emul.asm cyrus-emul-hardcoded.asm cyrus-emul-hardcoded-white.asm cyrus-emul4.asm cyrus-emul-apc-injector.asm cyrus-emul-msgbox-no-params.asm
cl asm2valid.c
cl dump-text.c

::
:: shellcode-simple-msgbox.c -- just pops up MessageBox()
::
cl /c /FAs /GS- /Gs999999999 shellcode-simple-msgbox.c
copy /y shellcode-simple-msgbox.asm shellcode-simple-msgbox.asm.bak
asm2valid shellcode-simple-msgbox.asm > 1.asm
move /y 1.asm shellcode-simple-msgbox.asm

::
:: shellcode-msgbox-no-params.c -- pops up MessageBox() and two consoles, runs two threads and uses no params
::
cl /c /FAs /GS- /Gs999999999 shellcode-msgbox-no-params.c
copy /y shellcode-msgbox-no-params.asm shellcode-msgbox-no-params.asm.bak
asm2valid shellcode-msgbox-no-params.asm > 1.asm
move /y 1.asm shellcode-msgbox-no-params.asm
