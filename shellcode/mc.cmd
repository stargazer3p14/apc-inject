::
:: shellcode-simple-msgbox.bin -- just pops up MessageBox()
::
ml64 shellcode-simple-msgbox.asm /link /entry:AlignRSP /force:multiple
dump-text shellcode-simple-msgbox.exe shellcode-simple-msgbox.bin

:: Copy to default shellcode name "shellcode1.txt"
:: copy /y shellcode-simple-msgbox.bin shellcode1.txt

::
:: shellcode-msgbox-no-params.bin -- pops up MessageBox() and two consoles, runs two threads and uses no params
::

ml64 shellcode-msgbox-no-params.asm /link /entry:AlignRSP /force:multiple
dump-text shellcode-msgbox-no-params.exe shellcode-msgbox-no-params.bin

:: Copy to default shellcode name "shellcode1.txt"
copy /y shellcode-msgbox-no-params.bin shellcode1.txt
