:: coff dump
cl coff-dump.c

:: coff runner
ml64 /c coff-run-helper.asm
cl coff-run.c coff-run-helper.obj advapi32.lib

:: APC injector as loadable coff opject
cl /c 123_m.c
