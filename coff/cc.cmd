:: coff dump
cl coff-dump.c

:: coff runner
ml64 /c coff-run-helper.asm
cl coff-run.c coff-run-helper.obj
