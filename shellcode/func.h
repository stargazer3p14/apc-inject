/*
 *	Functions and handles/other parameters that injected shellcode may/will use for stable/static data (possibly between threads)
 */

#include <windows.h>

// Some typedefs for functions with many parameters, that are too long to type repeatedly

// From WRK 1.2 -- NTIOAPI.H, NTOBAPI.H

#ifdef NTAPI
#undef NTAPI
#define NTAPI
#endif

typedef
NTSYSCALLAPI
NTSTATUS
NTAPI
(*NtCreateFile_t) (
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength
    );

typedef
NTSYSCALLAPI
NTSTATUS
NTAPI
(*NtReadFile_t) (
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in_opt PLARGE_INTEGER ByteOffset,
    __in_opt PULONG Key
    );

typedef
NTSYSCALLAPI
NTSTATUS
NTAPI
(*NtWriteFile_t) (
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in_opt PLARGE_INTEGER ByteOffset,
    __in_opt PULONG Key
    );

typedef
NTSYSCALLAPI
NTSTATUS
NTAPI
(*NtClose_t) (
    __in HANDLE Handle
    );


// From MSDN

typedef
void (*RtlInitUnicodeString_t)(
  PUNICODE_STRING DestinationString,
  PCWSTR          SourceString
);


typedef 
int (*MessageBoxA_t)(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

typedef
int (*MessageBoxW_t)(
	HWND hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT uType
);

typedef
BOOL (WINAPI *WriteConsoleA_t)(
	HANDLE  hConsoleOutput,
	const VOID    *lpBuffer,
	DWORD   nNumberOfCharsToWrite,
	LPDWORD lpNumberOfCharsWritten,
	LPVOID  lpReserved
);

typedef
BOOL (WINAPI *WriteConsoleW_t)(
	HANDLE  hConsoleOutput,
	const VOID    *lpBuffer,
	DWORD   nNumberOfCharsToWrite,
	LPDWORD lpNumberOfCharsWritten,
	LPVOID  lpReserved
);

typedef DWORD (*GetCurrentThreadId_t)();

typedef HGLOBAL (*GlobalFree_t)(
	HGLOBAL hMem
);

typedef HANDLE (*CreateFileA_t)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

typedef BOOL (*ReadFile_t)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

typedef BOOL (*WriteFile_t)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

typedef BOOL (*DeviceIoControl_t)(
	HANDLE       hDevice,
	DWORD        dwIoControlCode,
	LPVOID       lpInBuffer,
	DWORD        nInBufferSize,
	LPVOID       lpOutBuffer,
	DWORD        nOutBufferSize,
	LPDWORD      lpBytesReturned,
	LPOVERLAPPED lpOverlapped
);

typedef BOOL (*CloseHandle_t)(
	HANDLE hObject
);

typedef NTSTATUS (*NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef DWORD (*GetFileSize_t)(
	HANDLE  hFile,
	LPDWORD lpFileSizeHigh
);

typedef void (*Sleep_t)(
	DWORD dwMilliseconds
);

typedef DWORD (*GetTickCount_t)();

typedef DWORD (*SetFilePointer_t)(
	HANDLE hFile,
	LONG   lDistanceToMove,
	PLONG  lpDistanceToMoveHigh,
	DWORD  dwMoveMethod
);

typedef HANDLE (*OpenProcess_t)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
);

typedef LPVOID (*VirtualAllocEx_t)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

typedef BOOL (*WriteProcessMemory_t)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
);

typedef DWORD (*QueueUserAPC_t)(
	PAPCFUNC  pfnAPC,
	HANDLE    hThread,
	ULONG_PTR dwData
);

typedef HANDLE (*OpenThread_t)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
);





struct _func
{
	// Modules
	void *_kernel32_dll;
	void *_user32_dll;
	void *_ntdll_dll;

	// Handles
	HANDLE _std_out;
	HANDLE _master_thread_event;
	HANDLE _worker_thread_event;

	// IDs
	unsigned __int64 _client_id;

	// Parameters
	unsigned _param_size;
	unsigned _param_type;
	unsigned _no_mb;
	unsigned _no_console;
	unsigned _no_sysinfo_0x40;
	unsigned _lay;
	unsigned _lay_fname_size;
	char *_lay_fname;
	unsigned _lay_size;
	void *_lay_data;
	unsigned _param_write_reg_frlog;

	// Functions
	HMODULE(WINAPI *_LoadLibraryA)(LPCSTR lpLibFileName);
	FARPROC(WINAPI *_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	HANDLE (*_CreateThread)(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		LPVOID lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
	);
	MessageBoxW_t _MessageBoxW;
	MessageBoxW_t _DbgMessageBoxW;
	MessageBoxA_t _MessageBoxA;
	MessageBoxA_t _DbgMessageBoxA;
	NTSTATUS (*_NtQuerySystemInformation)(
			SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID                    SystemInformation,
			ULONG                    SystemInformationLength,
			PULONG                   ReturnLength
	);
	BOOL (WINAPI *_AllocConsole)(void);
	HANDLE (WINAPI *_GetStdHandle)(DWORD nStdHandle);
	BOOL (WINAPI *_WriteConsoleA)(
		HANDLE  hConsoleOutput,
		const VOID    *lpBuffer,
		DWORD   nNumberOfCharsToWrite,
		LPDWORD lpNumberOfCharsWritten,
		LPVOID  lpReserved
	);
	WriteConsoleW_t _WriteConsoleW;
	HGLOBAL (*_GlobalAlloc)(
		UINT   uFlags,
		SIZE_T dwBytes
	);
	GlobalFree_t _GlobalFree;
	HANDLE (*_CreateEventA)(
		LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL                  bManualReset,
		BOOL                  bInitialState,
		LPCSTR                lpName
	);
	void (*_Sleep)(
		DWORD dwMilliseconds
	);
	DWORD (*_SignalObjectAndWait)(
		HANDLE hObjectToSignal,
		HANDLE hObjectToWaitOn,
		DWORD  dwMilliseconds,
		BOOL   bAlertable
	);
	NtCreateFile_t _NtCreateFile;
	NtReadFile_t _NtReadFile;
	NtWriteFile_t _NtWriteFile;
	NtClose_t _NtClose;
	RtlInitUnicodeString_t _RtlInitUnicodeString;
	GetCurrentThreadId_t _GetCurrentThreadId;
	CreateFileA_t _CreateFileA;
	ReadFile_t _ReadFile;
	WriteFile_t _WriteFile;
	DeviceIoControl_t _DeviceIoControl;
	CloseHandle_t _CloseHandle;
	GetFileSize_t _GetFileSize;
	GetTickCount_t _GetTickCount;
	SetFilePointer_t _SetFilePointer;
	OpenProcess_t _OpenProcess;
	VirtualAllocEx_t _VirtualAllocEx;
	WriteProcessMemory_t _WriteProcessMemory;
	QueueUserAPC_t _QueueUserAPC;
	OpenThread_t _OpenThread;
};

static void nop_func(void)
{
}
