#include <Windows.h>
#include <winternl.h>
#include "peb-lookup.h"
#include "lib.h"
#include "func.h"

// It's worth noting that strings can be defined inside the .text section:
/*
#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";

__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";
*/

#define __func__	__FUNCTION__

// Do we need other enums?
#define SystemExtendedHandleInformation		(0x40)

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles [1];
} SYSTEM_HANDLE_INFORMATION_EX;

////////////////////////////////////////////

// Functions prototypes
static DWORD WINAPI master_thread(void *param);
static DWORD WINAPI slave_thread(void *param);

static void print_sysinfo_returned(struct _func *func, NTSTATUS rv, unsigned ret_len, int i)
{
	char _func_name[] = { 'p','r','i','n','t','_','s','y','s','i','n','f','o','_','r','e','t','u','r','n','e','d','(',')',':','\0' };
	char _str1[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n','(',')',' ','r','e','t','u','r','n','e','d',' ','r','v',' ','=',' ','\0' };
	char _str2[] = { ',',' ','r','e','t','_','l','e','n',' ','=',' ','\0' };
	char _str3[] = { ' ','[','i',' ','=',' ','\0' };
	char _str4[] = {']','\n','\0'};
	char buf[256];

//	printf("%s(): NtQuerySystemInformation() returned rv = %08X, ret_len = %u [i = %d]\n", __func__, rv, ret_len, i);
	func->_WriteConsoleA(func->_std_out, _func_name, sizeof(_func_name), NULL, NULL);
	func->_WriteConsoleA(
			func->_std_out,
			_str1,
			sizeof(_str1),
			NULL,
			NULL
	);
	_ltoa_(rv, buf, 16);
	func->_WriteConsoleA(
			func->_std_out,
			buf,
			_strlen(buf),
			NULL,
			NULL);
	func->_WriteConsoleA(
			func->_std_out,
			_str2,
			sizeof(_str2),
			NULL,
			NULL
	);
	_ltoa_(ret_len, buf, 10);
	func->_WriteConsoleA(
			func->_std_out,
			buf,
			_strlen(buf),
			NULL,
			NULL);
	func->_WriteConsoleA(
			func->_std_out,
			_str3,
			_strlen(_str3),
			NULL,
			NULL);
	_ltoa_(i, buf, 10);
	func->_WriteConsoleA(
			func->_std_out,
			buf,
			_strlen(buf),
			NULL,
			NULL);
	func->_WriteConsoleA(
			func->_std_out,
			_str4,
			_strlen(_str4),
			NULL,
			NULL);

}

int main()
{
    // Stack kernel32.dll strings for libraries and functions that the shellcode needs
	wchar_t ntdll_dll_name[] = { 'n','t','d','l','l','.','d','l','l', 0 };
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char message_box_name[] = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };
	char create_thread_name[] = { 'C','r','e','a','t','e','T','h','r','e','a','d','\0' };
	char nt_query_system_information_name[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n','\0' };
	char alloc_console_name[] = { 'A','l','l','o','c','C','o','n','s','o','l','e','\0' };
	char write_console_a_name[] = { 'W','r','i','t','e','C','o','n','s','o','l','e','A','\0' };
	char get_std_handle_name[] = { 'G','e','t','S','t','d','H','a','n','d','l','e','\0' };
	char create_event_a_name[] = { 'C','r','e','a','t','e','E','v','e','n','t','A','\0' };
	char sleep_name[] = { 'S','l','e','e','p','\0' };
	char signal_object_and_wait_name[] = { 'S','i','g','n','a','l','O','b','j','e','c','t','A','n','d','W','a','i','t','\0' };
	char global_alloc_name[] = { 'G','l','o','b','a','l','A','l','l','o','c','\0'};

	void *kernel32_dll = NULL;
	void *user32_dll = NULL;
	void *ntdll_dll = NULL;
	
	void *load_lib = NULL;
	void *get_proc = NULL;
	HMODULE(WINAPI *_LoadLibraryA)(LPCSTR lpLibFileName) = NULL;
	FARPROC(WINAPI *_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

	int i = 0;
	struct _SYSTEM_HANDLE_INFORMATION_EX info_stub = {0}, *p_handle_info = NULL;
	struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *p_handle_entry_info = NULL;
	void *system_information = NULL;
	unsigned long system_information_length = 0;
	unsigned long offs = 0;
	ULONG_PTR idx = 0;
	ULONG ret_len = 0;
	NTSTATUS rv = 0;
	char buf[256];

	// Function ptrs definitions -- more
	HANDLE (*_CreateThread)(
		LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		SIZE_T                  dwStackSize,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		LPVOID lpParameter,
		DWORD                   dwCreationFlags,
		LPDWORD                 lpThreadId
	) = NULL;

	int (*_MessageBoxW)(
        HWND hWnd,
        LPCWSTR lpText,
        LPCWSTR lpCaption,
        UINT uType
	) = NULL;

	NTSTATUS (*_NtQuerySystemInformation)(
			SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID                    SystemInformation,
			ULONG                    SystemInformationLength,
			PULONG                   ReturnLength
	) = NULL;

	BOOL (WINAPI *_AllocConsole)(void) = NULL;
	
	HANDLE (WINAPI *_GetStdHandle)(DWORD nStdHandle) = NULL;

	BOOL (WINAPI *_WriteConsoleA)(
		HANDLE  hConsoleOutput,
		const VOID    *lpBuffer,
		DWORD   nNumberOfCharsToWrite,
		LPDWORD lpNumberOfCharsWritten,
		LPVOID  lpReserved
	) = NULL;

	HGLOBAL (*_GlobalAlloc)(
		UINT   uFlags,
		SIZE_T dwBytes
	) = NULL;

	HANDLE (*_CreateEventA)(
		LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL                  bManualReset,
		BOOL                  bInitialState,
		LPCSTR                lpName
	) = NULL;

	void (*_Sleep)(
		DWORD dwMilliseconds
	) = NULL;

	DWORD (*_SignalObjectAndWait)(
		HANDLE hObjectToSignal,
		HANDLE hObjectToWaitOn,
		DWORD  dwMilliseconds,
		BOOL   bAlertable
	) = NULL;

    // stack kernel32_dlld strings to be passed to the MessageBox WinApi
    wchar_t msg_content[] = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
    wchar_t msg_title[] = { 'D','e','m','o','!', 0 };
	
	char hello_world_str [] = { 'H','E','L','L','O',',',' ','W','O','R','L','D','\n', '\0' };

	char _func_name[] = { 'm','a','i','n','(',')',':',' ','\0' };
	
	HANDLE std_out = NULL;
	HANDLE master_thread_event = NULL;
	HANDLE slave_thread_event = NULL;

	struct _func *func = NULL;

    // resolve ntdll image base
	ntdll_dll = get_module_by_name((const LPWSTR)ntdll_dll_name);
    if (!ntdll_dll)
        return	1;

    // resolve kernel32 image base
    kernel32_dll = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!kernel32_dll)
        return	1;

    // resolve LoadLibraryA() address
    load_lib = get_func_by_name((HMODULE)kernel32_dll, (LPSTR)load_lib_name);
    if (!load_lib)
        return	2;

    // resolve GetProcAddress() address
    get_proc = get_func_by_name((HMODULE)kernel32_dll, (LPSTR)get_proc_name);
    if (!get_proc)
        return	3;

    // LoadLibraryA and GetProcAddress function definitions
    _LoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))load_lib;
	_GetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))get_proc;

    // load user32.dll
	// It should be there loaded  by default for any process, so that we could use get_module_by_name().
	// Left here for demonstating possibilities
    user32_dll = _LoadLibraryA(user32_dll_name);
	if (!user32_dll)
		return	4;

    // Get MessageBoxW function
	// The same as above - this function is likely in any process together with user32.dll
	_MessageBoxW = (int (WINAPI*)(
			_In_opt_ HWND,
			_In_opt_ LPCWSTR,
			_In_opt_ LPCWSTR,
			_In_ UINT)) _GetProcAddress((HMODULE)user32_dll, message_box_name);

    if (_MessageBoxW == NULL)
		return 4;

	// Resolve kernel32!CreateThread
	_CreateThread = (HANDLE(*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))get_func_by_name(kernel32_dll, create_thread_name);
	if (!_CreateThread)
		return	5;

	_NtQuerySystemInformation = (NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))_GetProcAddress((HMODULE)ntdll_dll, nt_query_system_information_name);
	if (!_NtQuerySystemInformation)
		return	6;

//	printf("_NtQuerySystemInformation = %p\n", _NtQuerySystemInformation);
//

	_AllocConsole = (BOOL (*)(void))get_func_by_name((HMODULE)kernel32_dll, (LPSTR)alloc_console_name);
	if (!_AllocConsole)
		return	7;

	_WriteConsoleA = (BOOL (*)(HANDLE, const VOID *, DWORD, LPDWORD, LPVOID))get_func_by_name((HMODULE)kernel32_dll, (LPSTR)write_console_a_name);
	if (!_WriteConsoleA)
		return	8;

	_GetStdHandle = (HANDLE (WINAPI *)(DWORD nStdHandle))get_func_by_name((HMODULE)kernel32_dll, (LPSTR)get_std_handle_name);
	if (!_GetStdHandle)
		return	9;

	_GlobalAlloc = (HGLOBAL (*)(
		UINT   uFlags,
		SIZE_T dwBytes
	))get_func_by_name((HMODULE)kernel32_dll, (LPSTR)global_alloc_name);
	if (!_GlobalAlloc)
		return	10;

	_CreateEventA = (HANDLE (*)(
		LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL                  bManualReset,
		BOOL                  bInitialState,
		LPCSTR                lpName
	))get_func_by_name((HMODULE)kernel32_dll, (LPSTR)create_event_a_name);
	if (!_CreateEventA)
		return	11;

	_Sleep = (void (*)(
		DWORD dwMilliseconds
	))get_func_by_name((HMODULE)kernel32_dll, (LPSTR)sleep_name);
	if (!_Sleep)
		return	12;

	_SignalObjectAndWait = (DWORD (*)(
		HANDLE hObjectToSignal,
		HANDLE hObjectToWaitOn,
		DWORD  dwMilliseconds,
		BOOL   bAlertable
	))get_func_by_name((HMODULE)kernel32_dll, (LPSTR)signal_object_and_wait_name);
	if (!_SignalObjectAndWait)
		return	13;

	// Allocate console for further printing. We need a console here, don't care if we fail (then we already have a console)
	_AllocConsole();
	std_out = _GetStdHandle(STD_OUTPUT_HANDLE);

	// Prepare struct _func for common use with threads
	func = _GlobalAlloc(GMEM_FIXED, sizeof(struct _func));
	if (!func)
		return	30;

	_memset(func, 0, sizeof(struct _func));

	func->_kernel32_dll = kernel32_dll;
	func->_user32_dll = user32_dll;
	func->_ntdll_dll = ntdll_dll;

	func->_std_out = std_out;

	func->_LoadLibraryA =_LoadLibraryA;
	func->_GetProcAddress =_GetProcAddress;
	func->_CreateThread = _CreateThread;
	func->_MessageBoxW = _MessageBoxW;
	func->_NtQuerySystemInformation = _NtQuerySystemInformation;
	func->_AllocConsole =_AllocConsole;
	func->_GetStdHandle = _GetStdHandle;
	func->_WriteConsoleA = _WriteConsoleA;
	func->_GlobalAlloc =_GlobalAlloc;
	func->_CreateEventA = _CreateEventA;
	func->_Sleep = _Sleep;
	func->_SignalObjectAndWait =_SignalObjectAndWait;

	// Create events for threads
//	master_thread_event = _CreateEventA(NULL, FALSE, FALSE, NULL);
	master_thread_event = func->_CreateEventA(NULL, FALSE, FALSE, NULL);
	if (!master_thread_event)
		return	50;
	
//	slave_thread_event = _CreateEventA(NULL, FALSE, FALSE, NULL);
	slave_thread_event = func->_CreateEventA(NULL, FALSE, FALSE, NULL);
	if (!slave_thread_event)
		return	50;

	func->_master_thread_event = master_thread_event;
	func->_worker_thread_event = slave_thread_event;

	// (!) We don't close event handles

//	_WriteConsoleA(std_out, "HELLO, WORLD\n", sizeof("HELLO, WORLD\n"), NULL, NULL);
	func->_WriteConsoleA(func->_std_out, hello_world_str, sizeof(hello_world_str), NULL, NULL);

//	_MessageBoxW(0, msg_content, msg_title, MB_OK);
	func->_MessageBoxW(0, msg_content, msg_title, MB_OK);


//	_CreateThread(NULL, 0, master_thread, NULL, 0, NULL);
	func->_CreateThread(NULL, 0, master_thread, func, 0, NULL);
//	_CreateThread(NULL, 0, slave_thread, NULL, 0, NULL);
	func->_CreateThread(NULL, 0, slave_thread, func, 0, NULL);
	
//	_Sleep(5000);
	func->_Sleep(5000);
	
	//
	//	Get amount of memory that we need
	//	(!) NtQuerySystemInformation() behaves this way with regard to SystemInformationLength parameter:
	//
	//	1) when it's 0 (or otherwise less than 1 structure SYSTEM_HANDLE_INFORMATION_EX -- sizeof(SYSTEM_HANDLE_INFORMATION_EX) --  e.g. 5),
	//	  it sets ret_len = sizeof(SYSTEM_HANDLE_INFORMATION_EX) and doesn't fill return data (so that SystemInformation may be NULL).
	//	  Returns not enough buffer space (0xC0000004).
	//	2) when it's at least 1 structure  SYSTEM_HANDLE_INFORMATION_EX, (sizeof(SYSTEM_HANDLE_INFORMATION_EX)), it fills it and
	//	  sets ret_len = real length needed, returning not enough buffer space (0xC0000004).
	//
	//	This is not in accordance with general Windows API concept, where setting length = 0 always returns the length of complete output buffer
	//	to be filled, so that consequent call with the returned value succeeds
	//
//	rv = _NtQuerySystemInformation(SystemExtendedHandleInformation, &info_stub, /*5*/ sizeof(info_stub), &ret_len);
	rv = func->_NtQuerySystemInformation(SystemExtendedHandleInformation, &info_stub, /*5*/ sizeof(info_stub), &ret_len);

	print_sysinfo_returned(func, rv, ret_len, i);

//	printf("%s(): we need %u bytes for SystemExtendedHandleInformation (rv = %08X)\n", __func__, ret_len, rv);
	do
	{
		char _str1[] = { 'w','e',' ','n','e','e','d',' ','\0' };
		char _str2[] =
				{ ' ','b','y','t','e','s',' ','f','o','r',' ','S','y','s','t','e','m','E','x','t','e','n','d','e','d','H','a','n','d','l','e','I','n','f','o','r','m','a','t','i','o','n',' ','(','\0' };
		char _str3[] = { ')','\n','\0' };
		char buf[256];

		func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
		func->_WriteConsoleA(func->_std_out, _str1, _strlen(_str1), NULL, NULL);
		_ltoa_(ret_len, buf, 10);
		func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);
		func->_WriteConsoleA(func->_std_out, _str2, _strlen(_str2), NULL, NULL);
		_ltoa_(rv, buf, 16);
		func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);
		func->_WriteConsoleA(func->_std_out, _str3, _strlen(_str3), NULL, NULL);
	} while (0);

	system_information_length = ret_len;
	system_information = _GlobalAlloc(GMEM_FIXED, system_information_length);
	
	if (!system_information)
		return	60;
	
	for (i = 0; i < 8; ++i)
	{
//		printf("%s(): Calling NtQuerySystemInformation(SystemExtendedHandleInformation)\n", __func__);
		do
		{
			char _str1[] = { ' ','C','a','l','l','i','n','g',' ','N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n','(','0','x','\0' };
			char _str2[] = { ')','\n','\0' };

			func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
			func->_WriteConsoleA(func->_std_out, _str1, _strlen(_str1), NULL, NULL);
			_ltoa_(SystemExtendedHandleInformation, buf, 16);
			func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);
			func->_WriteConsoleA(func->_std_out, _str2, _strlen(_str2), NULL, NULL);
		} while (0);

//		rv = _NtQuerySystemInformation(SystemExtendedHandleInformation, system_information, system_information_length, &ret_len);
		rv = func->_NtQuerySystemInformation(SystemExtendedHandleInformation, system_information, system_information_length, &ret_len);

//		printf("%s(): NtQuerySystemInformation() returned rv = %08X, ret_len = %u [i = %d]\n", __func__, rv, ret_len, i);
		print_sysinfo_returned(func, rv, ret_len, i);

		p_handle_info = (struct _SYSTEM_HANDLE_INFORMATION_EX*)system_information;
		p_handle_entry_info = (struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX*)p_handle_info->Handles;
		offs = sizeof(SYSTEM_HANDLE_INFORMATION_EX) - sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);

//		printf("NumberOfHandles = %lu\n", (unsigned long)p_handle_info->NumberOfHandles);
		do
		{
			char _str1[] = { 'N','u','m','b','e','r','O','f','H','a','n','d','l','e','s',' ','=',' ','\0'};
			char buf[256];
			char _str2[] = { '\n','\0' };

			func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
			func->_WriteConsoleA(func->_std_out, _str1, _strlen(_str1), NULL, NULL);
			_ltoa_((long)p_handle_info->NumberOfHandles, buf, 10);
			func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);
			func->_WriteConsoleA(func->_std_out, _str2, _strlen(_str2), NULL, NULL);
		} while (0);

//		printf("Handles:\n");
		do
		{
			char _str1[] = { 'H','a','n','d','l','e','s',':','\n','\0' };
			func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
			func->_WriteConsoleA(func->_std_out, _str1, _strlen(_str1), NULL, NULL);
		} while (0);

		for (idx = 0; idx < p_handle_info->NumberOfHandles && offs < ret_len && idx < 0x10; ++idx, offs += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX))
		{
/*
			printf("	[%lu]: Object = %p, UniqueProcessId = %lu, HandleValue = %p, GrantedAccess = %08lX, CreatorBackTraceIndex = %hu, ObjectTypeIndex = %hu, HandleAttributes = %08lX, Reserved = %08lX\n",
					(unsigned long)idx, p_handle_entry_info[idx].Object, (unsigned long)p_handle_entry_info[idx].UniqueProcessId, (void*)p_handle_entry_info[idx].HandleValue,
					p_handle_entry_info[idx].GrantedAccess, p_handle_entry_info[idx].CreatorBackTraceIndex, p_handle_entry_info[idx].ObjectTypeIndex, p_handle_entry_info[idx].HandleAttributes,
					p_handle_entry_info[idx].Reserved);
*/
			do
			{
				char buf[256];
				char _str1[] = { '\t','[','\0' };
				char _str2[] = { ']',':',' ','O','b','j','e','c','t',' ','=',' ','\0' };
				char _str3[] = { ',',' ','U','n','i','q','u','e','P','r','o','c','e','s','s','I','d',' ','=',' ','\0' };
				char _str4[] = { ',',' ','H','a','n','d','l','e','V','a','l','u','e',' ','=',' ','\0' };
				char _str5[] = { ',',' ','G','r','a','n','t','e','d','A','c','c','e','s','s',' ','=',' ','\0' };
				char _str6[] = { ',',' ','C','r','e','a','t','o','r','B','a','c','k','T','r','a','c','e','I','n','d','e','x',' ','=',' ','\0' };
				char _str7[] = { ',',' ','O','b','j','e','c','t','T','y','p','e','I','n','d','e','x',' ','=',' ','\0' };
				char _str8[] = { ',',' ','H','a','n','d','l','e','A','t','t','r','i','b','u','t','e','s',' ','=',' ','\0' };
				char _str9[] = { ',',' ','R','e','s','e','r','v','e','d',' ','=',' ','\0' };
				char _str10[] = { '\n','\0' };

				func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str1, _strlen(_str1), NULL, NULL);
				_ltoa_((long)idx, buf, 10);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str2, _strlen(_str2), NULL, NULL);
				_lltoa_((long long)p_handle_entry_info[idx].Object, buf, 16);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str3, _strlen(_str3), NULL, NULL);
				_ltoa_((long)p_handle_entry_info[idx].UniqueProcessId, buf, 10);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str4, _strlen(_str4), NULL, NULL);
				_lltoa_((long long)p_handle_entry_info[idx].HandleValue, buf, 16);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str5, _strlen(_str5), NULL, NULL);
				_ltoa_((long)p_handle_entry_info[idx].GrantedAccess, buf, 16);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str6, _strlen(_str6), NULL, NULL);
				_ltoa_((long)p_handle_entry_info[idx].CreatorBackTraceIndex, buf, 10);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str7, _strlen(_str7), NULL, NULL);
				_ltoa_((long)p_handle_entry_info[idx].ObjectTypeIndex, buf, 10);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str8, _strlen(_str8), NULL, NULL);
				_ltoa_((long)p_handle_entry_info[idx].HandleAttributes, buf, 16);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str9, _strlen(_str9), NULL, NULL);
				_ltoa_((long)p_handle_entry_info[idx].Reserved, buf, 16);
				func->_WriteConsoleA(func->_std_out, buf, _strlen(buf), NULL, NULL);

				func->_WriteConsoleA(func->_std_out, _str10, _strlen(_str10), NULL, NULL);
			} while (0);
		}

//		Sleep(1000);
		func->_Sleep(1000);
	
	}

    return 0;
}

static DWORD WINAPI master_thread(void *param)
{
	int i;
	struct _func *func = param;
	char _func_name[] = { 'm','a','s','t','e','r','_','t','h','r','e','a','d','(',')',':','\0' };
	char _enter_str[] = { '+','+','+','\n','\0' };
	char _exit_str[] = { '-','-','-','\n','\0' };
	char _i_eq_str[] = { 'i',' ','=',' ','\0' };
	char _nl[] = { '\n', '\0' };
	char s[1024];

	if (!func)
		return	(DWORD)-1;

//	printf("%s(): +++\n", __func__);
	func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
	func->_WriteConsoleA(func->_std_out, _enter_str, _strlen(_enter_str), NULL, NULL);

	for (i = 0; i < 4; ++i)
	{
//		printf("%s(): i = %d\n", __func__, i);
		func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
		func->_WriteConsoleA(func->_std_out, _i_eq_str, _strlen(_i_eq_str), NULL, NULL);
		_ltoa_(i, s, 10);
		func->_WriteConsoleA(func->_std_out, s, _strlen(s), NULL, NULL);
		func->_WriteConsoleA(func->_std_out, _nl, _strlen(_nl), NULL, NULL);

//		SignalObjectAndWait(slave_thread_event, master_thread_event, INFINITE, FALSE);
		func->_SignalObjectAndWait(func->_worker_thread_event, func->_master_thread_event, INFINITE, FALSE);
//		Sleep(1000);
	}

//	printf("%s(): ---\n", __func__);
	func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
	func->_WriteConsoleA(func->_std_out, _exit_str, _strlen(_exit_str), NULL, NULL);

	return	0;
}

static DWORD WINAPI slave_thread(void *param)
{
	int i;
	struct _func *func = param;
	char _func_name[] = { 's','l','a','v','e','_','t','h','r','e','a','d','(',')',':','\0' };
	char _enter_str[] = { '+','+','+','\n','\0' };
	char _exit_str[] = { '-','-','-','\n','\0' };
	char _i_eq_str[] = { 'i',' ','=',' ','\0' };
	char _nl[] = { '\n', '\0' };
	char s[1024];

	if (!func)
		return	(DWORD)-1;

//	printf("%s(): +++\n", __func__);
	func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
	func->_WriteConsoleA(func->_std_out, _enter_str, _strlen(_enter_str), NULL, NULL);
	
	for (i = 0; i < 4; ++i)
	{
//		Sleep(1000);
		func->_Sleep(1000);
//		printf("%s(): i = %d\n", __func__, i);
		func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
		func->_WriteConsoleA(func->_std_out, _i_eq_str, _strlen(_i_eq_str), NULL, NULL);
		_ltoa_(i, s, 10);
		func->_WriteConsoleA(func->_std_out, s, _strlen(s), NULL, NULL);
		func->_WriteConsoleA(func->_std_out, _nl, _strlen(_nl), NULL, NULL);

//		SignalObjectAndWait(master_thread_event, slave_thread_event, INFINITE, FALSE);
		func->_SignalObjectAndWait(func->_master_thread_event, func->_worker_thread_event, INFINITE, FALSE);
	}

//	printf("%s(): ---\n", __func__);
	func->_WriteConsoleA(func->_std_out, _func_name, _strlen(_func_name), NULL, NULL);
	func->_WriteConsoleA(func->_std_out, _exit_str, _strlen(_exit_str), NULL, NULL);

	return	0;
}
