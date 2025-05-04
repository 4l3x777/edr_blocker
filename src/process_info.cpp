#include <process_info.h>

typedef LONG KPRIORITY;

struct CLIENT_ID
{
	DWORD UniqueProcess; // Process ID
#ifdef _WIN64
	ULONG pad1;
#endif
  DWORD UniqueThread;  // Thread ID
#ifdef _WIN64
	ULONG pad2;
#endif
};

typedef struct
{
	FILETIME ProcessorTime;
	FILETIME UserTime;
	FILETIME CreateTime;
	ULONG WaitTime;
#ifdef _WIN64
	ULONG pad1;
#endif
	PVOID StartAddress;
	CLIENT_ID Client_Id;
	KPRIORITY CurrentPriority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchesPerSec;
	ULONG ThreadState;
	ULONG ThreadWaitReason;
	ULONG pad2;
} SYSTEM_THREAD_INFORMATION;

typedef struct
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#define SYSTEMPROCESSINFORMATION 5
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

typedef NTSTATUS(__stdcall* t_NtQuerySystemInformation)(
	IN ULONG,
	OUT PVOID,
	IN ULONG,
	OUT PULONG);


std::string getProcessName(DWORD process_id) {
    ULONG buflen = 0;
	BYTE* buffer = NULL;
    NTSTATUS lResult = 0;
    std::string process_path;
    PSYSTEM_PROCESS_INFORMATION info = NULL;

	t_NtQuerySystemInformation f_NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
    if (!f_NtQuerySystemInformation)
    {
        goto clean;
    }

    lResult = f_NtQuerySystemInformation(SYSTEMPROCESSINFORMATION, buffer, buflen, &buflen);
    while (lResult == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (buffer) {
            LocalFree(buffer);
        }
        buffer = (BYTE*)LocalAlloc(LMEM_FIXED, buflen);
        memset(buffer, 0x0, buflen);
        lResult = f_NtQuerySystemInformation(SYSTEMPROCESSINFORMATION, buffer, buflen, &buflen);
    }

    info = (PSYSTEM_PROCESS_INFORMATION)buffer;

	while (true) {
        
        if ((DWORD)info->UniqueProcessId == process_id) {
            auto wprocess_path = std::wstring(info->ImageName.Buffer);
            process_path = std::string(wprocess_path.begin(), wprocess_path.end());
            break;
        }

        if (info->NextEntryOffset == 0) {
            break;
        }
        info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(info) + info->NextEntryOffset);
	}

clean:
	// free memory
    if (buffer) { 
	    LocalFree(buffer);
    }

    return process_path;
}