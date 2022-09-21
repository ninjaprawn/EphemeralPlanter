#pragma once
#include <Windows.h>
#include <DbgHelp.h>
#include <cstdint>

inline int get_hash(char* src) {
    uint32_t out = 0;
    int i = 0;
    while (src[i] != 0) {
        out += src[i] << ((i % 4) * 8);
        i++;
    }
    return out;
}

typedef void (WINAPI* MyOutputDebugStringA)(LPCSTR lpOutputString); 
typedef void (WINAPI* MyOutputDebugStringW)(LPWSTR lpOutputString);

typedef void* (WINAPI* MyVirtualAlloc)(void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* MyVirtualProtect)(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOL(WINAPI* MyVirtualFree)(void* lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef SIZE_T(WINAPI* MyVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef SIZE_T(WINAPI* MyReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);

typedef HANDLE (WINAPI* MyCreateFileA)(char* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, void* lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL (WINAPI* MyReadFile)(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, void* lpOverlapped);
typedef BOOL (WINAPI* MyWriteFile)(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, void* lpOverlapped);
typedef DWORD (WINAPI* MyGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef DWORD(WINAPI* MySetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef BOOL (WINAPI* MyCloseHandle)(HANDLE hObject);
typedef BOOL(WINAPI* MyFlushViewOfFile)(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush);

typedef DWORD(WINAPI* MyGetLastError)(void);


typedef HANDLE (WINAPI* MyGetCurrentProcess)(void);
typedef DWORD (WINAPI* MyGetCurrentProcessId)(void);


typedef BOOL (WINAPI* MyMiniDumpWriteDump)(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, void* ExceptionParam, void* UserStreamParam, void* CallbackParam);

typedef HANDLE (WINAPI* MyGetProcessHeap)(void);
typedef BOOL (WINAPI* MyHeapWalk)(HANDLE hHeap, LPPROCESS_HEAP_ENTRY lpEntry);
typedef BOOL(WINAPI* MyHeapLock)(HANDLE hHeap);
typedef BOOL(WINAPI* MyHeapUnlock)(HANDLE hHeap);
typedef DWORD(WINAPI* MyGetProcessHeaps)(DWORD NumberOfHeaps, PHANDLE ProcessHeaps);

typedef BOOL(WINAPI* MyK32EnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
typedef DWORD(WINAPI* MyK32GetModuleFileNameExA)(HANDLE hProcess, HMODULE hModule, LPCSTR lpFilename, DWORD nSize);
typedef UINT(WINAPI* MyWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
typedef UINT(WINAPI* MyCreateProcessA)(LPCSTR lpApplicationName, LPCSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, 
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

typedef PVOID(WINAPI* MyAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);

typedef HINSTANCE(WINAPI* MyShellExecuteA)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, int nShowCmd);

#define FUNC(name) My ## name name;

static const char* kernel32_func_names[] = {
    "OutputDebugStringA",
    "CreateFileA",
    "ReadFile",
    "GetFileSize",
    "WriteFile",
    "CloseHandle",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetLastError",
    "GetProcessHeap",
    "HeapWalk",
    "HeapLock",
    "HeapUnlock",
    "GetProcessHeaps",
    "VirtualQueryEx",
    "ReadProcessMemory",
    "K32GetModuleFileNameExA",
    "K32EnumProcessModules",
    "SetFilePointer",
    "AddVectoredExceptionHandler",
    "FlushViewOfFile",
    NULL
};

static const char* user32_func_names[] = {
    "ShellExecuteA",
    NULL
};

typedef struct {
    FUNC(OutputDebugStringA);
    FUNC(CreateFileA);
    FUNC(ReadFile);
    FUNC(GetFileSize);
    FUNC(WriteFile);
    FUNC(CloseHandle);
    FUNC(VirtualAlloc);
    FUNC(VirtualProtect);
    FUNC(VirtualFree);
    FUNC(GetCurrentProcess);
    FUNC(GetCurrentProcessId);
    FUNC(GetLastError);
    FUNC(GetProcessHeap);
    FUNC(HeapWalk);
    FUNC(HeapLock);
    FUNC(HeapUnlock);
    FUNC(GetProcessHeaps);
    FUNC(VirtualQueryEx);
    FUNC(ReadProcessMemory);
    FUNC(K32GetModuleFileNameExA);
    FUNC(K32EnumProcessModules);
    FUNC(SetFilePointer);
    FUNC(AddVectoredExceptionHandler);
    FUNC(FlushViewOfFile);
} KernelFuncs;



typedef struct {
    FUNC(ShellExecuteA);
} UserFuncs;
