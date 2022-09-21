#pragma once
#include <Windows.h>

#define KERNEL32DLL_HASH 0xecf1f5be
#define kernel32DLL_HASH 0xd1235fe
#define VirtualAlloc_HASH 0x194e3737
#define VirtualProtect_HASH 0x2a53aea0
#define GetFileSize_HASH 0x9a3f4c19
#define CreateFileA_HASH 0xcaed3d23
#define ReadFile_HASH 0xc9cdce98
#define CloseHandle_HASH 0xe236210c

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

typedef void* (WINAPI* MyVirtualAlloc)(void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI* MyVirtualProtect)(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef HANDLE (WINAPI* MyCreateFileA)(char* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, void* lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL (WINAPI* MyReadFile)(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, void* lpOverlapped);
typedef DWORD (WINAPI* MyGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef BOOL(WINAPI* MyCloseHandle)(HANDLE hObject);