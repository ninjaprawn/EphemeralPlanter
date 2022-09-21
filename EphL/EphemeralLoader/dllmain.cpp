// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

#include "dllmain.h"
#include "function_types.h"

#if defined(_M_X64) // x64
#define get_peb() ((PTEB)__readgsqword(offsetof(NT_TIB, Self)))->ProcessEnvironmentBlock
#else // x86
#define get_peb() ((PTEB)__readfsdword(offsetof(NT_TIB, Self)))->ProcessEnvironmentBlock
#endif

extern "C" __declspec(dllexport) __declspec(safebuffers)
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    DisableThreadLibraryCalls(hinstDLL);
    void* return_addr = _ReturnAddress();

    // Step 1: Find the Kernel32.dll import
    char* targetBase = NULL;
    PPEB peb = get_peb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* lstHead = ldr->InMemoryOrderModuleList.Flink;
    while (lstHead != NULL) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)lstHead;
        LDR_DATA_TABLE_ENTRY* entry_complete = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(lstHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        char* currentBase = (char*)entry_complete->DllBase;

        if (currentBase != NULL) {
            IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)currentBase;
            IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(currentBase + hdr->e_lfanew);

            IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(currentBase + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            if (exportDir->Name != NULL) {
                uint32_t hash = get_hash(currentBase + exportDir->Name);
                if (hash == KERNEL32DLL_HASH || hash == kernel32DLL_HASH) {
                    targetBase = currentBase;
                    break;
                }
            }
        }

        lstHead = lstHead->Flink;
        if (lstHead == ldr->InMemoryOrderModuleList.Flink) {
            break;
        }
    }

    // Step 2: Find required functions that are exported
    MyVirtualAlloc myVirtualAlloc = NULL;
    MyVirtualProtect myVirtualProtect = NULL;
    MyReadFile myReadFile = NULL;
    MyCreateFileA myCreateFile = NULL;
    MyGetFileSize myGetFileSize = NULL;
    MyCloseHandle myCloseHandle = NULL;

    if (targetBase != NULL && fdwReason == DLL_PROCESS_ATTACH) {
        IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)targetBase;
        IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(targetBase + hdr->e_lfanew);

        IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(targetBase + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        uint32_t* nameArray = (uint32_t*)(targetBase + exportDir->AddressOfNames);
        uint32_t* funcArray = (uint32_t*)(targetBase + exportDir->AddressOfFunctions);
        for (int i = 0; i < exportDir->NumberOfNames; i++) {
            uint32_t nameHash = get_hash(targetBase + nameArray[i]);
            if (nameHash == ReadFile_HASH) {
                myReadFile = (MyReadFile)(targetBase + funcArray[i]);
            }
            else if (nameHash == VirtualAlloc_HASH) {
                myVirtualAlloc = (MyVirtualAlloc)(targetBase + funcArray[i]);
            }
            else if (nameHash == VirtualProtect_HASH) {
                myVirtualProtect = (MyVirtualProtect)(targetBase + funcArray[i]);
            }
            else if (nameHash == CreateFileA_HASH) {
                myCreateFile = (MyCreateFileA)(targetBase + funcArray[i]);
            }
            else if (nameHash == GetFileSize_HASH) {
                myGetFileSize = (MyGetFileSize)(targetBase + funcArray[i]);
            }
            else if (nameHash == CloseHandle_HASH) {
                myCloseHandle = (MyCloseHandle)(targetBase + funcArray[i]);
            }
        }
    }

    // Step 3: Load EphemeralPayload.dll
    if (myReadFile != NULL && myVirtualAlloc != NULL && myVirtualProtect != NULL && myCreateFile != NULL && myGetFileSize != NULL && myCloseHandle != NULL) {
        //OutputDebugStringA("Collected them all!");
        HANDLE targetFile = myCreateFile((char*)"E:\\gamehax\\lostark\\LostArkRev\\EphL\\x64\\Release\\EphemeralPayload.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (targetFile == INVALID_HANDLE_VALUE) {
            //OutputDebugStringA("Failed to open file!");
        }
        else {
            DWORD fileSize = myGetFileSize(targetFile, NULL);
            //output_hex(fileSize, 8);
            char* mymem = (char*)myVirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!myReadFile(targetFile, mymem, fileSize, &fileSize, NULL)) {
                //OutputDebugStringA("Failed to read file");
            }
            else {
                myCloseHandle(targetFile);
                
                // Get the export function list. We only export one function in EphemeralPayload
                IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)mymem;
                IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(mymem + hdr->e_lfanew);
                IMAGE_SECTION_HEADER* txtSection = (IMAGE_SECTION_HEADER*)((char*)newHdr + sizeof(IMAGE_NT_HEADERS64));
                IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(mymem + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - txtSection->VirtualAddress + txtSection->PointerToRawData);
                uint32_t* functionList = (uint32_t*)(mymem + exportDir->AddressOfFunctions - txtSection->VirtualAddress + txtSection->PointerToRawData);

                // Apply relocations. Should only be in the .text section so thats where we look. 
                int reloc_counter = 0;
                IMAGE_SECTION_HEADER* relocSection = (IMAGE_SECTION_HEADER*)((char*)newHdr + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER));
                char* relocationDir = (mymem + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress - relocSection->VirtualAddress + relocSection->PointerToRawData);
                while (reloc_counter < newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
                    uint32_t page = *(uint32_t*)(relocationDir+reloc_counter);
                    reloc_counter += 4;
                    uint32_t curr_size = *(uint32_t*)(relocationDir + reloc_counter);
                    reloc_counter += 4;
                    for (int i = 0; i < curr_size - 8; i += 2) {
                        uint16_t offset = *(uint16_t*)(relocationDir + reloc_counter + i);

                        if ((offset >> 12) == 0xA) { // IMAGE_REL_BASED_DIR64
                            char* target = (mymem + page + (offset & 0x0FFF) - txtSection->VirtualAddress + txtSection->PointerToRawData);
                            // Remove the image base (normal) and the virtual address part from the text section base (new)
                            *(uint64_t*)target = *(uint64_t*)target - newHdr->OptionalHeader.ImageBase - txtSection->VirtualAddress;
                            // Add the new image base (normal) and the file offset part from the text section base (new)
                            *(uint64_t*)target += (uint64_t)mymem + txtSection->PointerToRawData;
                        }
                        else {
                            // TODO - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format .reloc section
                        }
                    }
                    reloc_counter += curr_size - 8;
                }

                for (int i = 0; i < sizeof(IMAGE_DOS_HEADER); i++) {
                    mymem[i] = 0xAB;
                }


                DWORD old;
                if (!myVirtualProtect(mymem, fileSize, PAGE_EXECUTE_READ, &old)) {
                    //output_hex(GetLastError(), 8);
                }
                else {
                    typedef void (WINAPI* myPayload)(void*);
                    myPayload pd = (myPayload)(mymem + functionList[0] - txtSection->VirtualAddress + txtSection->PointerToRawData);
                    pd(hinstDLL);
                }

            }
        }
    }
    else {
        //OutputDebugStringA("Failed to find all functions");
    }

    return TRUE;
}