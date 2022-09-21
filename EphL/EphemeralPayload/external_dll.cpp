#include "pch.h"
#include "external_dll.h"
#include "utils.h"

extern "C"
char* __stdcall find_library_with_name(const char* name) {
    char* targetBase = NULL;
    PPEB peb = get_peb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* lstHead = ldr->InMemoryOrderModuleList.Flink;
    while (lstHead != NULL) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)lstHead;
        LDR_DATA_TABLE_ENTRY* entry_complete = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(lstHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        char* currentBase = (char*)entry_complete->DllBase;

        if (currentBase != NULL) {
            if (strcmpwi(name, entry->FullDllName.Buffer)) {
                targetBase = currentBase;
                break;
            }
        }

        lstHead = lstHead->Flink;
        if (lstHead == ldr->InMemoryOrderModuleList.Flink) {
            break;
        }
    }
    return targetBase;
}

extern "C"
LDR_DATA_TABLE_ENTRY * __stdcall find_buffer_library_with_name(const char* name) {
    LDR_DATA_TABLE_ENTRY* targetBase = NULL;
    PPEB peb = get_peb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* lstHead = ldr->InMemoryOrderModuleList.Flink;
    while (lstHead != NULL) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)lstHead;
        LDR_DATA_TABLE_ENTRY* entry_complete = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(lstHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        char* currentBase = (char*)entry_complete->DllBase;

        if (currentBase != NULL) {
            if (strcmpwi(name, entry->FullDllName.Buffer)) {
                targetBase = entry;
                break;
            }
        }

        lstHead = lstHead->Flink;
        if (lstHead == ldr->InMemoryOrderModuleList.Flink) {
            break;
        }
    }
    return targetBase;
}

extern "C"
void __stdcall break_it_all(void* p) {
    char* targetBase = NULL;
    PPEB peb = get_peb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* lstHead = ldr->InMemoryOrderModuleList.Flink;
    while (lstHead != NULL) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)lstHead;
        LDR_DATA_TABLE_ENTRY* entry_complete = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(lstHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        char* currentBase = (char*)entry_complete->DllBase;

        if (currentBase != NULL) {
            if (strcmpwi("oo2net_9_win64.dll", entry->FullDllName.Buffer)) {
                entry_complete->DllBase = p;
                //LDR_DATA_TABLE_ENTRY* kern = find_buffer_library_with_name("kernel32.dll");
                //entry->FullDllName.Buffer = kern->FullDllName.Buffer;
                //entry->FullDllName.Length = kern->FullDllName.Length;
                break;
            }
        }

        lstHead = lstHead->Flink;
        if (lstHead == ldr->InMemoryOrderModuleList.Flink) {
            break;
        }
    }
}

extern "C"
int __stdcall resolve_functions(char* dll, const char** names, void** funcs) {
    int success_count = 0;
    if (dll != NULL) {
        IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)dll;
        IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(dll + hdr->e_lfanew);

        IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(dll + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        DWORD* nameArray = (DWORD*)(dll + exportDir->AddressOfNames);
        DWORD* funcArray = (DWORD*)(dll + exportDir->AddressOfFunctions);
        for (int i = 0; i < exportDir->NumberOfNames; i++) {
            int j = 0; 
            while (names[j] != NULL) {
                if (_strcmp(names[j], dll + nameArray[i])) {
                    funcs[j] = (dll + funcArray[i]);
                    success_count++;
                }
                j++;
            }
        }
    }
    return success_count;
}

extern "C"
int __stdcall resolve_functions_for_dll(const char* dll_name, const char** names, void** funcs) {
    return resolve_functions(find_library_with_name(dll_name), names, funcs);
}

extern "C"
char* __stdcall find_library_containing_address(uint64_t addr) {
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

            IMAGE_SECTION_HEADER* section_headers = (IMAGE_SECTION_HEADER*)((char*)newHdr + sizeof(IMAGE_NT_HEADERS64));

            if (addr >= (uint64_t)hdr && addr <= (uint64_t)((char*)section_headers + sizeof(IMAGE_SECTION_HEADER) * newHdr->FileHeader.NumberOfSections)) {
                return currentBase;
            }
            else {
                for (int i = 0; i < newHdr->FileHeader.NumberOfSections; i++) {
                    if (addr >= section_headers[i].VirtualAddress + (uint64_t)currentBase && addr <= section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize + (uint64_t)currentBase) {
                        return currentBase;
                    }
                }
            }
        }

        lstHead = lstHead->Flink;
        if (lstHead == ldr->InMemoryOrderModuleList.Flink) {
            break;
        }
    }

    return NULL;
}


extern "C"
char* __stdcall check_if_forwarded(char* function_name, char* found_in_library) {
    char* targetBase = NULL;
    PPEB peb = get_peb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* lstHead = ldr->InMemoryOrderModuleList.Flink;

    while (lstHead != NULL) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)lstHead;
        LDR_DATA_TABLE_ENTRY* entry_complete = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(lstHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        char* currentBase = (char*)entry_complete->DllBase;

        if (currentBase != NULL && currentBase != found_in_library) {
            IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)currentBase;
            IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(currentBase + hdr->e_lfanew);

            if (newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
                IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(currentBase + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

                uint32_t* funcs = (uint32_t*)(currentBase + exportDir->AddressOfFunctions);
                uint32_t* names = (uint32_t*)(currentBase + exportDir->AddressOfNames);
                uint16_t* ordinals = (uint16_t*)(currentBase + exportDir->AddressOfNameOrdinals);

                for (int i = 0; i < exportDir->NumberOfNames; i++) {
                    uint32_t exportAddrOffset = funcs[ordinals[i]];
                    char* exportName = currentBase + names[i];

                    if (exportAddrOffset > newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && exportAddrOffset < newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                        if (_strcmp(function_name, exportName) == TRUE) {
                            // Forwarded instance found
                            return currentBase;
                        }
                    }
                }
            }
        }

        lstHead = lstHead->Flink;
        if (lstHead == ldr->InMemoryOrderModuleList.Flink) {
            break;
        }
    }
    return 0;
}

extern "C"
int __stdcall number_of_modules() {
    char* targetBase = NULL;
    PPEB peb = get_peb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* lstHead = ldr->InMemoryOrderModuleList.Flink;

    int count = 0;
    while (lstHead != NULL) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)lstHead;
        LDR_DATA_TABLE_ENTRY* entry_complete = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(lstHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        char* currentBase = (char*)entry_complete->DllBase;

        if (currentBase != NULL) {
            count += 1;
        }

        lstHead = lstHead->Flink;
        if (lstHead == ldr->InMemoryOrderModuleList.Flink) {
            break;
        }
    }
    return count - 1;
}


extern "C"
uint16_t __stdcall get_export_in_preferred_lib(uint64_t symbol, char* preferred_library, char** name) {
    char* poss_lib = find_library_containing_address(symbol);
    if (poss_lib == NULL) {
        return -1;
    } else {
        IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)poss_lib;
        IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(poss_lib + hdr->e_lfanew);

        IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(poss_lib + newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (exportDir->Name != NULL) {
            char* dllName = poss_lib + exportDir->Name;
            uint32_t* funcs = (uint32_t*)(poss_lib + exportDir->AddressOfFunctions);
            uint32_t* names = (uint32_t*)(poss_lib + exportDir->AddressOfNames);
            uint16_t* ordinals = (uint16_t*)(poss_lib + exportDir->AddressOfNameOrdinals);

            for (int i = 0; i < exportDir->NumberOfNames; i++) {
                uint32_t exportAddrOffset = funcs[ordinals[i]];
                uint64_t exportVA = (uint64_t)poss_lib + exportAddrOffset;
                char* exportName = poss_lib + names[i];

                if (exportVA == symbol) {
                    *name = exportName;
                    // Found in a library. Now to find in preferred

                    if (poss_lib == preferred_library) {
                        *name = exportName;
                        return ordinals[i];
                    }

                    IMAGE_DOS_HEADER* hdr2 = (IMAGE_DOS_HEADER*)preferred_library;
                    IMAGE_NT_HEADERS64* newHdr2 = (IMAGE_NT_HEADERS64*)(preferred_library + hdr2->e_lfanew);

                    IMAGE_EXPORT_DIRECTORY* exportDir2 = (IMAGE_EXPORT_DIRECTORY*)(preferred_library + newHdr2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    if (exportDir2->Name != NULL) {
                        uint32_t* funcs2 = (uint32_t*)(preferred_library + exportDir2->AddressOfFunctions);
                        uint32_t* names2 = (uint32_t*)(preferred_library + exportDir2->AddressOfNames);
                        uint16_t* ordinals2 = (uint16_t*)(preferred_library + exportDir2->AddressOfNameOrdinals);

                        for (int j = 0; j < exportDir2->NumberOfNames; j++) {
                            char* exportName2 = preferred_library + names2[j];
                            uint32_t exportAddrOffset = funcs2[ordinals2[j]];

                            if (_strcmp(exportName, exportName2) == TRUE) {
                                *name = exportName2;
                                return ordinals2[j];
                            }

                            // Maybe a function forwarded to the passed in one, check that
                            if (exportAddrOffset > newHdr2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && exportAddrOffset < newHdr2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + newHdr2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                                char* forwarded_str = preferred_library + exportAddrOffset;
                                int dot_idx = _strtok(forwarded_str, ".");
                                if (_strcmp(exportName, forwarded_str + _strtok(forwarded_str, ".")+1) == TRUE) {
                                    *name = exportName2;
                                    return ordinals2[j];
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return -1;
}