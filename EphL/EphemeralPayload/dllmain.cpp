// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdint>
#include <winternl.h>
#include <cstddef>
#include "external_dll.h"
#include "function_types.h"
#include "utils.h"
#include <intrin.h>


#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(_AddressOfReturnAddress)

// Required to keep everything in one section. Allows for laziness in loading the binary (smaller loader code size)
#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(linker,"/MERGE:.data=.text")
#pragma comment(linker,"/MERGE:.pdata=.text")

void output_hex(uint64_t val, int digits, KernelFuncs ctx) {
    char out[17];
    for (int i = digits - 1; i >= 0; i--) {
        char c = (val >> (i * 4)) & 0xf;
        if (c < 0xa) {
            out[digits - 1 - i] = c + '0';
        }
        else {
            out[digits - 1 - i] = c-0xa + 'A';
        }
    }
    out[digits] = 0;
    ctx.OutputDebugStringA(out);
}

extern "C" void __fastcall asm_func(void);

extern "C" __declspec(dllexport)
void APIENTRY LiveEphemerally(uint64_t return_addr) {
    KernelFuncs kernel32_funcs;

    int result = resolve_functions_for_dll("kernel32.dll", kernel32_func_names, (void**)&kernel32_funcs);
    if (result == (sizeof(kernel32_func_names) / sizeof(const char*)) - 1) {
        kernel32_funcs.OutputDebugStringA("Injected >:)");

        uint64_t exe_base = (uint64_t)find_library_with_name("lostark.exe");
        if (exe_base != 0) {
            //output_hex(exe_base, 16, kernel32_funcs);
        }
        output_hex(return_addr, 16, kernel32_funcs);




        IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)return_addr;
        IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(return_addr + hdr->e_lfanew);
        IMAGE_SECTION_HEADER* section_headers = (IMAGE_SECTION_HEADER*)((char*)newHdr + sizeof(IMAGE_NT_HEADERS64));
        uint64_t real_text_base_address;
        uint64_t real_text_size;
        for (int i = 0; i < newHdr->FileHeader.NumberOfSections; i++) {
            if (section_headers[i].Name[1] == 't') { // .text section
                kernel32_funcs.OutputDebugStringA("found text");
                uint64_t va = section_headers[i].VirtualAddress;
                uint64_t ra = va + return_addr;
                real_text_base_address = ra;
                uint64_t vs = section_headers[i].Misc.VirtualSize;
                real_text_size = vs;

                output_hex(ra, 16, kernel32_funcs);
                output_hex(*(uint64_t*)ra, 16, kernel32_funcs);
                output_hex(vs, 16, kernel32_funcs);

                // Make .text writable
                DWORD old_prot;
                kernel32_funcs.VirtualProtect((void*)ra, vs, PAGE_EXECUTE_READWRITE, &old_prot);


                // Get real file
                HANDLE targetFile = kernel32_funcs.CreateFileA((char*)"E:\\gamehax\\lostark\\LostArkRev\\oo2net_9_win64.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                DWORD fileSize = kernel32_funcs.GetFileSize(targetFile, NULL);
                char* real_dll_buffer = (char*)kernel32_funcs.VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                kernel32_funcs.ReadFile(targetFile, real_dll_buffer, fileSize, &fileSize, NULL);

                IMAGE_DOS_HEADER* real_hdr = (IMAGE_DOS_HEADER*)real_dll_buffer;
                IMAGE_NT_HEADERS64* real_newHdr = (IMAGE_NT_HEADERS64*)(real_dll_buffer + hdr->e_lfanew);
                IMAGE_SECTION_HEADER* real_section_headers = (IMAGE_SECTION_HEADER*)((char*)newHdr + sizeof(IMAGE_NT_HEADERS64));
                uint64_t real_va;
                uint64_t real_pointer_to_raw;
                for (int j = 0; j < real_newHdr->FileHeader.NumberOfSections; j++) {
                    if (real_section_headers[j].Name[1] == 't') { // .text section
                        kernel32_funcs.OutputDebugStringA("found text in real dll");

                        // copy .text memory over
                        char* real_text = real_dll_buffer + real_section_headers[j].PointerToRawData;

                        for (int k = 0; k < real_section_headers[j].SizeOfRawData; k++) {
                            *(uint8_t*)(ra + k) = real_text[k];
                        }
                        real_va = real_section_headers[j].VirtualAddress;
                        real_pointer_to_raw = real_section_headers[j].PointerToRawData;

                        output_hex(kernel32_funcs.FlushViewOfFile((void*)return_addr, 0), 16, kernel32_funcs);

                        kernel32_funcs.OutputDebugStringA("copied");
                    }
                    else if (real_section_headers[j].Name[3] == 'l') { // .reloc
                        kernel32_funcs.OutputDebugStringA("found reloc");

                        /*int reloc_counter = 0;
                        char* relocationDir = ((char*)real_dll_buffer + real_newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress - real_section_headers[j].VirtualAddress + real_section_headers[j].PointerToRawData);
                        while (reloc_counter < real_newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
                            uint32_t page = *(uint32_t*)(relocationDir + reloc_counter);
                            reloc_counter += 4;
                            uint32_t curr_size = *(uint32_t*)(relocationDir + reloc_counter);
                            reloc_counter += 4;
                            for (int k = 0; k < curr_size - 8; k += 2) {
                                uint16_t offset = *(uint16_t*)(relocationDir + reloc_counter + k);
                                output_hex(offset, 16, kernel32_funcs);

                                if ((offset >> 12) == 0xA) { // IMAGE_REL_BASED_DIR64
                                    char* target = ((char*)return_addr + page + (offset & 0x0FFF) - real_va + real_pointer_to_raw);
                                    output_hex((uint64_t)target, 16, kernel32_funcs);
                                    output_hex(return_addr + page + (offset & 0x0FFF), 16, kernel32_funcs);
                                    // Remove the image base (normal) and the virtual address part from the text section base (new)
                                    *(uint64_t*)target = *(uint64_t*)target - real_newHdr->OptionalHeader.ImageBase - real_va;
                                    // Add the new image base (normal) and the file offset part from the text section base (new)
                                    *(uint64_t*)target += (uint64_t)return_addr + real_pointer_to_raw;

                                }
                                else {
                                    // TODO - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format .reloc section
                                }
                            }
                            reloc_counter += curr_size - 8;
                        }*/

                        kernel32_funcs.OutputDebugStringA("fixed reloc");
                    }
                }

                // Cleanup
                kernel32_funcs.VirtualFree(real_dll_buffer, 0, MEM_RELEASE);
                kernel32_funcs.CloseHandle(targetFile);

                // Revert write permission
                kernel32_funcs.VirtualProtect((void*)ra, vs, old_prot, &old_prot);
            }            
        }


        // Fix return address for previous stack cleanup
        uint64_t* a_ra = (uint64_t *)_AddressOfReturnAddress();

        *a_ra = (uint64_t)asm_func;
        output_hex((uint64_t)_ReturnAddress(), 16, kernel32_funcs);

        

        kernel32_funcs.OutputDebugStringA("Done >:)");

        return;

        HANDLE targetFile = kernel32_funcs.CreateFileA((char*)"E:\\gamehax\\lostark\\LostArkRev\\leph_dump.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (targetFile == INVALID_HANDLE_VALUE) {
            kernel32_funcs.OutputDebugStringA("Failed to open file!");
        }
        else {
            DWORD written = 0;
            kernel32_funcs.OutputDebugStringA("Opened file!");
            //output_hex((uint64_t)target, 16, kernel32_funcs.OutputDebugStringA);

            // Find the actual base
            uint64_t start_addr = return_addr & ~0xfff;
            while (start_addr > 0) {
                IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)start_addr;
                if (hdr->e_magic == 0x5a4d) {
                    // Potentially
                    IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)((char*)start_addr + hdr->e_lfanew);
                    if (newHdr->Signature == 0x4550) {
                        kernel32_funcs.OutputDebugStringA((char*)"Real image base found!");
                        break;
                    }
                }
                start_addr -= 0x1000;
            }
            output_hex(return_addr, 16, kernel32_funcs);
            output_hex(*(uint64_t*)return_addr, 16, kernel32_funcs);
            output_hex(start_addr, 16, kernel32_funcs);
            char* target = (char*)start_addr;

            // NT Header 
            IMAGE_DOS_HEADER* hdr = (IMAGE_DOS_HEADER*)target;
            kernel32_funcs.WriteFile(targetFile, hdr, sizeof(IMAGE_DOS_HEADER), &written, NULL);
            // Rich header - Not much doco about this, so ignoring it and filling with zeros
            for (int i = 0; i < hdr->e_lfanew - sizeof(IMAGE_DOS_HEADER); i++) {
                kernel32_funcs.WriteFile(targetFile, (char*)"\x00", 1, &written, NULL);
            }

            // PE Header
            IMAGE_NT_HEADERS64* newHdr = (IMAGE_NT_HEADERS64*)(target + hdr->e_lfanew);
            kernel32_funcs.WriteFile(targetFile, newHdr, sizeof(IMAGE_NT_HEADERS64), &written, NULL);

            // Section headers
            IMAGE_SECTION_HEADER* section_headers = (IMAGE_SECTION_HEADER*)((char*)newHdr + sizeof(IMAGE_NT_HEADERS64));

            // Get the sections ordered by how they should appear in the file
            IMAGE_SECTION_HEADER* fixed_sections = (IMAGE_SECTION_HEADER*)kernel32_funcs.VirtualAlloc(NULL, sizeof(IMAGE_SECTION_HEADER) * newHdr->FileHeader.NumberOfSections, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            _memcpy(fixed_sections, section_headers, sizeof(IMAGE_SECTION_HEADER)* newHdr->FileHeader.NumberOfSections);

            // Recalculate file offsets for writing to the file
            uint32_t current_offset = ((char*)section_headers + sizeof(IMAGE_SECTION_HEADER) * newHdr->FileHeader.NumberOfSections) - target;
            uint32_t biggest_va = 0;
            current_offset = (current_offset & ~0x1ff) + 0x200;
            for (int i = 0; i < newHdr->FileHeader.NumberOfSections; i++) {
                /*kernel32_funcs.OutputDebugStringA((char*)fixed_sections[i].Name);
                output_hex(fixed_sections[i].PointerToRawData, 8, kernel32_funcs.OutputDebugStringA);
                output_hex(fixed_sections[i].Misc.VirtualSize, 8, kernel32_funcs.OutputDebugStringA);
                output_hex(fixed_sections[i].SizeOfRawData, 8, kernel32_funcs.OutputDebugStringA);*/
                fixed_sections[i].PointerToRawData = current_offset;
                if (section_headers[i].SizeOfRawData < section_headers[i].Misc.VirtualSize) {
                    fixed_sections[i].SizeOfRawData = fixed_sections[i].Misc.VirtualSize;
                }

                // Ignore extremely large sections, probably used to throw off people.
                if (fixed_sections[i].SizeOfRawData > 0x10000000) { // 256mib
                    //fixed_sections[i].SizeOfRawData = fixed_sections[i].Misc.VirtualSize;
                    fixed_sections[i].SizeOfRawData = 0;
                    fixed_sections[i].VirtualAddress = 0;
                    fixed_sections[i].Misc.VirtualSize = 0;
                }

                if (fixed_sections[i].VirtualAddress >= biggest_va) {
                    biggest_va = fixed_sections[i].VirtualAddress + fixed_sections[i].SizeOfRawData;
                }
                current_offset += fixed_sections[i].SizeOfRawData;
                current_offset = (current_offset & ~0x1ff) + 0x200;
            }

            kernel32_funcs.WriteFile(targetFile, fixed_sections, sizeof(IMAGE_SECTION_HEADER)* newHdr->FileHeader.NumberOfSections, &written, NULL);
            kernel32_funcs.OutputDebugStringA((char*)"Writing sections");

            // Write each section data
            uint32_t current_pointer = ((char*)section_headers + sizeof(IMAGE_SECTION_HEADER) * newHdr->FileHeader.NumberOfSections) - target;
            for (int i = 0; i < newHdr->FileHeader.NumberOfSections; i++) {
                uint32_t current_sec_offset = fixed_sections[i].PointerToRawData;
                // Fill empty space with zeros
                for (int i = 0; i < current_sec_offset - current_pointer; i++) {
                    kernel32_funcs.WriteFile(targetFile, (char*)"\x00", 1, &written, NULL);
                }
                    
                // Write section data
                current_pointer += fixed_sections[i].SizeOfRawData;
                written = 0;
                if (!kernel32_funcs.WriteFile(targetFile, target + fixed_sections[i].VirtualAddress, fixed_sections[i].SizeOfRawData, &written, NULL)) {
                    //kernel32_funcs.OutputDebugStringA((char*)fixed_sections[i].Name);
                    //output_hex(kernel32_funcs.GetLastError(), 8, kernel32_funcs);
                    //output_hex(written, 8, kernel32_funcs);
                }
            }

            //
            // Reconstructing imports
            //

            // NOTE: This is extremely lazy because we rely on all pointers to be contigious in memory, NULL pointer seperated.
            //       The actual way to do this is to find all calls to locations that contain a pointer, check if pointer is in a loaded DLL, add pointer and dll to a list.
            //       Reconstruct from there
            // Basic and extremely lazy way to reconstruct imports is to do the following:
            // - Find a call to a location that has an external pointer
            // - From that location, go up until we find two null pointers next to eachother. First address after

            uint64_t call_offset = return_addr;
            while (call_offset > (uint64_t)target) {
                BYTE* curr = (BYTE*)call_offset;
                if (curr[0] == 0xff && curr[1] == 0x15) { // Call to qword
                    uint64_t call_val = (uint64_t)(*(uint32_t*)(curr+2));
                    uint64_t func_pointer_addr = call_offset + call_val + 6;
                    kernel32_funcs.OutputDebugStringA((char*)"Call found");
                       
                    // Currently a bad assumption to make:
                    // Goes up from the found function pointer until two null pointers back to back. This is bad because you can have huge gaps. 
                    // Need to do same approach going down, where you keep going until you find a value that isn't valid or kernel

                    while (func_pointer_addr > (uint64_t)target) {
                        if (*(uint64_t*)func_pointer_addr == 0 && *(uint64_t*)(func_pointer_addr-8) == 0) {
                            kernel32_funcs.OutputDebugStringA((char*)"Found start");
                            func_pointer_addr += 8;
                            output_hex(func_pointer_addr, 16, kernel32_funcs);
                            
                            // Now go down the list and resolve imports.
                            int total_count = 0;

                            typedef struct {
                                char* base;
                                uint64_t start_addr;
                                uint64_t count;
                            } DLLEntry;

                            typedef struct {
                                char* base;
                                uint64_t count;
                            } DllBattle;

                            uint32_t entry_count = 0;
                            DLLEntry* entries = (DLLEntry*)kernel32_funcs.VirtualAlloc(NULL, sizeof(DLLEntry) * number_of_modules(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                            uint32_t battle_count = 0;
                            DllBattle* battles = (DllBattle*)kernel32_funcs.VirtualAlloc(NULL, sizeof(DllBattle) * number_of_modules(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                            char* currentDLL = NULL;
                            while (true) {
                                uint64_t current_val = *(uint64_t*)func_pointer_addr;
                                if (current_val != 0) {
                                    char* poss_lib = find_library_containing_address(current_val);
                                    if (poss_lib == NULL) {
                                        kernel32_funcs.OutputDebugStringA((char*)"Unknown before end");
                                    }
                                    else if (poss_lib == target) {
                                        kernel32_funcs.OutputDebugStringA((char*)"Internal address, time to end");
                                        break;
                                    }
                                    else {
                                        if (currentDLL == NULL) {
                                            currentDLL = poss_lib;
                                            entries[entry_count].base = currentDLL;
                                            entries[entry_count].start_addr = func_pointer_addr;
                                        }
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

                                                int t = 0;
                                                SIZE_T read;
                                                if (exportVA == current_val) {
                                                    char* forwarded_lib = check_if_forwarded(exportName, poss_lib);
                                                    if (forwarded_lib != NULL) {
                                                        //kernel32_funcs.OutputDebugStringA((char*)"Forwarded!");
                                                        IMAGE_DOS_HEADER* hdr2 = (IMAGE_DOS_HEADER*)forwarded_lib;
                                                        IMAGE_NT_HEADERS64* newHdr2 = (IMAGE_NT_HEADERS64*)(forwarded_lib + hdr2->e_lfanew);

                                                        IMAGE_EXPORT_DIRECTORY* exportDir2 = (IMAGE_EXPORT_DIRECTORY*)(forwarded_lib + newHdr2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                                                        dllName = forwarded_lib + exportDir2->Name;

                                                        int found = 0;
                                                        for (int battle_idx = 0; battle_idx < battle_count; battle_idx++) {
                                                            if (battles[battle_idx].base == forwarded_lib) {
                                                                battles[battle_idx].count += 1;
                                                                found = 1;
                                                                break;
                                                            }
                                                        }

                                                        if (!found) {
                                                            battles[battle_count].base = forwarded_lib;
                                                            battles[battle_count].count = 1;
                                                            battle_count += 1;
                                                        }
                                                    }
                                                    else {
                                                        int found = 0;
                                                        for (int battle_idx = 0; battle_idx < battle_count; battle_idx++) {
                                                            if (battles[battle_idx].base == poss_lib) {
                                                                battles[battle_idx].count += 1;
                                                                found = 1;
                                                                break;
                                                            }
                                                        }

                                                        if (!found) {
                                                            battles[battle_count].base = poss_lib;
                                                            battles[battle_count].count = 1;
                                                            battle_count += 1;
                                                        }
                                                    }

                                                    total_count += 1;
                                                    entries[entry_count].count += 1;
                                                    //kernel32_funcs.OutputDebugStringA(dllName);
                                                    //kernel32_funcs.OutputDebugStringA(exportName);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                else {
                                    if (currentDLL != NULL) {
                                        kernel32_funcs.OutputDebugStringA((char*)"Finished library. Getting Battle Winner");
                                        int highest_idx = 0;
                                        for (int i = 1; i < battle_count; i++) {
                                            if (battles[i].count > battles[highest_idx].count) {
                                                highest_idx = i;
                                            }
                                        }

                                        entries[entry_count].base = battles[highest_idx].base;

                                        currentDLL = NULL;
                                        entry_count++;
                                        battle_count = 0;
                                    }

                                }

                                func_pointer_addr += 8;
                            }

                            output_hex(total_count, 8, kernel32_funcs);
                            output_hex(entry_count, 8, kernel32_funcs);

                            // Now we have all possible entries, need to put together all the parts.

                            // + 1 for null descriptor
                            uint64_t section_base = biggest_va;

                            IMAGE_SECTION_HEADER import_section;
                            import_section.Name[0] = '.';
                            import_section.Name[1] = 'l';
                            import_section.Name[2] = 'p';
                            import_section.Name[3] = 'h';
                            import_section.Name[4] = 0;
                            import_section.Name[5] = 0;
                            import_section.Name[6] = 0;
                            import_section.Name[7] = 0;
                            import_section.NumberOfLinenumbers = 0;
                            import_section.VirtualAddress = section_base;
                            import_section.SizeOfRawData = 0; // TO REPLACE
                            import_section.PointerToRelocations = 0;
                            import_section.PointerToRawData = current_offset;
                            import_section.PointerToLinenumbers = 0;
                            import_section.NumberOfRelocations = 0;
                            import_section.NumberOfLinenumbers = 0;
                            import_section.Misc.VirtualSize = 0; // TO REPLACE
                            import_section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

                            for (int i = 0; i < current_offset - current_pointer; i++) {
                                kernel32_funcs.WriteFile(targetFile, (char*)"\x00", 1, &written, NULL);
                            }

                            kernel32_funcs.SetFilePointer(targetFile, import_section.PointerToRawData, NULL, 0x0);

                            uint64_t descriptor_sz = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (entry_count + 1);
                            IMAGE_IMPORT_DESCRIPTOR* descriptors = (IMAGE_IMPORT_DESCRIPTOR*)kernel32_funcs.VirtualAlloc(NULL, descriptor_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                            kernel32_funcs.WriteFile(targetFile, descriptors, descriptor_sz, &written, NULL);
                            //current_pointer += descriptor_sz;

                            uint64_t thunk_start_addr = section_base + descriptor_sz;

                            uint64_t thunk_sz = sizeof(IMAGE_THUNK_DATA64) * ((uint32_t)total_count + entry_count);
                            output_hex(thunk_sz, 8, kernel32_funcs);
                            
                            IMAGE_THUNK_DATA64* thunks = (IMAGE_THUNK_DATA64*)kernel32_funcs.VirtualAlloc(NULL, thunk_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                            written = 0;
                            kernel32_funcs.WriteFile(targetFile, thunks, thunk_sz, &written, NULL);

                            uint64_t data_addr = thunk_start_addr + thunk_sz;

                            newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = section_base;
                            newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (entry_count + 1);
                            // TODO: Write import directory

                            uint32_t thunk_idx = 0;
                            for (int i = 0; i < entry_count; i++) {
                                char* currDllBase = entries[i].base;
                                IMAGE_DOS_HEADER* hdr2 = (IMAGE_DOS_HEADER*)currDllBase;
                                IMAGE_NT_HEADERS64* newHdr2 = (IMAGE_NT_HEADERS64*)(currDllBase + hdr2->e_lfanew);
                                IMAGE_EXPORT_DIRECTORY* exportDir2 = (IMAGE_EXPORT_DIRECTORY*)(currDllBase + newHdr2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                                
                                char* dllName = currDllBase + exportDir2->Name;
                                kernel32_funcs.OutputDebugStringA(dllName);

                                descriptors[i].Name = data_addr;
                                kernel32_funcs.WriteFile(targetFile, dllName, _strlen(dllName) + 1, &written, NULL);
                                data_addr += _strlen(dllName) + 1;

                                descriptors[i].FirstThunk = entries[i].start_addr - (uint64_t)target;

                                uint32_t start_thunk_idx = thunk_idx;
                                descriptors[i].OriginalFirstThunk = thunk_start_addr + (start_thunk_idx * sizeof(IMAGE_THUNK_DATA64));

                                for (uint64_t thunk_start_addr = entries[i].start_addr; *(uint64_t*)thunk_start_addr != 0; thunk_start_addr += 8) {
                                    char* actual_name = NULL;
                                    uint16_t ordinal = get_export_in_preferred_lib(*(uint64_t*)thunk_start_addr, currDllBase, &actual_name);
                                    if (ordinal != 0xFFFF) {
                                        uint32_t length = _strlen(actual_name);
                                        thunks[thunk_idx++].u1.AddressOfData = data_addr;

                                        kernel32_funcs.WriteFile(targetFile, &ordinal, sizeof(uint16_t), &written, NULL);
                                        data_addr += sizeof(uint16_t);
                                        kernel32_funcs.WriteFile(targetFile, actual_name, length + 1, &written, NULL);
                                        data_addr += length + 1;

                                    }
                                    else {
                                        kernel32_funcs.OutputDebugStringA("Failed to find export!!!");
                                        if (actual_name != NULL) {
                                            kernel32_funcs.OutputDebugStringA(actual_name);
                                        }
                                    }
                                }
                                thunk_idx++;
                            }

                            if (thunk_idx != total_count + entry_count) {
                                kernel32_funcs.OutputDebugStringA("Thunk mismatch");
                                output_hex(thunk_idx, 8, kernel32_funcs);
                                output_hex(total_count + entry_count, 8, kernel32_funcs);


                            }

                            kernel32_funcs.SetFilePointer(targetFile, import_section.PointerToRawData, NULL, 0x0);
                            kernel32_funcs.WriteFile(targetFile, descriptors, descriptor_sz, &written, NULL);
                            kernel32_funcs.WriteFile(targetFile, thunks, thunk_sz, &written, NULL);

                            hdr = (IMAGE_DOS_HEADER*)target;
                            newHdr = (IMAGE_NT_HEADERS64*)(target + hdr->e_lfanew);


                            // Change number of sections
                            kernel32_funcs.SetFilePointer(targetFile, hdr->e_lfanew + offsetof(IMAGE_NT_HEADERS64, FileHeader.NumberOfSections) , NULL, 0x0);
                            uint32_t secs = newHdr->FileHeader.NumberOfSections + 1;
                            kernel32_funcs.WriteFile(targetFile, &secs, sizeof(uint32_t), &written, NULL);


                            // Change Directory
                            kernel32_funcs.SetFilePointer(targetFile, hdr->e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]), NULL, 0x0);
                            kernel32_funcs.WriteFile(targetFile, &(newHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]), sizeof(IMAGE_DATA_DIRECTORY), &written, NULL);

                            // Add section
                            import_section.Misc.VirtualSize = data_addr - section_base;
                            import_section.SizeOfRawData = data_addr - section_base;
                            kernel32_funcs.SetFilePointer(targetFile, hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (secs-1)*sizeof(IMAGE_SECTION_HEADER), NULL, 0x0);
                            kernel32_funcs.WriteFile(targetFile, &import_section, sizeof(IMAGE_SECTION_HEADER), &written, NULL);

                            // Section headers
                            //IMAGE_SECTION_HEADER* section_headers = (IMAGE_SECTION_HEADER*)((char*)newHdr + sizeof(IMAGE_NT_HEADERS64));
                            //kernel32_funcs.SetFilePointer(targetFile, import_section.PointerToRawData, NULL, 0x0);

                            break;
                        }
                        func_pointer_addr -= 8;
                    }

                    break;
                }
                call_offset--;
            }

            //uint64_t thunk_addr = return_addr + call_offset;

            // The thunk contains a single jmp (if its not delay loaded, need to develop a case for that). get address of what it jumps to
            //uint64_t jmp_offset = (uint64_t)(*(uint32_t*)(thunk_addr - 4));
            //uint64_t func_pointer_addr = thunk_addr + jmp_offset + 6;
            //uint64_t func_pointer_file_offset = func_pointer_addr - (uint64_t)target;

            // 

            /*
                    
                We then search for 
            */

            kernel32_funcs.VirtualFree(fixed_sections, 0, MEM_RELEASE);
            kernel32_funcs.OutputDebugStringA((char*)"Chillin");
        }
        kernel32_funcs.CloseHandle(targetFile);

#if 0
        targetFile = kernel32_funcs.CreateFileA((char*)"E:\\gamehax\\lostark\\LostArkRev\\la_heap_dump", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (targetFile == INVALID_HANDLE_VALUE) {
            //OutputDebugStringA("Failed to open file!");
        }
        else {
            MEMORY_BASIC_INFORMATION info;
            unsigned char* p = NULL;
            for (p = NULL;
                kernel32_funcs.VirtualQueryEx(kernel32_funcs.GetCurrentProcess(), p, &info, sizeof(info)) == sizeof(info);
                p += info.RegionSize) {
                if (info.State == MEM_COMMIT && (info.Type == MEM_MAPPED || info.Type == MEM_PRIVATE)) {
                    if ((info.Protect & (~PAGE_NOACCESS)) != 0) {
                        char x[10];
                        SIZE_T w;
                        if (kernel32_funcs.ReadProcessMemory(kernel32_funcs.GetCurrentProcess(), p, x, 1, &w)) {
                            output_hex((uint64_t)p, 16, kernel32_funcs);
                            output_hex((uint64_t)info.RegionSize, 16, kernel32_funcs);
                            DWORD written = 0;
                            if (!kernel32_funcs.WriteFile(targetFile, p, info.RegionSize, &written, NULL)) {
                            }
                            else {
                                for (uint64_t mem_offset = 0; mem_offset < info.RegionSize - 5; mem_offset++) {
                                    if (p[mem_offset] == 0x5c && p[mem_offset + 1] == 0xb3 && p[mem_offset + 2] == 0x74 && p[mem_offset + 3] == 0x2d) {
                                        kernel32_funcs.OutputDebugStringA("Xor key located!");
                                        output_hex((uint64_t)p + mem_offset, 16, kernel32_funcs);
                                    }
                                }
                            }
                        }
                        else {
                            //kernel32_funcs.OutputDebugStringA("Failed to read!");
                        }
                    }
                    else {
                        //kernel32_funcs.OutputDebugStringA("NoReadPerms!");

                    }
                }
            }
            kernel32_funcs.CloseHandle(targetFile);
        }
#endif


#if 0
            DWORD numHeaps = kernel32_funcs.GetProcessHeaps(0, NULL);
            PHANDLE heapHandles = (PHANDLE)kernel32_funcs.VirtualAlloc(NULL, numHeaps*sizeof(HANDLE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            kernel32_funcs.GetProcessHeaps(numHeaps, heapHandles);

            output_hex(numHeaps, 8, kernel32_funcs.OutputDebugStringA);
            for (int j = 0; j < numHeaps; j++) {
                HANDLE procHeap = heapHandles[j];
                PROCESS_HEAP_ENTRY hEntry;
                hEntry.lpData = NULL;
                kernel32_funcs.OutputDebugStringA((char*)"Got heap, walking");
                while (kernel32_funcs.HeapWalk(procHeap, &hEntry) != FALSE) {
                    //if (hEntry.cbData == 0x100) {
                        // Look for allocated blocks where the first 8 bytes are not a pointer to something else (which is probably a c++ object)
                    if ((hEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {

                        /*if ((Entry.wFlags & PROCESS_HEAP_ENTRY_MOVEABLE) != 0) {
                            _tprintf(TEXT(", movable with HANDLE %#p"), Entry.Block.hMem);
                        }

                        if ((Entry.wFlags & PROCESS_HEAP_ENTRY_DDESHARE) != 0) {
                            _tprintf(TEXT(", DDESHARE"));
                        }*/


                        char* curBlock = (char*)hEntry.lpData;
                        for (int i = 0; i < hEntry.cbData - 8; i++) {
                            if (curBlock[i] == 0x42 && curBlock[i + 1] == 0x89 && curBlock[i + 2] == 0x7a) {
                                kernel32_funcs.OutputDebugStringA((char*)"Allocated block");
                                kernel32_funcs.OutputDebugStringA((char*)"BROOOOOOOO");
                                kernel32_funcs.OutputDebugStringA((char*)"Data portion at: ");
                                output_hex((uint64_t)hEntry.lpData, 16, kernel32_funcs.OutputDebugStringA);
                                kernel32_funcs.OutputDebugStringA((char*)"Size: ");
                                output_hex((uint64_t)hEntry.cbData, 8, kernel32_funcs.OutputDebugStringA);
                                output_hex(*(uint64_t*)hEntry.lpData, 16, kernel32_funcs.OutputDebugStringA);

                            }
                        }

                    }
                    else if ((hEntry.wFlags & PROCESS_HEAP_REGION) != 0) {
                        kernel32_funcs.OutputDebugStringA((char*)"Committed region");
                        output_hex((uint64_t)hEntry.Region.lpFirstBlock, 16, kernel32_funcs.OutputDebugStringA);
                        
                        /*_tprintf(TEXT("Region\n  %d bytes committed\n") \
                            TEXT("  %d bytes uncommitted\n  First block address: %#p\n") \
                            TEXT("  Last block address: %#p\n"),
                            Entry.Region.dwCommittedSize,
                            Entry.Region.dwUnCommittedSize,
                            Entry.Region.lpFirstBlock,
                            Entry.Region.lpLastBlock);*/
                    }
                    else if ((hEntry.wFlags & PROCESS_HEAP_UNCOMMITTED_RANGE) != 0) {
                        //kernel32_funcs.OutputDebugStringA((char*)"Uncommitted range");
                    }
                    else {
                        //kernel32_funcs.OutputDebugStringA((char*)"Block");
                    }


                    //}

                    /*_tprintf(TEXT("  Data portion begins at: %#p\n  Size: %d bytes\n") \
                        TEXT("  Overhead: %d bytes\n  Region index: %d\n\n"),
                        Entry.lpData,
                        Entry.cbData,
                        Entry.cbOverhead,
                        Entry.iRegionIndex);*/
                }
            }
#endif
        kernel32_funcs.OutputDebugStringA((char*)"At least, I felt something.");
    }
}


