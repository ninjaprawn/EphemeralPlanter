#pragma once

#include <Windows.h>
#include <winternl.h>
#include <cstddef>
#include <cstdint>
#include "function_types.h"

#if defined(_M_X64) // x64
#define get_peb() ((PTEB)__readgsqword(offsetof(NT_TIB, Self)))->ProcessEnvironmentBlock
#else // x86
#define get_peb() ((PTEB)__readfsdword(offsetof(NT_TIB, Self)))->ProcessEnvironmentBlock
#endif

extern "C" {
	char* __stdcall find_library_with_name(const char* name);
	void __stdcall break_it_all(void* p);
	int __stdcall resolve_functions(char* dll, const char** names, void** funcs);
	int __stdcall resolve_functions_for_dll(const char* dll_name, const char** names, void** funcs);
	char* __stdcall find_library_containing_address(uint64_t addr);
	char* __stdcall check_if_forwarded(char* function_name, char* found_in_library);
	int __stdcall number_of_modules(void);
	uint16_t __stdcall get_export_in_preferred_lib(uint64_t symbol, char* preferred_library, char** name);
}