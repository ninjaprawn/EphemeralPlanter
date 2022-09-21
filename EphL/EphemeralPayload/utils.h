#pragma once

#include <Windows.h>

BOOL _strcmp(const char* s1, const char* s2);
BOOL strcmpi(char* s1, char* s2);
BOOL strcmpwi(const char* s1, wchar_t* ws2);
void _memcpy(void* dst, void* src, unsigned int cnt);
int _strlen(const char* s1);
int _strtok(const char* s1, const char* tok);
BOOL strncmpi(char* s1, char* s2, unsigned int idx);
BOOL _strncmp(const char* s1, const char* s2, unsigned int idx);