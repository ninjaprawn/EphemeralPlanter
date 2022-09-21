#include "pch.h"
#include "utils.h"

int _strlen(const char* s1) {
    int count = 0;
    while (s1[count] != 0) {
        count++;
    }
    return count;
}

BOOL _strcmp(const char* s1, const char* s2) {
    int i = 0;
    while (true) {
        if (s1[i] != s2[i]) {
            return false;
        }
        if (s1[i] == 0 || s2[i] == 0) {
            return s1[i] == s2[i];
        }
        i++;
    }
}

BOOL _strncmp(const char* s1, const char* s2, unsigned int idx) {
    int i = 0;
    while (i < idx) {
        if (s1[i] != s2[i]) {
            return false;
        }
        if (s1[i] == 0 || s2[i] == 0) {
            return s1[i] == s2[i];
        }
        i++;
    }
    return false;
}

BOOL strcmpi(char* s1, char* s2) {
    int i = 0;
    while (true) {
        char s1_c = s1[i];
        if (s1_c >= 'A' && s1_c <= 'Z')
            s1_c += 0x20;
        char s2_c = s2[i];
        if (s2_c >= 'A' && s2_c <= 'Z')
            s2_c += 0x20;
        if (s1_c != s2_c) {
            return false;
        }
        if ((s1[i] & s2[i]) == 0) {
            return s1[i] == s2[i];
        }
        i += 1;
    }
}


BOOL strncmpi(const char* s1, const char* s2, unsigned int idx) {
    int i = 0;
    while (i < idx) {
        char s1_c = s1[i];
        if (s1_c >= 'A' && s1_c <= 'Z')
            s1_c += 0x20;
        char s2_c = s2[i];
        if (s2_c >= 'A' && s2_c <= 'Z')
            s2_c += 0x20;
        if (s1_c != s2_c) {
            return false;
        }
        if ((s1[i] & s2[i]) == 0) {
            return s1[i] == s2[i];
        }
        i += 1;
    }
    return false;
}

int _strtok(const char* s1, const char* tok) {
    int s1len = _strlen(s1);
    int toklen = _strlen(tok);
    for (int i = 0; i < s1len - toklen + 1; i++) {
        if (s1[i] == tok[0]) {
            int match_count = 1;
            for (int j = 1; j < toklen; j++) {
                if (s1[i + j] == tok[j]) {
                    match_count += 1;
                }
                else {
                    break;
                }
            }
            if (match_count == toklen) {
                return i;
            }
        }
    }
    return -1;
}

BOOL strcmpwi(const char* s1, wchar_t* ws2) {
    char* s2 = (char*)ws2;
    int i = 0;
    while (true) {
        unsigned char s1_c = s1[i];
        if (s1_c >= 'A' && s1_c <= 'Z')
            s1_c += 0x20;
        unsigned char s2_c = s2[i * 2];
        if (s2_c >= 'A' && s2_c <= 'Z')
            s2_c += 0x20;
        if (s1_c != s2_c) {
            return false;
        }
        if (s1_c == 0 || s2_c == 0) {
            return s1_c == s2_c;
        }
        i += 1;
    }
}

void _memcpy(void* dst, void* src, unsigned int cnt) {
    for (int i = 0; i < cnt; i++) {
        ((char*)dst)[i] = ((char*)src)[i];
    }
}