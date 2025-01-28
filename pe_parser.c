// pe_parser_refactored.cpp
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pe_struct.h"

IMAGE_DOS_HEADER gDosHdr;
IMAGE_FILE_HEADER gFileHdr;

static void processFile(const char*);
static void parseDosHeader(FILE*);
static void parseDosStub(FILE*);
static void showAsciiStub(FILE*, long, long);
static void parseNtHeader(FILE*);
static char* convertTime(DWORD);

int main(int argc, char* argv[]) {
    if (argc != 3 || strcmp(argv[1], "-f") != 0) {
        fprintf(stderr, "Usage: %s -f <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    processFile(argv[2]);
    return EXIT_SUCCESS;
}

static void processFile(const char* path) {
    FILE* filePtr = NULL;
    errno_t err = fopen_s(&filePtr, path, "rb");
    if (err != 0 || filePtr == NULL) {
        perror("Error Message");
        return;
    }

    parseDosHeader(filePtr);
    parseDosStub(filePtr);
    parseNtHeader(filePtr);

    fclose(filePtr);
}

static void parseDosHeader(FILE* filePtr) {
    if (fread(&gDosHdr, sizeof(IMAGE_DOS_HEADER), 1, filePtr) != 1) {
        perror("Error Reading Dos Header : ");
        return;
    }

    if (gDosHdr.MZSignature != 0x5A4D) {
        printf("The file is not a PE file.\n");
        return;
    }

    printf("\n - Dos Header\n");
    printf("     - MZ Signature                : 0x%X\n", gDosHdr.MZSignature);
    printf("     - Address of New EXE Header   : 0x%lX\n", gDosHdr.AddressOfNewExeHeader);
}

static void parseDosStub(FILE* filePtr) {
    long stubPos = ftell(filePtr);
    long curPos = stubPos;
    if (stubPos == -1L) {
        perror("Error To Get Current File Position : ");
        return;
    }

    DWORD richId = 0;
    DWORD richChk = 0;
    DWORD val;

    while (curPos < gDosHdr.AddressOfNewExeHeader) {
        size_t readCount = fread(&val, sizeof(DWORD), 1, filePtr);
        if (readCount != 1) {
            break;
        }
        if (val == 0x68636952u) {
            richId = val;
            fread(&richChk, sizeof(DWORD), 1, filePtr);
            while (0 <= curPos - stubPos) {
                DWORD decoded;
                fseek(filePtr, curPos - sizeof(DWORD), SEEK_SET);
                fread(&decoded, sizeof(DWORD), 1, filePtr);
                decoded ^= richChk;
                if (decoded == 0x536E6144) {
                    break;
                }
                curPos -= sizeof(DWORD);
            }
            break;
        }
        curPos = ftell(filePtr);
    }

    if (richId != 0x68636952u) {
        printf("\n - Dos STUB\n");
        printf("     - Dos STUB (ASCII)        : ");
        showAsciiStub(filePtr, stubPos, gDosHdr.AddressOfNewExeHeader);
        printf("     - RICH Header Does Not Exist.\n");
        return;
    }

    long richPos = ftell(filePtr);
    printf("\n - Dos STUB\n");
    printf("     - Dos STUB (ASCII)            : ");
    showAsciiStub(filePtr, stubPos, richPos);
    printf("     - RICH Header Exists.\n");
}

static void showAsciiStub(FILE* filePtr, long start, long end) {
    fseek(filePtr, start, SEEK_SET);
    for (long i = start; i < end; i++) {
        unsigned char c;
        fread(&c, sizeof(unsigned char), 1, filePtr);
        if (isprint(c)) {
            putchar(c);
        }
    }
    printf("\n");
}

static void parseNtHeader(FILE* filePtr) {
    fseek(filePtr, gDosHdr.AddressOfNewExeHeader, SEEK_SET);
    DWORD ntSig;
    if (fread(&ntSig, sizeof(DWORD), 1, filePtr) != 1) {
        perror("Error reading NT header signature");
        return;
    }
    if (ntSig != 0x4550u) {
        printf("Invalid NT Header signature.\n");
        return;
    }

    printf("\n - NT Header\n");
    printf("     - Signature                   : 0x50450000 ('PE  ')\n");

    if (fread(&gFileHdr, sizeof(IMAGE_FILE_HEADER), 1, filePtr) != 1) {
        perror("Error reading file header of NT header");
        return;
    }

    printf("     - File Header\n");
    printf("         - Machine                 : 0x%s\n", getMachineName(gFileHdr.Machine));
    printf("         - Number of Sections      : 0x%X\n", gFileHdr.NumberOfSections);
    printf("         - TimeDateStamp           : %s\n", convertTime(gFileHdr.TimeDateStamp));
    printf("         - PointerToSymbolTable    : 0x%X\n", gFileHdr.PointerToSymbolTable);
    printf("         - NumberOfSymbols         : 0x%X\n", gFileHdr.NumberOfSymbols);
    printf("         - Size of Optional Header : 0x%X\n", gFileHdr.SizeOfOptionalHeader);
    printf("         - Characteristics         : 0x%X\n", gFileHdr.Characteristics);
    showFileCharacteristics(gFileHdr.Characteristics);
}

static char* convertTime(DWORD t) {
    static char buf[20];
    time_t raw = (time_t)(uint32_t)t;
    struct tm tmData;
    if (gmtime_s(&tmData, &raw) == 0) {
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmData);
    }
    else {
        snprintf(buf, sizeof(buf), "Invalid Time");
    }
    return buf;
}
