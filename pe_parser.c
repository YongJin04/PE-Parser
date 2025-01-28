#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pe_struct.h"

void readFile(const char*);
void readDosHeader(FILE*, IMAGE_DOS_HEADER*);
void readDosStub(FILE*, const IMAGE_DOS_HEADER*);
void printAsciiFromDosStub(FILE*, long, long);

int main(int argc, char* argv[]) {
    if (argc != 3 || strcmp(argv[1], "-f") != 0) {
        fprintf(stderr, "Usage: %s -f <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    readFile(argv[2]);
    return EXIT_SUCCESS;
}

void readFile(const char* peFilePath) {
    FILE* peFile = NULL;
    errno_t err = fopen_s(&peFile, peFilePath, "rb");
    if (err != 0 || peFile == NULL) {
        perror("Error Message");
        return;
    }

    IMAGE_DOS_HEADER dosHeader;
    readDosHeader(peFile, &dosHeader);
    readDosStub(peFile, &dosHeader);

    fclose(peFile);
}

void readDosHeader(FILE* peFile, IMAGE_DOS_HEADER* dosHeader) {
    if (fread(dosHeader, sizeof(IMAGE_DOS_HEADER), 1, peFile) != 1) {
        perror("Error Reading Dos Header : ");
        return;
    }

    if (dosHeader->MZSignature != 0x5A4D) {
        printf("The file is not a PE file.\n");
        return;
    }

    printf("\n - Dos Header\n");
    printf("     - MZ Signature              : 0x%X\n", dosHeader->MZSignature);
    printf("     - Address of New EXE Header : 0x%lX\n", dosHeader->AddressOfNewExeHeader);
}

void readDosStub(FILE* peFile, const IMAGE_DOS_HEADER* dosHeader) {
    long dosStubPos = ftell(peFile);
    if (dosStubPos == -1L) {
        perror("Error To Get Current File Position : ");
        return;
    }

    long currentPos = dosStubPos;
    DWORD richIdentifier = 0;
    DWORD richChecksum = 0;
    DWORD value;

    while (currentPos < dosHeader->AddressOfNewExeHeader) {
        size_t bytesRead = fread(&value, sizeof(DWORD), 1, peFile);
        if (bytesRead != 1) {
            break;
        }

        if (value == 0x68636952u) {
            richIdentifier = value;
            fread(&richChecksum, sizeof(DWORD), 1, peFile);

            while (0 <= currentPos - dosStubPos) {
                DWORD decodedValue;
                fseek(peFile, currentPos - sizeof(DWORD), SEEK_SET);
                fread(&decodedValue, sizeof(DWORD), 1, peFile);
                decodedValue ^= richChecksum;

                if (decodedValue == 0x536E6144) {
                    break;
                }

                currentPos -= sizeof(DWORD);
            }
            break;
        }
        currentPos = ftell(peFile);
    }

    if (richIdentifier != 0x68636952u) {
        printf("\n - Dos Header\n");
        printf("     - Dos STUB (ASCII) : ");
        printAsciiFromDosStub(peFile, dosStubPos, dosHeader->AddressOfNewExeHeader);
        printf("     - RICH Header Does Not Exist.\n");
        return;
    }

    long richHeaderPos = ftell(peFile);
    printf("\n - Dos Header\n");
    printf("     - Dos STUB (ASCII) : ");
    printAsciiFromDosStub(peFile, dosStubPos, richHeaderPos);
    printf("     - RICH Header Exists.\n");
}

void printAsciiFromDosStub(FILE* peFile, long startPoint, long endPoint) {
    fseek(peFile, startPoint, SEEK_SET);
    for (long i = startPoint; i < endPoint; i++) {
        unsigned char c;
        fread(&c, sizeof(unsigned char), 1, peFile);
        if (isprint(c)) {
            putchar(c);
        }
    }
    printf("\n");
}
