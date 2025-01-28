#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pe_struct.h"

IMAGE_DOS_HEADER dosHeader;

void readFile(const char*);
void readDosHeader(FILE*);
void readDosStub(FILE*);
void printAsciiFromDosStub(FILE*, long, long);

void readFile(const char* peFilePath) {
    FILE* peFile = NULL;
    errno_t err = fopen_s(&peFile, peFilePath, "rb");

    if (err != 0 || peFile == NULL) {
        perror("Error Message");
        return;
    }

    // Read Dos Header
    readDosHeader(peFile);

    // Read Dos STUB
    readDosStub(peFile);


    fclose(peFile);
}

void readDosHeader(FILE* peFile) {
    if (fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, peFile) != 1) {
        perror("Error Reading Dos Header : ");
        return;
    }

    if (dosHeader.MZSignature != 0x5A4D) {  // Compair PE Signature ('0x5A4D' / MZ)
        printf("The file is not a PE file.\n");
        return;
    }

    printf(" - Dos Header\n");
    printf("     - MZ Signature              : 0x%X\n", dosHeader.MZSignature);
    printf("     - Address of New EXE Header : 0x%lX\n", dosHeader.AddressOfNewExeHeader);
}

void readDosStub(FILE* peFile) {
    long dosStubPos = ftell(peFile);
    long currentPos = dosStubPos;

    if (dosStubPos == -1L) {
        perror("Error To Get Current File Position : ");
        return;
    }

    DWORD richIdentifier = 0;
    DWORD richChecksum = 0;

    DWORD value;
    while (currentPos < dosHeader.AddressOfNewExeHeader) {
        size_t bytesRead = fread(&value, sizeof(DWORD), 1, peFile);

        if (bytesRead != 1) {
            break;
        }

        // Find RICH Header
        if (value == 0x68636952u) {
            richIdentifier = value;

            fread(&richChecksum, sizeof(DWORD), 1, peFile);  // Store RICH Header Checksum
            
            while (0 <= currentPos - dosStubPos) {
                DWORD decodedValue;
                fseek(peFile, currentPos - sizeof(DWORD), SEEK_SET);  // Roll Back
                fread(&decodedValue, sizeof(DWORD), 1, peFile);

                decodedValue ^= richChecksum; // XOR

                // Find DanS Header
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
        printf(" - Dos Header\n");
        printf("     - Dos STUB (ASCII) : ");
        printAsciiFromDosStub(peFile, dosStubPos, dosHeader.AddressOfNewExeHeader);
        printf("     - RICH Header Does Not Exist.\n");
        return;
    }

    long richHeaderPos = ftell(peFile);
    printf(" - Dos Header\n");
    printf("     - Dos STUB (ASCII) : ");
    printAsciiFromDosStub(peFile, dosStubPos, richHeaderPos);
    printf("     - RICH Header Exists.\n");
}

void printAsciiFromDosStub(FILE* peFile, long startPoint, long endPoint) {
    fseek(peFile, startPoint, SEEK_SET);

    // Print Dos STUB Information Format By ASCII
    for (long i = startPoint; i < endPoint; i++) {
        unsigned char c;
        fread(&c, sizeof(unsigned char), 1, peFile);
        if (isprint(c)) {  // Check If The Character Is Printable ASCII
            putchar(c);
        }
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 3 || strcmp(argv[1], "-f") != 0) {
        fprintf(stderr, "Usage: %s -f <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    readFile(argv[2]);
    return EXIT_SUCCESS;
}
