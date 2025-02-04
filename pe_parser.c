#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pe_struct.h"

IMAGE_DOS_HEADER gDosHdr;
IMAGE_FILE_HEADER gFileHdr;
IMAGE_OPTIONAL_HEADER32 gOptionalHdr32;
IMAGE_OPTIONAL_HEADER64 gOptionalHdr64;
IMAGE_DATA_DIRECTORY gDataDirectory[16];
IMAGE_SECTION_HEADER* gSectionHeaders = NULL;
IMAGE_IMPORT_DESCRIPTOR gImportDescriptor;
IMAGE_EXPORT_DIRECTORY gExportDirectory;

static void processFile(const char*);
static void parseDosHeader(FILE*);
static void parseDosStub(FILE*);
static void showAsciiStub(FILE*, long, long);
static void parseNtHeader(FILE*);
static char* convertTime(DWORD);
static void parseSectionHeader(FILE*);
static void parseSection(FILE*);
static void parseImportAddressTable32(FILE*);
static void parseImportAddressTable64(FILE*);
static void parseExportAddressTable32(FILE*);
static void parseExportAddressTable64(FILE*);
char* readNullTerminatedString(FILE*);

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
    parseSectionHeader(filePtr);

    parseSection(filePtr);

    free(gSectionHeaders);
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
    printf("     - MZ Signature                  : 0x%X\n", gDosHdr.MZSignature);
    printf("     - Address of New EXE Header     : 0x%lX\n", (unsigned long)gDosHdr.AddressOfNewExeHeader);
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

    while (curPos < (long)gDosHdr.AddressOfNewExeHeader) {
        size_t readCount = fread(&val, sizeof(DWORD), 1, filePtr);
        if (readCount != 1) {
            break;
        }
        if (val == 0x68636952u) {
            richId = val;
            fread(&richChk, sizeof(DWORD), 1, filePtr);
            while (0 <= curPos - stubPos) {
                DWORD decoded;
                fseek(filePtr, curPos - (long)sizeof(DWORD), SEEK_SET);
                fread(&decoded, sizeof(DWORD), 1, filePtr);
                decoded ^= richChk;
                if (decoded == 0x536E6144) {
                    break;
                }
                curPos -= (long)sizeof(DWORD);
            }
            break;
        }
        curPos = ftell(filePtr);
    }

    if (richId != 0x68636952u) {
        printf("\n - Dos STUB\n");
        printf("     - Dos STUB (ASCII)          : ");
        showAsciiStub(filePtr, stubPos, (long)gDosHdr.AddressOfNewExeHeader);
        printf("     - RICH Header Does Not Exist.\n");
        return;
    }

    long richPos = ftell(filePtr);
    printf("\n - Dos STUB\n");
    printf("     - Dos STUB (ASCII)              : ");
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
    printf("     - Signature                     : 0x50450000 ('PE  ')\n");

    if (fread(&gFileHdr, sizeof(IMAGE_FILE_HEADER), 1, filePtr) != 1) {
        perror("Error reading file header of NT header");
        return;
    }

    printf("     - File Header\n");
    printf("         - Machine                   : 0x%s\n", getMachineName(gFileHdr.Machine));
    printf("         - Number of Sections        : 0x%X\n", gFileHdr.NumberOfSections);
    printf("         - Time DateStamp            : %s\n", convertTime(gFileHdr.TimeDateStamp));
    printf("         - Pointer To SymbolTable    : 0x%X\n", gFileHdr.PointerToSymbolTable);
    printf("         - Number Of Symbols         : 0x%X\n", gFileHdr.NumberOfSymbols);
    printf("         - Size of Optional Header   : 0x%X\n", gFileHdr.SizeOfOptionalHeader);
    printf("         - Characteristics           : 0x%X\n", gFileHdr.Characteristics);
    showFileCharacteristics(gFileHdr.Characteristics);

    printf("     - Optional Header\n");
    WORD optionalHeaderSignature;
    if (fread(&optionalHeaderSignature, sizeof(WORD), 1, filePtr) != 1) {
        perror("Error reading Optional Header Signature of NT header");
        return;
    }
    fseek(filePtr, -static_cast<long>(sizeof(WORD)), SEEK_CUR);
    if (optionalHeaderSignature == 0x010B) {
        if (fread(&gOptionalHdr32, sizeof(IMAGE_OPTIONAL_HEADER32), 1, filePtr) != 1) {
            perror("Error reading Optional Header x86 Signature of NT header");
            return;
        }
        
        printf("         - Optional Header Signature : 0x%X (%s)\n", gOptionalHdr32.Magic, getOptionalMagicName(gOptionalHdr32.Magic));
        printf("         - Major Linker Version      : 0x%X\n", gOptionalHdr32.MajorLinkerVersion);
        printf("         - Minor Linker Version      : 0x%X\n", gOptionalHdr32.MinorLinkerVersion);
        printf("         - Size Of Code              : 0x%X\n", gOptionalHdr32.SizeOfCode);
        printf("         - Size Of Initialized Data  : 0x%X\n", gOptionalHdr32.SizeOfInitializedData);
        printf("         - Size Of Uninitialized Data: 0x%X\n", gOptionalHdr32.SizeOfUninitializedData);
        printf("         - Address Of Entry Point    : 0x%X\n", gOptionalHdr32.AddressOfEntryPoint);
        printf("         - Base Of Code              : 0x%X\n", gOptionalHdr32.BaseOfCode);
        printf("         - Base Of Data              : 0x%X\n", gOptionalHdr32.BaseOfData);
        printf("         - Image Base                : 0x%X\n", gOptionalHdr32.ImageBase);
        printf("         - Section Alignment         : 0x%X\n", gOptionalHdr32.SectionAlignment);
        printf("         - File Alignment            : 0x%X\n", gOptionalHdr32.FileAlignment);
        printf("         - Major OS Version          : 0x%X\n", gOptionalHdr32.MajorOperatingSystemVersion);
        printf("         - Minor OS Version          : 0x%X\n", gOptionalHdr32.MinorOperatingSystemVersion);
        printf("         - Major Image Version       : 0x%X\n", gOptionalHdr32.MajorImageVersion);
        printf("         - Minor Image Version       : 0x%X\n", gOptionalHdr32.MinorImageVersion);
        printf("         - Major Subsystem Version   : 0x%X\n", gOptionalHdr32.MajorSubsystemVersion);
        printf("         - Minor Subsystem Version   : 0x%X\n", gOptionalHdr32.MinorSubsystemVersion);
        printf("         - Win32 Version Value       : 0x%X\n", gOptionalHdr32.Win32VersionValue);
        printf("         - Size Of Image             : 0x%X\n", gOptionalHdr32.SizeOfImage);
        printf("         - Size Of Headers           : 0x%X\n", gOptionalHdr32.SizeOfHeaders);
        printf("         - Check Sum                 : 0x%X\n", gOptionalHdr32.CheckSum);
        printf("         - Subsystem                 : 0x%X (%s)\n", gOptionalHdr32.Subsystem, getImageSubsystemName(gOptionalHdr32.Subsystem));
        printf("         - Dll Characteristics       : 0x%X\n", gOptionalHdr32.DllCharacteristics);
        showDllCharacteristics(gOptionalHdr32.DllCharacteristics);
        printf("         - Size Of Stack Reserve     : 0x%X\n", gOptionalHdr32.SizeOfStackReserve);
        printf("         - Size Of Stack Commit      : 0x%X\n", gOptionalHdr32.SizeOfStackCommit);
        printf("         - Size Of Heap Reserve      : 0x%X\n", gOptionalHdr32.SizeOfHeapReserve);
        printf("         - Size Of Heap Commit       : 0x%X\n", gOptionalHdr32.SizeOfHeapCommit);
        printf("         - Loader Flags              : 0x%X\n", gOptionalHdr32.LoaderFlags);
        printf("         - Number Of RVA And Sizes   : 0x%X\n", gOptionalHdr32.NumberOfRvaAndSizes);
        printf("         - Data Directory\n");
        for (DWORD i = 0; i < gOptionalHdr32.NumberOfRvaAndSizes; i++) {
            if (fread(&gDataDirectory[i], sizeof(IMAGE_DATA_DIRECTORY), 1, filePtr) != 1) {
                perror("Error Reading Dos Header : ");
                break;
            }
            if (gDataDirectory[i].VirtualAddress != 0x00000000) {
                printf("             - %s (RVA : 0x%X / Virtual Size : 0x%X)\n", directoryNames[i], gDataDirectory[i].VirtualAddress, gDataDirectory[i].Size);
            }
        }
    }
    else if (optionalHeaderSignature == 0x020B) {
        if (fread(&gOptionalHdr64, sizeof(IMAGE_OPTIONAL_HEADER64), 1, filePtr) != 1) {
            perror("Error reading Optional Header x86-64 Signature of NT header");
            return;
        }

        printf("         - Optional Header Signature : 0x%X (%s)\n", gOptionalHdr64.Magic, getOptionalMagicName(gOptionalHdr64.Magic));
        printf("         - Major Linker Version      : 0x%X\n", gOptionalHdr64.MajorLinkerVersion);
        printf("         - Minor Linker Version      : 0x%X\n", gOptionalHdr64.MinorLinkerVersion);
        printf("         - Size Of Code              : 0x%X\n", gOptionalHdr64.SizeOfCode);
        printf("         - Size Of Initialized Data  : 0x%X\n", gOptionalHdr64.SizeOfInitializedData);
        printf("         - Size Of Uninitialized Data: 0x%X\n", gOptionalHdr64.SizeOfUninitializedData);
        printf("         - Address Of Entry Point    : 0x%X\n", gOptionalHdr64.AddressOfEntryPoint);
        printf("         - Base Of Code              : 0x%X\n", gOptionalHdr64.BaseOfCode);
        printf("         - Image Base                : 0x%llX\n", gOptionalHdr64.ImageBase);
        printf("         - Section Alignment         : 0x%X\n", gOptionalHdr64.SectionAlignment);
        printf("         - File Alignment            : 0x%X\n", gOptionalHdr64.FileAlignment);
        printf("         - Major OS Version          : 0x%X\n", gOptionalHdr64.MajorOperatingSystemVersion);
        printf("         - Minor OS Version          : 0x%X\n", gOptionalHdr64.MinorOperatingSystemVersion);
        printf("         - Major Image Version       : 0x%X\n", gOptionalHdr64.MajorImageVersion);
        printf("         - Minor Image Version       : 0x%X\n", gOptionalHdr64.MinorImageVersion);
        printf("         - Major Subsystem Version   : 0x%X\n", gOptionalHdr64.MajorSubsystemVersion);
        printf("         - Minor Subsystem Version   : 0x%X\n", gOptionalHdr64.MinorSubsystemVersion);
        printf("         - Win32 Version Value       : 0x%X\n", gOptionalHdr64.Win32VersionValue);
        printf("         - Size Of Image             : 0x%X\n", gOptionalHdr64.SizeOfImage);
        printf("         - Size Of Headers           : 0x%X\n", gOptionalHdr64.SizeOfHeaders);
        printf("         - Check Sum                 : 0x%X\n", gOptionalHdr64.CheckSum);
        printf("         - Subsystem                 : 0x%X (%s)\n", gOptionalHdr64.Subsystem, getImageSubsystemName(gOptionalHdr64.Subsystem));
        printf("         - Dll Characteristics       : 0x%X\n", gOptionalHdr64.DllCharacteristics);
        showDllCharacteristics(gOptionalHdr64.DllCharacteristics);
        printf("         - Size Of Stack Reserve     : 0x%llX\n", gOptionalHdr64.SizeOfStackReserve);
        printf("         - Size Of Stack Commit      : 0x%llX\n", gOptionalHdr64.SizeOfStackCommit);
        printf("         - Size Of Heap Reserve      : 0x%llX\n", gOptionalHdr64.SizeOfHeapReserve);
        printf("         - Size Of Heap Commit       : 0x%llX\n", gOptionalHdr64.SizeOfHeapCommit);
        printf("         - Loader Flags              : 0x%X\n", gOptionalHdr64.LoaderFlags);
        printf("         - Number Of RVA And Sizes   : 0x%X\n", gOptionalHdr64.NumberOfRvaAndSizes);
        printf("         - Data Directory\n");
        for (DWORD i = 0; i < gOptionalHdr64.NumberOfRvaAndSizes; i++) {
            if (fread(&gDataDirectory[i], sizeof(IMAGE_DATA_DIRECTORY), 1, filePtr) != 1) {
                perror("Error Reading Dos Header : ");
                break;
            }
            if (gDataDirectory[i].VirtualAddress != 0x00000000) {
                printf("             - %s (RVA : 0x%X / Virtual Size : 0x%X)\n", directoryNames[i], gDataDirectory[i].VirtualAddress, gDataDirectory[i].Size);
            }
        }
    }
}

static void parseSectionHeader(FILE* filePtr) {
    printf("\n - Section Header\n");

    gSectionHeaders = (IMAGE_SECTION_HEADER*)malloc(gFileHdr.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (gSectionHeaders == NULL) {
        perror("Memory allocation failed for section headers");
        return;
    }

    for (int i = 0; i < gFileHdr.NumberOfSections; i++) {
        if (fread(&gSectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), 1, filePtr) != 1) {
            perror("Error Reading Section Header");
            free(gSectionHeaders);
            gSectionHeaders = NULL;
            return;
        }

        printf("     - Name                          : %.8s\n", gSectionHeaders[i].Name);
        printf("     - Virtual Size                  : 0x%X\n", gSectionHeaders[i].VirtualSize);
        printf("     - Virtual Address               : 0x%X\n", gSectionHeaders[i].VirtualAddress);
        printf("     - Size of Raw Data              : 0x%X\n", gSectionHeaders[i].SizeOfRawData);
        printf("     - Pointer to Raw Data           : 0x%X\n", gSectionHeaders[i].PointerToRawData);
        printf("     - Pointer to Relocations        : 0x%X\n", gSectionHeaders[i].PointerToRelocations);
        printf("     - Pointer to Line Numbers       : 0x%X\n", gSectionHeaders[i].PointerToLinenumbers);
        printf("     - Number of Relocations         : 0x%X\n", gSectionHeaders[i].NumberOfRelocations);
        printf("     - Number of Line Numbers        : 0x%X\n", gSectionHeaders[i].NumberOfLinenumbers);
        printf("     - Characteristics               : 0x%X\n", gSectionHeaders[i].Characteristics);
        showSectionCharacteristics(gSectionHeaders[i].Characteristics);
        printf("\n");
    }
}

static void parseSection(FILE* filePtr) {
    printf(" - Section\n");

    // IAT Parsing
    if (gOptionalHdr32.Magic == 0x010B) {
        parseImportAddressTable32(filePtr);
        parseExportAddressTable32(filePtr);
    }
    else if (gOptionalHdr64.Magic == 0x020B) {
        parseImportAddressTable64(filePtr);
        parseExportAddressTable64(filePtr);
    }
}

static void parseImportAddressTable32(FILE* filePtr) {
    for (int i = 0; i < gFileHdr.NumberOfSections; i++) {
        if ((gSectionHeaders[i].VirtualAddress <= gDataDirectory[12].VirtualAddress) && (gDataDirectory[12].VirtualAddress < gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].VirtualSize)) {
            printf("     - %.8s\n", gSectionHeaders[i].Name);
            printf("         - Import Descriptor\n");

            QWORD current_point = gSectionHeaders[i].PointerToRawData + gDataDirectory[12].Size;
            while (1) {
                fseek(filePtr, current_point, SEEK_SET);
                if (fread(&gImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, filePtr) != 1) {
                    perror("Error Import Descriptorr");
                    return;
                }

                current_point = ftell(filePtr);
                if (gImportDescriptor.OriginalFirstThunk == 0x00000000) {
                    break;
                }

                fseek(filePtr, (gImportDescriptor.Name - gSectionHeaders[i].VirtualAddress) + gSectionHeaders[i].PointerToRawData, SEEK_SET);
                char* name = readNullTerminatedString(filePtr);
                printf("             - DLL Name : %s\n", name);

                QWORD current_point_1 = (gImportDescriptor.FirstThunk - gSectionHeaders[i].VirtualAddress) + gSectionHeaders[i].PointerToRawData;
                while (1) {
                    fseek(filePtr, current_point_1, SEEK_SET);
                    DWORD temp_ptr;
                    if (fread(&temp_ptr, sizeof(DWORD), 1, filePtr) != 1) {
                        perror("Error Import Descriptorr");
                        return;
                    }

                    current_point_1 = ftell(filePtr);
                    if (temp_ptr == 0x00000000) {
                        break;
                    }

                    fseek(filePtr, (temp_ptr - gSectionHeaders[i].VirtualAddress) + gSectionHeaders[i].PointerToRawData + 0x02, SEEK_SET);
                    char* name = readNullTerminatedString(filePtr);
                    printf("                 - Import Symbol Name : %s\n", name);
                }
                printf("\n");
            }
            break;
        }
    }
}

static void parseImportAddressTable64(FILE* filePtr) {
    for (int i = 0; i < gFileHdr.NumberOfSections; i++) {
        if ((gSectionHeaders[i].VirtualAddress <= gDataDirectory[12].VirtualAddress) && (gDataDirectory[12].VirtualAddress < gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].VirtualSize)) {
            printf("     - %.8s\n", gSectionHeaders[i].Name);
            printf("         - Import Descriptor\n");

            QWORD current_point = gSectionHeaders[i].PointerToRawData + gDataDirectory[12].Size;
            while (1) {
                fseek(filePtr, current_point, SEEK_SET);
                if (fread(&gImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, filePtr) != 1) {
                    perror("Error Import Descriptorr");
                    return;
                }

                current_point = ftell(filePtr);
                if (gImportDescriptor.OriginalFirstThunk == 0x0000000000000000) {
                    break;
                }

                fseek(filePtr, (gImportDescriptor.Name - gSectionHeaders[i].VirtualAddress) + gSectionHeaders[i].PointerToRawData, SEEK_SET);
                char* name = readNullTerminatedString(filePtr);
                printf("             - DLL Name : %s\n", name);

                QWORD current_point_1 = (gImportDescriptor.FirstThunk - gSectionHeaders[i].VirtualAddress) + gSectionHeaders[i].PointerToRawData;
                while (1) {
                    fseek(filePtr, current_point_1, SEEK_SET);
                    QWORD temp_ptr;
                    if (fread(&temp_ptr, sizeof(QWORD), 1, filePtr) != 1) {
                        perror("Error Import Descriptorr");
                        return;
                    }

                    current_point_1 = ftell(filePtr);
                    if (temp_ptr == 0x00000000) {
                        break;
                    }

                    fseek(filePtr, (temp_ptr - gSectionHeaders[i].VirtualAddress) + gSectionHeaders[i].PointerToRawData + 0x02, SEEK_SET);
                    char* name = readNullTerminatedString(filePtr);
                    printf("                 - Import Symbol Name : %s\n", name);
                }
                printf("\n");
            }
            break;
        }
    }
}

static void parseExportAddressTable32(FILE* filePtr) {
    for (int i = 0; i < gFileHdr.NumberOfSections; i++) {
        if ((gSectionHeaders[i].VirtualAddress <= gDataDirectory[0].VirtualAddress) && (gDataDirectory[0].VirtualAddress < gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].VirtualSize)) {
            printf("     - %.8s\n", gSectionHeaders[i].Name);
            printf("         - Export Descriptor\n");

            QWORD current_point = gDataDirectory[0].VirtualAddress - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData;

            fseek(filePtr, current_point, SEEK_SET);
            if (fread(&gExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), 1, filePtr) != 1) {
                perror("Error Export Directory");
                return;
            }

            current_point = gExportDirectory.Name - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData;
            fseek(filePtr, current_point, SEEK_SET);
            char* name = readNullTerminatedString(filePtr);
            printf("             - DLL Name : %s\n", name);

            QWORD current_point_1 = gExportDirectory.AddressOfNames - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData;
            fseek(filePtr, current_point_1, SEEK_SET);
            for (int j = 0; j < gExportDirectory.NumberOfNames;j++) {
                fseek(filePtr, current_point_1, SEEK_SET);
                DWORD temp_ptr;
                if (fread(&temp_ptr, sizeof(DWORD), 1, filePtr) != 1) {
                    perror("Error Import Descriptorr");
                    return;
                }
                current_point_1 = ftell(filePtr);

                fseek(filePtr, temp_ptr - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData, SEEK_SET);
                char* name = readNullTerminatedString(filePtr);
                printf("                 - Export Symbol Name : %s\n", name);
            }
            printf("\n");
        }
    }
}

static void parseExportAddressTable64(FILE* filePtr) {
    for (int i = 0; i < gFileHdr.NumberOfSections; i++) {
        if ((gSectionHeaders[i].VirtualAddress <= gDataDirectory[0].VirtualAddress) && (gDataDirectory[0].VirtualAddress < gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].VirtualSize)) {
            printf("     - %.8s\n", gSectionHeaders[i].Name);
            printf("         - Export Descriptor\n");

            QWORD current_point = gDataDirectory[0].VirtualAddress - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData;

            fseek(filePtr, current_point, SEEK_SET);
            if (fread(&gExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), 1, filePtr) != 1) {
                perror("Error Export Directory");
                return;
            }

            current_point = gExportDirectory.Name - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData;
            fseek(filePtr, current_point, SEEK_SET);
            char* name = readNullTerminatedString(filePtr);
            printf("             - DLL Name : %s\n", name);

            QWORD current_point_1 = gExportDirectory.AddressOfNames - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData;
            fseek(filePtr, current_point_1, SEEK_SET);
            for (int j = 0; j < gExportDirectory.NumberOfNames;j++) {
                fseek(filePtr, current_point_1, SEEK_SET);
                DWORD temp_ptr;
                if (fread(&temp_ptr, sizeof(DWORD), 1, filePtr) != 1) {
                    perror("Error Import Descriptorr");
                    return;
                }
                current_point_1 = ftell(filePtr);

                fseek(filePtr, temp_ptr - gSectionHeaders[i].VirtualAddress + gSectionHeaders[i].PointerToRawData, SEEK_SET);
                char* name = readNullTerminatedString(filePtr);
                printf("                 - Export Symbol Name : %s\n", name);
            }
            printf("\n");
        }
    }
}

char* readNullTerminatedString(FILE* filePtr) {
    char* name = NULL;
    size_t length = 0;
    char ch;

    while (fread(&ch, 1, 1, filePtr) == 1 && ch != '\0') {
        char* temp = (char*)realloc(name, length + 2);
        if (!temp) {
            free(name);
            return NULL;
        }
        name = temp;
        name[length++] = ch;
    }

    if (name) {
        name[length] = '\0';
    }

    return name;
}
