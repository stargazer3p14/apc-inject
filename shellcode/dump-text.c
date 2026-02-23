/*
 *	Dump .text section of a PE executable to a given file
 *
 *	Helper tool to create shellcode
 */

#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <errno.h>

#define PROG_NAME	"dump-text"

/*
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/

int main(int argc, char **argv)
{
	FILE *fin = NULL, *fout = NULL;
	long fsize = 0;
	unsigned char *buf = NULL;
	IMAGE_DOS_HEADER *dos_hdr = NULL;
	IMAGE_NT_HEADERS64 *nt_hdr = NULL;
	IMAGE_FILE_HEADER *ifh = NULL;
	IMAGE_OPTIONAL_HEADER64 *ioh64 = NULL;
	IMAGE_SECTION_HEADER *sectionHeader = NULL;
	IMAGE_SECTION_HEADER *importSection = NULL;
	void *text_raw_data = NULL;
	unsigned text_size = 0;
	unsigned __int64 sectionLocation = 0;
	DWORD sectionSize = 0;
	DWORD importDirectoryRVA = 0;

	if (argc < 3)
	{
		fprintf(stderr, "Usage:  %s exe_file dump_file\n", PROG_NAME);
		exit(-1);
	}

	if (!(fin = fopen(argv[1], "rb")))
	{
		fprintf(stderr, "Can't open input file '%s': %s (%d)\n", argv[1], strerror(errno), errno);
		exit(-1);
	}
	if (!(fout = fopen(argv[2], "wb")))
	{
		fprintf(stderr, "Can't open output file '%s': %s (%d)\n", argv[2], strerror(errno), errno);
		fclose(fin);
		exit(-1);
	}

	// Read entire file
	fseek(fin, 0, SEEK_END);
	fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	if (!(buf = malloc(fsize)))
	{
		fprintf(stderr, "Can't allocate %ld bytes for input file\n", fsize);
		fclose(fin);
		fclose(fout);
		exit(-1);
	}
	
	fread(buf, 1, fsize, fin);
	fclose(fin);

	dos_hdr = (IMAGE_DOS_HEADER*)buf;
	printf("[IMAGE_DOS_HEADER] e_magic = '%c%c', e_lfanew = %08X\n", dos_hdr->e_magic & 0xFF, dos_hdr->e_magic >> 8 & 0xFF, dos_hdr->e_lfanew);
	nt_hdr = (IMAGE_NT_HEADERS64*)(buf + dos_hdr->e_lfanew);
	printf("[IMAGE_NT_HEADERS64] Signature = '%s' (%08X)\n", (char*)&nt_hdr->Signature, nt_hdr->Signature);
	ifh = &nt_hdr->FileHeader;
	printf("[IMAGE_FILE_HEADER] Machine = %04X, NumberOfSections = %04X, SizeOfOptionalHeader = %04X\n", ifh->Machine, ifh->NumberOfSections, ifh->SizeOfOptionalHeader);
	ioh64 = (IMAGE_OPTIONAL_HEADER64*)((char*)ifh + ifh->SizeOfOptionalHeader);
	printf("[IMAGE_OPTIONAL_HEADER64] BaseOfCode = %08X\n", ioh64->BaseOfCode);

	sectionLocation = (unsigned __int64)nt_hdr + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)nt_hdr->FileHeader.SizeOfOptionalHeader;
	sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);
	
	// get offset to the import directory RVA
	importDirectoryRVA = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// print section data
	for (int i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++)
	{
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		printf("\t%s\n", sectionHeader->Name);
		printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
		printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
		printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
		printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
		printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}

		// Save .text's pointer
		if (!strcmp(sectionHeader->Name, ".text"))
		{
			text_raw_data = buf + sectionHeader->PointerToRawData;
			text_size = sectionHeader->SizeOfRawData;
		}
		
		sectionLocation += sectionSize;
	}

	// Dump .text's raw data to output file
	fwrite(text_raw_data, 1, text_size, fout);
	
	fclose(fout);
	
	return	0;
}
