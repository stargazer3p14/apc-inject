#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

/**
Source: MSDN

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
*/

/**
Source: MS COFF spec
*/

#pragma pack(1)

typedef struct _RELOC_REC
{
	DWORD VirtualAddress;
	DWORD SymbolTableIndex;
	WORD Type;
} RELOC_REC, *PRELOC_REC;

typedef struct _SYMTBL_REC
{
	char Name[8];
	DWORD Value;
	WORD SectionNumber;
	WORD Type;
	BYTE StorageClass;
	BYTE NumberOfAuxSymbols;
}SYMTBL_REC, *PSYMTBL_REC;


int coff_dump(unsigned char *obj_buf)
{
	IMAGE_FILE_HEADER *pifh;
	IMAGE_SECTION_HEADER *pish;
	unsigned long obj_offs;

	unsigned char *raw_data;

	struct _RELOC_REC *preloc;
	struct _SYMTBL_REC *psym;
	char *pstr_tbl;

	unsigned i;

//printf("%s()++++++++++++++++++++++++++++++++++++++++++\n", __func__);

	obj_offs = 0;
	pifh = (IMAGE_FILE_HEADER*)obj_buf;

	// Dump IMAGE_FILE_HEADER
	printf("IMAGE_FILE_HEADER:\n");
	printf("	Machine = %04hX\n", pifh->Machine);
	printf("	NumberOfSections = %04hX\n", pifh->NumberOfSections);
	printf("	TimeDateStamp = %08X\n", pifh->TimeDateStamp);
	printf("	PointerToSymbolTable = %08X\n", pifh->PointerToSymbolTable);
	printf("	NumberOfSymbols = %08X\n", pifh->NumberOfSymbols);
	printf("	SizeOfOptionalHeader = %04hX\n", pifh->SizeOfOptionalHeader);
	printf("	Characteristics = %04X\n", pifh->Characteristics);

	obj_offs += sizeof(*pifh);
	pish = (IMAGE_SECTION_HEADER*)(obj_buf + obj_offs);

	printf("\n");
	printf("Section Table:\n");

	for (i = 0; i < pifh->NumberOfSections; ++i)
	{
		unsigned char *praw_data;
		unsigned long raw_data_size;
		unsigned j;

		// Dump IMAGE_SECTION_HEADERs
		printf("IMAGE_SECTION_HEADER #%u:\n", i + 1);		// Section indexes are 1-based, so this is more informative
		printf("	Name = '%s'\n", (pish+i)->Name);	
		printf("	Misc.VirtualSize = %08X\n", (pish+i)->Misc.VirtualSize);
		printf("	VirtualAddress = %08X\n", (pish+i)->VirtualAddress);
		printf("	SizeOfRawData = %08X\n", (pish+i)->SizeOfRawData);
		printf("	PointerToRawData = %08X\n", (pish+i)->PointerToRawData);

		// Dump raw data
		praw_data = (unsigned char*)(obj_buf + (pish+i)->PointerToRawData);
		raw_data_size = (pish+i)->SizeOfRawData;
		if (raw_data_size)
		{
			printf("		");
			printf("%08X ", j);
			for (j = 0; j < raw_data_size; ++j)
			{
				printf("%02hhX ", praw_data[j]);
				if (j % 16 == 15)
				{
					printf("\n");
					printf("		");
					printf("%08X ", j);
				}
			}
			printf("\n");
			printf("[\n");

			printf("		");
			printf("%08X ", j);

			for (j = 0; j < raw_data_size; ++j)
			{
				printf("%c", (praw_data[j] >= ' ' && praw_data[j] <= 0x7F) ? praw_data[j] : '.');
				if (j % 16 == 15)
				{
					printf("\n");
					printf("		");
					printf("%08X ", j);
				}
			}
			printf("]\n");
			printf("\n");
		}

		printf("	PointerToRelocations = %08X\n", (pish+i)->PointerToRelocations);
		printf("	PointerToLinenumbers = %08X\n", (pish+i)->PointerToLinenumbers);
		printf("	NumberOfRelocations = %04hX\n", (pish+i)->NumberOfRelocations);
		printf("	NumberOfLinenumbers = %04hX\n", (pish+i)->NumberOfLinenumbers);

/**
typedef struct _RELOC_REC
{
	DWORD VirtualAddress;
	DWORD SymbolTableIndex;
	WORD Type;
} RELOC_REC, *PRELOC_REC;
*/
			
		preloc = (struct _RELOC_REC*)((obj_buf + (pish+i)->PointerToRelocations));

		printf("		Relocations raw dump:\n");
		printf("			");
		for(j = 0; j < (pish+i)->NumberOfRelocations * sizeof(RELOC_REC); ++j)
			printf("%02hhX ", *((unsigned char*)preloc + j));
		printf("\n");
		printf("\n");

		// Dump relocations. Line numbers ptr and number should be 0s, COFF debug info is not supported (and not interesting anyway)
		for(j = 0; j < (pish+i)->NumberOfRelocations; ++j)
		{
			printf("\n");
			printf("		Relocation:\n");	
			printf("			VirtualAddress = %08X\n", (preloc+j)->VirtualAddress);
			printf("			SymbolTableIndex = %08X\n", (preloc+j)->SymbolTableIndex);
			printf("			Type = %04hX\n", (preloc+j)->Type);
		}

		printf("	Characteristics = %08X\n", (pish+i)->Characteristics);

		// Dump Characteristics
		if ((pish+i)->Characteristics & IMAGE_SCN_CNT_CODE)
			printf("		IMAGE_SCN_CNT_CODE\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			printf("		IMAGE_SCN_CNT_INITIALIZED_DATA\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			printf("		IMAGE_SCN_CNT_UNINITIALIZED_DATA\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_LNK_INFO)
			printf("		IMAGE_SCN_LNK_INFO\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_LNK_REMOVE)
			printf("		IMAGE_SCN_LNK_REMOVE\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_LNK_COMDAT)
			printf("		IMAGE_SCN_LNK_COMDAT\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_GPREL)
			printf("		IMAGE_SCN_GPREL\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_GPREL)
			printf("		IMAGE_SCN_GPREL\n");
		if ((pish+i)->Characteristics & 0xF0000)
		{
			printf("		IMAGE_SCN_ALIGN_%uBYTES\n", (1 << ((pish+i)->Characteristics >> 16 & 0xF0000)) - 1);
			if (((pish+i)->Characteristics & 0xF0000) == 0xF0000)
				printf("			Bad value\n");
		}
		if ((pish+i)->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
			printf("		IMAGE_SCN_LNK_NRELOC_OVFL\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			printf("		IMAGE_SCN_MEM_DISCARDABLE\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			printf("		IMAGE_SCN_MEM_NOT_CACHED\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
			printf("		IMAGE_SCN_MEM_NOT_PAGED\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_MEM_SHARED)
			printf("		IMAGE_SCN_MEM_SHARED\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("		IMAGE_SCN_MEM_EXECUTE\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_MEM_READ)
			printf("		IMAGE_SCN_MEM_READ\n");
		if ((pish+i)->Characteristics & IMAGE_SCN_MEM_WRITE)
			printf("		IMAGE_SCN_MEM_WRITE\n");
	}

// Pointers to raw COFF data starting after headers. We apparently have nothing to do with them this way, only raw dump
// Everything interesting is reached with PointerTo... fields from headers
/*
	obj_offs += pifh->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	raw_data = obj_buf + obj_offs;
*/

	// Now we have raw data and can go on parse and get info from PointerTo... fields in headers
	
	// Dump symbol table (relocation tables are dumped in section headers parsing)
/**
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;			// !!
  DWORD NumberOfSymbols;				// !!
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/

/**
typedef struct _SYMTBL_REC
{
	char Name[8];
	DWORD Value;
	WORD SectionNumber;
	WORD Type;
	BYTE StorageClass;
	BYTE NumberOfAuxSymbols;
}SYMTBL_REC, *PSYMTBL_REC;
*/

	printf("\n");
	printf("Symbol Table:\n");
	printf("\n");

	psym = (struct _SYMTBL_REC*)(obj_buf + pifh->PointerToSymbolTable);
	pstr_tbl = (char*)(psym + pifh->NumberOfSymbols);

	for (i = 0; i < pifh->NumberOfSymbols; ++i)
	{
		char _name[9];
		BYTE byte_val;
		int j;

		// Table of Type values [Source: COFF spec]

		const char *type_vals[] =
		{
			"IMAGE_SYM_TYPE_NULL",
			"IMAGE_SYM_TYPE_VOID",
			"IMAGE_SYM_TYPE_CHAR",
			"IMAGE_SYM_TYPE_SHORT",
			"IMAGE_SYM_TYPE_INT",
			"IMAGE_SYM_TYPE_LONG",
			"IMAGE_SYM_TYPE_FLOAT",
			"IMAGE_SYM_TYPE_DOUBLE",
			"IMAGE_SYM_TYPE_STRUCT",
			"IMAGE_SYM_TYPE_UNION",
			"IMAGE_SYM_TYPE_ENUM",
			"IMAGE_SYM_TYPE_MOE",
			"IMAGE_SYM_TYPE_BYTE",
			"IMAGE_SYM_TYPE_WORD",
			"IMAGE_SYM_TYPE_UINT",
			"IMAGE_SYM_TYPE_DWORD"
		};
		const unsigned num_type_vals = sizeof(type_vals) / sizeof(type_vals[0]);

		const char *type_msb_vals[] =
		{
			"IMAGE_SYM_DTYPE_NULL",
			"IMAGE_SYM_DTYPE_POINTER",
			"IMAGE_SYM_DTYPE_FUNCTION",
			"IMAGE_SYM_DTYPE_ARRAY"
		};
		const unsigned num_type_msb_vals = sizeof(type_msb_vals) / sizeof(type_msb_vals[0]);

		struct _stor_class_val
		{
			BYTE val;
			const char *val_str;
		};

		const struct _stor_class_val stor_class_vals[] =
		{
			{
				IMAGE_SYM_CLASS_END_OF_FUNCTION,
				"IMAGE_SYM_CLASS_END_OF_FUNCTION"
			},
			{
				IMAGE_SYM_CLASS_NULL,
				"IMAGE_SYM_CLASS_NULL"
			},
			{
				IMAGE_SYM_CLASS_AUTOMATIC,
				"IMAGE_SYM_CLASS_AUTOMATIC"
			},
			{
				IMAGE_SYM_CLASS_EXTERNAL,
				"IMAGE_SYM_CLASS_EXTERNAL"
			},
			{
				IMAGE_SYM_CLASS_STATIC,
				"IMAGE_SYM_CLASS_STATIC"
			},
			{
				IMAGE_SYM_CLASS_REGISTER,
				"IMAGE_SYM_CLASS_REGISTER"
			},
			{
				IMAGE_SYM_CLASS_EXTERNAL_DEF,
				"IMAGE_SYM_CLASS_EXTERNAL_DEF"
			},
			{
				IMAGE_SYM_CLASS_LABEL,
				"IMAGE_SYM_CLASS_LABEL"
			},
			{
				IMAGE_SYM_CLASS_UNDEFINED_LABEL,
				"IMAGE_SYM_CLASS_UNDEFINED_LABEL"
			},
			{
				IMAGE_SYM_CLASS_MEMBER_OF_STRUCT,
				"IMAGE_SYM_CLASS_MEMBER_OF_STRUCT"
			},
			{
				IMAGE_SYM_CLASS_ARGUMENT,
				"IMAGE_SYM_CLASS_ARGUMENT"
			},
			{
				IMAGE_SYM_CLASS_STRUCT_TAG,
				"IMAGE_SYM_CLASS_STRUCT_TAG"
			},
			{
				IMAGE_SYM_CLASS_MEMBER_OF_UNION,
				"IMAGE_SYM_CLASS_MEMBER_OF_UNION"
			},
			{
				IMAGE_SYM_CLASS_UNION_TAG,
				"IMAGE_SYM_CLASS_UNION_TAG"
			},
			{
				IMAGE_SYM_CLASS_TYPE_DEFINITION,
				"IMAGE_SYM_CLASS_TYPE_DEFINITION",
			},
			{
				IMAGE_SYM_CLASS_UNDEFINED_STATIC,
				"IMAGE_SYM_CLASS_UNDEFINED_STATIC"
			},
			{
				IMAGE_SYM_CLASS_ENUM_TAG,
				"IMAGE_SYM_CLASS_ENUM_TAG"
			},
			{
				IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
				"IMAGE_SYM_CLASS_MEMBER_OF_ENUM"
			},
			{
				IMAGE_SYM_CLASS_REGISTER_PARAM,
				"IMAGE_SYM_CLASS_REGISTER_PARAM"
			},
			{
				IMAGE_SYM_CLASS_BIT_FIELD,
				"IMAGE_SYM_CLASS_BIT_FIELD"
			},
			{
				IMAGE_SYM_CLASS_BLOCK,
				"IMAGE_SYM_CLASS_BLOCK"
			},
			{
				IMAGE_SYM_CLASS_FUNCTION,
				"IMAGE_SYM_CLASS_FUNCTION"
			},
			{
				IMAGE_SYM_CLASS_END_OF_STRUCT,
				"IMAGE_SYM_CLASS_END_OF_STRUCT"
			},
			{
				IMAGE_SYM_CLASS_FILE,
				"IMAGE_SYM_CLASS_FILE"
			},
			{
				IMAGE_SYM_CLASS_SECTION,
				"IMAGE_SYM_CLASS_SECTION"
			},
			{
				IMAGE_SYM_CLASS_WEAK_EXTERNAL,
				"IMAGE_SYM_CLASS_WEAK_EXTERNAL"
			},
			{
				IMAGE_SYM_CLASS_CLR_TOKEN,
				"IMAGE_SYM_CLASS_CLR_TOKEN"
			}
		};
		const unsigned num_stor_class_vals = sizeof(stor_class_vals) / sizeof(stor_class_vals[0]);

		printf("SymRec #%u:\n", i);

		if (*(DWORD*)(psym+i)->Name != 0)
		{
			memcpy(_name, (psym+i)->Name, 8);
			_name[8] = '\0';
			printf("	Name = '%s' (%016llX)\n", _name, *(uint64_t*)(psym+i)->Name);
		}
		else
		{
			unsigned str_offs = *(DWORD*)((psym+i)->Name + 4);

			printf("[str_offs = %08X]\n", str_offs);
			printf("	Name = '%s'\n", pstr_tbl + str_offs);
		}
		printf("	Value = %08X\n", (psym+i)->Value);
		printf("	SectionNumber = %04hX\n", (psym+i)->SectionNumber);
		printf("	Type = %04hX	[", (psym+i)->Type);
		// Print LSB
		byte_val = (BYTE)(psym+i)->Type;
		if (byte_val > num_type_vals)
			printf("BAD");
		else
			printf("%s", type_vals[byte_val]);
		printf(", ");
		// Print MSB
		byte_val = (BYTE)((psym+i)->Type >> 8);
		if (byte_val > num_type_msb_vals)
			printf("BAD", byte_val);
		else
			printf("%s", type_msb_vals[byte_val]);
		printf("]\n");

		printf("	StorageClass = %02hhX	[", (psym+i)->StorageClass);
		for (j = 0; j < num_stor_class_vals; ++j)
		{
			if (stor_class_vals[j].val == (psym+i)->StorageClass)
			{
				printf("%s", stor_class_vals[j].val_str);
				break;
			}
		}

		if (j == num_stor_class_vals)
			printf("BAD");
		printf("]");
		
		// Print undefined external
		if ((psym+i)->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && !(psym+i)->SectionNumber)
			printf("[IMAGE_SYM_UNDEFINED]");

		printf("\n");
		
		printf("	NumberOfAuxSymbols = %02hhX\n", (psym+i)->NumberOfAuxSymbols);
		printf("\n");
	}

	return 0;
}


int main(int argc, char **argv)
{
	FILE *f;
	unsigned long fsize;
	unsigned char *obj_buf;

//printf("%s()++++++++++++++++++++++++++++++++++++++++++\n", __func__);

	// Params check
	if (argc < 2)
	{
		fprintf(stderr, "Usage:  %s <obj_file>\n", argv[0]);
		exit(-1);
	}

	// Open .obj
	f = fopen(argv[1], "rb");
	if (!f)
	{
		fprintf(stderr, "Can't open '%s': %s\n", argv[1], strerror(errno));
		exit(-1);
	}

	// Read entire file
	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	obj_buf = malloc(fsize);
	if (!obj_buf)
	{
		fprintf(stderr, "Can't allocate %lu bytes for '%s' contents\n", fsize, argv[1]);
		exit(-1);
	}
	fread(obj_buf, 1, fsize, f);
	fclose(f);

	coff_dump(obj_buf);

	return 0;
}
