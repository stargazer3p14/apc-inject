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

// 
// imp_plug and imp_plug_size are defined in coff-run-helper.asm, intended to resolve static unresolved externals
//
extern void imp_plug(void);
extern DWORD imp_plug_size;
extern DWORD imp_plug_addr_offs;

unsigned char *imp_area;
unsigned imp_area_offs;

unsigned char *imp_addrs;
unsigned imp_addrs_offs;

struct _resolved_local
{
	char *name;
	void *addr;
};

struct _resolved_local resolved_locals[] =
{
	{"printf", printf}
};

const unsigned num_resolved_locals = sizeof(resolved_locals) / sizeof(resolved_locals[0]);

typedef 
int (*MessageBoxA_t)(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

//int (*entry_point)();
MessageBoxA_t entry_point;
int (*start)();

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


int coff_run(unsigned char *obj_buf, DWORD obj_size)
{
	IMAGE_FILE_HEADER *pifh;
	IMAGE_SECTION_HEADER *pish;
	unsigned long obj_offs;

	unsigned char *raw_data;

	struct _RELOC_REC *preloc;
	struct _SYMTBL_REC *psym;
	char *pstr_tbl;

	unsigned i;

	// Start address of array of imp addresses
	imp_addrs = obj_buf + obj_size + 0x1000;

	// Start area of our external plugs
	imp_area = obj_buf + obj_size + 0x2000;

	int dont_run = 0;						// Indicates that something went wrong during processing, won't run this object
	int sect_idx = -1;

	// Set up necessary ponters

	obj_offs = 0;
	pifh = (IMAGE_FILE_HEADER*)obj_buf;

	obj_offs += sizeof(*pifh);
	pish = (IMAGE_SECTION_HEADER*)(obj_buf + obj_offs);

	psym = (struct _SYMTBL_REC*)(obj_buf + pifh->PointerToSymbolTable);
	pstr_tbl = (char*)(psym + pifh->NumberOfSymbols);

	// Dump all relocations in .text section. We will need to resolve them
	// For now we don't care about relocs in .data (like errno). FWIW except for errno there will be not much to do to resolve - libs don't usually have public variables and other objects we assume that we don't have. For errno we may add handling

	for (i = 0; i < pifh->NumberOfSections; ++i)
	{
		unsigned char *praw_data;
		unsigned long raw_data_size;
		unsigned j;

		// Skip not interesting ections (not code)
		// (!) Actually COFF spec says that .text is part of reserved sections, so we can follow only .text/.text$N named sections,
		// instead of IMAGE_SCN_CNT_CODE Characteristicss
		//
		// (!?) We well need to resolve also relocations in initialized data - there may be pointers with relocated
		// imports or lib externs. May be we can get away with this for POC, for field applicable version need to take care
		//

		if (memcmp((pish + i)->Name, ".text", strlen(".text")))
			continue;

		// Got .text[$X]. Dump what we have

		// Dump IMAGE_SECTION_HEADERs
		printf("IMAGE_SECTION_HEADER #%u:\n", i + 1);		// Section indexes are 1-based, so this is more informative
		printf("	Name = '%s'\n", (pish + i)->Name);
		printf("	Misc.VirtualSize = %08X\n", (pish + i)->Misc.VirtualSize);
		printf("	VirtualAddress = %08X\n", (pish + i)->VirtualAddress);
		printf("	SizeOfRawData = %08X\n", (pish + i)->SizeOfRawData);
		printf("	PointerToRawData = %08X\n", (pish + i)->PointerToRawData);
		printf("	PointerToRelocations = %08X\n", (pish + i)->PointerToRelocations);
		printf("	PointerToLinenumbers = %08X\n", (pish + i)->PointerToLinenumbers);
		printf("	NumberOfRelocations = %04hX\n", (pish + i)->NumberOfRelocations);
		printf("	NumberOfLinenumbers = %04hX\n", (pish + i)->NumberOfLinenumbers);

		// Dump relocatioins

		preloc = (struct _RELOC_REC*)((obj_buf + (pish + i)->PointerToRelocations));

		for (j = 0; j < (pish + i)->NumberOfRelocations; ++j)
		{
			DWORD stab_idx;
			unsigned char *paddr;
			char _name[9];
			BYTE byte_val;
			unsigned k;
			char name[256];

			printf("\n");
			printf("		Relocation:\n");
			printf("			VirtualAddress = %08X\n", (preloc + j)->VirtualAddress);
			printf("			SymbolTableIndex = %08X\n", (preloc + j)->SymbolTableIndex);
			printf("			Type = %04hX\n", (preloc + j)->Type);

			// For relative function calls we expect to see this (from COFF spec)
			// (?) data relocs from another section of this object? Probably the same or IMAGE_REL_AMD64_REL32_N, data are referred to as RIP-related

			/**
			IMAGE_REL_AMD64_REL32
			0x0004
			The 32-bit relative address from the byte following the relocation.
			*/
			if ((preloc + j)->Type != IMAGE_REL_AMD64_REL32)
			{
				dont_run = 1;
				continue;
			}

			// Dump what we have in symtab
			stab_idx = (preloc + j)->SymbolTableIndex;
			paddr = obj_buf + (pish + i)->PointerToRawData + (preloc + j)->VirtualAddress;
			printf("1 --- [paddr] = %08X\n", *((DWORD*)paddr));

			//////////////////////////////////////////////////////////////////////
			printf("SymRec #%u:\n", stab_idx);

			if (*(DWORD*)(psym + stab_idx)->Name != 0)
			{
				memcpy(_name, (psym + stab_idx)->Name, 8);
				_name[8] = '\0';
				printf("	Name = '%s' (%016llX)\n", _name, *(uint64_t*)(psym + stab_idx)->Name);
				strcpy(name, _name);
			}
			else
			{
				unsigned str_offs = *(DWORD*)((psym + stab_idx)->Name + 4);

				printf("[str_offs = %08X]\n", str_offs);
				printf("	Name = '%s'\n", pstr_tbl + str_offs);
				strcpy(name, pstr_tbl + str_offs);
			}
			printf("	Value = %08X\n", (psym + stab_idx)->Value);
			printf("	SectionNumber = %04hX\n", (psym + stab_idx)->SectionNumber);
			printf("	Type = %04hX	[", (psym + stab_idx)->Type);
			// Print LSB
			byte_val = (BYTE)(psym + stab_idx)->Type;
			if (byte_val > num_type_vals)
				printf("BAD");
			else
				printf("%s", type_vals[byte_val]);
			printf(", ");
			// Print MSB
			byte_val = (BYTE)((psym + stab_idx)->Type >> 8);
			if (byte_val > num_type_msb_vals)
				printf("BAD");
			else
				printf("%s", type_msb_vals[byte_val]);
			printf("]\n");

			printf("	StorageClass = %02hhX	[", (psym + stab_idx)->StorageClass);
			for (k = 0; k < num_stor_class_vals; ++k)
			{
				if (stor_class_vals[k].val == (psym + stab_idx)->StorageClass)
				{
					printf("%s", stor_class_vals[k].val_str);
					break;
				}
			}

			if (k == num_stor_class_vals)
				printf("BAD");
			printf("]");

			// Print undefined external
			if ((psym + stab_idx)->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && !(psym + stab_idx)->SectionNumber)
				printf("[IMAGE_SYM_UNDEFINED]");

			printf("\n");

			printf("	NumberOfAuxSymbols = %02hhX\n", (psym + stab_idx)->NumberOfAuxSymbols);
			printf("\n");

			//////////////////////////////////////////////////////////////////////

			//
			// Try to resolve.
			//

			// IMAGE_SYM_CLASS_STATIC is something that is defined in this object file. Like static variable

			if ((psym + stab_idx)->StorageClass == IMAGE_SYM_CLASS_STATIC)
			{
				unsigned char *pdata;

			resolve_local:
				printf("Trying to resolve\n");

				sect_idx = (psym + stab_idx)->SectionNumber - 1;
				pdata = obj_buf + (pish + sect_idx)->PointerToRawData + (psym + stab_idx)->Value;

				// (!) Interestingly, static data are accessed as RIP-relative
				*(DWORD*)paddr = pdata - (paddr + 4);
			}
			else if ((psym + stab_idx)->StorageClass == IMAGE_SYM_CLASS_EXTERNAL)
			{

				// If storage is EXTERNAL but SectionNumber is not 0, the target has to be in this object.
				// No idea what this case should mean (and whether it indeed happens), but looks like we just resolve it
				// the same way as STATIC
				// (!) This is an untested flow
				if ((psym + stab_idx)->SectionNumber != 0)
					goto resolve_local;

				// UNDEF

				printf("Trying to resolve\n");

				// TODO: Meanwhile we only have a single undef external and only one ref to it.
				// Later we will need to keep a list of already resolved externals and pointer to end of imp area (growing)
				if (!memcmp(name, "__imp__", strlen("__imp_")))
				{
					// If fails, also try "kerrnel32.dll" and "gdi32.dll". And "ntdll.dll" for Nt/Zw imports
					void *proc_addr;

					// (!) This grows imp_addrs as many times as there are relocations - we don't reuse already resolved

					proc_addr = GetProcAddress(LoadLibraryA("user32.dll"), name + strlen("__imp_"));
					if (!proc_addr)
						proc_addr = GetProcAddress(LoadLibraryA("kernel32.dll"), name + strlen("__imp_"));
					if (!proc_addr)
						proc_addr = GetProcAddress(LoadLibraryA("gdi32.dll"), name + strlen("__imp_"));
					if (!proc_addr)
						proc_addr = GetProcAddress(LoadLibraryA("ntdll.dll"), name + strlen("__imp_"));

					if (!proc_addr)
					{
unresolved_quit:
						fprintf(stderr, "Can't resolve '%s'\n", name);
						exit(-1);
					}

					// Resolve COFF relocation

					// (!) This is *not* a relative call, it's indirect call with imm32 address RIP-relative
					*(uint64_t*)(imp_addrs + imp_addrs_offs) = (uint64_t)proc_addr;
					*(DWORD*)paddr = (char*)(imp_addrs + imp_addrs_offs) - (paddr + 4);
					imp_addrs_offs += sizeof(uint64_t);
				}
				else
				{
					void *proc_addr;
					struct _resolved_local *p_resolv;
					unsigned x;

					for (x = 0; x < num_resolved_locals; ++x)
						if (!strcmp(name, resolved_locals[x].name))
							break;
					if (x == num_resolved_locals)
						goto unresolved_quit;

					// This we will probably change to names/addresses table

					proc_addr = (void*)printf;
					int(*p)() = (int(*)())proc_addr;

					printf("proc_addr = %p\n", proc_addr);

					p("Hello...");

					// We have our own relocation in imp_plug, resolve it

					// Copy plug and resolve its call
					memcpy(imp_area + imp_area_offs, imp_plug, imp_plug_size);
					*(uint64_t*)(imp_area + imp_area_offs + imp_plug_addr_offs) =
						(uint64_t)proc_addr;

					// Resolve COFF reloc to the plug code
					*(DWORD*)paddr = (char*)(imp_area + imp_area_offs) - (paddr + 4);
					imp_area_offs += imp_plug_size;
				}
			}
		} // for (relocations)

		// Only text[$Nn] section gets here
		if (!dont_run)
		{
			// We assume a single code section
			sect_idx = i;
		}
	} // for (sections)

	if (!dont_run)
	{
		start = (int(*)())(obj_buf + (pish + sect_idx)->PointerToRawData);
		printf("start = %p\n", start);
		start();
	}

	return 0;
}



int main(int argc, char **argv)
{
	FILE *f;
	unsigned long fsize;
	unsigned char *obj_buf;

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

	// We need obj_buf to be executable, so use VirtualAlloc instead
	//obj_buf = malloc(fsize);

	// Allocate fsize + 0x8000 to allow space for our imp's
	obj_buf = VirtualAlloc(NULL, fsize + 0x8000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!obj_buf)
	{
		fprintf(stderr, "Can't allocate %lu bytes for '%s' contents\n", fsize, argv[1]);
		exit(-1);
	}

printf("%s():   obj_buf = %p, fProtect = %08X\n", __func__, obj_buf, PAGE_EXECUTE_READWRITE);

	fread(obj_buf, 1, fsize, f);
	fclose(f);

	coff_run(obj_buf, fsize);

printf("%s() ----------------------\n", __func__);
	return 0;
}
