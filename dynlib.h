#pragma once

#ifndef DYNLIB_HPP
#define DYNLIB_HPP

#define s16(n) \
	((ushort)(((((ushort)n) & 0xff00) >> 8) | \
	((((ushort)n) & 0x00ff) << 8)))

#define s32(n) \
	((int)(((((int)n) & 0xff000000) >> 24) | \
	((((int)n) & 0x00ff0000) >> 8 ) | \
	((((int)n) & 0x0000ff00) << 8 ) | \
	((((int)n) & 0x000000ff) << 24)))

#define s64(n) \
	((unsigned __int64)(((((unsigned __int64)n) & 0xff00000000000000ull) >> 56) | \
	((((unsigned __int64)n) & 0x00ff000000000000ull) >> 40) | \
	((((unsigned __int64)n) & 0x0000ff0000000000ull) >> 24) | \
	((((unsigned __int64)n) & 0x000000ff00000000ull) >> 8 ) | \
	((((unsigned __int64)n) & 0x00000000ff000000ull) << 8 ) | \
	((((unsigned __int64)n) & 0x0000000000ff0000ull) << 24) | \
	((((unsigned __int64)n) & 0x000000000000ff00ull) << 40) | \
	((((unsigned __int64)n) & 0x00000000000000ffull) << 56)))

typedef unsigned short	Elf32_Half;
typedef unsigned short	Elf64_Half;

typedef unsigned int	Elf32_Off;
typedef unsigned long long	Elf64_Off;

typedef unsigned int	Elf32_Word;
typedef signed int		Elf32_Sword;
typedef unsigned int	Elf64_Word;
typedef signed int		Elf64_Sword;

typedef unsigned long long	Elf32_Xword;
typedef signed long long		Elf32_Sxword;
typedef unsigned long long	Elf64_Xword;
typedef signed long long		Elf64_Sxword;

typedef unsigned int	Elf32_Addr;
typedef unsigned long long	Elf64_Addr;

typedef unsigned short	Elf32_Section;
typedef unsigned short	Elf64_Section;

#define EI_NIDENT (16)

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf32_Half	e_type;			/* Object file type */
  Elf32_Half	e_machine;		/* Architecture */
  Elf32_Word	e_version;		/* Object file version */
  Elf32_Addr	e_entry;		/* Entry point virtual address */
  Elf32_Off		e_phoff;		/* Program header table file offset */
  Elf32_Off		e_shoff;		/* Section header table file offset */
  Elf32_Word	e_flags;		/* Processor-specific flags */
  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
  Elf32_Half	e_phentsize;	/* Program header table entry size */
  Elf32_Half	e_phnum;		/* Program header table entry count */
  Elf32_Half	e_shentsize;	/* Section header table entry size */
  Elf32_Half	e_shnum;		/* Section header table entry count */
  Elf32_Half	e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off		e_phoff;		/* Program header table file offset */
  Elf64_Off		e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;	/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;	/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;

#define EI_MAG0     0
#define   ELFMAG0      0x7f
#define EI_MAG1     1
#define   ELFMAG1      'E'
#define EI_MAG2     2
#define   ELFMAG2      'L'
#define EI_MAG3     3
#define   ELFMAG3      'F'

#define EI_CLASS    4
#define   ELFCLASSNONE  0   /* Invalid class */
#define   ELFCLASS32    1   /* 32-bit objects */
#define   ELFCLASS64    2   /* 64-bit objects */
#define   ELFCLASSNUM	3

#define EI_DATA		5		/* Data encoding byte index */
#define   ELFDATANONE	0		/* Invalid data encoding */
#define   ELFDATA2LSB	1		/* 2's complement, little endian */
#define   ELFDATA2MSB	2		/* 2's complement, big endian */
#define   ELFDATANUM	3

#define EI_VERSION	6		/* File version byte index */
							/* Value must be EV_CURRENT */

#define EI_OSABI	7		/* OS ABI identification */
#define   ELFOSABI_NONE			0	/* UNIX System V ABI */
#define   ELFOSABI_SYSV			0	/* Alias.  */
#define   ELFOSABI_HPUX			1	/* HP-UX */
#define   ELFOSABI_NETBSD		2	/* NetBSD.  */
#define   ELFOSABI_LINUX		3	/* Linux.  */
#define   ELFOSABI_SOLARIS		6	/* Sun Solaris.  */
#define   ELFOSABI_AIX			7	/* IBM AIX.  */
#define   ELFOSABI_IRIX			8	/* SGI Irix.  */
#define   ELFOSABI_FREEBSD		9	/* FreeBSD.  */
#define   ELFOSABI_TRU64		10	/* Compaq TRU64 UNIX.  */
#define   ELFOSABI_MODESTO		11	/* Novell Modesto.  */
#define   ELFOSABI_OPENBSD		12	/* OpenBSD.  */
#define   ELFOSABI_ARM			97	/* ARM */
#define   ELFOSABI_CELLOSLV2    102     /* CellOS Lv2 */ /* sce local */
#define   ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */

#define EI_ABIVERSION   8       // ABI version

#define EI_PAD          9       // Start of padding bytes

#define ET_NONE		0		/* No file type */
#define ET_REL		1		/* Relocatable file */
#define ET_EXEC		2		/* Executable file */
#define ET_DYN		3		/* Shared object file */
#define ET_CORE		4		/* Core file */
#define	ET_NUM		5		/* Number of defined types */
#define ET_LOOS		0xfe00		/* OS-specific range start */
/* Playstation 4 */
#define ET_SCE_EXEC     0xfe00
#define ET_SCE_DYNEXEC  0xfe10		/* Main module - ASLR */
#define ET_SCE_RELEXEC  0xfe04		/* PRX */
#define ET_SCE_STUBLIB  0xfe0c		/* Stub library */
#define ET_SCE_DYNAMIC  0xfe18		/* PRX */
#define ET_HIOS		0xfeff		/* OS-specific range end */
#define ET_LOPROC	0xff00		/* Processor-specific range start */
#define ET_HIPROC	0xffff		/* Processor-specific range end */

#define EM_NONE		 0		/* No machine */
#define EM_M32		 1		/* AT&T WE 32100 */
#define EM_SPARC	 2		/* SUN SPARC */
#define EM_386		 3		/* Intel 80386 */
#define EM_68K		 4		/* Motorola m68k family */
#define EM_88K		 5		/* Motorola m88k family */
#define EM_860		 7		/* Intel 80860 */
#define EM_MIPS		 8		/* MIPS R3000 big-endian */
#define EM_S370		 9		/* IBM System/370 */
#define EM_MIPS_RS3_LE	10	/* MIPS R3000 little-endian */

#define EM_PARISC	15		/* HPPA */
#define EM_VPP500	17		/* Fujitsu VPP500 */
#define EM_SPARC32PLUS	18	/* Sun's "v8plus" */
#define EM_960		19		/* Intel 80960 */
#define EM_PPC		20		/* PowerPC */
#define EM_PPC64	21		/* PowerPC 64-bit */
#define EM_S390		22		/* IBM S390 */
#define EM_SPU		23	 	/* Cell BE SPU */

#define EM_V800		36		/* NEC V800 series */
#define EM_FR20		37		/* Fujitsu FR20 */
#define EM_RH32		38		/* TRW RH-32 */
#define EM_RCE		39		/* Motorola RCE */
#define EM_ARM		40		/* ARM */
#define EM_FAKE_ALPHA	41	/* Digital Alpha */
#define EM_SH		42		/* Hitachi SH */
#define EM_SPARCV9	43		/* SPARC v9 64-bit */
#define EM_TRICORE	44		/* Siemens Tricore */
#define EM_ARC		45		/* Argonaut RISC Core */
#define EM_H8_300	46		/* Hitachi H8/300 */
#define EM_H8_300H	47		/* Hitachi H8/300H */
#define EM_H8S		48		/* Hitachi H8S */
#define EM_H8_500	49		/* Hitachi H8/500 */
#define EM_IA_64	50		/* Intel Merced */
#define EM_MIPS_X	51		/* Stanford MIPS-X */
#define EM_COLDFIRE	52		/* Motorola Coldfire */
#define EM_68HC12	53		/* Motorola M68HC12 */
#define EM_MMA		54		/* Fujitsu MMA Multimedia Accelerator*/
#define EM_PCP		55		/* Siemens PCP */
#define EM_NCPU		56		/* Sony nCPU embeeded RISC */
#define EM_NDR1		57		/* Denso NDR1 microprocessor */
#define EM_STARCORE	58		/* Motorola Start*Core processor */
#define EM_ME16		59		/* Toyota ME16 processor */
#define EM_ST100	60		/* STMicroelectronic ST100 processor */
#define EM_TINYJ	61		/* Advanced Logic Corp. Tinyj emb.fam*/
#define EM_X86_64	62		/* AMD x86-64 architecture */
#define EM_PDSP		63		/* Sony DSP Processor */

#define EM_FX66		66		/* Siemens FX66 microcontroller */
#define EM_ST9PLUS	67		/* STMicroelectronics ST9+ 8/16 mc */
#define EM_ST7		68		/* STmicroelectronics ST7 8 bit mc */
#define EM_68HC16	69		/* Motorola MC68HC16 microcontroller */
#define EM_68HC11	70		/* Motorola MC68HC11 microcontroller */
#define EM_68HC08	71		/* Motorola MC68HC08 microcontroller */
#define EM_68HC05	72		/* Motorola MC68HC05 microcontroller */
#define EM_SVX		73		/* Silicon Graphics SVx */
#define EM_ST19		74		/* STMicroelectronics ST19 8 bit mc */
#define EM_VAX		75		/* Digital VAX */
#define EM_CRIS		76		/* Axis Communications 32-bit embedded processor */
#define EM_JAVELIN	77		/* Infineon Technologies 32-bit embedded processor */
#define EM_FIREPATH	78		/* Element 14 64-bit DSP Processor */
#define EM_ZSP		79		/* LSI Logic 16-bit DSP Processor */
#define EM_MMIX		80		/* Donald Knuth's educational 64-bit processor */
#define EM_HUANY	81		/* Harvard University machine-independent object files */
#define EM_PRISM	82		/* SiTera Prism */
#define EM_AVR		83		/* Atmel AVR 8-bit microcontroller */
#define EM_FR30		84		/* Fujitsu FR30 */
#define EM_D10V		85		/* Mitsubishi D10V */
#define EM_D30V		86		/* Mitsubishi D30V */
#define EM_V850		87		/* NEC v850 */
#define EM_M32R		88		/* Mitsubishi M32R */
#define EM_MN10300	89		/* Matsushita MN10300 */
#define EM_MN10200	90		/* Matsushita MN10200 */
#define EM_PJ		91		/* picoJava */
#define EM_OPENRISC	92		/* OpenRISC 32-bit embedded processor */
#define EM_ARC_A5	93		/* ARC Cores Tangent-A5 */
#define EM_XTENSA	94		/* Tensilica Xtensa Architecture */
#define EM_NUM		95

#define EV_NONE		0		/* Invalid ELF version */
#define EV_CURRENT	1		/* Current version */
#define EV_NUM		2

#define VER_FLG_BASE    0x1   // in vd_flags
#define VER_FLG_WEAK    0x2   // -"-

typedef struct
{
  Elf32_Word	sh_name;		/* Section name (string tbl index) */
  Elf32_Word	sh_type;		/* Section type */
  Elf32_Word	sh_flags;		/* Section flags */
  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf32_Off		sh_offset;		/* Section file offset */
  Elf32_Word	sh_size;		/* Section size in bytes */
  Elf32_Word	sh_link;		/* Link to another section */
  Elf32_Word	sh_info;		/* Additional section information */
  Elf32_Word	sh_addralign;	/* Section alignment */
  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
} Elf32_Shdr;

typedef struct
{
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;		/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf64_Shdr;

// special section indexed
#define SHN_UNDEF	0		/* Undefined section */
#define SHN_LORESERVE	0xff00		/* Start of reserved indices */
#define SHN_LOPROC	0xff00		/* Start of processor-specific */
#define SHN_HIPROC	0xff1f		/* End of processor-specific */
#define SHN_LOOS	0xff20		/* Start of OS-specific */
#define SHN_HIOS	0xff3f		/* End of OS-specific */
#define SHN_ABS		0xfff1		/* Associated symbol is absolute */
#define SHN_COMMON	0xfff2		/* Associated symbol is common */
#define SHN_XINDEX	0xffff		/* Index is in extra table.  */
#define SHN_HIRESERVE	0xffff		/* End of reserved indices */

#define SHN_XINDEX	0xffff
#define SHN_RADDR	0xff1f

#define SHT_NULL	  0		/* Section header table entry unused */
#define SHT_PROGBITS	  1		/* Program data */
#define SHT_SYMTAB	  2		/* Symbol table */
#define SHT_STRTAB	  3		/* String table */
#define SHT_RELA	  4		/* Relocation entries with addends */
#define SHT_HASH	  5		/* Symbol hash table */
#define SHT_DYNAMIC	  6		/* Dynamic linking information */
#define SHT_NOTE	  7		/* Notes */
#define SHT_NOBITS	  8		/* Program space with no data (bss) */
#define SHT_REL		  9		/* Relocation entries, no addends */
#define SHT_SHLIB	  10		/* Reserved */
#define SHT_DYNSYM	  11		/* Dynamic linker symbol table */
#define SHT_INIT_ARRAY	  14		/* Array of constructors */
#define SHT_FINI_ARRAY	  15		/* Array of destructors */
#define SHT_PREINIT_ARRAY 16		/* Array of pre-constructors */
#define SHT_GROUP	  17		/* Section group */
#define SHT_SYMTAB_SHNDX  18		/* Extended section indeces */
#define	SHT_NUM		  19		/* Number of defined types.  */
#define SHT_LOOS	  0x60000000	/* Start OS-specific */
/* Playstation 4 */
#define SHT_SCENID	  0x61000001

#define SHT_GNU_LIBLIST	  0x6ffffff7	/* Prelink library list */
#define SHT_CHECKSUM	  0x6ffffff8	/* Checksum for DSO content.  */
#define SHT_LOSUNW	  0x6ffffffa	/* Sun-specific low bound.  */
#define SHT_SUNW_move	  0x6ffffffa
#define SHT_SUNW_COMDAT   0x6ffffffb
#define SHT_SUNW_syminfo  0x6ffffffc
#define SHT_GNU_verdef	  0x6ffffffd	/* Version definition section.  */
#define SHT_GNU_verneed	  0x6ffffffe	/* Version needs section.  */
#define SHT_GNU_versym	  0x6fffffff	/* Version symbol table.  */
#define SHT_HISUNW	  0x6fffffff	/* Sun-specific high bound.  */
#define SHT_HIOS	  0x6fffffff	/* End OS-specific type */
#define SHT_LOPROC	  0x70000000	/* Start of processor-specific */
#define SHT_HIPROC	  0x7fffffff	/* End of processor-specific */
#define SHT_LOUSER	  0x80000000	/* Start of application-specific */
#define SHT_HIUSER	  0x8fffffff	/* End of application-specific */

#define SHF_WRITE				(1 << 0)	/* Writable */
#define SHF_ALLOC				(1 << 1)	/* Occupies memory during execution */
#define SHF_EXECINSTR			(1 << 2)	/* Executable */
#define SHF_MERGE				(1 << 4)	/* Might be merged */
#define SHF_STRINGS				(1 << 5)	/* Contains nul-terminated strings */
#define SHF_INFO_LINK			(1 << 6)	/* `sh_info' contains SHT index */
#define SHF_LINK_ORDER			(1 << 7)	/* Preserve order after combining */
#define SHF_OS_NONCONFORMING	(1 << 8)	/* Non-standard OS specific handling
										required */
#define SHF_GROUP			(1 << 9)	/* Section is member of a group.  */
#define SHF_TLS				(1 << 10)	/* Section hold thread-local data.  */
#define SHF_MASKOS			0x0ff00000	/* OS-specific.  */
#define SHF_MASKPROC		0xf0000000	/* Processor-specific */

typedef struct
{
  Elf32_Word	p_type;			/* Segment type */
  Elf32_Off	p_offset;		/* Segment file offset */
  Elf32_Addr	p_vaddr;		/* Segment virtual address */
  Elf32_Addr	p_paddr;		/* Segment physical address */
  Elf32_Word	p_filesz;		/* Segment size in file */
  Elf32_Word	p_memsz;		/* Segment size in memory */
  Elf32_Word	p_flags;		/* Segment flags */
  Elf32_Word	p_align;		/* Segment alignment */
} Elf32_Phdr;

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off		p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

#define	PT_NULL			0			/* Program header table entry unused */
#define PT_LOAD			1			/* Loadable program segment */
#define PT_DYNAMIC		2			/* Dynamic linking information */
#define PT_INTERP		3			/* Program interpreter */
#define PT_NOTE			4			/* Auxiliary information */
#define PT_SHLIB		5			/* Reserved */
#define PT_PHDR			6			/* Entry for header table itself */
#define PT_TLS			7			/* Thread-local storage segment */
#define	PT_NUM			8			/* Number of defined types */
#define PT_LOOS			0x60000000	/* Start of OS-specific */

/* Playstation 4 */
#define PT_SCE_DYNLIBDATA	0x61000000
#define PT_SCE_PROCPARAM	0x61000001
#define PT_SCE_MODULEPARAM	0x61000002
#define PT_SCE_RELRO		0x61000010

#define PT_GNU_EH_FRAME	0x6474e550	/* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK	0x6474e551	/* Indicates stack executability */

/* Playstation 4 */
#define PT_SCE_COMMENT  0x6fffff00
#define PT_SCE_VERSION	0x6fffff01

#define PT_LOSUNW		0x6ffffffa
#define PT_SUNWBSS		0x6ffffffa	/* Sun Specific segment */
#define PT_SUNWSTACK	0x6ffffffb	/* Stack segment */
#define PT_HISUNW		0x6fffffff
#define PT_HIOS			0x6fffffff	/* End of OS-specific */
#define PT_LOPROC		0x70000000	/* Start of processor-specific */
#define PT_HIPROC		0x7fffffff	/* End of processor-specific */

#define PF_X		(1 << 0)	/* Segment is executable */
#define PF_W		(1 << 1)	/* Segment is writable */
#define PF_R		(1 << 2)	/* Segment is readable */
#define PF_MASKOS	0x0ff00000	/* OS-specific */
#define PF_MASKPROC	0xf0000000	/* Processor-specific */

typedef struct
{
  Elf32_Word	st_name;		/* Symbol name (string tbl index) */
  Elf32_Addr	st_value;		/* Symbol value */
  Elf32_Word	st_size;		/* Symbol size */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char	st_other;		/* Symbol visibility */
  Elf32_Section	st_shndx;		/* Section index */
} Elf32_Sym;

typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;

#define ELF64_ST_BIND(val)		(((unsigned char) (val)) >> 4)
#define ELF64_ST_TYPE(val)		((val) & 0xf)
#define ELF64_ST_INFO(bind, type)	(((bind) << 4) + ((type) & 0xf))

#define STB_LOCAL	0		/* Local symbol */
#define STB_GLOBAL	1		/* Global symbol */
#define STB_WEAK	2		/* Weak symbol */
#define	STB_NUM		3		/* Number of defined types.  */
#define STB_LOOS	10		/* Start of OS-specific */
#define STB_HIOS	12		/* End of OS-specific */
#define STB_LOPROC	13		/* Start of processor-specific */
#define STB_HIPROC	15

#define STT_NOTYPE	0		/* Symbol type is unspecified */
#define STT_OBJECT	1		/* Symbol is a data object */
#define STT_FUNC	2		/* Symbol is a code object */
#define STT_SECTION	3		/* Symbol associated with a section */
#define STT_FILE	4		/* Symbol's name is file name */
#define STT_COMMON	5		/* Symbol is a common data object */
#define STT_TLS		6		/* Symbol is thread-local data object*/
#define	STT_NUM		7		/* Number of defined types.  */
#define STT_LOOS	10		/* Start of OS-specific */
#define STT_HIOS	12		/* End of OS-specific */
#define STT_LOPROC	13		/* Start of processor-specific */
#define STT_HIPROC	15		/* End of processor-specific */

#define STV_DEFAULT		0		/* Default symbol visibility rules */
#define STV_INTERNAL	1		/* Processor specific hidden class */
#define STV_HIDDEN		2		/* Sym unavailable in other modules */
#define STV_PROTECTED	3		/* Not preemptible, not exported */

typedef struct
{
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
} Elf32_Rel;

typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
} Elf64_Rel;

typedef struct
{
  Elf32_Addr	r_offset;		/* Address */
  Elf32_Word	r_info;			/* Relocation type and symbol index */
  Elf32_Sword	r_addend;		/* Addend */
} Elf32_Rela;

typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;

#define ELF32_R_SYM(val)			((val) >> 8)
#define ELF32_R_TYPE(val)			((val) & 0xff)
#define ELF32_R_INFO(sym, type)		(((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)				((i) >> 32)
#define ELF64_R_TYPE(i)				((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)		((((Elf64_Xword) (sym)) << 32) + (type))

typedef struct
{
  Elf32_Sword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf32_Word d_val;			/* Integer value */
      Elf32_Addr d_ptr;			/* Address value */
    } d_un;
} Elf32_Dyn;

typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;

#define DT_NULL		0		/* Marks end of dynamic section */
#define DT_NEEDED	1		/* Name of needed library */
#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
#define DT_PLTGOT	3		/* Processor defined value */
#define DT_HASH		4		/* Address of symbol hash table */
#define DT_STRTAB	5		/* Address of string table */
#define DT_SYMTAB	6		/* Address of symbol table */
#define DT_RELA		7		/* Address of Rela relocs */
#define DT_RELASZ	8		/* Total size of Rela relocs */
#define DT_RELAENT	9		/* Size of one Rela reloc */
#define DT_STRSZ	10		/* Size of string table */
#define DT_SYMENT	11		/* Size of one symbol table entry */
#define DT_INIT		12		/* Address of init function */
#define DT_FINI		13		/* Address of termination function */
#define DT_SONAME	14		/* Name of shared object */
#define DT_RPATH	15		/* Library search path (deprecated) */
#define DT_SYMBOLIC	16		/* Start symbol search here */
#define DT_REL		17		/* Address of Rel relocs */
#define DT_RELSZ	18		/* Total size of Rel relocs */
#define DT_RELENT	19		/* Size of one Rel reloc */
#define DT_PLTREL	20		/* Type of reloc in PLT */
#define DT_DEBUG	21		/* For debugging; unspecified */
#define DT_TEXTREL	22		/* Reloc might modify .text */
#define DT_JMPREL	23		/* Address of PLT relocs */
#define	DT_BIND_NOW	24		/* Process relocations of object */
#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	29		/* Library search path */
#define DT_FLAGS	30		/* Flags for the object being loaded */
#define DT_ENCODING	32		/* Start of encoded range */
#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
#define	DT_NUM		34		/* Number used */
#define DT_LOOS		0x6000000d	/* Start of OS-specific */

/* Playstation 4 */
#define DT_SCE_FINGERPRINT			0x61000007
#define DT_SCE_ORIGINAL_FILENAME	0x61000009
#define DT_SCE_MODULE_INFO			0x6100000d
#define DT_SCE_NEEDED_MODULE		0x6100000f
#define DT_SCE_MODULE_ATTR			0x61000011
#define DT_SCE_EXPORT_LIB			0x61000013
#define DT_SCE_IMPORT_LIB			0x61000015
#define DT_SCE_EXPORT_LIB_ATTR		0x61000017
#define DT_SCE_IMPORT_LIB_ATTR		0x61000019
#define DT_SCE_STUB_MODULE_NAME		0x6100001d
#define DT_SCE_STUB_MODULE_VERSION	0x6100001f
#define DT_SCE_STUB_LIBRARY_NAME	0x61000021
#define DT_SCE_STUB_LIBRARY_VERSION	0x61000023
#define DT_SCE_HASH					0x61000025
#define DT_SCE_PLTGOT				0x61000027
#define DT_SCE_JMPREL				0x61000029
#define DT_SCE_PLTREL				0x6100002b
#define DT_SCE_PLTRELSZ				0x6100002d
#define DT_SCE_RELA					0x6100002f
#define DT_SCE_RELASZ				0x61000031
#define DT_SCE_RELAENT				0x61000033
#define DT_SCE_STRTAB				0x61000035
#define DT_SCE_STRSZ				0x61000037
#define DT_SCE_SYMTAB				0x61000039
#define DT_SCE_SYMENT				0x6100003b
#define DT_SCE_HASHSZ				0x6100003d
#define DT_SCE_SYMTABSZ				0x6100003f

#define DT_HIOS		0x6ffff000	/* End of OS-specific */
#define DT_LOPROC	0x70000000	/* Start of processor-specific */
#define DT_HIPROC	0x7fffffff	/* End of processor-specific */
#define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */

/* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
   Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
   approach.  */
#define DT_VALRNGLO	0x6ffffd00
#define DT_GNU_PRELINKED 0x6ffffdf5	/* Prelinking timestamp */
#define DT_GNU_CONFLICTSZ 0x6ffffdf6	/* Size of conflict section */
#define DT_GNU_LIBLISTSZ 0x6ffffdf7	/* Size of library list */
#define DT_CHECKSUM	0x6ffffdf8
#define DT_PLTPADSZ	0x6ffffdf9
#define DT_MOVEENT	0x6ffffdfa
#define DT_MOVESZ	0x6ffffdfb
#define DT_FEATURE_1	0x6ffffdfc	/* Feature selection (DTF_*).  */
#define DT_POSFLAG_1	0x6ffffdfd	/* Flags for DT_* entries, effecting
					   the following DT_* entry.  */
#define DT_SYMINSZ	0x6ffffdfe	/* Size of syminfo table (in bytes) */
#define DT_SYMINENT	0x6ffffdff	/* Entry size of syminfo */
#define DT_VALRNGHI	0x6ffffdff
#define DT_VALTAGIDX(tag)	(DT_VALRNGHI - (tag))	/* Reverse order! */
#define DT_VALNUM 12

/* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
   Dyn.d_un.d_ptr field of the Elf*_Dyn structure.

   If any adjustment is made to the ELF object after it has been
   built these entries will need to be adjusted.  */
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_GNU_CONFLICT	0x6ffffef8	/* Start of conflict section */
#define DT_GNU_LIBLIST	0x6ffffef9	/* Library list */
#define DT_CONFIG	0x6ffffefa	/* Configuration information.  */
#define DT_DEPAUDIT	0x6ffffefb	/* Dependency auditing.  */
#define DT_AUDIT	0x6ffffefc	/* Object auditing.  */
#define	DT_PLTPAD	0x6ffffefd	/* PLT padding.  */
#define	DT_MOVETAB	0x6ffffefe	/* Move table.  */
#define DT_SYMINFO	0x6ffffeff	/* Syminfo table.  */
#define DT_ADDRRNGHI	0x6ffffeff
#define DT_ADDRTAGIDX(tag)	(DT_ADDRRNGHI - (tag))	/* Reverse order! */
#define DT_ADDRNUM 10

/* The versioning entry types.  The next are defined as part of the
   GNU extension.  */
#define DT_VERSYM	0x6ffffff0

#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa

/* These were chosen by Sun.  */
#define DT_FLAGS_1	0x6ffffffb	/* State flags, see DF_1_* below.  */
#define	DT_VERDEF	0x6ffffffc	/* Address of version definition
					   table */
#define	DT_VERDEFNUM	0x6ffffffd	/* Number of version definitions */
#define	DT_VERNEED	0x6ffffffe	/* Address of table with needed
					   versions */
#define	DT_VERNEEDNUM	0x6fffffff	/* Number of needed versions */
#define DT_VERSIONTAGIDX(tag)	(DT_VERNEEDNUM - (tag))	/* Reverse order! */
#define DT_VERSIONTAGNUM 16

/* Sun added these machine-independent extensions in the "processor-specific"
   range.  Be compatible.  */
#define DT_AUXILIARY    0x7ffffffd      /* Shared object to load before self */
#define DT_FILTER       0x7fffffff      /* Shared object to get values from */
#define DT_EXTRATAGIDX(tag)	((Elf32_Word)-((Elf32_Sword) (tag) <<1>>1)-1)
#define DT_EXTRANUM	3

/* Values of `d_un.d_val' in the DT_FLAGS entry.  */
#define DF_ORIGIN	0x00000001	/* Object may use DF_ORIGIN */
#define DF_SYMBOLIC	0x00000002	/* Symbol resolutions starts here */
#define DF_TEXTREL	0x00000004	/* Object contains text relocations */
#define DF_BIND_NOW	0x00000008	/* No lazy binding for this object */
#define DF_STATIC_TLS	0x00000010	/* Module uses the static TLS model */

/* State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
   entry in the dynamic section.  */
#define DF_1_NOW	0x00000001	/* Set RTLD_NOW for this object.  */
#define DF_1_GLOBAL	0x00000002	/* Set RTLD_GLOBAL for this object.  */
#define DF_1_GROUP	0x00000004	/* Set RTLD_GROUP for this object.  */
#define DF_1_NODELETE	0x00000008	/* Set RTLD_NODELETE for this object.*/
#define DF_1_LOADFLTR	0x00000010	/* Trigger filtee loading at runtime.*/
#define DF_1_INITFIRST	0x00000020	/* Set RTLD_INITFIRST for this object*/
#define DF_1_NOOPEN	0x00000040	/* Set RTLD_NOOPEN for this object.  */
#define DF_1_ORIGIN	0x00000080	/* $ORIGIN must be handled.  */
#define DF_1_DIRECT	0x00000100	/* Direct binding enabled.  */
#define DF_1_TRANS	0x00000200
#define DF_1_INTERPOSE	0x00000400	/* Object is used to interpose.  */
#define DF_1_NODEFLIB	0x00000800	/* Ignore default lib search path.  */
#define DF_1_NODUMP	0x00001000	/* Object can't be dldump'ed.  */
#define DF_1_CONFALT	0x00002000	/* Configuration alternative created.*/
#define DF_1_ENDFILTEE	0x00004000	/* Filtee terminates filters search. */
#define	DF_1_DISPRELDNE	0x00008000	/* Disp reloc applied at build time. */
#define	DF_1_DISPRELPND	0x00010000	/* Disp reloc applied at run-time.  */

/* Flags for the feature selection in DT_FEATURE_1.  */
#define DTF_1_PARINIT	0x00000001
#define DTF_1_CONFEXP	0x00000002

/* Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry.  */
#define DF_P1_LAZYLOAD	0x00000001	/* Lazyload following object.  */
#define DF_P1_GROUPPERM	0x00000002	/* Symbols from next object are not
									   generally available.  */

/* Relocation types for AMD x86-64 architecture */
#define R_X86_64_NONE             0 /* No reloc */
#define R_X86_64_64               1 /* Direct 64 bit  */
#define R_X86_64_PC32             2 /* PC relative 32 bit signed */
#define R_X86_64_GOT32            3 /* 32 bit GOT entry */
#define R_X86_64_PLT32            4 /* 32 bit PLT address */
#define R_X86_64_COPY             5 /* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT         6 /* Create GOT entry */
#define R_X86_64_JUMP_SLOT        7 /* Create PLT entry */
#define R_X86_64_RELATIVE	      8 /* Adjust by program base */
#define R_X86_64_GOTPCREL	      9 /* 32 bit signed pc relative offset to GOT */
#define R_X86_64_32		         10 /* Direct 32 bit zero extended */
#define R_X86_64_32S		     11 /* Direct 32 bit sign extended */
#define R_X86_64_16		         12 /* Direct 16 bit zero extended */
#define R_X86_64_PC16		     13 /* 16 bit sign extended pc relative */
#define R_X86_64_8		         14 /* Direct 8 bit sign extended  */
#define R_X86_64_PC8		     15 /* 8 bit sign extended pc relative */
#define R_X86_64_DTPMOD64        16 /* ID of module containing symbol */
#define R_X86_64_DTPOFF64        17 /* Offset in module's TLS block */
#define R_X86_64_TPOFF64         18 /* Offset in initial TLS block */
#define R_X86_64_TLSGD           19 /* 32 bit signed PC relative offset
                                        to two GOT entries for GD symbol */
#define R_X86_64_TLSLD           20 /* 32 bit signed PC relative offset
                                        to two GOT entries for LD symbol */
#define R_X86_64_DTPOFF32        21 /* Offset in TLS block */
#define R_X86_64_GOTTPOFF        22 /* 32 bit signed PC relative offset
                                        to GOT entry for IE symbol */
#define R_X86_64_TPOFF32         23 /* Offset in initial TLS block */
#define R_X86_64_PC64            24 /* PC relative 64 bit */
#define R_X86_64_GOTOFF64        25 /* 64 bit offset to GOT */
#define R_X86_64_GOTPC32         26 /* 32 bit signed pc relative offset to GOT */
#define R_X86_64_GOT64           27 /* 64-bit GOT entry offset */
#define R_X86_64_GOTPCREL64      28 /* 64-bit PC relative offset to GOT entry */
#define R_X86_64_GOTPC64         29 /* 64-bit PC relative offset to GOT */
#define R_X86_64_GOTPLT64        30 /* like GOT64, says PLT entry needed */
#define R_X86_64_PLTOFF64        31 /* 64-bit GOT relative offset to PLT entry */
#define R_X86_64_SIZE32          32 /* Size of symbol plus 32-bit addend */
#define R_X86_64_SIZE64          33 /* Size of symbol plus 64-bit addend */
#define R_X86_64_GOTPC32_TLSDESC 34 /* GOT offset for TLS descriptor */
#define R_X86_64_TLSDESC_CALL    35 /* Marker for call through TLS descriptor */
#define R_X86_64_TLSDESC         36 /* TLS descriptor */
#define R_X86_64_IRELATIVE       37 /* Adjust indirectly by program base */
#define R_X86_64_RELATIVE64      38 /* 64bit adjust by program base */
#define R_X86_64_ORBIS_GOTPCREL_LOAD   40

#endif /* DYNLIB_HPP */