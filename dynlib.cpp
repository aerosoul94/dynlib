/*
 *  DYNLIB
 *  An IDA Pro plugin that processes the 
 *  dynamic library data in PS4 ELF's.
 */

#define USE_STANDARD_FILE_FUNCTIONS	// for tinyxml...

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <diskio.hpp>
#include <nalt.hpp>
#include <auto.hpp>
#include <pro.h>

#include <stddef.h>
#include <ctime>    // for timer

#include "TinyXML\tinyxml.h"
#include "dynlib.h"

/* Debug print to log file */
#define DEV_LOG         0
/* Debug print to IDA output */
#define DEBUG_MSG       0
/* Debug log file handle */
static FILE *logFile  = NULL;

/*
 * Only print to msg if debug is enabled.
 */
#if DEBUG_MSG
#define lmdprint(fmt, ...)  lmprint(fmt, __VA_ARGS__)
#else
#define lmdprint(fmt, ...)  lprint(fmt "\n", __VA_ARGS__)
#endif

/*
 * Print line to both log and msg.
 */
#define lmprint(fmt, ...)    \
do {        \
    lprint(fmt "\n", __VA_ARGS__);    \
    msg(fmt "\n", __VA_ARGS__);     \
} while (0)

/*
 * Print to log only.
 */
static inline void 
lprint(char *format, ...)
{
#if DEV_LOG
    if ( logFile ) {
        char buffer[1024];
        va_list va;
        va_start(va, format);
        vsnprintf(buffer, sizeof(buffer), format, va);
        va_end(va);

        fputs(buffer, logFile);
        fflush(logFile);    // flush in case of crash
    }
#endif
}

static inline void 
lopen(const char *filename)
{
#if DEV_LOG
    if (logFile == NULL)
        logFile = fopen(filename, "w");
#endif
}

static inline void 
lclose()
{
#if DEV_LOG
    if ( logFile )
        fclose(logFile);
#endif
}

/* Dynlib database file */
#define DYNLIB_DB_FILE  "dynlib.xml"

/*
 * Program segments
 */
Elf64_Dyn *dyn = NULL;
uint32    ndyn = 0;

char      *dynld     = NULL;
uint32     dynld_len = 0;

/*
 * Dynamic segments
 */
Elf64_Sym  *sym = NULL;
uint32     nsym = 0;

char       *strtab = NULL;
uint32      strsz  = 0;

Elf64_Rela *jmpslots = NULL;
uint32     njmpslots = 0;

Elf64_Rela *rela = NULL;
uint32     nrela = 0;

struct import {
    char *name;
    int mid;
    import *next;
}  *modlist;

/* some code copied/pasted/slightly modified from readelf source */
static const char *
get_symbol_type (unsigned int type) {
    static char buff[32];

    switch ( type ) {
#define STT_CASE(t)    case STT_##t: return #t;
    STT_CASE(NOTYPE)
    STT_CASE(OBJECT)
    STT_CASE(FUNC) 
    STT_CASE(SECTION)
    STT_CASE(FILE)   
    STT_CASE(COMMON)
    STT_CASE(TLS) 

    default:
        if (type >= STT_LOPROC && type <= STT_HIPROC)
            qsnprintf (buff, sizeof(buff), "<processor specific>: %d", type);
        else if (type >= STT_LOOS && type <= STT_HIOS)
            qsnprintf (buff, sizeof(buff), "<OS specific>: %d", type);
        else
            qsnprintf (buff, sizeof(buff), "<unknown>: %d", type);

        return buff;
    }
}

static const char *
get_symbol_binding (unsigned int binding) {
    static char buff[32];

    switch ( binding ) {
#define STB_CASE(t)    case STB_##t: return #t;
    STB_CASE(LOCAL)
    STB_CASE(GLOBAL)
    STB_CASE(WEAK)

    default:
        if (binding >= STB_LOPROC && binding <= STB_HIPROC)
            qsnprintf (buff, sizeof (buff), "<processor specific>: %d", binding);
        else if (binding >= STB_LOOS && binding <= STB_HIOS)
            qsnprintf (buff, sizeof (buff), "<OS specific>: %d", binding);
        else
            qsnprintf (buff, sizeof (buff), "<unknown>: %d", binding);
    
        return buff;
    }
}

static const char *
get_symbol_index_type (unsigned int type) {
    static char buff[32];

    switch ( type ) {
#define SHN_CASE(t) case SHN_##t: return #t;
    SHN_CASE(UNDEF)
    SHN_CASE(ABS)
    SHN_CASE(COMMON)

    default:
        if (type >= SHN_LOPROC && type <= SHN_HIPROC)
            qsnprintf (buff, sizeof (buff), "PRC[0x%04x]", type);
        else if (type >= SHN_LOOS && type <= SHN_HIOS)
            qsnprintf (buff, sizeof (buff), "OS [0x%04x]", type);
        else if (type >= SHN_LORESERVE && type <= SHN_HIRESERVE)
            qsnprintf (buff, sizeof (buff), "RSV[0x%04x]", type);
        else
            qsnprintf (buff, sizeof (buff), "%3d", type);

        return buff;
    }
}

static const char *
elf_x86_64_reloc_type (unsigned int type) {
 
    switch ( type ) {
#define RELOC_CASE(r) case r: return #r;
    RELOC_CASE(R_X86_64_64)
    RELOC_CASE(R_X86_64_GLOB_DAT)
    RELOC_CASE(R_X86_64_JUMP_SLOT)
    RELOC_CASE(R_X86_64_RELATIVE)
    }
    return NULL;
}

/*
 * Print relocations table to log.
 */
static void
print_rela (Elf64_Rela *rela, size_t n) {
    Elf64_Rela *r = rela;  

    lprint("  Offset          Info           Type           Sym. Value    Sym. Name + Addend\n");
    for (size_t i = 0; i < n; r++, i++) {
                                       
        const char *rtype = elf_x86_64_reloc_type(ELF64_R_TYPE (r->r_info));
        int isym  = ELF64_R_SYM(r->r_info);

        lprint("%12.12llx  %12.12llx ", r->r_offset, r->r_info);
        if ( rtype == NULL )
            lprint("unrecognized: %-7lx", ELF64_R_TYPE (r->r_info));
        else
            lprint("%-17.17s", rtype);

        lprint(" %16.16lx", sym[isym].st_value);
        if ( isym ) {
            if ( isym > nsym )
                lprint(" bad symbol index: %08lx", isym);
            else
                lprint(" %s", &strtab[sym[isym].st_name]);

            lprint(" + %lx", (unsigned long) r->r_addend);
        } else {
            lprint(" %16.16lx", r->r_addend);
        }

        lprint("\n");
    }
}

/*
 * Print symbol table to log.
 */
static void
print_sym (Elf64_Sym *st, int n) {
    Elf64_Sym *s = st;

    lprint("   Num:    Value          Size Type    Bind   Ndx Name");
    for (size_t i = 0; i < n; i++, s++) {
        lprint( "%6d: ", i);
        lprint(" %16.16lx", s->st_value);
        lprint("%5ld", s->st_size);
        lprint(" %-7s", get_symbol_type(ELF64_ST_TYPE (s->st_info)));
        lprint(" %-6s", get_symbol_binding(ELF64_ST_BIND (s->st_info)));
        lprint("%4s ", get_symbol_index_type(s->st_shndx));

        if ( s->st_name < strsz )
            lprint("%s", &strtab[s->st_name]);
        else
            lprint("<corrupt: %14ld>", s->st_name);

        lprint("\n");
    }
}

/*
 * Lookup obfuscated symbol from database.
 */ 
static const char *
db_entry_by_obf (TiXmlDocument *db, const char *obf, const char *entry) {
    TiXmlElement *d = db->FirstChildElement(); // DynlibDatabase header
    TiXmlElement *e = d->FirstChildElement();  // first entry

    if ( d && e ) {
        do {
            if ( const char *obfstr = e->Attribute("obf") )
                if ( memcmp(obf, obfstr, 11) == 0 )
                    if ( const char *sym = e->Attribute(entry) )
                        return sym;
        } while ( e = e->NextSiblingElement() );
    }

    return NULL;
}

int decode_base64 (const char *str, int *a2)
{
  char chr; // dl@1
  int v3; // rcx@1
  const char *v4; // rdi@2
  int v5; // rcx@3
  int result; // rax@11

  chr = *str;
  v3 = 0LL;
  if ( *str ) {
    v4 = str + 1;
    v3 = 0LL;
    do {
      v5 = v3 << 6;
      if ( (unsigned __int8)(chr - 0x61) > 0x19u ) {
        if ( (unsigned __int8)(chr - 0x41) > 0x19u ) {
          if ( (unsigned __int8)(chr - 0x30) > 9u ) {
            if ( chr == '-' )
              v3 = v5 | 0x3F;
            else {
              result = 22LL;
              if ( chr != '+' )
                return result;
              v3 = v5 | 0x3E;
            }
          } else {
            v3 = chr + (v5 | 4);
          }
        } else {
          v3 = v5 + chr - 0x41;
        }
      } else {
        v3 = v5 + chr - 0x47;
      }
      chr = *v4++;
    } while ( chr );
  }
  *a2 = v3;
  return 0LL;
}

/*
 * Lookup module name for obfuscated symbol.
 */
static const char *
dynlib_mod_lookup (const char *obf) {
    int modid;

    const char *lib = strchr(obf, '#');
    if ( lib == NULL ) {
        lmdprint ("No lib id in this symbol.");
        return NULL;
    }

    lib = strchr(lib + 1, '#');
    if ( lib == NULL ) {
        lmdprint ("No mod id in this symbol.");
        return NULL;
    }

    if ( decode_base64(lib + 1, &modid) ) {
        lmdprint ("Invalid module id!");
        return NULL;
    }

    for ( import *l=modlist ; l ; l=l->next ) {
        if ( l->mid == modid )
            return l->name;
    }

    return NULL;
}

/*
 * Returns whether or not this symbol is an obfuscated one.
 */
static int
dynlib_sym_is_obf (const char *sym) {
    const char *p;
    if (strlen(sym) >= 13)
        if ((p = strchr(sym, '#')) != NULL) // contains first #
            if ((p - sym) == 11)                // obfuscated symbol is 11 chars
                if ((p = strchr(p + 1, '#')) != NULL) // contains second #
                    return 1;

    return 0;
}

/*
 *  Find and label imported functions.
 *  Symbol table does not include offsets for imports,
 *  which is why we rely on jmpslots to name them.
 */
static void
dynlib_iter_imports (TiXmlDocument &xml) {
    Elf64_Rela *r = jmpslots;

    if ( NULL == jmpslots || 0 == njmpslots ||
         NULL == sym      || 0 == nsym      ||
         NULL == strtab   || 0 == strsz ) {
        lmprint ("Failed to load imports. Missing one or more segments (JMPSLOTS, SYMTAB, STRTAB).");
        return;
    }

    lmprint ("Processing imported functions...");
    
#if DEV_LOG
    lprint("JMPSLOTS segment\n");
    print_rela(jmpslots, njmpslots);
#endif

    // Pointers to imported functions are patched using the JMPSLOT segment.
    for (size_t i = 0; i < njmpslots; r++, i++) {
        int type = ELF64_R_TYPE(r->r_info);
        int isym = ELF64_R_SYM (r->r_info);
        
        if ( type != R_X86_64_JUMP_SLOT ) {
            lmprint ("Unexpected reloc type %i for jump slot %i", type, i);
            continue;
        }
        
        if ( isym >= nsym ) {
            lmprint ("Invalid symbol index %i for relocation %i", isym, i);
            continue;
        }
        
        if ( sym[isym].st_name >= strsz ) {
            lmprint ("Invalid symbol string offset %x of symbol %i for relocation %i", sym[isym].st_name, isym, i);
            continue;
        }

        const char *name = &strtab[sym[isym].st_name];
        char obf[16], buf[MAXNAMELEN];

        // If symbol is obfuscated, retrieve the original symbol from database
        if ( dynlib_sym_is_obf(name) ) {
            memset(obf, 0, sizeof(obf));
            memcpy(obf, name, 11);

            lmdprint ("Addr: %08x", r->r_offset);
            lmdprint ("Obf: %s", name);

            const char *mod = dynlib_mod_lookup(name);

            if ( mod != NULL ) {
                lmdprint ("Module: %s", mod);
                qsnprintf(buf, MAXNAMELEN, "%s:%s", obf, mod);
                set_cmt(r->r_offset, buf, true);
            } else {
                lmdprint ("Unknown module!");
            }

            name = db_entry_by_obf(&xml, obf, "sym");
        }
        
        lmdprint ("Name: %s", name);

        if (name == NULL) {
            lmprint ("No match! obf: %s addr: %16.16lx", obf, r->r_offset);
        } else {
            // Prefix "__imp_" so that IDA names referenced functions without the ugly "j_" prefix.
            // Actual prefix used by Sony is "_PG" while the referenced function's prefix is "_PL"
            // Stub function pointed to by the function pointer does not ever appear to have a label.
            qsnprintf(buf, MAXNAMELEN, FUNC_IMPORT_PREFIX "%s", name);
            force_name(r->r_offset, buf);
        }
    }

    //lmprint ("");
}

/*
 * Processes the symbol table.
 */
static void
dynlib_iter_sym (TiXmlDocument &xml) {
    Elf64_Sym *s = sym;

    if ( NULL == sym    || 0 == nsym ||
         NULL == strtab || 0 == strsz ) {
        lmprint ("Failed to load symbol table. Missing one or more required segments (SYMTAB, STRTAB).");
        return;
    }

    lmprint ("Processing symbol table...");
    
#if DEV_LOG
    lprint("SYMTAB segment\n");
    print_sym(sym, nsym);
#endif
    
    for (size_t i = 0; i < nsym; i++, s++) {
        if ( s->st_value != 0 ) {
            if ( s->st_name > strsz ) {
                lmprint ("Invalid symbol string offset: %x", s->st_name);
                continue;
            }

            const char *name = &strtab[s->st_name];
            char obf[16];

            // if symbol is obfuscated, retrieve the original symbol from database
            if ( dynlib_sym_is_obf(name) ) {
                memset(obf, 0, sizeof(obf));
                memcpy(obf, name, 11);

                lmdprint ("addr: %08x", s->st_value);

                name = db_entry_by_obf(&xml, obf, "sym");
            }
            
            if ( name == NULL )    // don't apply obfuscated labels to database
                lmprint ("No match! obf: %s addr: %16.16lx", &obf, s->st_value);
            else
                force_name(s->st_value, name);

            // if is a symbol for a function, mark it as one
            if ( ELF64_ST_TYPE(s->st_info) == STT_FUNC )
                auto_make_proc(s->st_value);
        }
    }
}

/*
 * Patches relocations. Xml is unused for now.
 */
static void
dynlib_iter_rela (TiXmlDocument &xml) {
    Elf64_Rela *r = rela;
    
    if ( NULL == rela || 0 == nrela ) {
        lmprint ("Failed to load relocations. Missing RELA segment.");
        return;
    }

    lmprint ("Processing relocations...");
    
#if DEV_LOG
    lprint("RELA segment\n");
    print_rela(rela, nrela);
#endif
    
    for (size_t i = 0; i < nrela; i++, r++) {
        unsigned int isym = ELF64_R_SYM (r->r_info);
        int type = ELF64_R_TYPE(r->r_info);

        if ( type < R_X86_64_NONE || type > R_X86_64_RELATIVE64 ) {
            lmprint ("Invalid relocation type %i", type);
            continue;
        }
        
        if ( isym >= nsym ) {
            lmprint ("Invalid symbol index %i", sym);
            continue;
        }

        switch ( type ) {
/*      case R_x86_64_64:
            put_qword(r->r_offset, sym[isym].st_value + r->r_addend);
            break;
        case R_X86_64_GLOB_DAT:
            put_qword(r->r_offset, sym[isym].st_value);
            break;                                           */
        case R_X86_64_RELATIVE: /* Base + Addend */
            put_qword(r->r_offset, r->r_addend);
            break;

        }
    }
}

/*
 * Iterates dynlib data using database path stored in db.
 */
static int 
dynlib_iter_dynld (const char *db) {
    TiXmlDocument xml;

    if ( !xml.LoadFile(db) ) {
        lmprint ("Failed to load database file (%s).", db);
        return 0;
    }
    
    if ( strcmp(xml.FirstChildElement()->Value(), "DynlibDatabase") ) {
        lmprint ("Database requires \"DynlibDatabase\" header.");
        return 0;
    }
    
    // Process the various features of this dynlib plugin
    dynlib_iter_imports(xml);   // label import function stubs
    dynlib_iter_sym(xml);       // label symbols including export functions
    dynlib_iter_rela(xml);      // patch relocations

    return 1;
}

/*
 * Acquire needed module list.
 */
static int 
dynlib_load_needed () {
    Elf64_Dyn *d = dyn;

    lmprint ("Acquiring needed module list...");

    modlist = NULL;

    for (size_t i = 0; i < ndyn; i++, d++) {
        switch ( d->d_tag ) {
        case DT_NEEDED:
            lmdprint ("    %i: DT_NEEDED %s", i, (char *)(strtab + d->d_un.d_val));
            break;

        case DT_SCE_NEEDED_MODULE:
            import *lib = (import *)qalloc(sizeof(import));
            if ( lib == NULL ) {
                lmprint ("Failed to allocate memory for %s (%i bytes)", "imports", sizeof(import));
                return 0;
            }

            lib->name = (char *)(strtab + (d->d_un.d_val & 0xFFFFFFFF));
            lib->mid  = d->d_un.d_val >> 48;
            lib->next = modlist;

            lmdprint ("    %i: DT_SCE_NEEDED_MODULE mid: %x lib:%s", i, lib->mid, lib->name);
            modlist = lib;
            break;
        }
    }

    for (import *l = modlist; l; l=l->next)
        lmdprint (" mid: %x name: %s", l->mid, l->name);

    return 1;
}

/*
 * Load required dynamic segments.
 */
static int 
dynlib_load_dynamic () {
    Elf64_Dyn *d = dyn;
    int res = 1;
    
    lmprint  ("Loading dynamic segments...");

    // All dynamic segments should be offset into dynld.
    for (size_t i = 0; i < ndyn; i++, d++) {
        switch ( d->d_tag )  {
        /* general info */
        case DT_SCE_PLTGOT:
            lmprint ("PLTGOT addr: %08x", d->d_un.d_ptr);
            break;
        case DT_INIT:
            lmprint ("INIT addr: %08x", d->d_un.d_ptr);
            break;
        case DT_FINI:
            lmprint ("FINI addr: %08x", d->d_un.d_ptr);
            break;

        /* jmpslots info */
        case DT_SCE_JMPREL:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_JMPREL", d->d_un.d_val);
            if ( d->d_un.d_ptr > dynld_len ) {
                lmprint ("invalid JMPREL offset: %08x", d->d_un.d_ptr);
                continue;
            } jmpslots = (Elf64_Rela *)(dynld + d->d_un.d_ptr);
            break;
        case DT_SCE_PLTRELSZ:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_PLTRELSZ", d->d_un.d_val);
            njmpslots = d->d_un.d_val / sizeof(Elf64_Rela);
            break;

        /* symbol table info */
        case DT_SCE_SYMTAB:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_SYMTAB", d->d_un.d_val);
            if ( d->d_un.d_ptr > dynld_len ) {
                lmprint ("invalid SYMTAB offset: %08x", d->d_un.d_ptr);
                continue;
            } sym = (Elf64_Sym *)(dynld + d->d_un.d_ptr);
            break;
        case DT_SCE_SYMTABSZ:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_SYMTABSZ", d->d_un.d_val);
            nsym = d->d_un.d_val / sizeof(Elf64_Sym);
            break;

        /* string table info */
        case DT_SCE_STRTAB:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_STRTAB", d->d_un.d_val);
            if ( d->d_un.d_ptr > dynld_len ) {
                lmprint ("invalid STRTAB offset: %08x", d->d_un.d_ptr);
                continue;
            } strtab = &dynld[d->d_un.d_ptr];
            break;
        case DT_SCE_STRSZ:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_STRSZ", d->d_un.d_val);
            strsz = d->d_un.d_val;
            break;

        /* relocation table info */
        case DT_SCE_RELA:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_RELA", d->d_un.d_val);
            if ( d->d_un.d_ptr > dynld_len ) {
                lmprint ("invalid RELA offset: %08x", d->d_un.d_ptr);
                continue;
            } rela = (Elf64_Rela *)(dynld + d->d_un.d_ptr);
            break;
        case DT_SCE_RELASZ:
            lmdprint ("    %i: d_tag = %s, d_un = %08x", i, "DT_SCE_RELASZ", d->d_un.d_val);
            nrela = d->d_un.d_val / sizeof(Elf64_Rela);
            break;
        }
    }

    // strtab required for imports and exports
    if ( strtab == NULL )
        lmprint ("Missing STRTAB segment.");
    if ( strsz == 0 )
        lmprint ("String table size is zero.");

    // symtab required for imports and exports
    if ( sym == NULL ) 
        lmprint ("Missing SYMTAB segment.");
    if ( nsym == 0 )
        lmprint ("Number of symbols is zero.");

    // jmpslots required for imports
    if ( jmpslots == NULL )
        lmprint ("Missing JMPSLOTS segment.");
    if ( njmpslots == 0 )
        lmprint ("Number of jmpslots is zero.");

    // rela required for relocations
    if ( rela == NULL )
        lmprint ("Missing RELA segment.");
    if ( nrela == 0 )
        lmprint ("Number of relocations is zero.");

    return res;
}

/*
 * Load dynamic segment and dynlib data segment from program headers.
 */
static int 
dynlib_load_segments (FILE *f, uint64 offset, uint32 num) {
    Elf64_Phdr *phdr;
    int res = 1;

    lmprint ("Loading segments..");

    if ( num == 0 || offset == 0 )
        return 0;

    phdr = (Elf64_Phdr *)qalloc(sizeof(Elf64_Phdr) * num);
    if ( phdr == NULL ) {
        lmprint ("Failed to allocate memory for %s (%i bytes)", "program headers", sizeof(Elf64_Phdr) * num);
        return 0;
    }

    eseek(f, offset);
    eread(f, phdr, sizeof(Elf64_Phdr) * num);

    // get segments for dynlib data
	  Elf64_Phdr *p = phdr;
    for (size_t i = 0; i < num; i++, p++) {
        switch ( p->p_type ) {
        case PT_DYNAMIC:
            if ( p->p_filesz < sizeof(Elf64_Dyn) ) {
                lmprint ("Invalid DYNAMIC segment size.");
                res = 0; continue;
            }
            
            dyn = (Elf64_Dyn *)qalloc(p->p_filesz);
            if ( dyn == NULL ) {
                lmprint ("Failed to allocate memory for %s (%i bytes)", "DYNAMIC segment", p->p_filesz);
                return 0;
            }

            ndyn = p->p_filesz / sizeof(Elf64_Dyn);
            eseek(f, p->p_offset);
            eread(f, dyn, p->p_filesz);
            lmdprint ("    %i: PT_DYNAMIC offset: %08x size: %08x", i, p->p_offset, p->p_filesz);
            break;

        case PT_SCE_DYNLIBDATA:
            if ( p->p_filesz == 0 ) {
                lmprint ("Invalid DYNLIBDATA segment size.");
                res = 0; continue;
            }
            
            dynld = (char *)qalloc(p->p_filesz);
            if ( dynld == NULL ) {
                lmprint ("Failed to allocate memory for %s (%i bytes)", "DYNLIBDATA segment", p->p_filesz);
                return 0;
            }

            dynld_len = p->p_filesz;
            eseek(f, p->p_offset);
            eread(f, dynld, p->p_filesz);
            lmdprint ("    %i: PT_SCE_DYNLIBDATA offset %08x size: %08x", i, p->p_offset, p->p_filesz);
            break;
        }
    }

    if ( dyn == NULL ) {
        lmprint ("Missing DYNAMIC segment.");
        res = 0;
    }
    
    if ( dynld == NULL ) {
        lmprint ("Missing DYNLIBDATA segment.");
        res = 0;
    }

    qfree(phdr);

    return res;
}

static void inline
dynlib_unload () {
 /* 
    if (dyn)      qfree(dyn);
    if (dynld)    qfree(dynld);
    if (sym)      qfree(sym);
    if (jmpslots) qfree(jmpslots); 
    
    import *tmp;
    while (modlist != NULL) {
        tmp = modlist;
        modlist = modlist->next; 
        qfree(tmp);
    } 
 */
}

/*
 * Load dynlib data from Orbis ELF
 */
static int 
dynlib_load (const char *filename) {
    FILE *f;
    Elf64_Ehdr hdr;

    f = fopenRB(filename);

    if ( f == NULL ) {
        lmprint ("Failed to open file: %s", filename);
        return 0;
    }

    eread(f, &hdr, sizeof(Elf64_Ehdr));

    // check elf header
    if ( hdr.e_ident[EI_MAG0] != 0x7f || hdr.e_ident[EI_MAG1] != 'E'  || 
         hdr.e_ident[EI_MAG2] != 'L'  || hdr.e_ident[EI_MAG3] != 'F'  ||
        (hdr.e_type != ET_EXEC        && hdr.e_type != ET_SCE_EXEC    && 
         hdr.e_type != ET_SCE_DYNEXEC && hdr.e_type != ET_SCE_RELEXEC && 
         hdr.e_type != ET_SCE_STUBLIB && hdr.e_type != ET_SCE_DYNAMIC) || 
         hdr.e_machine != EM_X86_64   || hdr.e_ident[EI_OSABI] != ELFOSABI_FREEBSD ) {
        lmprint ("File is not an Orbis ELF!");
        return 0;
    }

    // load DYNAMIC and DYNLD program segments
    if ( dynlib_load_segments(f, hdr.e_phoff, hdr.e_phnum) == 0 ) {
        lmprint ("Failed to load required segments.");
        return 0;
    }

    // load dynamic segments using dynld
    if ( dynlib_load_dynamic() == 0 ) {
        lmprint ("Failed to load dynamic segments.");
        return 0;
    }

    // load list of needed modules
    if ( dynlib_load_needed() == 0 ) {
        lmprint ("Failed to load needed modules.");
        return 0;
    }

    return 1;
}

#if IDA_SDK_VERSION >= 700
#define RETURN_TRUE     return true
#define RETURN_FALSE    return false
#else
#define RETURN_TRUE     return
#define RETURN_FALSE    return
#endif

#if IDA_SDK_VERSION >= 700
bool idaapi run (size_t arg) {
#else
void idaapi run (int arg) {
#endif
    char *fname;
    char  db[QMAXPATH];
    clock_t t;

    lopen("log.txt");
 
    fname = ask_file(0, "PS4 ELF|*.elf;*.prx;*.self;*.sprx|All files (*.*)|*.*", "Please choose an input file");

    if ( fname == NULL ) {
        lmprint ("No file chosen.");
        RETURN_FALSE;
    }

    if ( ask_yn(0, "WARNING: You cannot undo this process!\n"
                    "Are you sure you want to load %s?" , fname) != ASKBTN_YES ) {
        lmprint ("Cancelled operation.");
        RETURN_FALSE;
    }
    
    t = clock();

    // load segments from file
    if ( dynlib_load(fname) == 0 ) {
        lmprint ("Invalid file %s.", fname);
        RETURN_FALSE;
    }

    // get path of dynlib database file
    if ( getsysfile(db, QMAXPATH, DYNLIB_DB_FILE, PLG_SUBDIR) == NULL ) {
        lmprint ("Could not find dynlib database file (%s).", DYNLIB_DB_FILE);
        RETURN_FALSE;
    }

    // iterate data from segments
    if ( dynlib_iter_dynld(db) == 0 ) {
        lmprint ("Failed to iterate dynlib data.");
        RETURN_FALSE;
    }

    // unload, free up memory
    dynlib_unload();

    t = clock() - t;

    lmprint ("Time to complete: %f seconds", ((float)t)/CLOCKS_PER_SEC);
    lmprint ("Dynlib loading completed!\n");
    
    lclose();

	RETURN_TRUE;
}

int idaapi init(void)
{
	lmprint ("DYNLIB plugin successfully loaded.");

    return PLUGIN_OK;
}

void idaapi term (void)
{
    dynlib_unload();
}

const char G_PLUGIN_COMMENT[]    =    "PS4 DYNLIBDATA loader";
const char G_PLUGIN_HELP[]       =    "This plugin loads symbols and relocations from DYNLIBDATA.";
const char G_PLUGIN_NAME[]       =    "DYNLIB";
const char G_PLUGIN_HOTKEY[]     =    "Ctrl-F10";

plugin_t PLUGIN =
{
    // values
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,     // plugin flags
    
    // functions
    init,           // initialize and test if plugin is supported
    term,           // terminate. this pointer may be NULL.
    run,            // invoke plugin
    
    // strings
    (char*)G_PLUGIN_COMMENT,// long comment about the plugin (may appear on status line or as a hint)
    (char*)G_PLUGIN_HELP,   // multiline help about the plugin
    (char*)G_PLUGIN_NAME,   // the preferred short name of the plugin, used by menu system
    (char*)G_PLUGIN_HOTKEY  // the preferred hotkey to run the plugin
};
