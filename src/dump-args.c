#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <linux/prctl.h> /* Definition of PR_* constants */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <unistd.h>

static const char *get_owner(void *addr, Dl_info *info) {
  if (addr == nullptr)
    return "(null)";
  else if (dladdr(addr, info))
    return info->dli_fname;
  else
    return "(unknown)";
}

struct r_scope_elem {
  /* Array of maps for the scope.  */
  struct link_map **r_list;
  /* Number of entries in the scope.  */
  unsigned int r_nlist;
};

struct link_map_ext {
  /* These first few members are part of the protocol with the debugger.
     This is the same format used in SVR4.  */

  ElfW(Addr) l_addr;                /* Difference between the address in the ELF
                                       file and the addresses in memory.  */
  char *l_name;                     /* Absolute file name object was found in.  */
  ElfW(Dyn) * l_ld;                 /* Dynamic section of the shared object.  */
  struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

  /* All following members are internal to the dynamic linker.
     They may change without notice.  */

  /* This is an element which is only ever different from a pointer to
     the very same copy of this type for ld.so when it is used in more
     than one namespace.  */
  struct link_map *l_real;

  /* Number of the namespace this link map belongs to.  */
  Lmid_t l_ns;

  struct libname_list *l_libname;
  /* Indexed pointers to dynamic section.
     [0,DT_NUM) are indexed by the processor-independent tags.
     [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
     [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
     indexed by DT_VERSIONTAGIDX(tagvalue).
     [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
      DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
     DT_EXTRATAGIDX(tagvalue).
     [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
      DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
     indexed by DT_VALTAGIDX(tagvalue) and
     [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
      DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
     are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

  ElfW(Dyn) * l_info[DT_NUM + 0 + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
  const ElfW(Phdr) * l_phdr; /* Pointer to program header table in core.  */
  ElfW(Addr) l_entry;        /* Entry point location.  */
  ElfW(Half) l_phnum;        /* Number of program header entries.  */
  ElfW(Half) l_ldnum;        /* Number of dynamic segment entries.  */

  /* Array of DT_NEEDED dependencies and their dependencies, in
     dependency order for symbol lookup (with and without
     duplicates).  There is no entry before the dependencies have
     been loaded.  */
  struct r_scope_elem l_searchlist;

  /* We need a special searchlist to process objects marked with
     DT_SYMBOLIC.  */
  struct r_scope_elem l_symbolic_searchlist;

  /* Dependent object that first caused this object to be loaded.  */
  struct link_map *l_loader;

  /* Array with version names.  */
  struct r_found_version *l_versions;
  unsigned int l_nversions;

  /* Symbol hash table.  */
  Elf_Symndx l_nbuckets;
  Elf32_Word l_gnu_bitmask_idxbits;
  Elf32_Word l_gnu_shift;
  const ElfW(Addr) * l_gnu_bitmask;
  union {
    const Elf32_Word *l_gnu_buckets;
    const Elf_Symndx *l_chain;
  };
  union {
    const Elf32_Word *l_gnu_chain_zero;
    const Elf_Symndx *l_buckets;
  };

  unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.  */
  enum                             /* Where this object came from.  */
  {
    lt_executable, /* The main executable program.  */
    lt_library,    /* Library needed by main executable.  */
    lt_loaded      /* Extra run-time loaded shared object.  */
  } l_type : 2;
  unsigned int l_dt_relr_ref : 1;           /* Nonzero if GLIBC_ABI_DT_RELR is
                                               referenced.  */
  unsigned int l_relocated : 1;             /* Nonzero if object's relocations done.  */
  unsigned int l_init_called : 1;           /* Nonzero if DT_INIT function called.  */
  unsigned int l_global : 1;                /* Nonzero if object in _dl_global_scope.  */
  unsigned int l_reserved : 2;              /* Reserved for internal use.  */
  unsigned int l_main_map : 1;              /* Nonzero for the map of the main program.  */
  unsigned int l_visited : 1;               /* Used internally for map dependency
                                               graph traversal.  */
  unsigned int l_map_used : 1;              /* These two bits are used during traversal */
  unsigned int l_map_done : 1;              /* of maps in _dl_close_worker. */
  unsigned int l_phdr_allocated : 1;        /* Nonzero if the data structure pointed
                                               to by `l_phdr' is allocated.  */
  unsigned int l_soname_added : 1;          /* Nonzero if the SONAME is for sure in
                                               the l_libname list.  */
  unsigned int l_faked : 1;                 /* Nonzero if this is a faked descriptor
                                               without associated file.  */
  unsigned int l_need_tls_init : 1;         /* Nonzero if GL(dl_init_static_tls)
                                               should be called on this link map
                                               when relocation finishes.  */
  unsigned int l_auditing : 1;              /* Nonzero if the DSO is used in auditing.  */
  unsigned int l_audit_any_plt : 1;         /* Nonzero if at least one audit module
                                               is interested in the PLT interception.*/
  unsigned int l_removed : 1;               /* Non-zero if the object cannot be used anymore
                                               since it is removed.  */
  unsigned int l_contiguous : 1;            /* Nonzero if inter-segment holes are
                                               mprotected or if no holes are present at
                                               all.  */
  unsigned int l_free_initfini : 1;         /* Nonzero if l_initfini can be
                                               freed, ie. not allocated with
                                               the dummy malloc in ld.so.  */
  unsigned int l_ld_readonly : 1;           /* Nonzero if dynamic section is readonly.  */
  unsigned int l_find_object_processed : 1; /* Zero if _dl_find_object_update
                                               needs to process this
                                               lt_library map.  */
  unsigned int l_tls_in_slotinfo : 1;       /* TLS slotinfo updated in dlopen.  */

  /* NODELETE status of the map.  Only valid for maps of type
     lt_loaded.  Lazy binding sets l_nodelete_active directly,
     potentially from signal handlers.  Initial loading of an
     DF_1_NODELETE object set l_nodelete_pending.  Relocation may
     set l_nodelete_pending as well.  l_nodelete_pending maps are
     promoted to l_nodelete_active status in the final stages of
     dlopen, prior to calling ELF constructors.  dlclose only
     refuses to unload l_nodelete_active maps, the pending status is
     ignored.  */
  bool l_nodelete_active;
  bool l_nodelete_pending;
};

extern char **_dl_argv;

int main(int argc, char *argv[]) {
  printf("==== COMM ====\n");
  char comm[64];
  prctl(PR_GET_NAME, comm);
  printf("comm=%s\n", comm);

  fprintf(stderr, "to stderr");

  int i;
  printf("==== ARGV ====\n");
  printf("argc=%d\n", argc);
  for (i = 0; i < argc; ++i)
    printf("%d:[%s]\n", i, argv[i]);

  printf("==== DL_ARGV ====\n");
  printf("&_dl_argv=%p  _dl_argv=%p\n", (void*)&_dl_argv, (void*)_dl_argv);
  for (i = 0; i < argc && _dl_argv; ++i)
    printf("%d:[%s]\n", i, _dl_argv[i]);

  printf("==== LINK MAP ====\n");
  extern struct r_debug _r_debug;
  struct link_map *m = _r_debug.r_map;

  //((struct link_map_ext *)m)->l_type = 0; // can restore dli_fname

  while (m) {
    printf("base=%p type=%d l_entry=%p name=%s\n", (void*)m->l_addr, ((struct link_map_ext *)m)->l_type,
           (void*)((struct link_map_ext *)m)->l_entry, m->l_name);
    m = m->l_next;
  }

  printf("==== AUXV ====\n");
  Dl_info info;
  printf("AT_EXECFN(%d)\t= %s\n", AT_EXECFN, (char *)getauxval(AT_EXECFN));
  printf("AT_BASE(%d)\t= %p  owner = %s\n", AT_BASE, (void *)getauxval(AT_BASE),
         get_owner((void *)getauxval(AT_BASE), &info));
  printf("AT_ENTRY(%d)\t= %p  owner = %s\n", AT_ENTRY, (void *)getauxval(AT_ENTRY),
         get_owner((void *)getauxval(AT_ENTRY), &info));
  printf("AT_PHDR(%d)\t= %p  owner = %s\n", AT_PHDR, (void *)getauxval(AT_PHDR),
         get_owner((void *)getauxval(AT_PHDR), &info));
  printf("AT_PHNUM(%d)\t= %lu\n", AT_PHNUM, getauxval(AT_PHNUM));
  printf("AT_SECURE(%d)\t= %lu\n", AT_SECURE, getauxval(AT_SECURE));
  printf("AT_SYSINFO_EHDR(%d)\t= %p  owner = %s\n", AT_SYSINFO_EHDR, (void *)getauxval(AT_SYSINFO_EHDR),
         get_owner((void *)getauxval(AT_SYSINFO_EHDR), &info));

  printf("==== MAP ====\n");
  char p[64];
  snprintf(p, 64, "cat /proc/%d/maps", getpid());
  system(p);
}
