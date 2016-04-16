#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>

#include "bcc_helpers.h"

static bool is_exe(const char *path)
{
	struct stat s;
	if (access(path, X_OK) < 0)
		return false;

	if (stat(path, &s) < 0)
		return false;

	return S_ISREG(s.st_mode);
}

char *bcc_procutils_which(const char *binpath)
{
	char buffer[4096];
	const char *PATH;

	if (strchr(binpath, '/'))
		return is_exe(binpath) ? strdup(binpath) : 0;

	if (!(PATH = getenv("PATH")))
		return 0;

	while (PATH) {
		const char *next = strchr(PATH, ':') ?: strchr(PATH, '\0');
		const size_t path_len = next - PATH;

		if (path_len) {
			memcpy(buffer, PATH, path_len);
			buffer[path_len] = '/';
			strcpy(buffer + path_len + 1, binpath);

			if (is_exe(buffer))
				return strdup(buffer);
		}

		PATH = *next ? (next + 1) : 0;
	}

	return 0;
}

int bcc_procutils_each_module(int pid, bcc_procutils_modulecb callback, void *payload)
{
	char procmap_filename[128];
    FILE *procmap;
	int ret;

    sprintf(procmap_filename, "/proc/%ld/maps", (long)pid);
    procmap = fopen(procmap_filename, "r");

    if (!procmap)
		return -1;

	do {
		char endline[4096];
		char perm[8], dev[8];
		long long begin, end, size, inode;

		ret = fscanf(procmap, "%llx-%llx %s %llx %s %llx",
				&begin, &end, perm, &size, dev, &inode);

		if (!fgets(endline, sizeof(endline), procmap))
			break;

		if (ret == 6) {
			char *mapname = endline;
			char *newline = strchr(endline, '\n');

			if (newline)
				newline[0] = '\0';

			while (isspace(mapname[0]))
				mapname++;

			if (strchr(perm, 'x') && mapname[0] && mapname[0] != '[')
				callback(mapname, (uint64_t)begin, (uint64_t)end, payload);
		}
    } while (ret && ret != EOF);

	fclose(procmap);
	return 0;
}

int bcc_procutils_each_ksym(bcc_procutils_ksymcb callback, void *payload)
{
	char line[2048];
    FILE *kallsyms = fopen("/proc/kallsyms", "r");

    if (!kallsyms)
		return -1;

	if (!fgets(line, sizeof(line), kallsyms)) {
		fclose(kallsyms);
		return -1;
	}

	while (fgets(line, sizeof(line), kallsyms)) {
		char *symname, *endsym;
		unsigned long long addr;

		addr = strtoull(line, &symname, 16);
		endsym = symname = symname + 3;

		while (*endsym && !isspace(*endsym))
			endsym++;

		*endsym = '\0';
		callback(symname, addr, payload);
	}

	fclose(kallsyms);
	return 0;
}

#define CACHE1_HEADER "ld.so-1.7.0"
#define CACHE1_HEADER_LEN (sizeof(CACHE1_HEADER) - 1)

#define CACHE2_HEADER "glibc-ld.so.cache"
#define CACHE2_HEADER_LEN (sizeof(CACHE2_HEADER) - 1)
#define CACHE2_VERSION "1.1"

struct ld_cache1_entry {
	int32_t flags;
	uint32_t key;
	uint32_t value;
};

struct ld_cache1 {
	char header[CACHE1_HEADER_LEN];
	uint32_t entry_count;
	struct ld_cache1_entry entries[0];
};

struct ld_cache2_entry {
	int32_t flags;
	uint32_t key;
	uint32_t value;
	uint32_t pad1_;
	uint64_t pad2_;
};

struct ld_cache2 {
	char header[CACHE2_HEADER_LEN];
	char version[3];
	uint32_t entry_count;
	uint32_t string_table_len;
	uint32_t pad_[5];
	struct ld_cache2_entry entries[0];
};

static int lib_cache_count;
static struct ld_lib {
	char *libname;
	char *path;
	int flags;
} *lib_cache;

static int read_cache1(const char *ld_map)
{
	struct ld_cache1 *ldcache = (struct ld_cache1 *)ld_map;
	const char *ldstrings = (const char *)(ldcache->entries + ldcache->entry_count);
	uint32_t i;

	lib_cache = (struct ld_lib *)malloc(ldcache->entry_count * sizeof(struct ld_lib));
	lib_cache_count = (int)ldcache->entry_count;

	for (i = 0; i < ldcache->entry_count; ++i) {
		const char *key = ldstrings + ldcache->entries[i].key;
		const char *val = ldstrings + ldcache->entries[i].value;
		const int flags = ldcache->entries[i].flags;

		lib_cache[i].libname = strdup(key);
		lib_cache[i].path = strdup(val);
		lib_cache[i].flags = flags;
	}
	return 0;
}

static int read_cache2(const char *ld_map)
{
	struct ld_cache2 *ldcache = (struct ld_cache2 *)ld_map;
	uint32_t i;

	if (memcmp(ld_map, CACHE2_HEADER, CACHE2_HEADER_LEN))
		return -1;

	lib_cache = (struct ld_lib *)malloc(ldcache->entry_count * sizeof(struct ld_lib));
	lib_cache_count = (int)ldcache->entry_count;

	for (i = 0; i < ldcache->entry_count; ++i) {
		const char *key = ld_map + ldcache->entries[i].key;
		const char *val = ld_map + ldcache->entries[i].value;
		const int flags = ldcache->entries[i].flags;

		lib_cache[i].libname = strdup(key);
		lib_cache[i].path = strdup(val);
		lib_cache[i].flags = flags;
	}
	return 0;
}

static int load_ld_cache(const char *cache_path)
{
	struct stat st;
	size_t ld_size;
	const char *ld_map;
	int ret, fd = open(cache_path, O_RDONLY);

	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0 || st.st_size < sizeof(struct ld_cache1)) {
		close(fd);
		return -1;
	}

	ld_size = st.st_size;
	ld_map = (const char *)mmap(NULL, ld_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ld_map == MAP_FAILED) {
		close(fd);
		return -1;
	}

	if (memcmp(ld_map, CACHE1_HEADER, CACHE1_HEADER_LEN) == 0) {
		const struct ld_cache1 *cache1 = (struct ld_cache1 *)ld_map;
		size_t cache1_len = sizeof(struct ld_cache1) +
			(cache1->entry_count * sizeof(struct ld_cache1_entry));
		cache1_len = (cache1_len + 0x7) & ~0x7ULL;

		if (ld_size > (cache1_len + sizeof(struct ld_cache2)))
			ret = read_cache2(ld_map + cache1_len);
		else
			ret = read_cache1(ld_map);
	} else {
		ret = read_cache2(ld_map);
	}

	munmap((void *)ld_map, ld_size);
	close(fd);
	return ret;
}

#define LD_SO_CACHE "/etc/ld.so.cache"
#define FLAG_TYPE_MASK 0x00ff
#define TYPE_ELF_LIBC6 0x0003
#define FLAG_ABI_MASK 0xff00
#define ABI_SPARC_LIB64 0x0100
#define ABI_IA64_LIB64 0x0200
#define ABI_X8664_LIB64 0x0300
#define ABI_S390_LIB64 0x0400
#define ABI_POWERPC_LIB64 0x0500

static bool match_so_flags(int flags)
{
	if ((flags & FLAG_TYPE_MASK) != TYPE_ELF_LIBC6)
		return false;

	switch (flags & FLAG_ABI_MASK) {
	case ABI_SPARC_LIB64:
	case ABI_IA64_LIB64:
	case ABI_X8664_LIB64:
	case ABI_S390_LIB64:
	case ABI_POWERPC_LIB64:
		return (sizeof(void *) == 8);
	}

	return true;
}

const char *bcc_procutils_which_so(const char *libname)
{
	const size_t soname_len = strlen(libname) + strlen("lib.so");
	char soname[soname_len + 1];
	int i;

	if (strchr(libname, '/'))
		return libname;

	if (lib_cache_count < 0)
		return NULL;

	if (!lib_cache_count && load_ld_cache(LD_SO_CACHE) < 0) {
		lib_cache_count = -1;
		return NULL;
	}

	snprintf(soname, soname_len + 1, "lib%s.so", libname);

	for (i = 0; i < lib_cache_count; ++i) {
		if (!strncmp(lib_cache[i].libname, soname, soname_len) &&
			match_so_flags(lib_cache[i].flags))
			return lib_cache[i].path;
	}
	return NULL;
}

static int _find_sym(const char *symname,
		uint64_t addr, uint64_t end, int flags, void *payload)
{
	struct bcc_symbol *sym = (struct bcc_symbol *)payload;
	if (!strcmp(sym->name, symname)) {
		sym->offset = addr;
		return -1;
	}
	return 0;
}

int bcc_resolve_symname(const char *module, const char *symname,
		const uint64_t addr, struct bcc_symbol *sym)
{
	uint64_t load_addr;

	sym->module = NULL;
	sym->name = NULL;
	sym->offset = 0x0;

	if (module == NULL)
		return -1;

	if (strchr(module, '/')) {
		sym->module = module;
	} else {
		sym->module = bcc_procutils_which_so(module);
	}

	if (sym->module == NULL)
		return -1;

	if (bcc_elf_loadaddr(sym->module, &load_addr) < 0) {
		sym->module = NULL;
		return -1;
	}

	sym->name = symname;
	sym->offset = addr;

	if (sym->name && sym->offset == 0x0)
		bcc_elf_foreach_sym(sym->module, _find_sym, sym);

	if (sym->offset == 0x0)
		return -1;

	sym->offset = (sym->offset - load_addr);
	return 0;
}
