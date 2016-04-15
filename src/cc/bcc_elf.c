#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "bcc_elf.h"
#define NT_STAPSDT 3

static int openelf(const char *path, Elf **elf_out, int *fd_out)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return -1;

	*fd_out = open(path, O_RDONLY);
	if (*fd_out < 0)
		return -1;

	*elf_out = elf_begin(*fd_out, ELF_C_READ, 0);
	if (*elf_out == 0) {
		close(*fd_out);
		return -1;
	}

	return 0;
}

static const char *
parse_stapsdt_note(struct bcc_elf_usdt *probe, const char *desc, int elf_class)
{
	if (elf_class == ELFCLASS32) {
		probe->pc = *((uint32_t *)(desc));
		probe->base_addr = *((uint32_t *)(desc + 4));
		probe->semaphore = *((uint32_t *)(desc + 8));
		desc = desc + 12;
	} else {
		probe->pc = *((uint64_t *)(desc));
		probe->base_addr = *((uint64_t *)(desc + 8));
		probe->semaphore = *((uint64_t *)(desc + 16));
		desc = desc + 24;
	}

	probe->provider = desc;
	desc += strlen(desc) + 1;

	probe->name = desc;
	desc += strlen(desc) + 1;

	probe->arg_fmt = desc;
	desc += strlen(desc) + 1;

	return desc;
}

static int do_note_segment(
	Elf_Scn *section, int elf_class,
	bcc_elf_probecb callback, const char *binpath, void *payload)
{
	Elf_Data *data = NULL;

	while ((data = elf_getdata(section, data)) != 0) {
		size_t offset = 0;
		GElf_Nhdr hdr;
		size_t name_off, desc_off;

		while ((offset = gelf_getnote(data, offset, &hdr, &name_off, &desc_off)) != 0) {
			const char *desc, *desc_end;
			struct bcc_elf_usdt probe;

			if (hdr.n_type != NT_STAPSDT)
				continue;

			if (hdr.n_namesz != 8)
				continue;

			if (memcmp(data->d_buf + name_off, "stapsdt", 8) != 0)
				continue;

			desc = (const char *)data->d_buf + desc_off;
			desc_end = desc + hdr.n_descsz;

			if (parse_stapsdt_note(&probe, desc, elf_class) == desc_end)
				callback(binpath, &probe, payload);
		}
	}
	return 0;
}

static int listprobes(Elf *e, bcc_elf_probecb callback, const char *binpath, void *payload)
{
	Elf_Scn *section = NULL;
	size_t stridx;
	int elf_class = gelf_getclass(e);

	if (elf_getshdrstrndx(e, &stridx) != 0)
		return -1;

	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;
		char *name;

		if (!gelf_getshdr(section, &header))
			continue;

		if (header.sh_type != SHT_NOTE)
			continue;

		name = elf_strptr(e, stridx, header.sh_name);
		if (name && !strcmp(name, ".note.stapsdt")) {
			if (do_note_segment(section, elf_class, callback, binpath, payload) < 0)
				return -1;
		}
	}

	return 0;
}

int bcc_elf_foreach_usdt(const char *path, bcc_elf_probecb callback, void *payload)
{
	Elf *e;
	int fd, res;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	res = listprobes(e, callback, path, payload);
	elf_end(e);
	close(fd);

	return res;
}



struct symtarget {
	const char *name;
	int binding;
	int type;
	uint64_t found_addr;
};

static int find_in_scn(
	Elf *e, Elf_Scn *section, size_t stridx, size_t symsize, struct symtarget *target)
{
	Elf_Data *data = NULL;

	while ((data = elf_getdata(section, data)) != 0) {
		size_t i, symcount = data->d_size / symsize;

		if (data->d_size % symsize)
			return -1;

		for (i = 0; i < symcount; ++i) {
			GElf_Sym sym;
			const char *name;

			if (!gelf_getsym(data, (int)i, &sym))
				continue;

			name = elf_strptr(e, stridx, sym.st_name);
			if (!name || strcmp(name, target->name))
				continue;

			if (target->binding >= 0 &&
				GELF_ST_BIND(sym.st_info) != target->binding)
				continue;

			if (target->type >= 0 &&
				GELF_ST_TYPE(sym.st_info) != target->type)
				continue;

			target->found_addr = sym.st_value;
			break;
		}
	}

	return 0;
}

static int findsymbol(Elf *e, struct symtarget *target)
{
	Elf_Scn *section = NULL;

	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;

		if (!gelf_getshdr(section, &header))
			continue;

		if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
			continue;

		if (find_in_scn(e, section, header.sh_link, header.sh_entsize, target) < 0)
			return -1;

		if (target->found_addr)
			return 0;
	}

	return -1; /* not found */
}

int bcc_elf_findsym(
	const char *path, const char *sym, int binding, int type, uint64_t *addr)
{
	Elf *e;
	int fd, res;
	struct symtarget target;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	target.name = sym;
	target.binding = binding;
	target.type = type;
	target.found_addr = 0x0;

	res = findsymbol(e, &target);
	elf_end(e);
	close(fd);

	*addr = target.found_addr;
	return res;
}


static int loadaddr(Elf *e, uint64_t *addr)
{
	size_t phnum, i;

	if (elf_getphdrnum(e, &phnum) != 0)
		return -1;

	for (i = 0; i < phnum; ++i) {
		GElf_Phdr header;

		if (!gelf_getphdr(e, (int)i, &header))
			continue;

		if (header.p_type != PT_LOAD)
			continue;

		*addr = (uint64_t)header.p_vaddr;
		return 0;
	}

	return -1;
}

int bcc_elf_loadaddr(const char *path, uint64_t *address)
{
	Elf *e;
	int fd, res;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	res = loadaddr(e, address);
	elf_end(e);
	close(fd);

	return res;
}

int bcc_elf_is_shared_obj(const char *path)
{
	Elf *e;
	GElf_Ehdr hdr;
	int fd, res = -1;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	if (gelf_getehdr(e, &hdr))
		res = (hdr.e_type == ET_DYN);

	elf_end(e);
	close(fd);

	return res;
}

#if 0
#include <stdio.h>

int main(int argc, char *argv[])
{
	uint64_t addr;
	if (bcc_elf_findsym(argv[1], argv[2], -1, STT_FUNC, &addr) < 0)
		return -1;

	printf("%s: %p\n", argv[2], (void *)addr);
	return 0;
}
#endif
