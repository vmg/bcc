#ifndef LIBBCC_ELF_H
#define LIBBCC_ELF_H

#include <gelf.h>

struct bcc_elf_usdt {
	uint64_t pc;
	uint64_t base_addr;
	uint64_t semaphore;

	const char *provider;
	const char *name;
	const char *arg_fmt;
};

typedef void (*bcc_elf_probecb)(struct bcc_elf_usdt *, void *);

int bcc_elf_foreach_usdt(const char *path, bcc_elf_probecb callback, void *payload);
int bcc_elf_loadaddr(const char *path, uint64_t *address);
int bcc_elf_findsym(
	const char *path, const char *sym, int binding, int type, uint64_t *addr);

#endif
