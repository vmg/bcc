#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

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

typedef void (*bcc_procutils_modulecb)(const char *, uint64_t, uint64_t);

int bcc_procutils_each_module(int pid, bcc_procutils_modulecb callback)
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
				callback(mapname, (uint64_t)begin, (uint64_t)end);
		}
    } while (ret && ret != EOF);

	return 0;
}
