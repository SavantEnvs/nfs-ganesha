/* Feeds a ganesha.conf-style file to the real config lexer/parser, then walks the tree (config_Print). */
#include "config.h"
#include "config_parsing.h"
#include "analyse.h"
#include "abstract_mem.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static int has_include_directive(const uint8_t *data, size_t size)
{
	static const char *const dirs[] = { "%include", "%dir", "%url", "%plugin" };
	size_t i, d;

	for (i = 0; i < size; i++) {
		if (data[i] != '%')
			continue;
		for (d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
			size_t n = strlen(dirs[d]);

			if (size - i >= n && memcmp(data + i, dirs[d], n) == 0)
				return 1;
		}
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct config_error_type err;
	config_file_t tree;
	char path[64];
	FILE *null;
	int fd;

	/* %include/%dir/%url/%plugin read other files or the network: not part of the fuzzed input */
	if (size > (1u << 18) || has_include_directive(data, size))
		return -1;

	fd = memfd_create("ganesha.conf", 0);
	if (fd < 0)
		return -1;
	if (size && write(fd, data, size) != (ssize_t)size) {
		close(fd);
		return -1;
	}
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

	if (!init_error_type(&err)) {
		close(fd);
		return -1;
	}
	tree = config_ParseFile(path, &err);
	if (tree != NULL) {
		struct config_root *root = tree;

		/* The parser's token table is a file-scope global that is only re-initialised once a parse
		 * saves its first token, and config_Free() leaves it dangling. A parse that saw no token (so
		 * no nodes either) must therefore neither print nor free through that stale table. */
		if (root->token_tree_initialized) {
			null = fopen("/dev/null", "w");
			if (null) {
				config_Print(null, tree);
				fclose(null);
			}
			config_Free(tree);
		} else {
			struct file_list *file, *next;

			for (file = root->files; file != NULL; file = next) {
				next = file->next;
				gsh_free(file->pathname, MEM_COMP_CONFIG);
				gsh_free(file, MEM_COMP_CONFIG);
			}
			gsh_free(root->root.filename, MEM_COMP_CONFIG);
			gsh_free(root->conf_dir, MEM_COMP_CONFIG);
			gsh_free(root, MEM_COMP_CONFIG);
		}
	}
	if (err.fp != NULL)
		fclose(err.fp);
	free(err.diag_buf);
	close(fd);
	return 0;
}
