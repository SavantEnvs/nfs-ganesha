/* Known-answer tests for the code the harnesses fuzz: XDR decoders (NFSv4 COMPOUND, NFSv3, MOUNT) and the
 * ganesha.conf parser. Every check prints PASS/FAIL <name>; mayhem/test.sh counts those lines. */
#define _GNU_SOURCE
#include "config.h"
#include "nfsv41.h"
#include "nfs23.h"
#include "mount.h"
#include "config_parsing.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static int failures;

static void check(int ok, const char *name)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", name);
	if (!ok)
		failures++;
}

struct wire {
	unsigned char b[512];
	size_t n;
};

static void put32(struct wire *w, uint32_t v)
{
	w->b[w->n++] = v >> 24;
	w->b[w->n++] = v >> 16;
	w->b[w->n++] = v >> 8;
	w->b[w->n++] = v;
}

static void putstr(struct wire *w, const char *s)
{
	size_t len = strlen(s);

	put32(w, len);
	memcpy(w->b + w->n, s, len);
	w->n += len;
	while (w->n & 3)
		w->b[w->n++] = 0;
}

static void *aligned_copy(const struct wire *w, size_t len)
{
	void *p = malloc(len ? len : 1);

	memcpy(p, w->b, len);
	return p;
}

static void test_compound(void)
{
	struct wire w = { .n = 0 };
	COMPOUND4args args;
	XDR x;
	char *buf;
	bool ok;

	putstr(&w, "mayh");
	put32(&w, 1);
	put32(&w, 3);
	put32(&w, NFS4_OP_PUTROOTFH);
	put32(&w, NFS4_OP_LOOKUP);
	putstr(&w, "foo");
	put32(&w, NFS4_OP_GETFH);

	buf = aligned_copy(&w, w.n);
	memset(&args, 0, sizeof(args));
	xdrmem_create(&x, buf, w.n, XDR_DECODE);
	ok = xdr_COMPOUND4args(&x, &args);
	check(ok, "compound4 decode succeeds");
	check(ok && args.tag.utf8string_len == 4 &&
		      memcmp(args.tag.utf8string_val, "mayh", 4) == 0,
	      "compound4 tag is 'mayh'");
	check(ok && args.minorversion == 1, "compound4 minorversion is 1");
	check(ok && args.argarray.argarray_len == 3, "compound4 has 3 ops");
	check(ok && args.argarray.argarray_val[0].argop == NFS4_OP_PUTROOTFH &&
		      args.argarray.argarray_val[1].argop == NFS4_OP_LOOKUP &&
		      args.argarray.argarray_val[2].argop == NFS4_OP_GETFH,
	      "compound4 opcodes are PUTROOTFH LOOKUP GETFH");
	check(ok && args.argarray.argarray_val[1].nfs_argop4_u.oplookup.objname.utf8string_len == 3 &&
		      memcmp(args.argarray.argarray_val[1].nfs_argop4_u.oplookup.objname.utf8string_val,
			     "foo", 3) == 0,
	      "compound4 LOOKUP component is 'foo'");
	xdr_free((xdrproc_t)xdr_COMPOUND4args, &args);
	XDR_DESTROY(&x);
	free(buf);

	/* the same stream cut inside the LOOKUP component must be rejected */
	buf = aligned_copy(&w, w.n - 12);
	memset(&args, 0, sizeof(args));
	xdrmem_create(&x, buf, w.n - 12, XDR_DECODE);
	ok = xdr_COMPOUND4args(&x, &args);
	check(!ok, "compound4 truncated stream is rejected");
	xdr_free((xdrproc_t)xdr_COMPOUND4args, &args);
	XDR_DESTROY(&x);
	free(buf);
}

static void test_lookup3(void)
{
	struct wire w = { .n = 0 };
	LOOKUP3args args;
	XDR x;
	char *buf;
	bool ok;

	put32(&w, 8);
	memcpy(w.b + w.n, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
	w.n += 8;
	putstr(&w, "hello");

	buf = aligned_copy(&w, w.n);
	memset(&args, 0, sizeof(args));
	xdrmem_create(&x, buf, w.n, XDR_DECODE);
	ok = xdr_LOOKUP3args(&x, &args);
	check(ok, "lookup3 decode succeeds");
	check(ok && args.what.dir.data.data_len == 8 &&
		      memcmp(args.what.dir.data.data_val, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0,
	      "lookup3 file handle is 01..08");
	check(ok && args.what.name != NULL && strcmp(args.what.name, "hello") == 0,
	      "lookup3 name is 'hello'");
	xdr_free((xdrproc_t)xdr_LOOKUP3args, &args);
	XDR_DESTROY(&x);
	free(buf);

	/* a 100-byte file handle exceeds NFS3_FHSIZE (64) */
	memset(&w, 0, sizeof(w));
	put32(&w, 100);
	memset(w.b + w.n, 0xaa, 100);
	w.n += 100;
	putstr(&w, "x");
	buf = aligned_copy(&w, w.n);
	memset(&args, 0, sizeof(args));
	xdrmem_create(&x, buf, w.n, XDR_DECODE);
	ok = xdr_LOOKUP3args(&x, &args);
	check(!ok, "lookup3 oversized file handle is rejected");
	xdr_free((xdrproc_t)xdr_LOOKUP3args, &args);
	XDR_DESTROY(&x);
	free(buf);
}

static void test_mount(void)
{
	struct wire w = { .n = 0 };
	mnt3_dirpath path = NULL;
	XDR x;
	char *buf;
	bool ok;

	putstr(&w, "/export/data");
	buf = aligned_copy(&w, w.n);
	xdrmem_create(&x, buf, w.n, XDR_DECODE);
	ok = xdr_dirpath(&x, &path);
	check(ok && path != NULL && strcmp(path, "/export/data") == 0,
	      "mount dirpath is '/export/data'");
	xdr_free((xdrproc_t)xdr_dirpath, &path);
	XDR_DESTROY(&x);
	free(buf);
}

static char diag[512];

static char *print_config(const char *text, struct config_error_type *err)
{
	char *out = NULL;
	size_t outlen = 0;
	char path[64];
	config_file_t tree;
	FILE *mem;
	int fd = memfd_create("ganesha.conf", 0);

	if (write(fd, text, strlen(text)) < 0)
		return NULL;
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	if (!init_error_type(err))
		return NULL;
	tree = config_ParseFile(path, err);
	mem = open_memstream(&out, &outlen);
	if (tree != NULL) {
		config_Print(mem, tree);
		config_Free(tree);
	}
	fclose(mem);
	fflush(err->fp);
	snprintf(diag, sizeof(diag), "%s", err->diag_buf ? err->diag_buf : "");
	fclose(err->fp);
	free(err->diag_buf);
	close(fd);
	return out;
}

static void test_config(void)
{
	static const char good[] =
		"NFS_CORE_PARAM {\n  NFS_Port = 2049;\n  Bind_addr = 10.1.2.3;\n}\n"
		"EXPORT {\n  Export_Id = 7;\n  Path = /srv/data;\n  Pseudo = /data;\n"
		"  CLIENT { Clients = 10.0.0.0/8; Access_Type = RW; }\n}\n";
	struct config_error_type err;
	char *out;

	out = print_config(good, &err);
	check(out && strstr(out, "BLOCK_COUNT> 2 ") != NULL, "config has 2 top-level blocks");
	check(out && strstr(out, "<TOKEN>NFS_CORE_PARAM</TOKEN>") != NULL, "config token NFS_CORE_PARAM saved");
	check(out && strstr(out, "'2049'") != NULL,
	      "config value 2049 parsed");
	check(out && strstr(out, "'/srv/data'") != NULL, "config Path value parsed");
	check(!err.scan && !err.parse, "config good input has no parse error");
	free(out);

	out = print_config("EXPORT {\n  Path = /x;\n", &err);
	printf("diag: %s\n", diag);
	check(strcasestr(diag, "syntax error") != NULL, "config unterminated block reports a syntax error");
	free(out);
}

int main(void)
{
	test_compound();
	test_lookup3();
	test_mount();
	test_config();
	printf("selftest failures=%d\n", failures);
	return failures ? 1 : 0;
}
