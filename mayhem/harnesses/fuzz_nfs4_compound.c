/* Decodes an NFSv4 COMPOUND request exactly as the nfsd worker does: xdr_COMPOUND4args over a memory stream. */
#include "config.h"
#include "nfsv41.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	XDR xdrs;
	COMPOUND4args args;
	char *buf;

	if (size > (1u << 20))
		return -1;
	buf = malloc(size ? size : 1);
	if (buf == NULL)
		return -1;
	memcpy(buf, data, size);
	memset(&args, 0, sizeof(args));
	xdrmem_create(&xdrs, buf, size, XDR_DECODE);
	(void)xdr_COMPOUND4args(&xdrs, &args);
	xdr_free((xdrproc_t)xdr_COMPOUND4args, &args);
	XDR_DESTROY(&xdrs);
	free(buf);
	return 0;
}
