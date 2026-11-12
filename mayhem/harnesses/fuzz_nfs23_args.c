/* Decodes the argument of one NFSv3 / MOUNT / NLM4 / RQUOTA / NFSACL procedure (selected by the first
 * input byte) with the same xdr_* routines the nfsd dispatch tables use. */
#include "config.h"
#include "nfs23.h"
#include "mount.h"
#include "nlm4.h"
#include "rquota.h"
#include "nfsacl.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

union fuzz_args {
	GETATTR3args getattr3;
	SETATTR3args setattr3;
	LOOKUP3args lookup3;
	ACCESS3args access3;
	READLINK3args readlink3;
	READ3args read3;
	WRITE3args write3;
	CREATE3args create3;
	MKDIR3args mkdir3;
	SYMLINK3args symlink3;
	MKNOD3args mknod3;
	REMOVE3args remove3;
	RMDIR3args rmdir3;
	RENAME3args rename3;
	LINK3args link3;
	READDIR3args readdir3;
	READDIRPLUS3args readdirplus3;
	FSSTAT3args fsstat3;
	FSINFO3args fsinfo3;
	PATHCONF3args pathconf3;
	COMMIT3args commit3;
	nlm4_testargs nlm_test;
	nlm4_lockargs nlm_lock;
	nlm4_cancargs nlm_cancel;
	nlm4_unlockargs nlm_unlock;
	nlm4_shareargs nlm_share;
	nlm4_sm_notifyargs nlm_notify;
	nlm4_free_allargs nlm_free_all;
	getquota_args getquota;
	setquota_args setquota;
	ext_getquota_args ext_getquota;
	ext_setquota_args ext_setquota;
	getaclargs getacl;
	setaclargs setacl;
	mnt3_dirpath mnt_path;
};

static const struct {
	xdrproc_t proc;
} decoders[] = {
	{ (xdrproc_t)xdr_GETATTR3args },   { (xdrproc_t)xdr_SETATTR3args },
	{ (xdrproc_t)xdr_LOOKUP3args },    { (xdrproc_t)xdr_ACCESS3args },
	{ (xdrproc_t)xdr_READLINK3args },  { (xdrproc_t)xdr_READ3args },
	{ (xdrproc_t)xdr_WRITE3args },     { (xdrproc_t)xdr_CREATE3args },
	{ (xdrproc_t)xdr_MKDIR3args },     { (xdrproc_t)xdr_SYMLINK3args },
	{ (xdrproc_t)xdr_MKNOD3args },     { (xdrproc_t)xdr_REMOVE3args },
	{ (xdrproc_t)xdr_RMDIR3args },     { (xdrproc_t)xdr_RENAME3args },
	{ (xdrproc_t)xdr_LINK3args },      { (xdrproc_t)xdr_READDIR3args },
	{ (xdrproc_t)xdr_READDIRPLUS3args }, { (xdrproc_t)xdr_FSSTAT3args },
	{ (xdrproc_t)xdr_FSINFO3args },    { (xdrproc_t)xdr_PATHCONF3args },
	{ (xdrproc_t)xdr_COMMIT3args },    { (xdrproc_t)xdr_nlm4_testargs },
	{ (xdrproc_t)xdr_nlm4_lockargs },  { (xdrproc_t)xdr_nlm4_cancargs },
	{ (xdrproc_t)xdr_nlm4_unlockargs }, { (xdrproc_t)xdr_nlm4_shareargs },
	{ (xdrproc_t)xdr_nlm4_sm_notifyargs }, { (xdrproc_t)xdr_nlm4_free_allargs },
	{ (xdrproc_t)xdr_getquota_args },  { (xdrproc_t)xdr_setquota_args },
	{ (xdrproc_t)xdr_ext_getquota_args }, { (xdrproc_t)xdr_ext_setquota_args },
	{ (xdrproc_t)xdr_getaclargs },     { (xdrproc_t)xdr_setaclargs },
	{ (xdrproc_t)xdr_dirpath },
};

#define NDEC (sizeof(decoders) / sizeof(decoders[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	XDR xdrs;
	union fuzz_args args;
	xdrproc_t proc;
	char *buf;

	if (size < 1 || size > (1u << 20))
		return -1;
	proc = decoders[data[0] % NDEC].proc;
	memset(&args, 0, sizeof(args));
	/* xdrmem needs a 4-byte aligned buffer; a private copy also gives ASan the exact bounds */
	buf = malloc(size - 1 ? size - 1 : 1);
	if (buf == NULL)
		return -1;
	memcpy(buf, data + 1, size - 1);
	xdrmem_create(&xdrs, buf, size - 1, XDR_DECODE);
	(void)proc(&xdrs, &args);
	xdr_free(proc, &args);
	XDR_DESTROY(&xdrs);
	free(buf);
	return 0;
}
