/*
 * Copyright (c) 2025 Mikael Abrahamsson <mikael.abrahamsson@fitaliv.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

#include "extern.h"
#include "rpki-asn1.h"

#define MAX_RASA_ENTRIES 10000

/*
 * RASA eContent ASN.1 definitions
 * Using only built-in OpenSSL types
 * authorizedAS [0] and authorizedSet [1] are mutually exclusive
 */

/* Forward declaration */
typedef struct RasaAuthContent_st RasaAuthContent;

/* RasaAuthContent ::= SEQUENCE */
struct RasaAuthContent_st {
	ASN1_INTEGER	*version;
	ASN1_INTEGER	*authorizedAS;		/* [0] IMPLICIT ASID OPTIONAL */
	ASN1_UTF8STRING	*authorizedSet;		/* [1] IMPLICIT UTF8String OPTIONAL */
	STACK_OF(ASN1_UTF8STRING)			*authorizedIn;	/* AS-SET names */
	ASN1_BIT_STRING	*flags;
	ASN1_GENERALIZEDTIME	*notBefore;
	ASN1_GENERALIZEDTIME	*notAfter;
};

/* ASN.1 template for RASA - note the explicit tags for optional fields */
ASN1_SEQUENCE(RasaAuthContent) = {
	ASN1_EXP_OPT(RasaAuthContent, version, ASN1_INTEGER, 0),
	ASN1_EXP_OPT(RasaAuthContent, authorizedAS, ASN1_INTEGER, 1),
	ASN1_EXP_OPT(RasaAuthContent, authorizedSet, ASN1_UTF8STRING, 2),
	ASN1_SEQUENCE_OF(RasaAuthContent, authorizedIn, ASN1_UTF8STRING),
	ASN1_EXP_OPT(RasaAuthContent, flags, ASN1_BIT_STRING, 3),
	ASN1_SIMPLE(RasaAuthContent, notBefore, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(RasaAuthContent, notAfter, ASN1_GENERALIZEDTIME)
} ASN1_SEQUENCE_END(RasaAuthContent);

IMPLEMENT_ASN1_FUNCTIONS(RasaAuthContent);

/*
 * Parse the eContent of a RASA file.
 * Returns zero on failure, non-zero on success.
 */
static int
rasa_parse_econtent(const char *fn, struct rasa *rasa, const unsigned char *d,
    size_t dsz)
{
	const unsigned char	*oder;
	RasaAuthContent		*rasa_asn1 = NULL;
	int			 rc = 0;
	size_t			 i, entriesz;
	const ASN1_UTF8STRING	*asSetName;

	oder = d;
	if ((rasa_asn1 = d2i_RasaAuthContent(NULL, &d, dsz)) == NULL) {
		warnx("%s: RASA: failed to parse RasaAuthContent", fn);
		goto out;
	}
	if (d != oder + dsz) {
		warnx("%s: %td bytes trailing garbage in eContent", fn,
		    oder + dsz - d);
		goto out;
	}

	if (!valid_econtent_version(fn, rasa_asn1->version, 0))
		goto out;

	/* Parse authorizedEntity - either authorizedAS or authorizedSet */
	if (rasa_asn1->authorizedAS != NULL && rasa_asn1->authorizedSet != NULL) {
		warnx("%s: RASA: cannot have both authorizedAS and authorizedSet", fn);
		goto out;
	}

	if (rasa_asn1->authorizedAS != NULL) {
		/* authorizedAS */
		rasa->is_asid = 1;
		if (!as_id_parse(rasa_asn1->authorizedAS, &rasa->asid)) {
			warnx("%s: RASA: malformed authorizedAS", fn);
			goto out;
		}
	} else if (rasa_asn1->authorizedSet != NULL) {
		/* authorizedSet */
		rasa->is_asid = 0;
		rasa->asset = strndup(
		    (char *)ASN1_STRING_get0_data(rasa_asn1->authorizedSet),
		    ASN1_STRING_length(rasa_asn1->authorizedSet));
		if (rasa->asset == NULL)
			err(1, NULL);
	} else {
		warnx("%s: RASA: must have either authorizedAS or authorizedSet", fn);
		goto out;
	}

	/* Parse authorizedIn entries - iterate through the stack of UTF8Strings */
	if (rasa_asn1->authorizedIn == NULL) {
		warnx("%s: RASA: authorizedIn is empty", fn);
		goto out;
	}

	entriesz = sk_ASN1_UTF8STRING_num(rasa_asn1->authorizedIn);
	if (entriesz == 0) {
		warnx("%s: RASA: authorizedIn needs at least one entry", fn);
		goto out;
	}

	if (entriesz >= MAX_RASA_ENTRIES) {
		warnx("%s: RASA: too many entries (more than %d)", fn,
		    MAX_RASA_ENTRIES);
		goto out;
	}

	rasa->entries = calloc(entriesz, sizeof(rasa->entries[0]));
	if (rasa->entries == NULL)
		err(1, NULL);

	for (i = 0; i < entriesz; i++) {
		asSetName = sk_ASN1_UTF8STRING_value(rasa_asn1->authorizedIn, i);

		if (asSetName == NULL) {
			warnx("%s: RASA: missing asSetName in entry %zu", fn, i);
			goto out;
		}

		rasa->entries[i].asset = strndup(
		    (char *)ASN1_STRING_get0_data(asSetName),
		    ASN1_STRING_length(asSetName));
		if (rasa->entries[i].asset == NULL)
			err(1, NULL);

		/* Default propagation scope - unrestricted */
		rasa->entries[i].propagation = 0;

		rasa->num_entries++;
	}

	/* Parse validity times */
	if (!x509_get_generalized_time(fn, "notBefore",
	    rasa_asn1->notBefore, &rasa->notbefore))
		goto out;

	if (!x509_get_generalized_time(fn, "notAfter",
	    rasa_asn1->notAfter, &rasa->notafter))
		goto out;

	rc = 1;
 out:
	RasaAuthContent_free(rasa_asn1);
	return rc;
}

/*
 * Parse a full RASA file.
 * Returns the payload or NULL if the file was malformed.
 */
struct rasa *
rasa_parse(struct cert **out_cert, const char *fn, int talid,
    const unsigned char *der, size_t len)
{
	struct rasa	*rasa;
	struct cert	*cert = NULL;
	size_t		 cmsz;
	unsigned char	*cms;
	time_t		 signtime = 0;
	int		 rc = 0;

	assert(*out_cert == NULL);

	cms = cms_parse_validate(&cert, fn, talid, der, len, rasa_oid, &cmsz,
	    &signtime);
	if (cms == NULL)
		return NULL;

	if ((rasa = calloc(1, sizeof(*rasa))) == NULL)
		err(1, NULL);
	rasa->signtime = signtime;

	if (cert->num_ips > 0) {
		warnx("%s: superfluous IP Resources extension present", fn);
		goto out;
	}

	if (x509_any_inherits(cert->x509)) {
		warnx("%s: inherit elements not allowed in EE cert", fn);
		goto out;
	}

	if (!rasa_parse_econtent(fn, rasa, cms, cmsz))
		goto out;

	rasa->valid = 1;
	rasa->expires = x509_find_expires(cert->notafter, NULL, NULL);

	*out_cert = cert;
	cert = NULL;

	rc = 1;
 out:
	if (rc == 0) {
		rasa_free(rasa);
		rasa = NULL;
	}
	cert_free(cert);
	free(cms);
	return rasa;
}

/*
 * Free a RASA pointer.
 * Safe to call with NULL.
 */
void
rasa_free(struct rasa *p)
{
	size_t	i;

	if (p == NULL)
		return;

	for (i = 0; i < p->num_entries; i++)
		free(p->entries[i].asset);
	free(p->entries);
	free(p->asset);
	free(p);
}

/*
 * Serialise parsed RASA content.
 * See rasa_read() for the reader on the other side.
 */
void
rasa_buffer(struct ibuf *b, const struct rasa *p)
{
	size_t	i;

	io_simple_buffer(b, &p->valid, sizeof(p->valid));
	io_simple_buffer(b, &p->talid, sizeof(p->talid));
	io_simple_buffer(b, &p->asid, sizeof(p->asid));
	io_simple_buffer(b, &p->is_asid, sizeof(p->is_asid));
	io_str_buffer(b, p->asset);
	io_simple_buffer(b, &p->num_entries, sizeof(size_t));

	for (i = 0; i < p->num_entries; i++) {
		io_str_buffer(b, p->entries[i].asset);
		io_simple_buffer(b, &p->entries[i].propagation,
		    sizeof(p->entries[i].propagation));
	}

	io_simple_buffer(b, &p->signtime, sizeof(p->signtime));
	io_simple_buffer(b, &p->expires, sizeof(p->expires));
	io_simple_buffer(b, &p->notbefore, sizeof(p->notbefore));
	io_simple_buffer(b, &p->notafter, sizeof(p->notafter));
}

/*
 * Read parsed RASA content from descriptor.
 * See rasa_buffer() for writer.
 * Result must be passed to rasa_free().
 */
struct rasa *
rasa_read(struct ibuf *b)
{
	struct rasa	*p;
	size_t		 i;

	if ((p = calloc(1, sizeof(struct rasa))) == NULL)
		err(1, NULL);

	io_read_buf(b, &p->valid, sizeof(p->valid));
	io_read_buf(b, &p->talid, sizeof(p->talid));
	io_read_buf(b, &p->asid, sizeof(p->asid));
	io_read_buf(b, &p->is_asid, sizeof(p->is_asid));
	io_read_str(b, &p->asset);
	io_read_buf(b, &p->num_entries, sizeof(size_t));

	if (p->num_entries > 0) {
		if ((p->entries = calloc(p->num_entries,
		    sizeof(p->entries[0]))) == NULL)
			err(1, NULL);

		for (i = 0; i < p->num_entries; i++) {
			io_read_str(b, &p->entries[i].asset);
			io_read_buf(b, &p->entries[i].propagation,
			    sizeof(p->entries[i].propagation));
		}
	}

	io_read_buf(b, &p->signtime, sizeof(p->signtime));
	io_read_buf(b, &p->expires, sizeof(p->expires));
	io_read_buf(b, &p->notbefore, sizeof(p->notbefore));
	io_read_buf(b, &p->notafter, sizeof(p->notafter));

	return p;
}

/*
 * Insert a RASA into the VRP RASA tree.
 * This is a simplified version for initial implementation.
 */
void
rasa_insert_vrp_rasas(char *fn, struct vrp_rasa_tree *tree, struct rasa *rasa,
    struct repo *rp)
{
	struct vrp_rasa	*vr, *found;

	if ((vr = calloc(1, sizeof(*vr))) == NULL)
		err(1, NULL);

	vr->is_asid = rasa->is_asid;
	vr->asid = rasa->asid;
	if (rasa->asset != NULL) {
		vr->asset = strdup(rasa->asset);
		if (vr->asset == NULL)
			err(1, NULL);
	}
	vr->talid = rasa->talid;
	vr->repoid = repo_id(rp);
	vr->expires = rasa->expires;
	vr->num_entries = rasa->num_entries;

	if (rasa->num_entries > 0) {
		vr->entries = calloc(rasa->num_entries, sizeof(vr->entries[0]));
		if (vr->entries == NULL)
			err(1, NULL);
		memcpy(vr->entries, rasa->entries,
		    rasa->num_entries * sizeof(vr->entries[0]));
	}

	if ((found = RB_INSERT(vrp_rasa_tree, tree, vr)) != NULL) {
		/* Handle duplicate - keep the one with later expiry */
		if (found->expires < vr->expires) {
			free(found->asset);
			free(found->entries);
			RB_REMOVE(vrp_rasa_tree, tree, found);
			free(found);
			RB_INSERT(vrp_rasa_tree, tree, vr);
		} else {
			free(vr->asset);
			free(vr->entries);
			free(vr);
		}
	}

	repo_stat_inc(rp, rasa->talid, RTYPE_RASA, STYPE_UNIQUE);
}

static inline int
vrp_rasa_cmp(struct vrp_rasa *a, struct vrp_rasa *b)
{
	if (a->is_asid != b->is_asid)
		return a->is_asid - b->is_asid;

	if (a->is_asid) {
		if (a->asid > b->asid)
			return 1;
		if (a->asid < b->asid)
			return -1;
	} else {
		int cmp = strcmp(a->asset, b->asset);
		if (cmp != 0)
			return cmp;
	}

	return 0;
}

RB_GENERATE(vrp_rasa_tree, vrp_rasa, entry, vrp_rasa_cmp);
