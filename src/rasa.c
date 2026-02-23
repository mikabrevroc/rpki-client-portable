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
#define MAX_RASA_SET_MEMBERS 10000

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



/*
 * RASA-SET Implementation
 * For AS-SET owners to declare member ASes
 */

/* Forward declaration */
typedef struct RasaSetContent_st RasaSetContent;

/* RasaSetContent ::= SEQUENCE */
struct RasaSetContent_st {
	ASN1_INTEGER	*version;
	ASN1_UTF8STRING	*asSetName;		/* AS-SET name */
	ASN1_INTEGER	*containingAS;		/* AS that owns this AS-SET */
	STACK_OF(ASN1_INTEGER)			*members;	/* Member ASes */
	STACK_OF(ASN1_UTF8STRING)		*nestedSets;	/* Nested AS-SETs (optional) */
	ASN1_UTF8STRING	*irrSource;		/* IRR source (optional) */
	ASN1_BIT_STRING	*flags;
	ASN1_GENERALIZEDTIME	*notBefore;
	ASN1_GENERALIZEDTIME	*notAfter;
};

/* ASN.1 template for RASA-SET */
ASN1_SEQUENCE(RasaSetContent) = {
	ASN1_EXP_OPT(RasaSetContent, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(RasaSetContent, asSetName, ASN1_UTF8STRING),
	ASN1_SIMPLE(RasaSetContent, containingAS, ASN1_INTEGER),
	ASN1_SEQUENCE_OF(RasaSetContent, members, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(RasaSetContent, nestedSets, ASN1_UTF8STRING),
	ASN1_EXP_OPT(RasaSetContent, irrSource, ASN1_UTF8STRING, 1),
	ASN1_EXP_OPT(RasaSetContent, flags, ASN1_BIT_STRING, 2),
	ASN1_SIMPLE(RasaSetContent, notBefore, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(RasaSetContent, notAfter, ASN1_GENERALIZEDTIME)
} ASN1_SEQUENCE_END(RasaSetContent);

IMPLEMENT_ASN1_FUNCTIONS(RasaSetContent);

/*
 * Parse RASA-SET eContent
 */
static int
rasa_set_parse_econtent(const char *fn, struct rasa_set *rasa_set,
    const unsigned char *d, size_t dsz)
{
	const unsigned char	*oder;
	RasaSetContent		*rasa_set_asn1 = NULL;
	int			 rc = 0;
	size_t			 i, membersz;

	oder = d;
	if ((rasa_set_asn1 = d2i_RasaSetContent(NULL, &d, dsz)) == NULL) {
		warnx("%s: RASA-SET: failed to parse RasaSetContent", fn);
		goto out;
	}
	if (d != oder + dsz) {
		warnx("%s: %td bytes trailing garbage in eContent", fn,
		    oder + dsz - d);
		goto out;
	}

	if (!valid_econtent_version(fn, rasa_set_asn1->version, 0))
		goto out;

	/* Parse AS-SET name */
	if (rasa_set_asn1->asSetName == NULL) {
		warnx("%s: RASA-SET: missing asSetName", fn);
		goto out;
	}
	rasa_set->as_set_name = strndup(
	    (char *)ASN1_STRING_get0_data(rasa_set_asn1->asSetName),
	    ASN1_STRING_length(rasa_set_asn1->asSetName));
	if (rasa_set->as_set_name == NULL)
		err(1, NULL);

	/* Parse containing AS */
	if (rasa_set_asn1->containingAS == NULL) {
		warnx("%s: RASA-SET: missing containingAS", fn);
		goto out;
	}
	if (!as_id_parse(rasa_set_asn1->containingAS, &rasa_set->containing_as)) {
		warnx("%s: RASA-SET: malformed containingAS", fn);
		goto out;
	}

	/* Parse members */
	if (rasa_set_asn1->members == NULL) {
		warnx("%s: RASA-SET: missing members", fn);
		goto out;
	}

	membersz = sk_ASN1_INTEGER_num(rasa_set_asn1->members);
	if (membersz == 0) {
		warnx("%s: RASA-SET: members is empty", fn);
		goto out;
	}

	if (membersz >= MAX_RASA_SET_MEMBERS) {
		warnx("%s: RASA-SET: too many members (more than %d)", fn,
		    MAX_RASA_SET_MEMBERS);
		goto out;
	}

	rasa_set->members = calloc(membersz, sizeof(rasa_set->members[0]));
	if (rasa_set->members == NULL)
		err(1, NULL);

	for (i = 0; i < membersz; i++) {
		const ASN1_INTEGER	*asid;

		asid = sk_ASN1_INTEGER_value(rasa_set_asn1->members, i);
		if (asid == NULL) {
			warnx("%s: RASA-SET: missing ASID in entry %zu", fn, i);
			goto out;
		}
		if (!as_id_parse(asid, &rasa_set->members[i].asid)) {
			warnx("%s: RASA-SET: malformed member ASID %zu", fn, i);
			goto out;
		}
		rasa_set->members[i].propagation = 0;
		rasa_set->num_members++;
	}

	/* Parse nested sets (optional) */
	if (rasa_set_asn1->nestedSets != NULL) {
		size_t nested_sz = sk_ASN1_UTF8STRING_num(rasa_set_asn1->nestedSets);
		if (nested_sz > 0) {
			rasa_set->nested_sets = calloc(nested_sz, sizeof(char *));
			if (rasa_set->nested_sets == NULL)
				err(1, NULL);

			for (i = 0; i < nested_sz; i++) {
				const ASN1_UTF8STRING	*nested;

				nested = sk_ASN1_UTF8STRING_value(rasa_set_asn1->nestedSets, i);
				if (nested == NULL)
					continue;
				rasa_set->nested_sets[i] = strndup(
				    (char *)ASN1_STRING_get0_data(nested),
				    ASN1_STRING_length(nested));
				if (rasa_set->nested_sets[i] == NULL)
					err(1, NULL);
				rasa_set->num_nested++;
			}
		}
	}

	/* Parse IRR source (optional) */
	if (rasa_set_asn1->irrSource != NULL) {
		rasa_set->irr_source = strndup(
		    (char *)ASN1_STRING_get0_data(rasa_set_asn1->irrSource),
		    ASN1_STRING_length(rasa_set_asn1->irrSource));
		if (rasa_set->irr_source == NULL)
			err(1, NULL);
	}

	/* Parse validity times */
	if (!x509_get_generalized_time(fn, "notBefore",
	    rasa_set_asn1->notBefore, &rasa_set->notbefore))
		goto out;

	if (!x509_get_generalized_time(fn, "notAfter",
	    rasa_set_asn1->notAfter, &rasa_set->notafter))
		goto out;

	rc = 1;
 out:
	RasaSetContent_free(rasa_set_asn1);
	return rc;
}

/*
 * Parse a full RASA-SET file
 */
struct rasa_set *
rasa_set_parse(struct cert **out_cert, const char *fn, int talid,
    const unsigned char *der, size_t len)
{
	struct rasa_set	*rasa_set;
	struct cert	*cert = NULL;
	size_t		 cmsz;
	unsigned char	*cms;
	time_t		 signtime = 0;
	int		 rc = 0;

	assert(*out_cert == NULL);

	/* Use rasa_set_oid for RASA-SET objects */
	extern ASN1_OBJECT	*rasa_set_oid;

	cms = cms_parse_validate(&cert, fn, talid, der, len, rasa_set_oid, &cmsz,
	    &signtime);
	if (cms == NULL)
		return NULL;

	if ((rasa_set = calloc(1, sizeof(*rasa_set))) == NULL)
		err(1, NULL);
	rasa_set->signtime = signtime;

	if (cert->num_ips > 0) {
		warnx("%s: superfluous IP Resources extension present", fn);
		goto out;
	}

	if (x509_any_inherits(cert->x509)) {
		warnx("%s: inherit elements not allowed in EE cert", fn);
		goto out;
	}

	if (!rasa_set_parse_econtent(fn, rasa_set, cms, cmsz))
		goto out;

	rasa_set->valid = 1;
	rasa_set->expires = x509_find_expires(cert->notafter, NULL, NULL);

	*out_cert = cert;
	cert = NULL;

	rc = 1;
 out:
	if (rc == 0) {
		rasa_set_free(rasa_set);
		rasa_set = NULL;
	}
	cert_free(cert);
	free(cms);
	return rasa_set;
}

/*
 * Free a RASA-SET pointer
 */
void
rasa_set_free(struct rasa_set *p)
{
	size_t	i;

	if (p == NULL)
		return;

	free(p->as_set_name);
	free(p->members);

	if (p->nested_sets != NULL) {
		for (i = 0; i < p->num_nested; i++)
			free(p->nested_sets[i]);
		free(p->nested_sets);
	}

	free(p->irr_source);
	free(p);
}

/*
 * Serialise parsed RASA-SET content
 */
void
rasa_set_buffer(struct ibuf *b, const struct rasa_set *p)
{
	size_t	i;

	io_simple_buffer(b, &p->valid, sizeof(p->valid));
	io_simple_buffer(b, &p->talid, sizeof(p->talid));
	io_str_buffer(b, p->as_set_name);
	io_simple_buffer(b, &p->containing_as, sizeof(p->containing_as));
	io_simple_buffer(b, &p->num_members, sizeof(size_t));

	for (i = 0; i < p->num_members; i++) {
		io_simple_buffer(b, &p->members[i].asid,
		    sizeof(p->members[i].asid));
		io_simple_buffer(b, &p->members[i].propagation,
		    sizeof(p->members[i].propagation));
	}

	io_simple_buffer(b, &p->num_nested, sizeof(size_t));
	for (i = 0; i < p->num_nested; i++)
		io_str_buffer(b, p->nested_sets[i]);

	io_str_buffer(b, p->irr_source);
	io_simple_buffer(b, &p->signtime, sizeof(p->signtime));
	io_simple_buffer(b, &p->expires, sizeof(p->expires));
	io_simple_buffer(b, &p->notbefore, sizeof(p->notbefore));
	io_simple_buffer(b, &p->notafter, sizeof(p->notafter));
}

/*
 * Read parsed RASA-SET content from descriptor
 */
struct rasa_set *
rasa_set_read(struct ibuf *b)
{
	struct rasa_set	*p;
	size_t		 i;

	if ((p = calloc(1, sizeof(struct rasa_set))) == NULL)
		err(1, NULL);

	io_read_buf(b, &p->valid, sizeof(p->valid));
	io_read_buf(b, &p->talid, sizeof(p->talid));
	io_read_str(b, &p->as_set_name);
	io_read_buf(b, &p->containing_as, sizeof(p->containing_as));
	io_read_buf(b, &p->num_members, sizeof(size_t));

	if (p->num_members > 0) {
		if ((p->members = calloc(p->num_members,
		    sizeof(p->members[0]))) == NULL)
			err(1, NULL);

		for (i = 0; i < p->num_members; i++) {
			io_read_buf(b, &p->members[i].asid,
			    sizeof(p->members[i].asid));
			io_read_buf(b, &p->members[i].propagation,
			    sizeof(p->members[i].propagation));
		}
	}

	io_read_buf(b, &p->num_nested, sizeof(size_t));
	if (p->num_nested > 0) {
		p->nested_sets = calloc(p->num_nested, sizeof(char *));
		if (p->nested_sets == NULL)
			err(1, NULL);
		for (i = 0; i < p->num_nested; i++)
			io_read_str(b, &p->nested_sets[i]);
	}

	io_read_str(b, &p->irr_source);
	io_read_buf(b, &p->signtime, sizeof(p->signtime));
	io_read_buf(b, &p->expires, sizeof(p->expires));
	io_read_buf(b, &p->notbefore, sizeof(p->notbefore));
	io_read_buf(b, &p->notafter, sizeof(p->notafter));

	return p;
}

/*
 * Insert a RASA-SET into the VRP RASA-SET tree
 */
void
rasa_set_insert_vrp(char *fn, struct vrp_rasa_set_tree *tree,
    struct rasa_set *rasa_set, struct repo *rp)
{
	struct vrp_rasa_set	*vr, *found;

	if ((vr = calloc(1, sizeof(*vr))) == NULL)
		err(1, NULL);

	vr->as_set_name = strdup(rasa_set->as_set_name);
	if (vr->as_set_name == NULL)
		err(1, NULL);

	vr->containing_as = rasa_set->containing_as;
	vr->talid = rasa_set->talid;
	vr->repoid = repo_id(rp);
	vr->expires = rasa_set->expires;
	vr->num_members = rasa_set->num_members;

	if (rasa_set->num_members > 0) {
		vr->members = calloc(rasa_set->num_members, sizeof(vr->members[0]));
		if (vr->members == NULL)
			err(1, NULL);
		memcpy(vr->members, rasa_set->members,
		    rasa_set->num_members * sizeof(vr->members[0]));
	}

	if ((found = RB_INSERT(vrp_rasa_set_tree, tree, vr)) != NULL) {
		/* Handle duplicate - keep the one with later expiry */
		if (found->expires < vr->expires) {
			free(found->as_set_name);
			free(found->members);
			RB_REMOVE(vrp_rasa_set_tree, tree, found);
			free(found);
			RB_INSERT(vrp_rasa_set_tree, tree, vr);
		} else {
			free(vr->as_set_name);
			free(vr->members);
			free(vr);
		}
	}

	repo_stat_inc(rp, rasa_set->talid, RTYPE_RASA_SET, STYPE_UNIQUE);
}

static inline int
vrp_rasa_set_cmp(struct vrp_rasa_set *a, struct vrp_rasa_set *b)
{
	return strcmp(a->as_set_name, b->as_set_name);
}

RB_GENERATE(vrp_rasa_set_tree, vrp_rasa_set, entry, vrp_rasa_set_cmp);
