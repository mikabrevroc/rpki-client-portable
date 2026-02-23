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

#ifndef RASA_H
#define RASA_H

#include <sys/tree.h>

#include <openssl/asn1.h>

/* Maximum number of authorized AS-SET entries per RASA object. */
#define MAX_RASA_ENTRIES 1000

/* Maximum number of members per RASA-SET object. */
#define MAX_RASA_SET_MEMBERS 10000

/* RASA authorization entry structure (for RASA-AUTH) */
struct rasa_entry {
	char		*asset;		/* AS-SET name */
	int		propagation;	/* propagation scope (0=unrestricted, 1=directOnly) */
};

/*
 * RASA-AUTH: AS declares authorization to be in AS-SETs
 */
struct rasa {
	int		 valid;	/* contained in issuer auth */
	int		 talid;		/* TAL the RASA is chained up to */
	uint32_t	 asid;		/* authorized AS (if is_asid is true) */
	char		*asset;		/* authorized AS-SET (if is_asid is false) */
	int		 is_asid;	/* true if authorizedEntity is ASID */
	struct rasa_entry *entries;	/* authorized AS-SET entries */
	size_t		 num_entries;	/* number of entries */
	time_t		 signtime;	/* CMS signing-time attribute */
	time_t		 expires;	/* when the signature path expires */
	time_t		 notbefore;	/* validity start */
	time_t		 notafter;	/* validity end */
};

/*
 * RASA-SET: AS-SET declares its member ASes
 */
struct rasa_set_member {
	uint32_t	asid;		/* Member AS number */
	int		propagation;	/* Propagation scope */
};

struct rasa_set {
	int		valid;		/* Validated */
	int		talid;		/* TAL ID */
	char		*as_set_name;	/* AS-SET name */
	uint32_t	containing_as;	/* AS that owns this AS-SET */
	struct rasa_set_member *members;	/* Member ASes */
	size_t		num_members;	/* Number of members */
	char		**nested_sets;	/* Nested AS-SET names */
	size_t		num_nested;	/* Number of nested sets */
	char		*irr_source;	/* IRR source (optional) */
	ASN1_BIT_STRING	*flags;		/* Flags (doNotInherit, authoritative) */
	time_t		signtime;	/* CMS signing time */
	time_t		expires;	/* Expiration */
	time_t		notbefore;	/* Validity start */
	time_t		notafter;	/* Validity end */
};

/*
 * A Validated RASA Payload tree element.
 */
struct vrp_rasa {
	RB_ENTRY(vrp_rasa)	 entry;
	uint32_t	 asid;		/* authorized AS (if applicable) */
	char		*asset;		/* authorized AS-SET (if applicable) */
	int		 is_asid;	/* true if ASID, false if AS-SET */
	struct rasa_entry	*entries;	/* authorized AS-SET entries */
	size_t		 num_entries;
	time_t		 expires;
	int		 talid;
	unsigned int	 repoid;
};

/*
 * A Validated RASA-SET tree element.
 */
struct vrp_rasa_set {
	RB_ENTRY(vrp_rasa_set)	 entry;
	char		*as_set_name;	/* AS-SET name */
	uint32_t	 containing_as;	/* Owning AS */
	struct rasa_set_member	*members;	/* Member ASes */
	size_t		 num_members;
	time_t		 expires;
	int		 talid;
	unsigned int	 repoid;
};

/* Tree of validated RASA payloads sorted by asid/asset */
RB_HEAD(vrp_rasa_tree, vrp_rasa);
RB_PROTOTYPE(vrp_rasa_tree, vrp_rasa, entry, vrp_rasa_cmp);

/* Tree of validated RASA-SET payloads sorted by AS-SET name */
RB_HEAD(vrp_rasa_set_tree, vrp_rasa_set);
RB_PROTOTYPE(vrp_rasa_set_tree, vrp_rasa_set, entry, vrp_rasa_set_cmp);

/* Function prototypes for RASA-AUTH */
void		 rasa_free(struct rasa *);
void		 rasa_buffer(struct ibuf *, const struct rasa *);
struct rasa	*rasa_parse(struct cert **, const char *, int,
		    const unsigned char *, size_t);
struct rasa	*rasa_read(struct ibuf *);
void		 rasa_insert_vrp_rasas(char *, struct vrp_rasa_tree *,
		    struct rasa *, struct repo *);

/* Function prototypes for RASA-SET */
void		 rasa_set_free(struct rasa_set *);
void		 rasa_set_buffer(struct ibuf *, const struct rasa_set *);
struct rasa_set	*rasa_set_parse(struct cert **, const char *, int,
		    const unsigned char *, size_t);
struct rasa_set	*rasa_set_read(struct ibuf *);
void		 rasa_set_insert_vrp(char *, struct vrp_rasa_set_tree *,
		    struct rasa_set *, struct repo *);

#endif /* !RASA_H */
