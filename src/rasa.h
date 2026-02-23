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

/* RASA authorization entry structure */
struct rasa_entry {
	char		*asset;		/* AS-SET name */
	int		propagation;	/* propagation scope (0=unrestricted, 1=directOnly) */
};

/*
 * A single RASA (RPKI AS-SET Authorization) record
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
 * A Validated RASA Payload tree element.
 */
struct vrp_rasa {
	RB_ENTRY(vrp_rasa)	 entry;
	uint32_t		 asid;		/* authorized AS (if applicable) */
	char			*asset;		/* authorized AS-SET (if applicable) */
	int			 is_asid;	/* true if ASID, false if AS-SET */
	struct rasa_entry	*entries;	/* authorized AS-SET entries */
	size_t			 num_entries;
	time_t			 expires;
	int			 talid;
	unsigned int		 repoid;
};

/* Tree of validated RASA payloads sorted by asid/asset */
RB_HEAD(vrp_rasa_tree, vrp_rasa);
RB_PROTOTYPE(vrp_rasa_tree, vrp_rasa, entry, vrp_rasa_cmp);

/* Function prototypes */
void		 rasa_free(struct rasa *);
void		 rasa_buffer(struct ibuf *, const struct rasa *);
struct rasa	*rasa_parse(struct cert **, const char *, int,
		    const unsigned char *, size_t);
struct rasa	*rasa_read(struct ibuf *);
void		 rasa_insert_vrp_rasas(char *, struct vrp_rasa_tree *,
		    struct rasa *, struct repo *);

#endif /* !RASA_H */
