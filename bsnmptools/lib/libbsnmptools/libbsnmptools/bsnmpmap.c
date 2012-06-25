/*-
 * Copyright (c) 2006 The FreeBSD Project
 * All rights reserved.
 *
 * Author: Shteryana Shopova <soc-shteryana@freebsd.org>
 *
 * Redistribution of this software and documentation and use in source and
 * binary forms, with or without modification, are permitted provided that
 * the following conditions are met:
 *
 * 1. Redistributions of source code or documentation must retain the above
 *    copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <ctype.h>
#if defined(HAVE_ERR_H)
#include <err.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
#include <unistd.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>
#include <bsnmp/snmpclient.h>
#if !defined(HAVE_STRLCPY) || !defined(HAVE_ERR_H)
#include <bsnmp/support.h>    /* err, errx, strlcpy, warn, warnx */
#endif
#include "bsnmptc.h"
#include "bsnmptools.h"

static int debug_on = 0;

#define DEBUG_BSNMPMAP	if (debug_on) warnx

/*
 * if argument > 0, enable debug
 * if argument = 0, disable debug
 * if argument < 0, does nothing
 * returns: current debug status (0 = off, 1 = on)
 */
int
snmp_mapping_debug(int on_off)
{
	if (on_off >= 0)
		debug_on = 1;
	return (debug_on);
}

static void
free_all(struct snmp_mappings *m)
{
	if (m == NULL)
		return;
	if (m->snmp_nodelist)
		free(m->snmp_nodelist);
	if (m->snmp_octlist)
		free(m->snmp_octlist);
	if (m->snmp_oidlist)
		free(m->snmp_oidlist);
	if (m->snmp_iplist)
		free(m->snmp_iplist);
	if (m->snmp_ticklist)
		free(m->snmp_ticklist);
	if (m->snmp_cntlist)
		free(m->snmp_cntlist);
	if (m->snmp_gaugelist)
		free(m->snmp_gaugelist);
	if (m->snmp_cnt64list)
		free(m->snmp_cnt64list);
	if (m->snmp_enumlist)
		free(m->snmp_enumlist);
	if (m->snmp_tablelist)
		free(m->snmp_tablelist);
	if (m->snmp_tclist)
		free(m->snmp_tclist);

	free(m);
	return;
}
/* allocate memory and initialize list */
struct snmp_mappings *
snmp_mapping_init(void)
{
	struct snmp_mappings 	*mapping;

	if ((mapping = snmp_malloc(sizeof(struct snmp_mappings))) == NULL) {
        	return (NULL);
	}
	memset(mapping, 0, sizeof(struct snmp_mappings));

	if ((mapping->snmp_nodelist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
	SLIST_INIT((mapping->snmp_nodelist));

	if ((mapping->snmp_intlist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
   	SLIST_INIT((mapping->snmp_intlist));

	if ((mapping->snmp_octlist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_octlist));

	if ((mapping->snmp_oidlist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_oidlist));

	if ((mapping->snmp_iplist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_iplist));

	if ((mapping->snmp_ticklist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_ticklist));

        if ((mapping->snmp_cntlist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_cntlist));

	if ((mapping->snmp_gaugelist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_gaugelist));

	if ((mapping->snmp_cnt64list = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_cnt64list));

	if ((mapping->snmp_enumlist = snmp_malloc(sizeof(struct snmp_mapping))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_enumlist));

	if ((mapping->snmp_tablelist = snmp_malloc(sizeof(struct snmp_table_index))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_tablelist));

	if ((mapping->snmp_tclist = snmp_malloc(sizeof(struct snmp_enum_tc))) == NULL) {
		free_all(mapping);
		return (NULL);
	}
        SLIST_INIT((mapping->snmp_tclist));

	return (mapping);
}

#define		snmp_nodelist(tool) 	(tool).mappings->snmp_nodelist
#define 	snmp_intlist(tool) 	(tool).mappings->snmp_intlist
#define 	snmp_octlist(tool) 	(tool).mappings->snmp_octlist
#define 	snmp_oidlist(tool) 	(tool).mappings->snmp_oidlist
#define 	snmp_iplist(tool) 	(tool).mappings->snmp_iplist
#define 	snmp_ticklist(tool) 	(tool).mappings->snmp_ticklist
#define 	snmp_cntlist(tool) 	(tool).mappings->snmp_cntlist
#define 	snmp_gaugelist(tool) 	(tool).mappings->snmp_gaugelist
#define 	snmp_cnt64list(tool) 	(tool).mappings->snmp_cnt64list
#define 	snmp_enumlist(tool) 	(tool).mappings->snmp_enumlist
#define		snmp_tablelist(tool)	(tool).mappings->snmp_tablelist
#define		snmp_tclist(tool)	(tool).mappings->snmp_tclist

void
enum_pairs_free(struct enum_pairs *headp)
{
	struct enum_pair *e, *e1;

	if (headp == NULL)
	       return;

	e = STAILQ_FIRST(headp);
	while (e != NULL) {
		e1 = STAILQ_NEXT(e, link);
		if (e->enum_str)
			free(e->enum_str);
		free(e);
		e = e1;
	}

	free(headp);
}
void
snmp_mapping_entryfree(struct snmp_oid2str *entry)
{
	if (entry->string)
		free(entry->string);

	if (entry->tc == SNMP_TC_OWN)
		enum_pairs_free(entry->snmp_enum);

	free(entry);
}
static void
snmp_mapping_listfree(struct snmp_mapping *headp)
{
	struct snmp_oid2str *p;

	while (!SLIST_EMPTY(headp)) {

		p = SLIST_FIRST(headp);
		SLIST_REMOVE_HEAD(headp, link);

		if (p->string)
			free(p->string);

		if (p->tc == SNMP_TC_OWN)
			enum_pairs_free(p->snmp_enum);
		free(p);
	}
}
void
snmp_index_listfree(struct snmp_idxlist *headp)
{
	struct index *i, *i1;

	i = STAILQ_FIRST(headp);
	while (i != NULL) {
		i1 = STAILQ_NEXT(i, link);
		enum_pairs_free(i->snmp_enum);
		free(i);
		i = i1;
	}
	STAILQ_INIT(headp);
}
static void
snmp_mapping_table_listfree(struct snmp_table_index *headp)
{
	struct snmp_index_entry *t;

	while (!SLIST_EMPTY(headp)) {

		t = SLIST_FIRST(headp);
		SLIST_REMOVE_HEAD(headp, link);

		if (t->string)
			free(t->string);

		snmp_index_listfree(&(t->index_list));
		free(t);
	}
}
static void
snmp_enumtc_listfree(struct snmp_enum_tc *headp)
{
	struct enum_type *t;

	while (!SLIST_EMPTY(headp)) {

		t = SLIST_FIRST(headp);
		SLIST_REMOVE_HEAD(headp, link);

		if (t->name)
			free(t->name);
		enum_pairs_free(t->snmp_enum);
		free(t);
	}
}
int
snmp_mapping_free(struct snmp_toolinfo *tool)
{
	if (tool->mappings == NULL)
		return (-1);

	if (snmp_nodelist(*tool)) {
		snmp_mapping_listfree(snmp_nodelist(*tool));
		free(snmp_nodelist(*tool));
	}

	if (snmp_intlist(*tool)) {
		snmp_mapping_listfree(snmp_intlist(*tool));
		free(snmp_intlist(*tool));
	}

	if (snmp_octlist(*tool)) {
		snmp_mapping_listfree(snmp_octlist(*tool));
		free(snmp_octlist(*tool));
	}

	if (snmp_oidlist(*tool)) {
		snmp_mapping_listfree(snmp_oidlist(*tool));
		free(snmp_oidlist(*tool));
	}

	if (snmp_iplist(*tool)) {
		snmp_mapping_listfree(snmp_iplist(*tool));
		free(snmp_iplist(*tool));
	}

	if (snmp_ticklist(*tool)) {
		snmp_mapping_listfree(snmp_ticklist(*tool));
		free(snmp_ticklist(*tool));
	}

	if (snmp_cntlist(*tool)) {
		snmp_mapping_listfree(snmp_cntlist(*tool));
		free(snmp_cntlist(*tool));
	}

	if (snmp_gaugelist(*tool)) {
		snmp_mapping_listfree(snmp_gaugelist(*tool));
		free(snmp_gaugelist(*tool));
	}

	if (snmp_cnt64list(*tool)) {
		snmp_mapping_listfree(snmp_cnt64list(*tool));
		free(snmp_cnt64list(*tool));
	}

	if (snmp_enumlist(*tool)) {
		snmp_mapping_listfree(snmp_enumlist(*tool));
		free(snmp_enumlist(*tool));
	}

	if (snmp_tablelist(*tool)) {
		snmp_mapping_table_listfree(snmp_tablelist(*tool));
		free(snmp_tablelist(*tool));
	}

	if (snmp_tclist(*tool)) {
		snmp_enumtc_listfree(snmp_tclist(*tool));
		free(snmp_tclist(*tool));
	}

	free(tool->mappings);

	return (0);
}
static void
snmp_dump_enumpairs(struct enum_pairs *headp)
{
	struct enum_pair *entry;

	if (headp == NULL)
		return;

	fprintf(stderr,"enums: ");
	STAILQ_FOREACH(entry, headp, link)
		fprintf(stderr,"%d - %s, ", entry->enum_val,
		(entry->enum_str == NULL)?"NULL":entry->enum_str);

	fprintf(stderr,"; ");
}
void
snmp_dump_oid2str(struct snmp_oid2str *entry)
{
	char buf[ASN_OIDSTRLEN];

	if (entry != NULL) {
		memset(buf,0,sizeof(buf));
		asn_oid2str_r(&(entry->var),buf);
		DEBUG_BSNMPMAP("%s - %s - %d - %d - %d", buf, entry->string,
				  entry->syntax,entry->access,entry->strlen);
		snmp_dump_enumpairs(entry->snmp_enum);
		DEBUG_BSNMPMAP("%s \n", (entry->table_idx == NULL)?\
				"No table":entry->table_idx->string);
	}
}
static void
snmp_dump_indexlist(struct snmp_idxlist *headp)
{
	struct index *entry;

	if (headp == NULL)
		return;

	STAILQ_FOREACH(entry, headp, link) {
		fprintf(stderr,"%d, ", entry->syntax);
		snmp_dump_enumpairs(entry->snmp_enum);
	}

	fprintf(stderr,"\n");
}
/* Initialize the enum pairs list of a oid2str entry */
struct enum_pairs *
enum_pairs_init(void)
{
	struct enum_pairs *snmp_enum;

	if ((snmp_enum = snmp_malloc(sizeof(struct enum_pairs))) == NULL) {
		return (NULL);
	}

	memset(snmp_enum, 0, sizeof(struct enum_pairs));
	return (snmp_enum);
}
/*
 * Given a number and string, allocate memory for a (int, string) pair and add it
 * to the given oid2str mapping entry's enum pairs list.
 */
int
enum_pair_insert(struct enum_pairs *headp, int32_t enum_val, char *enum_str)
{
	struct enum_pair *e_new;

	if ((e_new = snmp_malloc(sizeof(struct enum_pair))) == NULL) {
		return (-1);
	}

	memset(e_new, 0, sizeof(struct enum_pair));

	if ((e_new->enum_str = snmp_malloc(strlen(enum_str) + 1)) == NULL) {
		free(e_new);
		return (-1);
	}

	e_new->enum_val = enum_val;
	strlcpy(e_new->enum_str, enum_str, strlen(enum_str) + 1);

	if (STAILQ_EMPTY(headp))
		STAILQ_INSERT_HEAD(headp, e_new, link);
	else
		STAILQ_INSERT_TAIL(headp, e_new, link);

	return (1);

}
/*
 * Insert an entry in a list - entries are lexicographicaly order by asn_oid.
 * Returns 1 on success, -1 if list is not initialized, 0 if a matching oid already
 * exists. Error cheking is left to calling function.
 */
static int
snmp_mapping_insert(struct snmp_mapping *headp, struct snmp_oid2str *entry)
{
	int 	rc;
	struct snmp_oid2str *temp, *prev;

	if (entry == NULL)
		return(-1);

	if ((prev = SLIST_FIRST(headp)) == NULL ||
		asn_compare_oid(&(entry->var), &(prev->var)) < 0) {
	    SLIST_INSERT_HEAD(headp, entry, link);
	    return (1);
	} else
	    rc = -1;	/* make the compiler happy :/ */

	SLIST_FOREACH(temp, headp, link) {
	    if ((rc = asn_compare_oid(&(entry->var), &(temp->var))) <= 0)
		break;
	    prev = temp;
	    rc = -1;
	}

	switch (rc) {
	    case 0:
		/* ops, we have matching asn_oid's - hope the rest info also matches */
		if (strncmp(temp->string, entry->string, entry->strlen)) {
		    warnx("Matching OIDs with different string mapping"
			 " - old -%s, new - %s", temp->string, entry->string);
		    return (-1);
		}
		/*
		 * Ok, we have that already.
		 * As long as the strings match - don't complain.
		 */
		return (0);
	    case 1:
		SLIST_INSERT_AFTER(temp, entry, link);
		break;
	    case -1:
		SLIST_INSERT_AFTER(prev, entry, link);
		break;
	    default:
		/* NOTREACHED */
		return (-1);
	}

	return (1);
}
int
snmp_node_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_nodelist(*tool))
		return (snmp_mapping_insert(snmp_nodelist(*tool),entry));

	return (-1);
}
static int
snmp_int_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{

	if (snmp_intlist(*tool))
		return (snmp_mapping_insert(snmp_intlist(*tool),entry));

	return (-1);
}
static int
snmp_oct_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_octlist(*tool))
		return (snmp_mapping_insert(snmp_octlist(*tool),entry));

	return (-1);
}
static int
snmp_oid_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_oidlist(*tool))
		return (snmp_mapping_insert(snmp_oidlist(*tool),entry));

	return (-1);
}
static int
snmp_ip_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_iplist(*tool))
		return (snmp_mapping_insert(snmp_iplist(*tool),entry));

	return (-1);
}
static int
snmp_tick_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_ticklist(*tool))
		return (snmp_mapping_insert(snmp_ticklist(*tool),entry));

	return (-1);
}
static int
snmp_cnt_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_cntlist(*tool))
		return (snmp_mapping_insert(snmp_cntlist(*tool),entry));

	return (-1);
}
static int
snmp_gauge_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_gaugelist(*tool))
		return (snmp_mapping_insert(snmp_gaugelist(*tool),entry));

	return (-1);
}
static int
snmp_cnt64_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_cnt64list(*tool))
		return (snmp_mapping_insert(snmp_cnt64list(*tool),entry));

	return (-1);
}
int
snmp_enum_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{
	if (snmp_enumlist(*tool))
		return (snmp_mapping_insert(snmp_enumlist(*tool),entry));

	return (-1);
}
int
snmp_leaf_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry)
{

	switch (entry->syntax) {
		case SNMP_SYNTAX_INTEGER:
			return (snmp_int_insert(tool, entry));
		case SNMP_SYNTAX_OCTETSTRING:
			return (snmp_oct_insert(tool, entry));
		case SNMP_SYNTAX_OID:
			return (snmp_oid_insert(tool, entry));
		case SNMP_SYNTAX_IPADDRESS:
			return (snmp_ip_insert(tool, entry));
		case SNMP_SYNTAX_COUNTER:
			return (snmp_cnt_insert(tool, entry));
		case SNMP_SYNTAX_GAUGE:
			return (snmp_gauge_insert(tool, entry));
		case SNMP_SYNTAX_TIMETICKS:
			return (snmp_tick_insert(tool, entry));
		case SNMP_SYNTAX_COUNTER64:
			return (snmp_cnt64_insert(tool, entry));
		default:
			break;
	}

	return (-1);
}
static int
snmp_index_insert(struct snmp_idxlist *headp, struct index *idx)
{

	if (headp == NULL || idx == NULL)
		return (-1);

	if (STAILQ_EMPTY(headp))
		STAILQ_INSERT_HEAD(headp, idx, link);
	else
		STAILQ_INSERT_TAIL(headp, idx, link);

	return (1);
}
int
snmp_syntax_insert(struct snmp_idxlist *headp, struct enum_pairs *enums,
	enum snmp_syntax syntax, enum snmp_tc tc)
{
	struct index *idx;

	if ((idx = snmp_malloc(sizeof(struct index))) == NULL) {
		return (-1);
	}

	memset(idx, 0, sizeof(struct index));

	if (snmp_index_insert(headp, idx) < 0) {
		free(idx);
		return (-1);
	}

	idx->syntax = syntax;
	idx->snmp_enum = enums;
	idx->tc = tc;

	return (1);
}
int
snmp_table_insert(struct snmp_toolinfo *tool, struct snmp_index_entry *entry)
{
	int 	rc;
	struct snmp_index_entry *temp, *prev;

	if (snmp_tablelist(*tool) == NULL || entry == NULL)
	    return(-1);

	if ((prev = SLIST_FIRST(snmp_tablelist(*tool))) == NULL ||
		asn_compare_oid(&(entry->var), &(prev->var)) < 0) {
	    SLIST_INSERT_HEAD(snmp_tablelist(*tool), entry, link);
	    return (1);
	} else
	    rc = -1;    /* make the compiler happy :/ */

	SLIST_FOREACH(temp, snmp_tablelist(*tool), link) {
	    if ((rc = asn_compare_oid(&(entry->var), &(temp->var))) <= 0)
		break;
	    prev = temp;
	    rc = -1;
	}

	switch (rc) {
	    case 0:
		/* ops, we have matching asn_oid's - hope the rest info also matches */
		if (strncmp(temp->string, entry->string, entry->strlen)) {
		    warnx("Matching OIDs with different string mapping"
			" - old - %s, new - %s", temp->string, entry->string);
			return (-1);
		}
		return(0);
	    case 1:
		SLIST_INSERT_AFTER(temp, entry, link);
		    break;
	    case -1:
		SLIST_INSERT_AFTER(prev, entry, link);
		    break;
	    default:
		/* NOTREACHED */
		return (-1);
	}

	return (1);
}
struct enum_type *
snmp_enumtc_init(char *name)
{
	struct enum_type *enum_tc;

	if ((enum_tc = snmp_malloc(sizeof(struct enum_type))) == NULL) {
		return (NULL);
	}

	memset(enum_tc, 0, sizeof(struct enum_type));
	if ((enum_tc->name = snmp_malloc(strlen(name) + 1)) == NULL) {
		free(enum_tc);
		return (NULL);
	}
	strlcpy(enum_tc->name, name, strlen(name) + 1);

	return (enum_tc);
}
void
snmp_enumtc_free(struct enum_type *tc)
{
	if (tc->name)
		free(tc->name);

	if (tc->snmp_enum)
		enum_pairs_free(tc->snmp_enum);

	free(tc);
}
void
snmp_enumtc_insert(struct snmp_toolinfo *tool, struct enum_type *entry)
{
	SLIST_INSERT_HEAD(snmp_tclist(*tool), entry, link);
}
struct enum_type *
snmp_enumtc_lookup(struct snmp_toolinfo *tool, char *name)
{
	struct enum_type *temp;

	if (snmp_tclist(*tool) == NULL)
		return (NULL);

	SLIST_FOREACH(temp, snmp_tclist(*tool), link) {
		if (strcmp(temp->name, name) == 0)
			return (temp);
	}
	return (NULL);
}
static void
snmp_mapping_dumplist(struct snmp_mapping *headp)
{
	struct snmp_oid2str *entry;
	char 	buf[ASN_OIDSTRLEN];

	if (headp == NULL)
		return;

	SLIST_FOREACH(entry,headp,link) {
		memset(buf,0,sizeof(buf));
		asn_oid2str_r(&(entry->var),buf);
		fprintf(stderr,"%s - %s - %d - %d - %d",buf,entry->string,
				entry->syntax,entry->access,entry->strlen);
		fprintf(stderr," - %s \n", (entry->table_idx == NULL)?\
				"No table":entry->table_idx->string);
	}

	return;
}
static void
snmp_mapping_dumptable(struct snmp_table_index *headp)
{
	struct snmp_index_entry *entry;
	char 	buf[ASN_OIDSTRLEN];

	if (headp == NULL)
		return;

	SLIST_FOREACH(entry,headp,link) {
		memset(buf,0,sizeof(buf));
		asn_oid2str_r(&(entry->var),buf);
		fprintf(stderr,"%s - %s - %d - ",buf,entry->string,
				entry->strlen);
		snmp_dump_indexlist(&(entry->index_list));
	}

	return;
}
void
snmp_mapping_dump(struct snmp_toolinfo *tool /* int bits */)
{
	if (!debug_on)
		return;

	if (tool->mappings == NULL) {
		fprintf(stderr,"No mappings!\n");
		return;
	}

	fprintf(stderr,"snmp_nodelist:\n");
	snmp_mapping_dumplist(snmp_nodelist(*tool));

	fprintf(stderr,"snmp_intlist:\n");
	snmp_mapping_dumplist(snmp_intlist(*tool));

	fprintf(stderr,"snmp_octlist:\n");
	snmp_mapping_dumplist(snmp_octlist(*tool));

	fprintf(stderr,"snmp_oidlist:\n");
	snmp_mapping_dumplist(snmp_oidlist(*tool));

	fprintf(stderr,"snmp_iplist:\n");
	snmp_mapping_dumplist(snmp_iplist(*tool));

	fprintf(stderr,"snmp_ticklist:\n");
	snmp_mapping_dumplist(snmp_ticklist(*tool));

	fprintf(stderr,"snmp_cntlist:\n");
	snmp_mapping_dumplist(snmp_cntlist(*tool));

	fprintf(stderr,"snmp_gaugelist:\n");
	snmp_mapping_dumplist(snmp_gaugelist(*tool));

	fprintf(stderr,"snmp_cnt64list:\n");
	snmp_mapping_dumplist(snmp_cnt64list(*tool));

	fprintf(stderr,"snmp_enumlist:\n");
	snmp_mapping_dumplist(snmp_enumlist(*tool));

	fprintf(stderr,"snmp_tablelist:\n");
	snmp_mapping_dumptable(snmp_tablelist(*tool));

	return;
}
char *
enum_string_lookup(struct enum_pairs *headp, int32_t enum_val)
{
	struct enum_pair *temp;

	if (headp == NULL)
		return (NULL);

	STAILQ_FOREACH(temp, headp, link) {
		if (temp->enum_val == enum_val)
			return (temp->enum_str);
	}

	return (NULL);
}
int32_t
enum_number_lookup(struct enum_pairs *headp, char *enum_str)
{
	struct enum_pair *temp;

	if (headp == NULL)
		return (-1);

	STAILQ_FOREACH(temp, headp, link) {
		if (strncmp(temp->enum_str, enum_str, strlen(temp->enum_str)) == 0)
			return (temp->enum_val);
	}

	return (-1);
}
static int
snmp_lookuplist_string(struct snmp_mapping *headp, struct snmp_object *s)
{
	struct snmp_oid2str *temp;

	if (headp == NULL)
		return (-1);

	SLIST_FOREACH(temp, headp, link) {
		if (asn_compare_oid(&(temp->var), &(s->val.var)) != 0)
			continue;
		s->info = temp;
		return (1);
	}

	return (-1);
}
/* provided an asn_oid find the corresponding string for it */
static int
snmp_lookup_leaf(struct snmp_mapping *headp, struct snmp_object *s)
{
	struct snmp_oid2str *temp;

	if (headp == NULL)
		return (-1);

	SLIST_FOREACH(temp,headp,link) {
		if ((asn_compare_oid(&(temp->var), &(s->val.var)) == 0) ||\
	       		(asn_is_suboid(&(temp->var), &(s->val.var))))	{
			s->info = temp;
			return (1);
		}
	}

	return (-1);
}
int
snmp_lookup_leafstring(struct snmp_toolinfo *tool, struct snmp_object *s)
{
	if (s == NULL)
		return (-1);

	switch (s->val.syntax) {
		case SNMP_SYNTAX_INTEGER:
			return (snmp_lookup_leaf(snmp_intlist(*tool), s));
		case SNMP_SYNTAX_OCTETSTRING:
			return (snmp_lookup_leaf(snmp_octlist(*tool), s));
		case SNMP_SYNTAX_OID:
			return (snmp_lookup_leaf(snmp_oidlist(*tool), s));
		case SNMP_SYNTAX_IPADDRESS:
			return (snmp_lookup_leaf(snmp_iplist(*tool), s));
		case SNMP_SYNTAX_COUNTER:
			return (snmp_lookup_leaf(snmp_cntlist(*tool), s));
		case SNMP_SYNTAX_GAUGE:
			return (snmp_lookup_leaf(snmp_gaugelist(*tool), s));
		case SNMP_SYNTAX_TIMETICKS:
			return (snmp_lookup_leaf(snmp_ticklist(*tool), s));
		case SNMP_SYNTAX_COUNTER64:
			return (snmp_lookup_leaf(snmp_cnt64list(*tool), s));
		case SNMP_SYNTAX_NOSUCHOBJECT:
			/* FALLTHROUGH */
		case SNMP_SYNTAX_NOSUCHINSTANCE:
			/* FALLTHROUGH */
		case SNMP_SYNTAX_ENDOFMIBVIEW:
			return (snmp_lookup_allstring(tool, s));
		default:
			warnx("Unknown syntax - %d\n", s->val.syntax);
			break;
	}

	return (-1);
}
int
snmp_lookup_enumstring(struct snmp_toolinfo *tool, struct snmp_object *s)
{
	if (s == NULL)
		return (-1);

	return (snmp_lookuplist_string(snmp_enumlist(*tool), s));
}
int
snmp_lookup_oidstring(struct snmp_toolinfo *tool, struct snmp_object *s)
{
	if (s == NULL)
		return (-1);

	return (snmp_lookuplist_string(snmp_oidlist(*tool), s));
}
int
snmp_lookup_nodestring(struct snmp_toolinfo *tool, struct snmp_object *s)
{
	if (s == NULL)
		return (-1);

	return (snmp_lookuplist_string(snmp_nodelist(*tool), s));
}
int
snmp_lookup_allstring(struct snmp_toolinfo *tool, struct snmp_object *s)
{
	if (snmp_lookup_leaf(snmp_intlist(*tool), s) > 0)
		return (1);
	if (snmp_lookup_leaf(snmp_octlist(*tool), s) > 0)
		return (1);
	if (snmp_lookup_leaf(snmp_oidlist(*tool), s) > 0)
		return (1);
	if (snmp_lookup_leaf(snmp_iplist(*tool), s) > 0)
		return (1);
	if (snmp_lookup_leaf(snmp_cntlist(*tool), s) > 0)
		return (1);
	if (snmp_lookup_leaf(snmp_gaugelist(*tool), s) > 0)
		return (1);
	if (snmp_lookup_leaf(snmp_ticklist(*tool), s) > 0)
		return (1);
	if (snmp_lookup_leaf(snmp_cnt64list(*tool), s) > 0)
		return (1);
	if (snmp_lookuplist_string(snmp_enumlist(*tool), s) > 0)
		return (1);
	if (snmp_lookuplist_string(snmp_nodelist(*tool), s) > 0)
		return (1);

	return (-1);
}
int
snmp_lookup_nonleaf_string(struct snmp_toolinfo *tool, struct snmp_object *s)
{
	if (snmp_lookuplist_string(snmp_nodelist(*tool), s) > 0)
		return (1);
	if (snmp_lookuplist_string(snmp_enumlist(*tool), s) > 0)
		return (1);

	return (-1);
}
static int
snmp_lookup_oidlist(struct snmp_mapping *headp, struct snmp_object *s, char *oid)
{
	struct snmp_oid2str 	*temp;

	if (headp == NULL)
		return (-1);

	SLIST_FOREACH(temp, headp, link) {
		if (temp->strlen != strlen(oid))
			continue;

		if (strncmp(temp->string, oid, temp->strlen))
			continue;

		s->val.syntax = temp->syntax;
		s->info = temp;
		asn_append_oid(&(s->val.var), &(temp->var));
		return (1);
	}
	return (-1);
}
static int
snmp_lookup_tablelist(struct snmp_toolinfo *tool, struct snmp_table_index *headp, struct snmp_object *s, char *oid)
{
	struct snmp_index_entry *temp;

	if (headp == NULL)
		return (-1);

	SLIST_FOREACH(temp, headp, link) {
		if (temp->strlen != strlen(oid))
			continue;

		if (strncmp(temp->string, oid, temp->strlen))
			continue;

		/*
		 * Another hack here - if we were given a table name
		 * return the corresponding pointer to it's entry
		 * That should not change the reponce we'll get.
		 */
		s->val.syntax = SNMP_SYNTAX_NULL;
		asn_append_oid(&(s->val.var), &(temp->var));
		if (snmp_lookup_leaf(snmp_nodelist(*tool), s) > 0)
			return (1);
		else
			return (-1);
	}

	return (-1);
}
int
snmp_lookup_oidall(struct snmp_toolinfo *tool, struct snmp_object *s, char *oid)
{
	if (s == NULL || oid == NULL)
		return (-1);

	if (snmp_lookup_oidlist(snmp_intlist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_octlist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_oidlist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_iplist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_ticklist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_cntlist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_gaugelist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_cnt64list(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_oidlist(snmp_nodelist(*tool), s, oid) > 0)
		return (1);
	if (snmp_lookup_tablelist(tool, snmp_tablelist(*tool), s, oid) > 0)
		return (1);

	return (-1);
}
int
snmp_lookup_enumoid(struct snmp_toolinfo *tool, struct snmp_object *s, char *oid)
{
	if (s == NULL)
		return (-1);

	return (snmp_lookup_oidlist(snmp_enumlist(*tool), s, oid));
}
int
snmp_lookup_oid(struct snmp_toolinfo *tool, struct snmp_object *s, char *oid)
{
	if (s == NULL)
		return (-1);

	switch (s->val.syntax) {
		case SNMP_SYNTAX_INTEGER:
			return (snmp_lookup_oidlist(snmp_intlist(*tool), s, oid));
		case SNMP_SYNTAX_OCTETSTRING:
			return (snmp_lookup_oidlist(snmp_octlist(*tool), s, oid));
		case SNMP_SYNTAX_OID:
			return (snmp_lookup_oidlist(snmp_oidlist(*tool), s, oid));
		case SNMP_SYNTAX_IPADDRESS:
			return (snmp_lookup_oidlist(snmp_iplist(*tool), s, oid));
		case SNMP_SYNTAX_COUNTER:
			return (snmp_lookup_oidlist(snmp_cntlist(*tool), s, oid));
		case SNMP_SYNTAX_GAUGE:
			return (snmp_lookup_oidlist(snmp_gaugelist(*tool), s, oid));
		case SNMP_SYNTAX_TIMETICKS:
			return (snmp_lookup_oidlist(snmp_ticklist(*tool), s, oid));
		case SNMP_SYNTAX_COUNTER64:
			return (snmp_lookup_oidlist(snmp_cnt64list(*tool), s, oid));
		case SNMP_SYNTAX_NULL:
			return (snmp_lookup_oidlist(snmp_nodelist(*tool), s, oid));
		default:
			warnx("Unknown syntax - %d\n",s->val.syntax);
			break;
	}

	return (-1);
}
