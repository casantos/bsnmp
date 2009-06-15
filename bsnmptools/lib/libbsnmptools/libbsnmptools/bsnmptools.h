/*-
 * Copyright (c) 2005-2006 The FreeBSD Project
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
 *
 * Helper functions for getting user input
 */
#if !defined(_BSNMPTOOLS_BSNMPTOOLS_H_)
#define _BSNMPTOOLS_BSNMPTOOLS_H_

#ifdef __cplusplus
extern "C" {
#endif

/* from asn1.h + 1 byte for trailing zero */
#define MAX_OCTSTRING_LEN   	ASN_MAXOCTETSTRING + 1
#define MAX_CMD_SYNTAX_LEN  	12

/* arbitrary upper limit on node names and function names - from gensnmptree.c */
#define	MAXSTR	1000

/* should be enough to fetch the biggest allowed octet string */
#define MAX_BUFF_SIZE       	(ASN_MAXOCTETSTRING + 50)

#if !defined(DEFSDIR)
#define DEFSDIR		"/usr/share/snmp/defs"
#endif

#if !defined(LOCAL_DEFSDIR)
#if !defined(NO_LOCAL_DEFS_DIR)
#define LOCAL_DEFSDIR	"/usr/local/share/snmp/defs"
#endif
#endif

#if !defined(SNMP_DEFAULT_LOCAL)
#define SNMP_DEFAULT_LOCAL	"/var/run/snmpd.sock"
#endif

enum snmp_access {
	SNMP_ACCESS_NONE = 0,
	SNMP_ACCESS_GET,
	SNMP_ACCESS_SET,
	SNMP_ACCESS_GETSET,
};

/* struct for integer-string enumerations */
struct enum_pair {
	int32_t	enum_val;
	char	*enum_str;
	STAILQ_ENTRY(enum_pair) link;
};

STAILQ_HEAD(enum_pairs, enum_pair);

struct enum_type {
	char	*name;
	u_int		syntax;
	int		is_enum;
	struct enum_pairs *snmp_enum;
	SLIST_ENTRY(enum_type) link;
};
SLIST_HEAD(snmp_enum_tc, enum_type);

struct index {
	enum snmp_tc tc;
	enum snmp_syntax syntax;
	struct enum_pairs *snmp_enum;
	STAILQ_ENTRY(index) link;
};

STAILQ_HEAD(snmp_idxlist, index);

struct snmp_index_entry {
	char *string;
	uint32_t strlen;
	struct asn_oid var;
	struct	snmp_idxlist index_list;
	SLIST_ENTRY(snmp_index_entry) link;
};

/* info needed for oid to string conversion */
struct snmp_oid2str {
	char 	*string;
	uint32_t strlen;
	enum snmp_tc tc;
	enum snmp_syntax syntax;
	enum snmp_access access;
	struct asn_oid var;
	/* pointer to entry struct from the table list - OK if NULL */
	struct snmp_index_entry *table_idx;
	/* a singly-linked tail queue of all int - string pairs - fot INTEGER only */
	struct enum_pairs *snmp_enum;
	SLIST_ENTRY(snmp_oid2str) link;
};

/* a structure to hold each oid input by user */
struct snmp_object {
	/* flag - if set, the variable caused error in previous request */
	int error;
	/* a pointer in the mapping lists - not use if OIDs are input as numericals */
	struct snmp_oid2str *info;
	/* a snmp value to hold the actual asn_oid, syntax and value */
	struct	snmp_value val;
	SLIST_ENTRY(snmp_object) link;
};

struct fname {
	char *name;
	int done;
	struct asn_oid cut;
	SLIST_ENTRY(fname) link;
};

SLIST_HEAD(snmp_mapping, snmp_oid2str);
SLIST_HEAD(fname_list, fname);
SLIST_HEAD(snmp_table_index, snmp_index_entry);

/*
 * Keep a list for every syntax type
 */
struct snmp_mappings {
	/* the list containing all non-leaf nodes */
	struct snmp_mapping		*snmp_nodelist;
	/* integer32 types */
	struct snmp_mapping		*snmp_intlist;
	/* octetstring types */
	struct snmp_mapping		*snmp_octlist;
	/* OID types*/
	struct snmp_mapping		*snmp_oidlist;
	/* IPADDRESS types*/
	struct snmp_mapping		*snmp_iplist;
	/* timeticks types*/
	struct snmp_mapping		*snmp_ticklist;
	/* counter32 types*/
	struct snmp_mapping		*snmp_cntlist;
	/* gauge types*/
	struct snmp_mapping		*snmp_gaugelist;
	/* counter64 types*/
	struct snmp_mapping		*snmp_cnt64list;
	/* enum values for oid types */
	struct snmp_mapping		*snmp_enumlist;
	/* description of all table entry types */
	struct snmp_table_index *snmp_tablelist;
	/* defined enumerated textual conventions */
	struct snmp_enum_tc	*snmp_tclist;
};

struct snmp_toolinfo {
	struct snmp_client *client;
	const char *helptxt;
	uint32_t flags;
	/* number of initially input OIDs*/
	int  objects;
	/* list of all input OIDs*/
	SLIST_HEAD(snmp_objectlist, snmp_object) snmp_objectlist;
	/* All known OID to string mapping data */
	struct snmp_mappings *mappings;
	/* list of .defs filenames to search oid to string mapping */
	struct fname_list filelist;
};

/* definitions for some flags' bits */
#define OUTPUT_BITS		0x03	/* bit 0-1 for output type */
#define NUMERIC_BIT		0x04	/* bit 2 for numeric oids */
#define RETRY_BIT		0x08 	/* bit 3 for retry on error responce */
#define ERRIGNORE_BIT		0x10	/* bit 4 for skip access type checking */

enum output {
	OUTPUT_SHORT = 0,
	OUTPUT_VERBOSE,
	OUTPUT_TABULAR,
	OUTPUT_QUIET
};

/* macros for playing with flags' bits */
#define SET_OUTPUT(tool,type)	((tool).flags |= (type & OUTPUT_BITS))
#define GET_OUTPUT(tool)		((tool).flags & OUTPUT_BITS)

#define SET_NUMERIC(tool)	((tool).flags |= NUMERIC_BIT)
#define ISSET_NUMERIC(tool)	((tool).flags & NUMERIC_BIT)

#define SET_RETRY(tool)		((tool).flags |= RETRY_BIT)
#define ISSET_RETRY(tool)	((tool).flags & RETRY_BIT)

#define SET_ERRIGNORE(tool)	((tool).flags |= ERRIGNORE_BIT)
#define ISSET_ERRIGNORE(tool)	((tool).flags & ERRIGNORE_BIT)

extern const struct asn_oid IsoOrgDod_OID;

struct snmp_toolinfo *snmptool_init(const char *helptxt);
int snmp_import_file(struct snmp_toolinfo *tool, struct fname *file); /* bsnmpimport.c */
int snmp_import_all(struct snmp_toolinfo *tool);
int add_filename(struct snmp_toolinfo *tool, const char *filename, const struct asn_oid *cut, int done);
void free_filelist(struct snmp_toolinfo *tool);
void snmp_tool_freeall(struct snmp_toolinfo *tool);
void snmp_import_dump(int all);

/* from bsnmpmap.c */
struct snmp_mappings *snmp_mapping_init(void);
int snmp_mapping_free(struct snmp_toolinfo *tool);
void snmp_index_listfree(struct snmp_idxlist *headp);
void snmp_dump_oid2str(struct snmp_oid2str *entry);
int snmp_node_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry);
int snmp_leaf_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry);
int snmp_enum_insert(struct snmp_toolinfo *tool, struct snmp_oid2str *entry);
struct enum_pairs *enum_pairs_init(void);
void enum_pairs_free(struct enum_pairs *headp);
void snmp_mapping_entryfree(struct snmp_oid2str *entry);
int enum_pair_insert(struct enum_pairs *headp,
	int32_t enum_val, char *enum_str);
char * enum_string_lookup(struct enum_pairs *headp,
	 int32_t enum_val);
int32_t enum_number_lookup(struct enum_pairs *headp,
	char *enum_str);
int snmp_syntax_insert(struct snmp_idxlist *headp, struct enum_pairs *enums,
	enum snmp_syntax syntax, enum snmp_tc tc);
int snmp_table_insert(struct snmp_toolinfo *tool, struct snmp_index_entry *entry);

struct enum_type *snmp_enumtc_init(char *name);
void snmp_enumtc_free(struct enum_type *tc);
void snmp_enumtc_insert(struct snmp_toolinfo *tool, struct enum_type *entry);
struct enum_type *snmp_enumtc_lookup(struct snmp_toolinfo *tool, char *name);

void snmp_mapping_dump(struct snmp_toolinfo *tool /* int bits */);
int snmp_lookup_leafstring(struct snmp_toolinfo *tool, struct snmp_object *s);
int snmp_lookup_enumstring(struct snmp_toolinfo *tool, struct snmp_object *s);
int snmp_lookup_oidstring(struct snmp_toolinfo *tool, struct snmp_object *s);
int snmp_lookup_nonleaf_string(struct snmp_toolinfo *tool, struct snmp_object *s);
int snmp_lookup_allstring(struct snmp_toolinfo *tool, struct snmp_object *s);
int snmp_lookup_nodestring(struct snmp_toolinfo *tool, struct snmp_object *s);
int snmp_lookup_oidall(struct snmp_toolinfo *tool, struct snmp_object *s, char *oid);
int snmp_lookup_enumoid(struct snmp_toolinfo *tool, struct snmp_object *s, char *oid);
int snmp_lookup_oid(struct snmp_toolinfo *tool, struct snmp_object *s, char *oid);

/* functions parsing common options for all tools */
int parse_server(struct snmp_client *client, char opt, char *opt_arg);
int parse_timeout(struct snmp_client *client, char opt, char *opt_arg);
int parse_retry(struct snmp_client *client, char opt, char *opt_arg);
int parse_version(struct snmp_client *client, char opt, char *opt_arg);
int parse_local_path(struct snmp_client *client, char opt, char *opt_arg);
int parse_buflen(struct snmp_client *client, char opt, char *opt_arg);
int parse_debug(struct snmp_client *client, char *opt_arg);
int parse_num_oids(struct snmp_toolinfo *tool, char *opt_arg);
int parse_help(struct snmp_toolinfo *tool, char *opt_arg);
int parse_file(struct snmp_toolinfo *tool, char opt, char *opt_arg);
int parse_include(struct snmp_toolinfo *tool, char opt, char *opt_arg);
int parse_output(struct snmp_toolinfo *tool, char opt, char *opt_arg);
int parse_errors(struct snmp_toolinfo *tool, char *opt_arg);
int parse_skip_access(struct snmp_toolinfo *tool, char *opt_arg);

typedef int (*snmp_verify_inoid_f) (struct snmp_toolinfo *tool, struct snmp_object *obj, char *string);
int snmp_object_add(struct snmp_toolinfo *tool, snmp_verify_inoid_f func,char *string);
int snmp_object_remove(struct snmp_toolinfo *tool, struct asn_oid *oid);
int snmp_object_seterror(struct snmp_toolinfo *tool, struct snmp_value *err_value, int32_t error_status);

enum snmp_syntax parse_syntax(char * str);
char * snmp_parse_suboid(char *str, struct asn_oid *oid);
char * snmp_parse_index(struct snmp_toolinfo *tool, char *str, struct snmp_object *object);
int snmp_parse_numoid(char * argv, struct asn_oid * var);
int snmp_suboid_append(struct asn_oid *var, asn_subid_t suboid);
int32_t snmp_suboid_pop(struct asn_oid *var);

typedef int (*snmp_verify_vbind_f) (struct snmp_toolinfo *tool, struct snmp_pdu *pdu, struct snmp_object *obj);
typedef int (*snmp_add_vbind_f) (struct snmp_pdu *pdu,struct snmp_object *obj);
int snmp_pdu_add_bindings(struct snmp_toolinfo *tool, snmp_verify_vbind_f vfunc,
	snmp_add_vbind_f afunc, struct snmp_pdu *pdu);

int snmp_parse_get_resp(struct snmp_client *client, struct snmp_pdu * resp,struct snmp_pdu * req);
int snmp_parse_getbulk_resp(struct snmp_pdu * resp,struct snmp_pdu * req);
int snmp_parse_getnext_resp(struct snmp_pdu * resp,struct snmp_pdu * req);
int snmp_parse_resp(struct snmp_client *client, struct snmp_pdu * resp,struct snmp_pdu * req);
void snmp_output_numval(struct snmp_toolinfo *tool, struct snmp_value * val, struct snmp_oid2str *entry);
void snmp_output_val(struct snmp_value * val);
void snmp_output_resp(struct snmp_toolinfo *tool, struct snmp_pdu * pdu);
void snmp_output_err_resp(struct snmp_toolinfo *tool, struct snmp_pdu * pdu);

#ifdef __cplusplus
}
#endif

#endif /* _BSNMPTOOLS_BSNMPTOOLS_H_ */
