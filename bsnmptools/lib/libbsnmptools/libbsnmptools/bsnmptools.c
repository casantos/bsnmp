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
 * Helper functions for snmp client tools
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <ctype.h>
#if defined(HAVE_ERR_H)
#include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
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

/* defualt files to import mapping from if none explicitly provided */
#define BSNMPD_DEFS	"tree.def"
#define MIB_II_DEFS	"mibII_tree.def"

#if defined(DEFSDIR)
#define bsnmpd_defs	DEFSDIR "/" BSNMPD_DEFS
#define mibII_defs	DEFSDIR "/" MIB_II_DEFS
#endif

/*
 * The .iso.org.dod oid that has to
 * be prepended to every OID when requesting a value
 */
const struct asn_oid IsoOrgDod_OID = {
	3, { 1, 3, 6}
};


#define SNMP_ERR_UNKNOWN 0
/*
 * An array of error strings corresponding to error definitions
 * from libbsnmp
 */
static const struct {
	const char *str;
	int	 error;
} error_strings[] = {
	{ "Unknown", SNMP_ERR_UNKNOWN },
	{ "Too big ", SNMP_ERR_TOOBIG },
	{ "No such Name",SNMP_ERR_NOSUCHNAME },
	{ "Bad Value", SNMP_ERR_BADVALUE },
	{ "Readonly", SNMP_ERR_READONLY },
	{ "General error", SNMP_ERR_GENERR },
	{ "No access", SNMP_ERR_NO_ACCESS },
	{ "Wrong type", SNMP_ERR_WRONG_TYPE },
	{ "Wrong lenght", SNMP_ERR_WRONG_LENGTH },
	{ "Wrong encoding", SNMP_ERR_WRONG_ENCODING },
	{ "Wrong value", SNMP_ERR_WRONG_VALUE },
	{ "No creation",SNMP_ERR_NO_CREATION }, /* ??? */
	{ "Inconsistent value", SNMP_ERR_INCONS_VALUE },
	{ "Resource unavailable", SNMP_ERR_RES_UNAVAIL },
	{ "Commit failed", SNMP_ERR_COMMIT_FAILED },
	{ "Undo failed", SNMP_ERR_UNDO_FAILED },
	{ "Authorization error", SNMP_ERR_AUTH_ERR },
	{ "Not writable", SNMP_ERR_NOT_WRITEABLE },
	{ "Inconsistent name", SNMP_ERR_INCONS_NAME},
	{ NULL, 0}
};

/* this one and any following are exceptions */
#define SNMP_SYNTAX_UNKNOWN SNMP_SYNTAX_NOSUCHOBJECT

static const struct {
	const char *str;
	enum snmp_syntax stx;
} syntax_strings[] = {
	{ "Null", SNMP_SYNTAX_NULL },
	{ "Integer", SNMP_SYNTAX_INTEGER },
	{ "OctetString", SNMP_SYNTAX_OCTETSTRING },
	{ "OID", SNMP_SYNTAX_OID },
	{ "IpAddress", SNMP_SYNTAX_IPADDRESS },
	{ "Counter32", SNMP_SYNTAX_COUNTER },
	{ "Gauge", SNMP_SYNTAX_GAUGE },
	{ "TimeTicks", SNMP_SYNTAX_TIMETICKS },
	{ "Counter64", SNMP_SYNTAX_COUNTER64 },
	{ "Unknown", SNMP_SYNTAX_UNKNOWN },
};

struct snmp_toolinfo *
snmptool_init(const char *helptxt)
{
	struct snmp_toolinfo *tool;
	struct snmp_client *client;

	if ((tool = snmp_malloc(sizeof(*tool))) == NULL)
		return (NULL);

	if ((client = snmp_client_init()) == NULL) {
		free(tool);
                return NULL;
	}

	memset(tool, 0, sizeof(*tool));

	tool->client = client;
	tool->helptxt = helptxt;
	tool->objects = 0;
	tool->mappings = NULL;
	tool->flags = 0;
	SLIST_INIT(&(tool->filelist));

#if defined(bsnmpd_defs)
	if (add_filename(tool, bsnmpd_defs, &IsoOrgDod_OID, 0) < 0)
		warnx("Error adding file %s to list", bsnmpd_defs);
#endif

#if defined(mibII_defs)
	if (add_filename(tool, mibII_defs, &IsoOrgDod_OID, 0) < 0)
		warnx("Error adding file %s to list", mibII_defs);
#endif
	return tool;
}

#define SNMP_OBJS(tool)	 	((tool).snmp_objectlist)
#define OBJECT_IDX_LIST(obj)	((obj).info->table_idx->index_list)

/*
 * Walk through the file list and import string -> oid mappings
 * from each file read
 */
int
snmp_import_all(struct snmp_toolinfo *tool)
{
	int 	fc;
	struct 	fname *tmp;

	if (ISSET_NUMERIC(*tool))
		return (0);

	if ((tool->mappings = snmp_mapping_init()) == NULL)
		return (-1);

	fc = 0;
	if (SLIST_EMPTY(&(tool->filelist))) {
		warnx("No files to read OID <-> string conversions from");
		return (-1);
	} else {
		SLIST_FOREACH(tmp, &(tool->filelist), link) {
			if (tmp->done)
				continue;
			if (snmp_import_file(tool, tmp) < 0) {
				fc = -1;
				break;
			}
			fc++;
		}
	}

	/* snmp_mapping_dump(); */
	return (fc);
}
/*
 * Add a filename to the file list - the initail idea of keeping a list with all
 * files to read OIDs from was that an application might want to have loaded in memory
 * the OIDs from a single file only and when done with them read the OIDs from another file.
 * This is not used yet but might be a good idea at some point.
 * Size argument is number of bytes in string including trailing '\0', not string lenght
 */
int
add_filename(struct snmp_toolinfo *tool, const char *filename, const struct asn_oid *cut, int done)
{
	char 	 *fstring;
	struct fname *entry;

	/* Make sure file was not in list */
	SLIST_FOREACH(entry, &(tool->filelist), link) {
		if (strncmp(entry->name, filename, strlen(entry->name)) == 0)
			return (0);
	}

	if ((fstring = snmp_malloc(strlen(filename) + 1)) == NULL) {
		return (-1);
	}

	if ((entry = snmp_malloc(sizeof(struct fname))) == NULL) {
		free(fstring);
		return (-1);
	}

	memset(entry, 0, sizeof(struct fname));

	if (cut != NULL)
		asn_append_oid(&(entry->cut), cut);
	strlcpy(fstring, filename, strlen(filename) + 1);
	entry->name = fstring;
	entry->done = done;
	SLIST_INSERT_HEAD(&(tool->filelist), entry, link);

	return (1);
}
void
free_filelist(struct snmp_toolinfo *tool)
{
	struct fname *f;

	while (!SLIST_EMPTY(&tool->filelist)) {
		f = SLIST_FIRST(&tool->filelist);
		SLIST_REMOVE_HEAD(&tool->filelist, link);
		if (f->name)
			free(f->name);
		free(f);
	}
}
static char
isvalid_fchar(char c, int pos)
{
	if (isalpha(c)|| c == '/'|| c == '_' || c == '.' ||\
		c == '~' || (pos != 0 && isdigit(c))){
		return (c);
	}

	if (c == '\0')
		return (0);

	if (!isascii(c) || !isprint(c))
		warnx("Unexpected character %#2x", (u_int) c);
	else
		warnx("Illegal character '%c'", c);

	return (-1);
}
/*
 * Re-implement getsubopt from scratch, because the second argument is broken
 * and will not compile with WARNS=5.
 * Copied from src/contrib/bsnmp/snmpd/main.c
 */
static int
getsubopt1(char **arg, const char *const *options, char **valp, char **optp)
{
	static const char *const delim = ",\t ";
	u_int i;
	char *ptr;

	*optp = NULL;

	/* skip leading junk */
	for (ptr = *arg; *ptr != '\0'; ptr++)
		if (strchr(delim, *ptr) == NULL)
			break;
	if (*ptr == '\0') {
		*arg = ptr;
		return (-1);
	}
	*optp = ptr;

	/* find the end of the option */
	while (*++ptr != '\0')
		if (strchr(delim, *ptr) != NULL || *ptr == '=')
			break;

	if (*ptr != '\0') {
		if (*ptr == '=') {
			*ptr++ = '\0';
			*valp = ptr;
			while (*ptr != '\0' && strchr(delim, *ptr) == NULL)
				ptr++;
			if (*ptr != '\0')
				*ptr++ = '\0';
		} else
			*ptr++ = '\0';
	}

	*arg = ptr;

	for (i = 0; *options != NULL; options++, i++)
		if (strcmp(*optp, *options) == 0)
			return (i);
	return (-1);
}
static int
parse_path(char *value)
{
	int i, len;

	if (value == NULL)
		return (-1);

	for (len = 0; len < MAXPATHLEN; len++) {
		i = isvalid_fchar(*(value + len), len) ;

		if (i == 0)
			break;
		else if (i < 0)
			return (-1);
	}

	if (len >= MAXPATHLEN || value[len] != '\0') {
		warnx("Bad pathname - '%s'", value);
		return (-1);
	}

	return(len);
}
static int
parse_flist(struct snmp_toolinfo *tool, char *value, char *path, const struct asn_oid *cut)
{
	int namelen;
	char filename[MAXPATHLEN + 1];

	if (value == NULL)
		return (-1);

	do {
		memset(filename, 0, MAXPATHLEN + 1);

#if defined(DEFSDIR)
		if (isalpha(*value) && (path == NULL || path[0] == '\0')) {
			strlcpy(filename, DEFSDIR, MAXPATHLEN + 1);
			namelen = strlen(DEFSDIR);
		}
		else
#endif
		if (path != NULL){
			strlcpy(filename, path, MAXPATHLEN + 1);
			namelen = strlen(path);
		} else
			namelen = 0;

		for ( ; namelen < MAXPATHLEN; value++) {

			if (isvalid_fchar(*value, namelen) > 0) {
				filename[namelen++] = *value;
				continue;
			}

			if (*value == ',' )
				value++;
			else if (*value == '\0')
				;
			else {
				if (!isascii(*value) || !isprint(*value))
					warnx("Unexpected character %#2x in filename", (u_int)*value);
				 else
					warnx("Illegal character '%c' in filename", *value);
				return (-1);
			}

			filename[namelen]='\0';
			break;
		}

		if ((namelen == MAXPATHLEN) && (filename[MAXPATHLEN] != '\0')) {
			warnx("Filename %s too long", filename);
			return (-1);
		}

		if (add_filename(tool, filename, cut, 0) < 0) {
			warnx("Error adding file %s to list",filename);
			return (-1);
		}
	} while (*value != '\0');

	return(1);
}
/*
 * Functions to parse common input options for client tools and fill in
 * the client * structure.
 */
int
parse_file(struct snmp_toolinfo *tool, char opt, char *opt_arg)
{
	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	if (parse_flist(tool, opt_arg, NULL, &IsoOrgDod_OID) < 0)
		return (-1);

	return (2);
}
int
parse_include(struct snmp_toolinfo *tool, char opt, char *opt_arg)
{
	char pathname[MAXPATHLEN + 1];
	int cut_dflt, len, subopt;
	struct asn_oid cut;
	char *value, *option;
	const char *const subopts[] = {
		"cut",
		"path",
		"file",
		NULL
	};

#define INC_CUT 	0
#define INC_PATH	1
#define INC_LIST	2

	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	/* if (opt == 'i')
		free_filelist(); */
	/*
	 * This function should be called only after getopt(3) - otherwise if
	 * no previous validation of opt_arg strlen() may not return what is expected
	 */

	pathname[0] = '\0';
	memset(&cut, 0, sizeof(struct asn_oid));
	cut_dflt = -1;
	value = NULL;

	while ((subopt = getsubopt1(&opt_arg, subopts, &value, &option)) != EOF) {
		switch (subopt) {
			case INC_CUT:
				if (value == NULL) {
					warnx("Suboption 'cut' requires an argument");
					return (-1);
				} else {
					if (snmp_parse_numoid(value, &cut) < 0)
						return (-1);
				}
				cut_dflt = 1;
				break;

			case INC_PATH:
				if ((len = parse_path(value)) < 0)
					return (-1);
				strlcpy(pathname, value, len + 1);
				break;

			case INC_LIST:
				if (value == NULL)
					return (-1);

				if (cut_dflt == -1)
					len = parse_flist(tool, value, pathname, &IsoOrgDod_OID);
				else
					len = parse_flist(tool, value, pathname, &cut);

				if (len < 0)
					return (-1);

				break;

			default:
				if (option == NULL)
					warnx("missing sub option");
				else
					warnx("Unknown suboption - '%s'", option);
				return (-1);
		}
	}

	return (2);
}
int
parse_server(struct snmp_client *client, char opt, char *opt_arg)
{
	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	if (snmp_parse_server(client, opt_arg) < 0)
		return (-1);

	if (client->trans > SNMP_TRANS_UDP &&
		client->chost == NULL) {
		if ((client->chost = snmp_malloc(strlen(SNMP_DEFAULT_LOCAL + 1))) == NULL) {
			return (-1);
		}
		strcpy(client->chost, SNMP_DEFAULT_LOCAL);
	}

	return (2);
}
int
parse_timeout(struct snmp_client *client, char opt, char *opt_arg)
{
	int32_t v;
	int saved_errno;

	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	saved_errno = errno;
	errno = 0;

	v = strtol(opt_arg, (void *)NULL, 10);
	if (errno != 0) {
		warnx( "Error parsing timeout value - %s",
			   strerror(errno));
		errno = saved_errno;
		return (-1);
	}

	client->timeout.tv_sec = v;

	errno = saved_errno;
	return (2);
}
int
parse_retry(struct snmp_client *client, char opt, char *opt_arg)
{
	u_int v;
	int saved_errno;

	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	saved_errno = errno;
	errno = 0;

	v = strtoul(opt_arg, (void *)NULL, 10);
	if (errno != 0) {
		warnx("Error parsing retries count - %s",
			  strerror(errno));
		errno = saved_errno;
		return (-1);
	}
	client->retries = v;

	errno = saved_errno;
	return (2);
}
int
parse_version(struct snmp_client *client, char opt, char *opt_arg)
{
	u_int v;
	int saved_errno;

	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	saved_errno = errno;
	errno = 0;

	v = strtoul(opt_arg, (void *)NULL, 10);
	if (errno != 0) {
		warnx("Error parsing version - %s",
			  strerror(errno));
		errno = saved_errno;
		return (-1);
	}

	switch (v) {
		case 1:
			client->version = SNMP_V1;
			break;
		case 2:
			client->version = SNMP_V2c;
			break;
		default:
			warnx("Unsupported SNMP version - %u", v);
			errno = saved_errno;
			return (-1);
	}

	errno = saved_errno;
	return (2);
}
int
parse_local_path(struct snmp_client *client, char opt, char *opt_arg)
{
	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	if (strlen(opt_arg) >= sizeof(SNMP_LOCAL_PATH)) {
		warnx("Argument of option %c must be smaller than %d characters",
			opt, sizeof(SNMP_LOCAL_PATH));
		return (-1);
	}

	strlcpy(client->local_path, opt_arg, sizeof(SNMP_LOCAL_PATH));

	return (2);
}
int
parse_buflen(struct snmp_client *client, char opt, char *opt_arg)
{
	u_int size;
	int saved_errno;

	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	saved_errno = errno;
	errno = 0;

	size = strtoul(opt_arg, (void *)NULL, 10);
	if (errno != 0) {
		warnx("Error parsing buffer size - %s",
			  strerror(errno));
		errno = saved_errno;
		return (-1);
	}

	if (size > MAX_BUFF_SIZE) {
		warnx("Buffer size too big - %d maximum allowed", MAX_BUFF_SIZE);
		errno = saved_errno;
		return (-1);
	}

	client->txbuflen = client->rxbuflen = size;
	errno = saved_errno;
	return (2);
}
int
parse_debug(struct snmp_client *client, char *opt_arg)
{
	if (opt_arg) {
		/* try some more debug options here - for now none supported though */
		warnx("Invalid option argument - %s", opt_arg);
		return (-1);
	}

	client->dump_pdus = 1;
	return (1);
}
int
parse_num_oids(struct snmp_toolinfo *tool, char *opt_arg)
{
	if (opt_arg) {
		warnx("Invalid option argument - %s", opt_arg);
		return (-1);
	}

	SET_NUMERIC(*tool);
	return (1);
}
int
parse_help(struct snmp_toolinfo *tool, char *opt_arg)
{
	if (opt_arg == NULL) {
		fprintf(stderr, "%s", tool->helptxt);
	} else {
		warnx("Invalid option argument - %s", opt_arg);
	}

	return (-1);
}
int
parse_output(struct snmp_toolinfo *tool, char opt, char *opt_arg)
{
	if (opt_arg == NULL) {
		warnx("Option %c requires an argument", opt);
		return (-1);
	}

	if (strlen(opt_arg) > 7) {
		warnx( "Invalid output option - %s",opt_arg);
		return (-1);
	}

	if (!strncmp(opt_arg, "short", strlen("short"))) {
		SET_OUTPUT(*tool, OUTPUT_SHORT);
	} else if (!strncmp(opt_arg, "verbose", strlen(opt_arg))) {
		SET_OUTPUT(*tool, OUTPUT_VERBOSE);
	} else if (!strncmp(opt_arg,"tabular", strlen(opt_arg))) {
		SET_OUTPUT(*tool, OUTPUT_TABULAR);
	} else if (!strncmp(opt_arg, "quiet", strlen(opt_arg))) {
		SET_OUTPUT(*tool, OUTPUT_QUIET);
	} else {
		warnx( "Invalid output option - %s",opt_arg);
		return (-1);
	}

	return (2);
}
int
parse_errors(struct snmp_toolinfo *tool, char *opt_arg)
{
	if (opt_arg) {
	    warnx("Invalid option argument - %s", (char *)opt_arg);
	    return (-1);
	}

	SET_RETRY(*tool);
	return (1);
}
int
parse_skip_access(struct snmp_toolinfo *tool, char *opt_arg)
{
	if (opt_arg) {
	    warnx("Invalid option argument - %s", (char *)opt_arg);
	    return (-1);
	}

	SET_ERRIGNORE(*tool);
	return (1);
}
char *
snmp_parse_suboid(char *str, struct asn_oid *oid)
{
	char *endptr;
	asn_subid_t suboid;

	if (*str == '.')
	    str++;

	if (*str < '0' || *str > '9')
	    return (str);

	do {
	    suboid = strtoul(str, &endptr, 10);
	    if ((asn_subid_t) suboid > ASN_MAXID) {
		warnx("sub-OID %u > ASN_MAXID", suboid);
		return (NULL);
	    }
	    if (snmp_suboid_append(oid, suboid) < 0)
		return (NULL);
	    str = endptr + 1;
	} while (*endptr == '.');

	return (endptr);
}
static char *
snmp_int2asn_oid(char * str, struct asn_oid *oid)
{
	char * endptr;
	int32_t  v;
	int saved_errno;

	saved_errno = errno;
	errno = 0;

	v = strtol(str, &endptr, 10);

	if (errno != 0) {
	    warnx("Integer value %s not supported - %s\n", str, strerror(errno));
	    errno = saved_errno;
	    return (NULL);
	}
	errno = saved_errno;

	if (snmp_suboid_append(oid, (asn_subid_t) v) < 0)
	    return (NULL);

	return (endptr);
}
/* that's a bit weird to have a table indexed by OID but still */
static char *
snmp_oid2asn_oid(struct snmp_toolinfo *tool, char * str, struct asn_oid *oid)
{
	int i;
	char string[MAXSTR];
	char * endptr;
	struct snmp_object obj;

	for (i = 0; i < MAXSTR; i++) {
		if (isalpha (*(str + i)) == 0)
			break;
	}

	endptr = str + i;
	memset(&obj, 0, sizeof(struct snmp_object));
	if (i == 0) {
		if ((endptr = snmp_parse_suboid(str, &(obj.val.var))) == NULL)
			return (NULL);
		if (snmp_suboid_append(oid, (asn_subid_t) obj.val.var.len) < 0)
			return (NULL);
	} else {
		strlcpy(string, str, i + 1);
		string[i] = '\0';
		if (snmp_lookup_enumoid(tool, &obj, string) < 0) {
			warnx("Unknown string - %s\n", string);
			return (NULL);
		}
	}

	asn_append_oid(oid, &(obj.val.var));
	return (endptr);

}
static char *
snmp_ip2asn_oid(char * str, struct asn_oid *oid)
{
	uint32_t v;
	int i;
	char * endptr, * ptr;

	ptr = str;

	for (i = 0; i < 4; i++) {
		v = strtoul(ptr, &endptr, 10);

		if (v > 0xff)
			return (NULL);

		if ((*endptr != '.') && (strchr("],\0", *endptr) == NULL && i != 3))
			return (NULL);

		if (snmp_suboid_append(oid, (asn_subid_t) v) < 0)
			return (NULL);
		ptr = endptr + 1;
	}

	return (endptr);
}
/* that's for cnt, gauge, ticks */
static char *
snmp_uint2asn_oid(char * str, struct asn_oid *oid)
{
	char * endptr;
	uint32_t  v;
	int saved_errno;

	saved_errno = errno;
	errno = 0;

	v = strtoul(str, &endptr, 10);

	if (errno != 0) {
		warnx("Integer value %s not supported - %s\n", str, strerror(errno));
		errno = saved_errno;
		return (NULL);
	}
	errno = saved_errno;
	if (snmp_suboid_append(oid, (asn_subid_t) v) < 0)
		return (NULL);

	return (endptr);
}
static char *
snmp_cnt64_2asn_oid(char * str, struct asn_oid *oid)
{
	char * endptr;
	uint64_t  v;
	int saved_errno;

	saved_errno = errno;
	errno = 0;

	v = strtoull(str, &endptr, 10);

	if (errno != 0) {
		warnx("Integer value %s not supported - %s\n", str, strerror(errno));
		errno = saved_errno;
		return (NULL);
	}
	errno = saved_errno;

	if (snmp_suboid_append(oid, (asn_subid_t) (v & 0xffffffff)) < 0)
		return (NULL);

	if (snmp_suboid_append(oid, (asn_subid_t) (v >> 32)) < 0)
		return (NULL);

	return (endptr);
}
enum snmp_syntax
parse_syntax(char * str)
{
	int i;

	for (i = 0; i < SNMP_SYNTAX_UNKNOWN; i++) {
		if (strncmp(syntax_strings[i].str, str,
				strlen(syntax_strings[i].str)) == 0)
			return (syntax_strings[i].stx);
	}

	return (SNMP_SYNTAX_NULL);
}
static char *
snmp_parse_subindex(struct snmp_toolinfo *tool, char *str, struct index *idx, struct snmp_object *object)
{
	char *ptr;
	int	 i;
	enum snmp_syntax stx;
	char syntax[MAX_CMD_SYNTAX_LEN];

	ptr = str;
	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE) {
	    for (i = 0; i < MAX_CMD_SYNTAX_LEN ; i++) {
	    	if (*(ptr + i) == ':')
			break;
	    }

	    if (i >= MAX_CMD_SYNTAX_LEN) {
		warnx("Unknown syntax in OID - %s", str);
		return (NULL);
	    }
	    /* expect a syntax string here */
	    if ((stx = parse_syntax(str)) <= SNMP_SYNTAX_NULL) {
		warnx("Invalid  syntax - %s",syntax);
		return (NULL);
	    }

	    if (stx != idx->syntax && !ISSET_ERRIGNORE(*tool)) {
		warnx("Syntax mismatch - %d expected, %d given", stx != idx->syntax, stx);
		return (NULL);
	    }
	    /* that's where the suboid started + the syntax len + one char for ':' */
	    ptr = str + i + 1;
	} else
		stx = idx->syntax;

	switch (stx) {
	    case SNMP_SYNTAX_INTEGER:
		return (snmp_int2asn_oid(ptr, &(object->val.var)));
	    case SNMP_SYNTAX_OID:
		return (snmp_oid2asn_oid(tool, ptr, &(object->val.var)));
	    case SNMP_SYNTAX_IPADDRESS:
		return (snmp_ip2asn_oid(ptr, &(object->val.var)));
	    case SNMP_SYNTAX_COUNTER:
		/* FALLTHROUGH */
	    case SNMP_SYNTAX_GAUGE:
		/* FALLTHROUGH */
	    case SNMP_SYNTAX_TIMETICKS:
		return (snmp_uint2asn_oid(ptr, &(object->val.var)));
	    case SNMP_SYNTAX_COUNTER64:
		return (snmp_cnt64_2asn_oid(ptr, &(object->val.var)));
	    case SNMP_SYNTAX_OCTETSTRING:
		return (snmp_tc2oid(idx->tc, ptr, &(object->val.var)));
	    default:
		/* NOTREACHED */
		break;
	}

	return (NULL);
}
char *
snmp_parse_index(struct snmp_toolinfo *tool, char *str, struct snmp_object *object)
{
	char  *ptr;
	struct index  *temp;

	if (object->info->table_idx == NULL)
		return (NULL);

	ptr = NULL;
	STAILQ_FOREACH(temp, &(OBJECT_IDX_LIST(*object)), link) {
	    if ((ptr = snmp_parse_subindex(tool, str, temp, object)) == NULL)
		return (NULL);
	    if (*ptr != ',' && *ptr != ']')
		return (NULL);
	    str = ptr + 1;
	}

	if (ptr == NULL || *ptr != ']') {
	    warnx("Mismatching index - %s", str);
	    return (NULL);
	}

	return (ptr + 1);
}
/*
 * Fill in the struct asn_oid member of snmp_value with suboids from input.
 * If an error occurs - print message on stderr and return (-1).
 * If all is ok - return the length of the oid.
 */
int
snmp_parse_numoid(char *argv, struct asn_oid * var)
{
	char 	*endptr, *str;
	asn_subid_t suboid = 0;

	str = argv;

	do {
	    if (var->len == ASN_MAXOIDLEN) {
		warnx("Oid too long - %u", var->len);
		return (-1);
	    }

	    suboid = strtoul(str, &endptr, 10);
	    if (suboid > ASN_MAXID) {
		warnx("Oid too long - %u", var->len);
		return (-1);
	    }

	    var->subs[var->len++] = suboid;
	    str = endptr + 1;
	} while ( *endptr == '.');

	if (*endptr != '\0') {
	    warnx("Invalid oid string - %s", argv);
	    return (-1);
	}

	return (var->len);
}
/* append a length 1 suboid to an asn_oid structure */
int
snmp_suboid_append(struct asn_oid *var, asn_subid_t suboid)
{
	if (var == NULL)
		warnx("OID is null");
		return (-1);

	if (var->len >= ASN_MAXOIDLEN) {
		warnx("OID too long - %u", var->len);
		return (-1);
	}

	var->subs[var->len] = suboid;
	var->len++;

	return (1);
}
/* pop the last suboid from an asn_oid structure */
int32_t
snmp_suboid_pop(struct asn_oid *var)
{
	asn_subid_t suboid;

	if (var == NULL)
		return (-1);

	if (var->len < 1)
		return (-1);

	var->len--;
	suboid = var->subs[var->len];
	var->subs[var->len] = 0;

	return (suboid);
}

/*
 * Parse the command-line provided string into an oid -
 * alocate memory for struct snmp_value and fills in fields.
 * A snmp_verify_inoid_f function must be provided to validate
 * the input string.
 * Returns a pointer to allocated structure or NULL if parsing failed.
 */
int
snmp_object_add(struct snmp_toolinfo *tool, snmp_verify_inoid_f func, char *string)
{
	struct snmp_object *obj;

	if (tool->objects >= SNMP_MAX_BINDINGS) {
		warnx("Too many bindings in one PDU - %u", tool->objects + 1);
		return (-1);
	}

	if ((obj = snmp_malloc(sizeof(struct snmp_object))) == NULL) {
		return (-1);
	}

	memset(obj, 0, sizeof(struct snmp_object));

	if (func(tool, obj, string) < 0) {
		warnx("Invalid OID - %s", string);
		free(obj);
		return (-1);
	}

	tool->objects++;
	SLIST_INSERT_HEAD(&(SNMP_OBJS(*tool)), obj, link);

	return (1);
}
/* Given an asn_oid, find it in object list and remove it */
int
snmp_object_remove(struct snmp_toolinfo *tool, struct asn_oid *oid)
{
	struct snmp_object *temp;

	if (SLIST_EMPTY(&(SNMP_OBJS(*tool)))) {
		warnx("object list already empty");
		return (-1);
	}

	temp = NULL;
	SLIST_FOREACH(temp, &(SNMP_OBJS(*tool)), link) {
		if (asn_compare_oid(&(temp->val.var), oid) == 0)
			break;
	}

	if (temp == NULL) {
		warnx("No such object in list");
		return (-1);
	}

	SLIST_REMOVE(&(SNMP_OBJS(*tool)), temp, snmp_object, link);
	if (temp->val.syntax == SNMP_SYNTAX_OCTETSTRING &&\
			temp->val.v.octetstring.octets != NULL)
		free(temp->val.v.octetstring.octets);
	free(temp);

	return (1);
}
static void
snmp_object_freeall(struct snmp_toolinfo *tool)
{
	struct snmp_object *o;

	while (!SLIST_EMPTY(&SNMP_OBJS(*tool))) {
		o = SLIST_FIRST(&SNMP_OBJS(*tool));
		SLIST_REMOVE_HEAD(&SNMP_OBJS(*tool), link);

		if (o->val.syntax == SNMP_SYNTAX_OCTETSTRING &&
				o->val.v.octetstring.octets != NULL)
			free(o->val.v.octetstring.octets);
		free(o);
	}
}
/* do all possible memory release before exit */
void
snmp_tool_freeall(struct snmp_toolinfo *tool)
{
	if (tool->client->chost != NULL) {
		free(tool->client->chost);
		tool->client->chost = NULL;
	}

	if (tool->client->cport != NULL) {
		free(tool->client->cport);
		tool->client->cport = NULL;
	}

	snmp_close(tool->client);
	free(tool->client);

	snmp_mapping_free(tool);
	free_filelist(tool);
	snmp_object_freeall(tool);

	free(tool);
}
/*
 * Fill all variables from the object list into a PDU.
 * snmp_verify_vbind_f function should check whether the variable
 * is consistent in this PDU (e.g don't add non-leaf OIDs to a GET pdu,
 * or OIDs with read access only to a SET pdu) - might be NULL though.
 * snmp_add_vbind_f function is the function actually adds the variable to
 * the pdu and must not be NULL.
 */
int
snmp_pdu_add_bindings(struct snmp_toolinfo *tool, snmp_verify_vbind_f vfunc,
		snmp_add_vbind_f afunc, struct snmp_pdu *pdu)
{
	int nbindings;
	struct snmp_object *obj;

	if (pdu == NULL || afunc == NULL)
		return (-1);

	if (SLIST_EMPTY(&SNMP_OBJS(*tool))) {
		warnx("No bindings to add to PDU");
		return (-1);
	}

	nbindings = 0;
	SLIST_FOREACH(obj, &SNMP_OBJS(*tool), link) {
		if (obj-> error > 0)
			continue;

		if ((vfunc != NULL) && (vfunc(tool, pdu, obj) < 0)) {
			nbindings = -1;
			break;
		}
		if ((afunc(pdu,obj) < 0)) {
			nbindings = -1;
			break;
		}
		nbindings++;
	}

	return (nbindings);
}
/*
 * locate an object in the object list and set a corresponding error status
 */
int
snmp_object_seterror(struct snmp_toolinfo *tool, struct snmp_value *err_value, int32_t error_status)
{
	struct snmp_object *obj;

	if (SLIST_EMPTY(&SNMP_OBJS(*tool)) || err_value == NULL)
	    return (-1);

	SLIST_FOREACH(obj, &SNMP_OBJS(*tool), link) {
	    if (asn_compare_oid(&(err_value->var), &(obj->val.var)) == 0) {
		obj->error = error_status;
		return (1);
	    }
	}

	return (0);
}
/*
 * Check a pdu received in responce to a SNMP_PDU_GET/SNMP_PDU_GETBULK  request
 * but don't compare syntaxes - when sending a request pdu they must be null
 * This is a (almost) complete copy of snmp_pdu_check() -
 * with matching syntaxes checks skipped and some other checks skiped :-/
 */
int
snmp_parse_get_resp(struct snmp_client *client, struct snmp_pdu * resp, struct snmp_pdu * req)
{
    u_int i;

    for (i = 0; i < req->nbindings; i++) {
        if (asn_compare_oid(&req->bindings[i].var,
            &resp->bindings[i].var) != 0) {
            warnx("Bad OID in response");
            return (-1);
        }
        if (client->version != SNMP_V1 &&
            (resp->bindings[i].syntax == SNMP_SYNTAX_NOSUCHOBJECT ||
            resp->bindings[i].syntax == SNMP_SYNTAX_NOSUCHINSTANCE))
            return (0);
    }
    return (1);
}
int
snmp_parse_getbulk_resp(struct snmp_pdu * resp, struct snmp_pdu * req)
{
	int32_t N, R, M, r;

	if (req->error_status > (int32_t) resp->nbindings) {
		warnx("Bad number of bindings in response");
		return (-1);
	}

	for (N = 0; N < req->error_status; N++) {
		if (!asn_is_suboid(&req->bindings[N].var, &resp->bindings[N].var))
			return (0);
		if (resp->bindings[N].syntax == SNMP_SYNTAX_ENDOFMIBVIEW)
			return (0);
	}

	for (R = N , r = N; R  < (int32_t) req->nbindings; R++) {
		for (M = 0; M < req->error_index &&\
			       	(r + M) < (int32_t) resp->nbindings; M++) {
			if (!asn_is_suboid(&req->bindings[R].var,
					&resp->bindings[r + M].var))
				return (0);
			if (resp->bindings[r + M].syntax == SNMP_SYNTAX_ENDOFMIBVIEW) {
				M++;
				break;
			}
		}
		r += M;
	}

	return (0);
}
int
snmp_parse_getnext_resp(struct snmp_pdu * resp, struct snmp_pdu * req)
{
	u_int i;

	for (i = 0; i < req->nbindings; i++) {
		if (!asn_is_suboid(&req->bindings[i].var,
				&resp->bindings[i].var))
			return (0);
		if (resp->version != SNMP_V1 &&
				resp->bindings[i].syntax == SNMP_SYNTAX_ENDOFMIBVIEW)
			return (0);
	}

	return (1);
}
/*
 * Should be called to check a responce to get/getnext/getbulk
 */
int
snmp_parse_resp(struct snmp_client *client, struct snmp_pdu * resp, struct snmp_pdu * req)
{

	if (resp == NULL || req == NULL)
		return (-2);

	if (resp->version != req->version) {
		warnx("Response has wrong version");
		return (-1);
	}

	if (resp->error_status == SNMP_ERR_NOSUCHNAME) {
		warnx("Error - No Such Name");
		return (-1);
	}

	if (resp->error_status != SNMP_ERR_NOERROR) {
		warnx("Error %d in responce", resp->error_status);
		return (-1);
	}

	if (resp->nbindings != req->nbindings &&\
			req->type != SNMP_PDU_GETBULK) {
		warnx("Bad number of bindings in response");
		return (-1);
	}

	switch (req->type) {
		case SNMP_PDU_GET:
			return (snmp_parse_get_resp(client, resp, req));
		case SNMP_PDU_GETBULK:
			return (snmp_parse_getbulk_resp(resp, req));
		case SNMP_PDU_GETNEXT:
			return (snmp_parse_getnext_resp(resp, req));
		default:
			/* NOTREACHED */
			return (-2);
	}

	return (0);
}
static void
snmp_output_octetstring(struct snmp_toolinfo *tool, enum snmp_tc tc, uint32_t len, u_char *octets)
{
	u_char * buf = NULL;

	if (len == 0 || octets == NULL)
		return;

	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_OCTETSTRING].str);

	if ((buf = snmp_oct2tc(tc, len, octets)) != NULL) {
		fprintf(stdout, "%s", buf);
		free(buf);
	}
}
static void
snmp_output_octetindex(struct snmp_toolinfo *tool, enum snmp_tc tc, struct asn_oid *oid)
{
	u_int i;
	u_char *s;

	if ((s = snmp_malloc(oid->subs[0] + 1)) != NULL) {
		for (i = 0; i < oid->subs[0]; i++)
			s[i] = (u_char) (oid->subs[i + 1]);

		snmp_output_octetstring(tool, tc, oid->subs[0], s);
		free(s);
	}
}
/*
 * Check and output syntax type and value
 */
static void
snmp_output_oid_value(struct snmp_toolinfo *tool, struct asn_oid *oid)
{
	char oid_string[ASN_OIDSTRLEN];
	struct snmp_object obj;

	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_OID].str);

	if(!ISSET_NUMERIC(*tool)) {
		memset(&obj, 0, sizeof(struct snmp_object));
		asn_append_oid(&(obj.val.var), oid);

		if (snmp_lookup_enumstring(tool, &obj) > 0)
			fprintf(stdout, "%s" , obj.info->string);
		else if (snmp_lookup_oidstring(tool, &obj) > 0)
			fprintf(stdout, "%s" , obj.info->string);
		else if (snmp_lookup_nodestring(tool, &obj) > 0)
			fprintf(stdout, "%s" , obj.info->string);
		else {
			(void) asn_oid2str_r(oid, oid_string);
			fprintf(stdout, "%s", oid_string);
		}
	} else {
		(void) asn_oid2str_r(oid, oid_string);
		fprintf(stdout, "%s", oid_string);
	}
}
static void
snmp_output_int(struct snmp_toolinfo *tool, struct enum_pairs *enums, int32_t int_val)
{
	char * string;

	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_INTEGER].str);

	if (enums != NULL) {
		string = enum_string_lookup(enums, int_val);
		if (string)
			fprintf(stdout, "%s", string);
		else
			fprintf(stdout, "%d", int_val);
	} else
		fprintf(stdout, "%d", int_val);
}
static void
snmp_output_ipaddress(struct snmp_toolinfo *tool, u_char *ip)
{
	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_IPADDRESS].str);

	fprintf(stdout, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}
static void
snmp_output_counter(struct snmp_toolinfo *tool, uint32_t counter)
{
	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_COUNTER].str);

	fprintf(stdout, "%u", counter);
}
static void
snmp_output_gauge(struct snmp_toolinfo *tool, uint32_t gauge)
{
	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_GAUGE].str);

	fprintf(stdout, "%u", gauge);
}
static void
snmp_output_ticks(struct snmp_toolinfo *tool, uint32_t ticks)
{
	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_TIMETICKS].str);

	fprintf(stdout, "%u", ticks);
}
static void
snmp_output_counter64(struct snmp_toolinfo *tool, uint64_t counter64)
{
	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE)
		fprintf(stdout, "%s : ",
			syntax_strings[SNMP_SYNTAX_COUNTER64].str);

	fprintf(stdout,"%ju", counter64);
}
void
snmp_output_numval(struct snmp_toolinfo *tool, struct snmp_value * val, struct snmp_oid2str *entry)
{
	if (val == NULL)
		return;

	if (GET_OUTPUT(*tool) != OUTPUT_QUIET)
		fprintf(stdout, " = ");

	switch (val->syntax) {

	    case SNMP_SYNTAX_INTEGER:
		if (entry != NULL)
		    snmp_output_int(tool, entry->snmp_enum, val->v.integer);
		else
		    snmp_output_int(tool, NULL, val->v.integer);
		break;

	    case SNMP_SYNTAX_OCTETSTRING:
		if (entry != NULL)
			snmp_output_octetstring(tool, entry->tc, val->v.octetstring.len,
				val->v.octetstring.octets);
		else
			snmp_output_octetstring(tool, SNMP_STRING, val->v.octetstring.len,
				val->v.octetstring.octets);
		break;

	    case SNMP_SYNTAX_OID:
		snmp_output_oid_value(tool, &(val->v.oid));
		break;

	    case SNMP_SYNTAX_IPADDRESS:
		snmp_output_ipaddress(tool, val->v.ipaddress);
		break;

	    case SNMP_SYNTAX_COUNTER:
		snmp_output_counter(tool, val->v.uint32);
		break;

	    case SNMP_SYNTAX_GAUGE:
		snmp_output_gauge(tool, val->v.uint32);
		break;

	    case SNMP_SYNTAX_TIMETICKS:
		snmp_output_ticks(tool, val->v.uint32);
		break;

	    case SNMP_SYNTAX_COUNTER64:
		snmp_output_counter64(tool, val->v.counter64);
		break;

	    case SNMP_SYNTAX_NOSUCHOBJECT:
		fprintf(stdout, "No Such Object");
		break;

	    case SNMP_SYNTAX_NOSUCHINSTANCE:
		fprintf(stdout, "No Such Instance");
		break;

	    case SNMP_SYNTAX_ENDOFMIBVIEW:
		fprintf(stdout, "End of Mib View");
		break;

	    case SNMP_SYNTAX_NULL:
		/* NOTREACHED */
		fprintf(stdout, "agent returned NULL Syntax");
		break;

	    default:
		/* NOTREACHED - If here -then all went completely wrong :-( */
		fprintf(stdout, "agent returned unknown syntax");
		break;
	}

	fprintf(stdout, "\n");
}
static int
snmp_fill_object(struct snmp_toolinfo *tool, struct snmp_object *obj, struct snmp_value *val)
{
	int rc;
	asn_subid_t suboid;

	if (obj == NULL || val == NULL)
		return (-1);

	if ((suboid = snmp_suboid_pop(&(val->var))) > ASN_MAXID)
		return (-1);

	memset(obj, 0, sizeof(struct snmp_object));
	asn_append_oid(&(obj->val.var), &(val->var));
	obj->val.syntax = val->syntax;

	if (obj->val.syntax > 0)
		rc = snmp_lookup_leafstring(tool, obj);
	else
		rc = snmp_lookup_nonleaf_string(tool, obj);

	(void) snmp_suboid_append(&(val->var), suboid);
	(void) snmp_suboid_append(&(obj->val.var), suboid);

	return (rc);
}
static int
snmp_output_index(struct snmp_toolinfo *tool, struct index *stx, struct asn_oid *oid)
{
	u_char  ip[4];
	uint32_t bytes = 1;
	uint64_t cnt64;
	struct asn_oid temp, out;

	if (oid->len < bytes)
		return (-1);

	memset(&temp, 0, sizeof(struct asn_oid));
	asn_append_oid(&temp,oid);

	switch (stx->syntax) {
		case SNMP_SYNTAX_INTEGER:
			snmp_output_int(tool, stx->snmp_enum, temp.subs[0]);
			break;

		case SNMP_SYNTAX_OCTETSTRING:
			if ((temp.subs[0] > temp.len -1 ) || (temp.subs[0] > ASN_MAXOCTETSTRING))
				return (-1);
			snmp_output_octetindex(tool, stx->tc, &temp);
			bytes += temp.subs[0];
			break;

		case SNMP_SYNTAX_OID:
			if ((temp.subs[0] > temp.len -1) || (temp.subs[0] > ASN_MAXOIDLEN))
				return (-1);

			bytes += temp.subs[0];
			memset(&out, 0, sizeof(struct asn_oid));
			asn_slice_oid(&out, &temp, 1, bytes);
			snmp_output_oid_value(tool, &out);
			break;

		case SNMP_SYNTAX_IPADDRESS:
			if (temp.len < 4)
				return (-1);
			for (bytes = 0; bytes < 4; bytes++)
				ip[bytes] = temp.subs[bytes];

			snmp_output_ipaddress(tool, ip);
			bytes = 4;
			break;

		case SNMP_SYNTAX_COUNTER:
			snmp_output_counter(tool, temp.subs[0]);
			break;

		case SNMP_SYNTAX_GAUGE:
			snmp_output_gauge(tool, temp.subs[0]);
			break;

		case SNMP_SYNTAX_TIMETICKS:
			snmp_output_ticks(tool, temp.subs[0]);
			break;

		case SNMP_SYNTAX_COUNTER64:
			if (oid->len < 2)
				return (-1);
			bytes = 2;
			memcpy(&cnt64, temp.subs, bytes);
			snmp_output_counter64(tool, cnt64);
			break;

		default:
			return (-1);
	}

	return (bytes);
}
static int
snmp_output_object(struct snmp_toolinfo *tool, struct snmp_object *obj)
{
	int i, first, len;
	struct asn_oid oid;
	struct index *temp;

	if (ISSET_NUMERIC(*tool))
		return (-1);

	if (obj->info->table_idx == NULL) {
		fprintf(stdout,"%s.%d", obj->info->string,
 				obj->val.var.subs[obj->val.var.len - 1]);
		return (1);
	}

	fprintf(stdout,"%s[", obj->info->string);
	memset(&oid, 0, sizeof(struct asn_oid));

	len = 1;
	asn_slice_oid(&oid, &(obj->val.var),
			(obj->info->table_idx->var.len + len), obj->val.var.len);

	first = 1;
	STAILQ_FOREACH(temp, &(OBJECT_IDX_LIST(*obj)), link) {
		if(first)
			first = 0;
		else
			fprintf(stdout, ", ");

		if ((i = snmp_output_index(tool, temp, &oid)) < 0)
			break;

		len += i;
		memset(&oid, 0, sizeof(struct asn_oid));
		asn_slice_oid(&oid, &(obj->val.var),
			(obj->info->table_idx->var.len + len), obj->val.var.len + 1);
	}

	fprintf(stdout,"]");
	return (1);
}
void
snmp_output_err_resp(struct snmp_toolinfo *tool, struct snmp_pdu * pdu)
{
	char buf[ASN_OIDSTRLEN];
	struct snmp_object object;

	if (pdu == NULL || (pdu->error_index > (int32_t) pdu-> nbindings)) {
		fprintf(stdout,"Invalid error index in PDU\n");
		return;
	}

	fprintf(stdout, "Agent %s:%s returned error \n", tool->client->chost, tool->client->cport);

	if (!ISSET_NUMERIC(*tool) && (snmp_fill_object(tool, &object, &(pdu->bindings[pdu->error_index - 1])) > 0))
		snmp_output_object(tool, &object);
	else {
		(void) asn_oid2str_r(&(pdu->bindings[pdu->error_index - 1].var), buf);
		fprintf(stdout,"%s", buf);
	}

	fprintf(stdout," caused error - ");
	if((pdu->error_status > 0) && (pdu->error_status <= SNMP_ERR_INCONS_NAME))
		fprintf(stdout, "%s\n", error_strings[pdu->error_status].str);
	else
		fprintf(stdout,"%s\n", error_strings[SNMP_ERR_UNKNOWN].str);

}
void
snmp_output_resp(struct snmp_toolinfo *tool, struct snmp_pdu * pdu)
{
	char p[ASN_OIDSTRLEN];
	uint i;
	struct snmp_object object;

	for (i = 0; i < pdu->nbindings; i++) {
		if (GET_OUTPUT(*tool) != OUTPUT_QUIET) {
		    if (!ISSET_NUMERIC(*tool) && ((snmp_fill_object(tool, &object, &(pdu->bindings[i])) > 0))) {
			snmp_output_object(tool, &object);
		    } else {
			(void) asn_oid2str_r(&(pdu->bindings[i].var), p);
			fprintf(stdout, "%s", p);
		    }
		}
	    snmp_output_numval(tool, &(pdu->bindings[i]), object.info);
	}

}
