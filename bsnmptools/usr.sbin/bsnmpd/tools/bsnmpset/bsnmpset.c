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
 * a tool for sending SNMP SET requests
 */
#include <sys/queue.h>
#include <sys/types.h>

#include <ctype.h>
#if defined(HAVE_ERR_H)
#include <err.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#if defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
#include <string.h>
#include <unistd.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>
#include <bsnmp/snmpclient.h>
#if !defined(HAVE_STRLCPY) || !defined(HAVE_ERR_H)
#include <bsnmp/support.h>    /* err, errx, strlcpy, warn, warnx */
#endif
#include "bsnmptc.h"
#include "bsnmptools.h"

const char helptxt[] = "\
\n\
bsnmpset [-adehn] [-b buffersize] [-I options] [-i filelist] [-l filename] [-o output]\n\
         [-r retries] [-s [trans::][community@][server][:port]] [-t timeout] [-v version]\n\
         OID=syntax:value [OID=syntax:value [OID=syntax:value[...]]]\n\
options: \n\
 -a                      ingore syntax/access type and add OID to pdu\n\
 -d                      debug - dump raw Pdus\n\
 -e                      if error is returned in responce pdu, resend request\n\
                         removing the variable that caused the error\n\
 -h                      print this text\n\
 -n                      interpret the input as numerical OIDs rather than parse them\n\
 -b buffersize           size of receive/transmit buffer\n\
 -I options              include each of the files in the list - options are (keep order):\n\
	cut=OID          specify an initial OID that was cut from the file to be appended\n\
	path=pathname    specify a path where to read the files from\n\
	file=filelist    a list of comma separated files, to which the two options above will apply\n\
 -i filelist             comma-separated filelist to read string to oid mappings\n\
 -l filename             name of the client's socket if local sockets are used\n\
 -o output               specify result output : short | verbose | tabular | quiet (default: short)\n\
 -r retries              number of retries when sending a request (default: 3)\n\
 -s [trans::][community@][server][:port]    server specification\n\
           trans                   transport type: udp | stream | dgram (default: udp)\n\
           community               community name (default: public)\n\
           server                  SNMP server name or IP address\n\
           port                    server port (default: 161)\n\
 -t timeout              period to wait before a request times out (default: 3 sec)\n\
 -v version              SNMP version to use : 1 | 2 (default: 2)\n\
 OID=syntax:value        object identifier = syntax:value - no white spaces, where syntax is\n\
 syntax                  one of int(integer) , ip (ipaddress)\n\
                         cnt32 (counter32) , gauge (gauge) , ticks (timeticks), cnt64 (counter64)\n\
                         oct(octetstring) ,\n\
 value                   value to be set - ip addresses in form u.u.u.u\n\
";

static int
snmpset_parse_options(struct snmp_toolinfo *tool, int argc, char **argv)
{
	int opt = 0, optnum = 0, count = 0;
	char opts[] = "ab:dehI:i:l:no:r:s:t:v:";

	while ((opt = getopt(argc, argv, opts)) != EOF) {
	    switch (opt) {
		case 'a':
		    if ((count = parse_skip_access(tool, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'b':
		    if ((count = parse_buflen(tool->client, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'd':
		    if ((count = parse_debug(tool->client, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'e':
		    if ((count = parse_errors(tool, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'h':
		    (void) parse_help(tool, optarg);
		    return (-1);
		    break;
		case 'I':
		    if ((count = parse_include(tool, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'i':
		    if ((count = parse_file(tool, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'l':
		    if ((count = parse_local_path(tool->client, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'n':
		    if ((count = parse_num_oids(tool, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'o':
		    if ((count = parse_output(tool, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'r':
		    if ((count = parse_retry(tool->client, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 's':
		    if ((count = parse_server(tool->client, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 't':
		    if ((count = parse_timeout(tool->client, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'v':
		    if ((count = parse_version(tool->client, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		default:
		    fprintf(stderr, "%s", helptxt);
		    return (-1);
	    }
	}

	return (optnum);
}
static int
parse_int(struct snmp_value * value, char * val)
{
	char * endptr;
	int32_t  v = 0;
	int saved_errno;

	saved_errno = errno;
	errno = 0;

	v = strtol(val,&endptr,10);

	if (errno != 0) {
	    warnx("Integer value %s not supported - %s\n",val,strerror(errno));
	    errno = saved_errno;
	    return (-1);
	}

	value->syntax = SNMP_SYNTAX_INTEGER;
	value->v.integer = v;
	errno = saved_errno;

	return (0);
}
/*
 * Here syntax may be one of SNMP_SYNTAX_COUNTER, SNMP_SYNTAX_GAUGE,
 * SNMP_SYNTAX_TIMETICKS.
 */
static int
parse_uint(struct snmp_value * value, char * val)
{
	char * endptr;
	uint32_t  v = 0;
	int saved_errno;

	saved_errno = errno;
	errno = 0;

	v = strtoul(val,&endptr,10);

	if (errno != 0) {
	    warnx("Value %s not supported - %s\n",val,strerror(errno));
	    errno = saved_errno;
	    return (-1);
	}

	value->v.uint32 = v;
	errno = saved_errno;

	return (0);
}
static int
parse_ticks(struct snmp_value * value, char * val)
{
	if (parse_uint(value,val) < 0)
	    return (-1);

	value->syntax = SNMP_SYNTAX_TIMETICKS;
	return (0);
}
static int
parse_gauge(struct snmp_value * value, char * val)
{
	if (parse_uint(value,val) < 0)
	    return (-1);

	value->syntax = SNMP_SYNTAX_GAUGE;
	return (0);
}
static int
parse_counter(struct snmp_value * value, char * val)
{
	if (parse_uint(value,val) < 0)
	    return (-1);

	value->syntax = SNMP_SYNTAX_COUNTER;
	return (0);
}
static int
parse_uint64(struct snmp_value * value, char * val)
{
	char * endptr;
	uint64_t  v;
	int saved_errno;

	saved_errno = errno;
	errno = 0;

	v = strtoull(val,&endptr,10);

	if (errno != 0) {
	    warnx("Value %s not supported - %s\n", val, strerror(errno));
	    errno = saved_errno;
	    return (-1);
	}

	value->syntax = SNMP_SYNTAX_COUNTER64;
	value->v.counter64 = v;
	errno = saved_errno;

	return (0);
}
static int
parse_oid_numeric(struct snmp_value * value, char * val)
{
	char * endptr;
	asn_subid_t suboid;
	int saved_errno;

	do {
	    saved_errno = errno;
	    errno = 0;
	    suboid = strtoul(val, &endptr, 10);

	    if (errno != 0) {
		warnx("Value %s not supported - %s\n", val, strerror(errno));
		errno = saved_errno;
		return (-1);
	    }
	    errno = saved_errno;

	    if ((asn_subid_t) suboid > ASN_MAXID) {
		warnx("Suboid %u > ASN_MAXID", suboid);
			return (-1);
	    }

	    if (snmp_suboid_append(&(value->v.oid), suboid) < 0)
		return (-1);

	    val = endptr + 1;
	} while (*endptr == '.');

	if (*endptr != '\0') {
		warnx("OID value %s not supported", val);
	}

	value->syntax = SNMP_SYNTAX_OID;

	return (0);
}
static int
parse_ip(struct snmp_value * value, char * val)
{
	uint32_t v;
	int i;
	char *endptr, *str;

	str = val;

	for (i = 0; i < 4; i++) {
	    v = strtoul(str,&endptr,10);

	    if (v > 0xff)
		return (-1);

	    if ((*endptr != '.') && ((*endptr != '\0') && (i != 3)))
		break;

	    str = endptr + 1;
	    value->v.ipaddress[i] = (u_char) v;
	}

	value->syntax = SNMP_SYNTAX_IPADDRESS;
	return (0);
}
/*
 * Allow OID leaf in both forms:
 * 1) 1.3.6.1.2... ->  in such case call directly the function
 * reading raw OIDs
 * 2) begemotSnmpdAgentFreeBSD -> lookup the ASN OID corresponding to that
 */
static int
parse_oid_string(struct snmp_toolinfo *tool, struct snmp_value * value, char * string)
{
	struct snmp_object obj;

	if (isdigit(string[0]))
		return (parse_oid_numeric(value, string));

	memset(&obj, 0, sizeof(struct snmp_object));
	if (snmp_lookup_enumoid(tool, &obj, string) < 0) {
		warnx("Unknown OID enum string - %s", string);
		return (-1);
	}

	asn_append_oid(&(value->v.oid), &(obj.val.var));
	return (1);
}
static int
parse_int_string(struct snmp_object *object, char * val)
{
	int32_t	v;

	if (isdigit(val[0]))
		return ((parse_int(&(object->val), val)));

	if (object->info == NULL) {
		warnx("Unknown enumerated integer type - %s", val);
		return (-1);
	}
	if ((v = enum_number_lookup(object->info->snmp_enum, val)) < 0)
		warnx("Unknown enumerated integer type - %s", val);

	object->val.v.integer = v;

	return (1);
}
static int
parse_syntax_val(struct snmp_value * value, enum snmp_syntax syntax, char * val)
{

	switch (syntax) {
		case SNMP_SYNTAX_INTEGER:
			return (parse_int(value, val));
		case SNMP_SYNTAX_IPADDRESS:
			return (parse_ip(value, val));
		case SNMP_SYNTAX_COUNTER:
			return (parse_counter(value, val));
		case SNMP_SYNTAX_GAUGE:
			return (parse_gauge(value, val));
		case SNMP_SYNTAX_TIMETICKS:
			return (parse_ticks(value, val));
		case SNMP_SYNTAX_COUNTER64:
			return (parse_uint64(value, val));
		case SNMP_SYNTAX_OCTETSTRING:
			return (snmp_tc2oct(SNMP_STRING, value, val));
		case SNMP_SYNTAX_OID:
			return (parse_oid_numeric(value, val));
		default:
			/* NOTREACHED */
			break;
	}

	return (-1);
}
/*
 * Parse a command line argument of type OID=syntax:value and fill in whatever
 * fields can be derived from the input into snmp_value structure. Reads numeric OIDs.
 */
static int
parse_pair_numoid_val(char * str, struct snmp_value * snmp_val)
{
	int  cnt;
	char * ptr;
	enum snmp_syntax syntax;
	char oid_str[ASN_OIDSTRLEN];

	ptr = str;
	for (cnt = 0; cnt < ASN_OIDSTRLEN; cnt++) {
	    if (ptr[cnt] == '=')
		break;
	}
	if (cnt >= ASN_OIDSTRLEN) {
	    warnx("OID too long - %s", str);
	    return (-1);
	}
	strlcpy(oid_str, ptr, (size_t)(cnt + 1));

	ptr = (str + cnt + 1);
	for (cnt = 0; cnt < MAX_CMD_SYNTAX_LEN; cnt++) {
	    if(ptr[cnt] == ':')
		break;
	}

	if (cnt >= MAX_CMD_SYNTAX_LEN) {
	    warnx("Unknown syntax in OID - %s", str);
	    return (-1);
	}

	if ((syntax = parse_syntax(ptr)) <= SNMP_SYNTAX_NULL) {
	    warnx("Unknown syntax in OID - %s", ptr);
	    return (-1);
	}

	ptr = (ptr + cnt + 1);

	for (cnt = 0; cnt < MAX_OCTSTRING_LEN; cnt++) {
	    if (ptr[cnt] == '\0')
		break;
	}

	if (ptr[cnt] != '\0') {
	    warnx("Value string too long - %s",ptr);
	    return (-1);
	}

	/*
	 * Here try parsing the oids and syntaxes and then check values -
	 * have to know syntax to check value boundaries
	 */
	if (snmp_parse_numoid(oid_str, &(snmp_val->var)) < 0) {
	    warnx("Error parsing OID %s",oid_str);
	    return (-1);
	}

	if (parse_syntax_val(snmp_val, syntax, ptr) < 0)
	    return (-1);

	return (1);
}
static int
parse_syntax_strval(struct snmp_toolinfo *tool, char *str, struct snmp_object *object)
{
	uint len;
	enum snmp_syntax syn;

	/*
	 * Syntax string here not required  - still may be present.
	 */

	if (GET_OUTPUT(*tool) == OUTPUT_VERBOSE) {
		for (len = 0 ; *(str + len) != ':'; len++) {
			if (*(str + len) == '\0') {
				warnx("Syntax missing in value - %s", str);
				return (-1);
			}
		}

		if ((syn = parse_syntax(str)) <= SNMP_SYNTAX_NULL) {
			warnx("Unknown syntax in - %s", str);
			return (-1);
		}

		if (syn != object->val.syntax) {
			if (!ISSET_ERRIGNORE(*tool)) {
				warnx("Bad syntax in - %s", str);
				return (-1);
			} else
				object->val.syntax = syn;
		}
		len++;
	} else
		len = 0;

	switch (object->val.syntax) {
		case SNMP_SYNTAX_INTEGER:
			return (parse_int_string(object, str + len));
		case SNMP_SYNTAX_IPADDRESS:
			return (parse_ip(&(object->val), str + len));
		case SNMP_SYNTAX_COUNTER:
			return (parse_counter(&(object->val), str + len));
		case SNMP_SYNTAX_GAUGE:
			return (parse_gauge(&(object->val), str + len));
		case SNMP_SYNTAX_TIMETICKS:
			return (parse_ticks(&(object->val), str + len));
		case SNMP_SYNTAX_COUNTER64:
			return (parse_uint64(&(object->val), str + len));
		case SNMP_SYNTAX_OCTETSTRING:
			return (snmp_tc2oct(object->info->tc, &(object->val), str + len));
		case SNMP_SYNTAX_OID:
			return (parse_oid_string(tool, &(object->val), str + len));
		default:
			/* NOTREACHED */
			break;
	}

	return (-1);
}
static int
parse_pair_stroid_val(struct snmp_toolinfo *tool, struct snmp_object *obj, char *argv)
{
	char 		string[MAXSTR], *ptr;
	int 		i;
	struct asn_oid	in_oid;

	ptr = argv;
	i = 0;
	while (isalpha(*ptr)|| *ptr == '_' || (i != 0 && isdigit(*ptr))) {
		ptr++;
		i++;
	}

	if (i <= 0 || i >= MAXSTR)
		return (-1);

	memset(&in_oid, 0, sizeof(struct asn_oid));
	if ((ptr = snmp_parse_suboid((argv + i), &in_oid)) == NULL) {
		warnx("Invalid sub-OID - %s", argv);
		return(-1);
	}

	strlcpy(string, argv, i + 1);

	if (snmp_lookup_oidall(tool, obj, string) < 0) {
		warnx("No entry for %s in mapping lists", string);
		return (-1);
	}

	if (in_oid.len > 0)
	    asn_append_oid(&(obj->val.var), &in_oid);
	else if (*ptr == '[') {
	    if ((ptr = snmp_parse_index(tool, ptr + 1, obj)) == NULL)
		return (-1);
	} else {
	    if (snmp_suboid_append(&(obj->val.var), (asn_subid_t) 0) < 0)
		return (-1);
	}

	if (*ptr != '=') {
	    warnx("Value to set expected after OID");
	    return (-1);
	}

	if (parse_syntax_strval(tool, ptr + 1, obj) < 0)
	    return (-1);

	return (1);
}
static int
snmpset_parse_oid(struct snmp_toolinfo *tool, struct snmp_object *obj, char *argv)
{
	if (argv == NULL)
		return (-1);

	if (ISSET_NUMERIC(*tool)) {
		if (parse_pair_numoid_val(argv, &(obj->val)) < 0)
			return (-1);
	} else {
		if (parse_pair_stroid_val(tool, obj, argv) < 0)
			return (-1);
	}

	return (1);
}
static int
add_ip_syntax(struct snmp_value * dst,struct snmp_value * src)
{
	int i;

	dst->syntax = SNMP_SYNTAX_IPADDRESS;

	for(i = 0; i < 4; i++)
	    dst->v.ipaddress[i] = src->v.ipaddress[i];

	return (1);
}
static int
add_octstring_syntax(struct snmp_value * dst,struct snmp_value * src)
{
    u_char * ptr;

    if (src->v.octetstring.len > ASN_MAXOCTETSTRING) {
        warnx("OctetString len too big - %u",src->v.octetstring.len);
        return (-1);
    }

    if ((ptr = snmp_malloc(src->v.octetstring.len)) == NULL)
        return (-1);

    memcpy(ptr, src->v.octetstring.octets,(size_t) src->v.octetstring.len);

    dst->syntax = SNMP_SYNTAX_OCTETSTRING;
    dst->v.octetstring.len = src->v.octetstring.len;
    dst->v.octetstring.octets = ptr;

    return(0);
}
static int
add_oid_syntax(struct snmp_value * dst,struct snmp_value * src)
{
    asn_append_oid(&(dst->v.oid), &(src->v.oid));
    dst->syntax = SNMP_SYNTAX_OID;
    return (0);
}

/*
 * Check syntaxes - if syntax is one of SNMP_SYNTAX_NULL, SNMP_SYNTAX_NOSUCHOBJECT,
 * SNMP_SYNTAX_NOSUCHINSTANCE, SNMP_SYNTAX_ENDOFMIBVIEW or anything not known - return error
 */
static int
snmpset_add_value(struct snmp_value * dst,struct snmp_value * src)
{
    if (dst == NULL || src == NULL)
        return (-1);

    switch(src->syntax) {
        case SNMP_SYNTAX_INTEGER:
            dst->v.integer = src->v.integer;
            dst->syntax = SNMP_SYNTAX_INTEGER;
            break;
        case SNMP_SYNTAX_TIMETICKS:
            dst->v.uint32 = src->v.uint32;
            dst->syntax = SNMP_SYNTAX_TIMETICKS;
            break;
        case SNMP_SYNTAX_GAUGE:
            dst->v.uint32 = src->v.uint32;
            dst->syntax = SNMP_SYNTAX_GAUGE;
            break;
        case SNMP_SYNTAX_COUNTER:
            dst->v.uint32 = src->v.uint32;
            dst->syntax = SNMP_SYNTAX_COUNTER;
            break;
        case SNMP_SYNTAX_COUNTER64:
            dst->syntax = SNMP_SYNTAX_COUNTER64;
            dst->v.counter64 = src->v.counter64;
            break;
        case SNMP_SYNTAX_IPADDRESS:
            add_ip_syntax(dst,src);
            break;
        case SNMP_SYNTAX_OCTETSTRING:
            add_octstring_syntax(dst,src);
            break;
        case SNMP_SYNTAX_OID:
            add_oid_syntax(dst,src);
            break;
        default:
            warnx("unknown syntax %d",src->syntax);
            return (-1);
    }

    return (0);
}
static int
snmpset_verify_vbind(struct snmp_toolinfo *tool, struct snmp_pdu *pdu, struct snmp_object *obj)
{
    /*
     * Don't let cnt64 in a SNMPv1 PDU
     */
    if (pdu->version == SNMP_V1 && obj->val.syntax == SNMP_SYNTAX_COUNTER64)
        return (-1);

    if (ISSET_NUMERIC(*tool) || ISSET_ERRIGNORE(*tool))
        return (1);

    if (obj->info->access < SNMP_ACCESS_SET) {
        warnx("Object %s not accessible for set - try 'bsnmpset -a'", obj->info->string);
        return (-1);
    }

    return (1);
}
static int
snmpset_add_vbind(struct snmp_pdu *pdu,struct snmp_object *obj)
{
	if (pdu->nbindings > SNMP_MAX_BINDINGS) {
	    warnx("Too many OIDs for one PDU");
	    return (-1);
	}

	if (obj->error > 0)
	    return (0);

	if (snmpset_add_value(&(pdu->bindings[pdu->nbindings]), &(obj->val)) < 0)
	    return (-1);

	asn_append_oid(&(pdu->bindings[pdu->nbindings].var), &(obj->val.var));
	pdu->nbindings++;

	return (pdu->nbindings);
}
/*
 * According to command line options prepare SNMP Set PDU.
 * Wait for a response and print it.
 */
int main(int argc, char ** argv)
{
	struct snmp_toolinfo *tool;
	struct snmp_client *client_context;
	struct snmp_pdu req, resp;
	int oid_cnt, last_oid, opt_num;

	tool = snmptool_init(helptxt);
	client_context = tool->client;

	if ((opt_num = snmpset_parse_options(tool, argc, argv)) < 0) {
	    snmp_tool_freeall(tool);
	    exit(0);
	}

	oid_cnt = argc - opt_num - 1;
	if (oid_cnt == 0) {
	    warnx("Provide at least one OID\n");
	    snmp_tool_freeall(tool);
	    exit(0);
	}

	if ((oid_cnt < 0)||(oid_cnt > SNMP_MAX_BINDINGS)) {
	    warnx("Too many OIDs - %d", oid_cnt);
	    snmp_tool_freeall(tool);
	    exit(0);
	}

	if (snmp_import_all(tool) < 0) {
	    snmp_tool_freeall(tool);
	    exit(0);
	}

	/* parse the input OIDs vice versa */
	for (last_oid = argc - 1; oid_cnt > 0; last_oid--, oid_cnt--) {
	    if ((snmp_object_add(tool, snmpset_parse_oid, argv[last_oid])) < 0) {
		snmp_tool_freeall(tool);
		exit(0);
	    }
	}

	if (snmp_open(client_context, NULL, NULL, NULL, NULL)) {
	    warnx("Failed to open snmp session - %s\n", strerror (errno));
	    snmp_tool_freeall(tool);
	    exit(-1);
	}

	snmp_pdu_create(client_context, &req, SNMP_PDU_SET);

	while ((snmp_pdu_add_bindings(tool, snmpset_verify_vbind,
		snmpset_add_vbind, &req)) > 0) {
	    if(snmp_dialog(client_context, &req, &resp)) {
		warnx("Snmp dialog - %s\n", strerror (errno));
		break;
	    }

	    if (snmp_pdu_check(client_context, &req, &resp) > 0) {
		if (GET_OUTPUT(*tool) != OUTPUT_QUIET)
		    snmp_output_resp(tool, &resp);
		break;
	    }

	    snmp_output_err_resp(tool, &resp);

	    if (!ISSET_RETRY(*tool))
		break;

	    if (snmp_object_seterror(tool, &(resp.bindings[resp.error_index - 1]), resp.error_status) <= 0)
		break;

	    warnx("Retrying...");
	    snmp_pdu_free(&req);
	    snmp_pdu_free(&resp);
	    snmp_pdu_create(client_context, &req, SNMP_PDU_SET);
	}

	snmp_pdu_free(&req);
	snmp_pdu_free(&resp);
	snmp_tool_freeall(tool);

	exit(0);
}
