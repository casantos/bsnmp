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
 * a tool for sending SNMP get requests (GET, GETBULK, GETNEXT )
 */
#include <sys/queue.h>
#include <sys/types.h>

#include <ctype.h>
#if defined(HAVE_ERR_H)
#include <err.h>
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
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
bsnmpget [-adehn] [-b buffersize] [-I options] [-i filelist] [-l filename]\n\
         [-M max-repetitions] [-N non-repeaters] [-o output] [-p pdu] [-r retries]\n\
	 [-s [trans::][community@][server][:port]] \n\
         [-t timeout] [-v version] OID [OID [OID [...]]]\n\
options: \n\
 -a                      ingore syntax/access type and add OID to pdu\n\
 -d                      debug - dump raw Pdus\n\
 -e                      if error is returned in responce pdu, resend request\n\
                         removing the variable that caused the error (use with Get/GetNext)\n\
 -h                      print this text\n\
 -n                      interpret the input as numerical OIDs rather than parse them\n\
 -b buffersize           size of receive/transmit buffer\n\
 -I options              include each of the files in the list - options are (keep order):\n\
	cut=OID          specify an initial OID that was cut from the file to be appended\n\
	path=pathname    specify a path where to read the files from\n\
	file=filelist    a list of comma separated files, to which the two options above will apply\n\
 -i filelist             comma-separated filelist to read string to oid mappings\n\
 -l filename             name of the client's socket if local sockets are used\n\
 -M max-repetitions      specify a value for max-repetitions (use with GetBulk only - default:1)\n\
 -N non-repeaters        specify a value for non-repeaters (use with GetBulk only)\n\
 -o output               specify result output : short | verbose | quiet (default: short)\n\
 -p pdu                  pdu type to send : get | getbulk | getnext (default: getbulk)\n\
 -r retries              number of retries when sending a request (default: 3)\n\
 -s [trans::][community@][server][:port]    server specification\n\
           trans                   transport type: udp | stream | dgram (default: udp)\n\
           community               community name (default: public)\n\
           server                  SNMP server name or IP address\n\
           port                    server port (default: 161)\n\
 -t timeout              period to wait before a request times out (default: 3 sec)\n\
 -v version              SNMP version to use : 1 | 2 (default: 2)\n\
OID                      object identifier\n\
";

#define PDUTYPE_BITS	0xf00		/* bits 8-11 for pdu type */
#define MAXREP_BITS	0xff0000	/* bits 16-23 for max-repetitions value */
#define NONREP_BITS	0xff000000	/* bits 24-31 for non-repeaters value */

#define SET_PDUTYPE(tool,type)	((tool).flags |= (type << 8))
#define GET_PDUTYPE(tool)	(((tool).flags & PDUTYPE_BITS) >> 8)

#define SET_MAXREP(tool,i)	(((tool).flags |= (i << 16)))
#define GET_MAXREP(tool)		(((tool).flags & MAXREP_BITS) >> 16)

#define SET_NONREP(tool,i)	(((tool).flags |= (i << 24)))
#define GET_NONREP(tool)		(((tool).flags & NONREP_BITS) >> 24)

static int
parse_max_repetitions(struct snmp_toolinfo *tool, char opt, char *opt_arg)
{
	uint32_t v;

	if (opt_arg == NULL) {
	    warnx("Option %c requires an argument", opt);
	    return (-1);
	}

	v = strtoul((char *)opt_arg, (void *)NULL, 10);

	if (v > SNMP_MAX_BINDINGS) {
	    warnx( "Max repetitions value too big - %d maximum allowed", SNMP_MAX_BINDINGS);
	    return (-1);
	}
	SET_MAXREP(*tool, v);

	return (2);
}
static int
parse_non_repeaters(struct snmp_toolinfo *tool, char opt, char *opt_arg)
{
	uint32_t v;

	if (opt_arg == NULL) {
	    warnx("Option %c requires an argument", opt);
	    return (-1);
	}

	v = strtoul((char *)opt_arg, (void *)NULL, 10);

	if (v > SNMP_MAX_BINDINGS) {
	    warnx("Non repeaters  value too big - %d maximum allowed", SNMP_MAX_BINDINGS);
	    return (-1);
	}
	SET_NONREP(*tool, v);

	return (2);
}
static int
parse_pdu_type(struct snmp_toolinfo *tool, char opt, char *opt_arg)
{
	if (opt_arg == NULL) {
	    warnx("Option %c requires an argument", opt);
	    return (-1);
	}

	if(!strncasecmp(opt_arg,"getbulk",strlen("getbulk"))) {
	    SET_PDUTYPE(*tool, SNMP_PDU_GETBULK);
	} else if (!strncasecmp(opt_arg,"getnext",strlen("getnext"))) {
	    SET_PDUTYPE(*tool, SNMP_PDU_GETNEXT);
	} else if (!strncasecmp(opt_arg,"get",strlen("get"))){
	    SET_PDUTYPE(*tool, SNMP_PDU_GET);
	} else {
	    warnx( "PDU type not supported - %s",(char *)opt_arg);
	    return (-1);
	}

	return (2);
}
static int
snmpget_parse_options(struct snmp_toolinfo *tool, int argc, char **argv)
{
	int opt, count, optnum = 0;
	char opts[] = "ab:dehI:i:l:M:N:no:p:r:s:t:v:";

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
		    (void)parse_help(tool, optarg);
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
		case 'M':
		    if ((count = parse_max_repetitions(tool, opt, optarg)) < 0)
			return (-1);
		    optnum += count;
		    break;
		case 'N':
		    if ((count = parse_non_repeaters(tool, opt, optarg)) < 0)
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
		case 'p':
		    if ((count = parse_pdu_type(tool, opt, optarg)) < 0)
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
/*
 * read user input OID - one of following formats:
 * 1) 1.2.1.1.2.1.0 - that is if option numeric was given
 * 2) string - in such case append .0 to the asn_oid subs
 * 3) string.1 - no additional proccessing required in such case
 */
static int
snmpget_parse_stroid(struct snmp_toolinfo *tool, struct snmp_object *obj, char *argv)
{
	char 		string[MAXSTR], *ptr = NULL;
	int 		i = 0;
	struct asn_oid  in_oid;

	ptr = argv;
	while (isalpha(*ptr)|| *ptr == '_' || (i != 0 && isdigit(*ptr))) {
		ptr++;
		i++;
	}

	if (i <= 0 || i >= MAXSTR)
		return (-1);

	memset(&in_oid, 0, sizeof(struct asn_oid));
	if ((ptr = snmp_parse_suboid((argv + i), &in_oid)) == NULL) {
		warnx("Invalid sub-OID - %s", argv);
		return (-1);
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
	} else if (obj->val.syntax > 0 && GET_PDUTYPE(*tool) == SNMP_PDU_GET) {
	    if (snmp_suboid_append(&(obj->val.var), (asn_subid_t) 0) < 0)
		return (-1);
	}

	if (*ptr != '\0') {
	    warnx("Invalid character after OID - %c\n",*ptr);
	    return (-1);
	}

	return (1);
}
static int
snmpget_parse_oid(struct snmp_toolinfo *tool, struct snmp_object *obj, char *argv)
{
	if (argv == NULL)
		return (-1);

	if (ISSET_NUMERIC(*tool)) {
		if (snmp_parse_numoid(argv, &(obj->val.var)) < 0)
			return (-1);
	} else {
		if (snmpget_parse_stroid(tool, obj, argv) < 0)
			return (-1);
	}

	return (1);
}
static int
snmpget_verify_vbind(struct snmp_toolinfo *tool, struct snmp_pdu *pdu, struct snmp_object *obj)
{
	if (pdu->version == SNMP_V1 && obj->val.syntax == SNMP_SYNTAX_COUNTER64) {
	    warnx("64-bit counters are not supported in SNMPv1 PDU");
	    return (-1);
	}

	if (ISSET_NUMERIC(*tool) || pdu->type == SNMP_PDU_GETNEXT || pdu->type == SNMP_PDU_GETBULK)
	    return (1);

	if (pdu->type == SNMP_PDU_GET && obj->val.syntax == 0) {
	    warnx("Only leaf object values can be added to GET PDU");
	    return (-1);
	}

	return (1);
}
static int
snmpget_add_vbind(struct snmp_pdu *pdu,struct snmp_object *obj)
{
	if (pdu->nbindings > SNMP_MAX_BINDINGS) {
		warnx("Too many bindings in PDU");
		return (-1);
	}

	if (obj->error > 0) {
		warnx("Object already  returned error - skipping\n");
		return (0);
	}

	asn_append_oid(&(pdu->bindings[pdu->nbindings].var), &(obj->val.var));
	pdu->nbindings++;

	return (pdu->nbindings);
}
/*
 * In case of a getbulk PDU, the error_status and error_index fields are used by
 * libbsnmp to hold the values of the non-repeaters and max-repetitions fields
 * that are present only in the getbulk - so before sending the PDU make sure
 * these have correct values as well
 */
static int
snmp_fix_getbulk(struct snmp_pdu *pdu, uint32_t max_rep, uint32_t non_rep)
{
	if (pdu == NULL)
		return (-1);

	if (pdu->nbindings < non_rep)
		pdu->error_status = pdu->nbindings;
	else
		pdu->error_status = non_rep;

	if (max_rep > 0)
		pdu->error_index = max_rep;
	else
		pdu->error_index = 1;

	return (1);
}
/*
 * According to command line options prepare SNMP Get | GetNext | GetBulk PDU.
 * Wait for a response and print it.
 */
int
main(int argc, char ** argv)
{
	struct snmp_toolinfo *tool;
	struct snmp_client *client_context;
	struct snmp_pdu req, resp;
	int oid_cnt, last_oid, opt_num;

	tool = snmptool_init(helptxt);
	client_context = tool->client;

	if ((opt_num = snmpget_parse_options(tool, argc, argv)) < 0) {
	    snmp_tool_freeall(tool);
	    exit(1);
	}

	oid_cnt = argc - opt_num - 1;
	if(oid_cnt == 0) {
	    snmp_tool_freeall(tool);
	    errx(1, "Provide at least one OID");
	}

	if ((oid_cnt <= 0)||(oid_cnt > SNMP_MAX_BINDINGS)) {
	     snmp_tool_freeall(tool);
	     errx(1, "Too many OIDs %d", oid_cnt);
	}

	if (snmp_import_all(tool) < 0) {
	    snmp_tool_freeall(tool);
	    exit(1);
	}

	for (last_oid = argc - 1; oid_cnt > 0; last_oid--, oid_cnt--) {
	    if ((snmp_object_add(tool, snmpget_parse_oid, argv[last_oid])) < 0) {
		snmp_tool_freeall(tool);
		exit(1);
	    }
	}

	/*
	 * a simple sanity check - can't send GETBULK if we're using SNMPv1
	 */

	if ((client_context->version == SNMP_V1) && (GET_PDUTYPE(*tool) == SNMP_PDU_GETBULK)) {
	    snmp_tool_freeall(tool);
	    errx(1, "Can't send GETBULK requests with SNMPv1 PDU");
	}

	if (snmp_open(client_context, NULL,NULL,NULL,NULL)) {
	    snmp_tool_freeall(tool);
	    err(1, "Failed to open snmp session");
	}

	snmp_pdu_create(client_context, &req, GET_PDUTYPE(*tool));

	while ((snmp_pdu_add_bindings(tool, snmpget_verify_vbind,
				snmpget_add_vbind, &req)) > 0) {
	    if (GET_PDUTYPE(*tool) == SNMP_PDU_GETBULK)
		(void) snmp_fix_getbulk(&req, (uint32_t) GET_MAXREP(*tool), (uint32_t) GET_NONREP(*tool));

	    if (snmp_dialog(client_context, &req, &resp)) {
		warn("Snmp dialog");
		break;
	    }

	    if (snmp_parse_resp(client_context, &resp,&req) >= 0 /* SNMP_ERR_NOERROR */) {
		snmp_output_resp(tool, &resp);
		break;
	    }

	    snmp_output_err_resp(tool, &resp);
	    if (GET_PDUTYPE(*tool) == SNMP_PDU_GETBULK || !ISSET_RETRY(*tool))
		break;

	    /* loop through the object list and set object->error to the pdu that caused the error */
	    if (snmp_object_seterror(tool, &(resp.bindings[resp.error_index - 1]), resp.error_status) <= 0)
		break;

	    warnx("Retrying...");
	    snmp_pdu_free(&resp);
	    snmp_pdu_create(client_context, &req, GET_PDUTYPE(*tool));
	}

	snmp_pdu_free(&resp);
	snmp_tool_freeall(tool);

	exit(0);
}
