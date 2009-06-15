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
 *  a tool for doing a "snmp walk"
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

/* the default tree to walk */
static const struct asn_oid snmp_mibII_OID = {
	6 , { 1, 3, 6, 1, 2, 1 }
};

/* help text */
const char helptxt[] ="\
\n\
bsnmpwalk [-dhn] [-b buffersize] [-I options] [-i filelist] [-l filename]\n\
          [-o output] [-r retries] [-s [trans::][community@][server][:port]]\n\
          [-t timeout] [-v version] [OID]\n\
options: \n\
 -d                      debug - dump raw Pdus\n\
 -h                      print this text\n\
 -n                      interpret the input as numerical OIDs rather than parse them\n\
 -b buffersize           size of receive/transmit buffer\n\
 -I options              include each of the files in the list - options are (keep order):\n\
	cut=OID          specify an initial OID that was cut from the file to be appended\n\
	path=pathname    specify a path where to read the files from\n\
	file=filelist    a list of comma separated files, to which the two options above will apply\n\
 -i filelist             comma-separated filelist to read string to oid mappings\n\
 -l filename             name of the client's socket if local sockets are used\n\
 -o output               specify result output : short | verbose | quiet (default: short)\n\
 -r retries              number of retries when sending a request (default: 3)\n\
 -s [trans::][community@][server][:port]    server specification\n\
           trans                   transport type: udp | stream | dgram (default: udp)\n\
           community               community name (default: public)\n\
           server                  SNMP server name or IP address\n\
           port                    server port (default: 161)\n\
 -t timeout              period to wait before a request times out (default: 3 sec)\n\
 -v version              SNMP version to use : 1 | 2 (default: 2)\n\
 OID                     OID to start walk from - default - \n\
                         walk subtree rooted at mib-2 (1.3.6.1.2.1)\n\
";

static int
snmpwalk_parse_options(struct snmp_toolinfo *tool, int argc, char **argv)
{
	int opt, count, optnum = 0;
	char opts[] = "b:dhI:i:l:no:r:s:t:v:";

	while ((opt = getopt(argc, argv, opts)) != EOF) {
	    switch (opt) {
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
snmpwalk_add_default(struct snmp_toolinfo *tool, struct snmp_object *obj, char *string)
{
	asn_append_oid(&(obj->val.var), &snmp_mibII_OID);
	return (1);
}
static int
snmpwalk_add_vbind(struct snmp_pdu *pdu,struct snmp_object *obj)
{
	if (pdu->nbindings > 0) {
		warnx("Too many bindings for one PDU\n");
		return (-1);
	}


	asn_append_oid(&(pdu->bindings[pdu->nbindings].var), &(obj->val.var));
	pdu->nbindings++;

	return(pdu->nbindings);
}
static int
snmpwalk_parse_stroid(struct snmp_toolinfo *tool, struct snmp_object *obj, char *argv)
{
	char 		string[MAXSTR], *ptr;
	int 		i = 0;
	struct asn_oid  in_oid;

	ptr = argv;
	while (isalpha(*ptr)|| *ptr == '_' || (i != 0 \
			 && isdigit(*ptr))) {
		ptr++;
		i++;
	}

	if (i <= 0 || i >= MAXSTR)
		return (-1);

	memset(&in_oid, 0, sizeof(struct asn_oid));
	if ((ptr = snmp_parse_suboid((argv + i), &in_oid)) == NULL) {
	    return (-1);
	}

	strlcpy(string, argv, i + 1);

	if (snmp_lookup_oidall(tool, obj, string) < 0) {
		warnx("No entry for %s in mapping lists", string);
		return(-1);
	}

	/*
	 * If suboid provided on command line - append it as well
	 */

	if (in_oid.len > 0)
	    asn_append_oid(&(obj->val.var), &in_oid);
	else if (*ptr == '[') {
		if ((ptr = snmp_parse_index(tool, ptr + 1, obj)) == NULL)
		    return (-1);
	}

	if (*ptr != '\0') {
	    warnx("Invalid character after OID %s", argv);
	    return (-1);
	}
	return (1);
}
static int
snmpwalk_parse_oid(struct snmp_toolinfo *tool, struct snmp_object *obj, char *argv)
{
	if (argv == NULL)
		return (-1);

	if (ISSET_NUMERIC(*tool)) {
		if (snmp_parse_numoid(argv, &(obj->val.var)) < 0)
			return (-1);
	} else {
		if(snmpwalk_parse_stroid(tool, obj, argv) < 0)
			return (-1);
	}

	return(1);
}
/*
 * Prepare the next GetNext/Get PDU to send
 */
static void
snmpwalk_nextpdu_create(struct snmp_client *client, u_int op,
		struct asn_oid *var, struct snmp_pdu *pdu)
{
	snmp_pdu_create(client, pdu, op);
	asn_append_oid(&(pdu->bindings[0].var), var);
	pdu->nbindings = 1;

	return;
}
/*
 * Do a 'snmp walk' - according to command line options request for values lexicographically
 * subsequent and subrooted at a common node. Send a GetNext PDU requesting the value for each
 * next variable and print the responce. Stop when a Responce PDU is received that contains
 * the value of a variable not subrooted at the variable the walk started.
 */
int
main(int argc, char ** argv)
{
	struct snmp_toolinfo *tool;
	struct snmp_client *client_context;
	struct asn_oid root; /* keep the inital oid */
	struct snmp_pdu pdu_to_send, pdu_to_recv;
	int oid, opt_num, outputs;

	tool = snmptool_init(helptxt);
	client_context = tool->client;

	if ((opt_num = snmpwalk_parse_options(tool, argc, argv)) < 0) {
	    snmp_tool_freeall(tool);
	    exit(0);
	}

	if (snmp_import_all(tool) < 0) {
	    snmp_tool_freeall(tool);
	    exit(0);
	}

	oid = argc - opt_num - 1;

	switch (oid) {
	    case 0:
		if (snmp_object_add(tool, snmpwalk_add_default, NULL) < 0) {
		    snmp_tool_freeall(tool);
		    errx(1, "Error setting default tree OID to walk");
		}
		break;
	    case 1:
		/* last command line argument will always be the OID to start the walk from */
		if ((snmp_object_add(tool, snmpwalk_parse_oid, argv[argc - 1])) < 0) {
		    snmp_tool_freeall(tool);
		    exit(1);
		}
		break;
	    default:
		snmp_tool_freeall(tool);
		errx(1, "Only one OID allowed");
	}

	snmp_pdu_create(client_context, &pdu_to_send, SNMP_PDU_GETNEXT);

	if (snmp_pdu_add_bindings(tool, (snmp_verify_vbind_f) NULL,
			snmpwalk_add_vbind, &pdu_to_send) < 0) {
	    snmp_tool_freeall(tool);
	    exit(1);
	}

	if (snmp_open(client_context, NULL, NULL, NULL, NULL)) {
	    snmp_tool_freeall(tool);
	    err(1, "Failed to open snmp session");
	}

	/* remember the root where the walk started from */
	memset(&root, 0 ,sizeof(struct asn_oid));
	asn_append_oid(&root, &(pdu_to_send.bindings[0].var));

	outputs = 0;
	while (snmp_dialog(client_context, &pdu_to_send, &pdu_to_recv) >= 0) {

	    if ((snmp_parse_resp(client_context, &pdu_to_recv, &pdu_to_send)) < 0) {
		snmp_output_err_resp(tool, &pdu_to_recv);
		snmp_pdu_free(&pdu_to_recv);
		outputs = -1;
		break;
	    }

	    if (!(asn_is_suboid(&root, &(pdu_to_recv.bindings[0].var)))) {
		snmp_pdu_free(&pdu_to_recv);
		break;
	    }
	    snmp_output_resp(tool, &pdu_to_recv);
	    outputs++;
	    snmp_pdu_free(&pdu_to_recv);

	    snmpwalk_nextpdu_create(client_context, SNMP_PDU_GETNEXT,
			&(pdu_to_recv.bindings[0].var), &pdu_to_send);
	}

	/* Just a case our root was a leaf */
	if (outputs == 0) {

	    snmpwalk_nextpdu_create(client_context, SNMP_PDU_GET, &root, &pdu_to_send);

	    if (snmp_dialog(client_context, &pdu_to_send, &pdu_to_recv) == SNMP_CODE_OK /* 0 */) {

		if(snmp_parse_resp(client_context, &pdu_to_recv,&pdu_to_send)  < 0)
		    snmp_output_err_resp(tool, &pdu_to_recv);
		else
		    snmp_output_resp(tool, &(pdu_to_recv));

		snmp_pdu_free(&pdu_to_recv);
	    } else
		err(1, "Snmp dialog");
	}

	snmp_tool_freeall(tool);

	exit(0);
}
