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
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>
#include <bsnmp/snmpclient.h>
#if !defined(HAVE_STRLCPY) || !defined(HAVE_ERR_H)
#include <bsnmp/support.h>    /* err, errx, strlcpy, warn, warnx */
#endif
#include "bsnmptc.h"
#include "bsnmptools.h"

#define PDUTYPE_BITS		0xf00	/* bits 8-11 for pdu type */
#define GET_PDUTYPE(tool)	(((tool).flags & PDUTYPE_BITS) >> 8)

static int
snmptest_parse_oid(struct snmp_toolinfo *tool, struct snmp_object *obj, char *n_oid)
{
	return (snmp_parse_numoid(n_oid, &(obj->val.var)));
}

static int
snmptest_add_vbind(struct snmp_pdu *pdu,struct snmp_object *obj)
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
 * According to command line options prepare SNMP Get | GetNext | GetBulk PDU.
 * Wait for a response and print it.
 */
int
main(int argc, char ** argv)
{
	struct snmp_toolinfo *tool;
	struct snmp_client *client;
	struct snmp_pdu req, resp;
	struct sockaddr_in addr;
	int fd, i, j, ch;

	if (argc < 2) {
		errx(1, "Missing host argument");
	}

	if (argc < 3) {
		errx(1, "Must provide at lease one OID");
	}

	tool = snmptool_init(NULL);
	if (tool == NULL)
		return (1);
	client = tool->client;

	SET_NUMERIC(*tool);
	SET_OUTPUT(*tool, OUTPUT_QUIET);
	client->version = SNMP_V1;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	addr.sin_family = PF_INET;
	addr.sin_port = htons(161);
	inet_pton(PF_INET, argv[1], &addr.sin_addr);
	connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (snmp_fd_open(client, fd, NULL, NULL)) {
		snmp_tool_freeall(tool);
		err(1, "Failed to open SNMP session");
	}

	for (i = argc - 1; i > 1; i--) {
		if (snmp_object_add(tool, snmptest_parse_oid, argv[i]) < 0) {
			snmp_tool_freeall(tool);
			return (1);
		}
	}

	snmp_pdu_create(client, &req, GET_PDUTYPE(*tool));

	if (snmp_pdu_add_bindings(tool, NULL, snmptest_add_vbind, &req) <= 0) {
		warnx("ADD bindings");
		goto err_exit;
	}

	if (snmp_dialog(client, &req, &resp) < 0)
		warn("SNMP dialog");
	else if (snmp_parse_resp(client, &resp, &req) >= SNMP_ERR_NOERROR) {
		for (i = 0; i < (int) resp.nbindings; i++) {
			switch (resp.bindings[i].syntax) {
			case SNMP_SYNTAX_INTEGER:
				fprintf(stdout, "%d", resp.bindings[i].v.integer);
				break;
			case SNMP_SYNTAX_OCTETSTRING:
				fprintf(stdout, "\"");
				for (j = 0; j < (int) resp.bindings[i].v.octetstring.len; j++) {
					ch = resp.bindings[i].v.octetstring.octets[j];
					fprintf(stdout, isprint(ch) ? "%c" : "\\x%02x", ch);
				}
				fprintf(stdout, "\"");
				break;
			default:
				fprintf(stdout, "recognized syntaxes are INTEGER and OCTETSTRING");
				break;
			}
			fprintf(stdout, "\n");
		}
	} else
		snmp_output_err_resp(tool, &resp);

	snmp_pdu_free(&resp);

err_exit:
	snmp_tool_freeall(tool);

	return (0);
}
