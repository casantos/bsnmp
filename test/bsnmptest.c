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
snmptest_parse_oid(struct snmp_toolinfo *tool, struct snmp_object *obj, char *argv)
{
	if (argv == NULL || !ISSET_NUMERIC(*tool))
		return (-1);

	return (snmp_parse_numoid(argv, &(obj->val.var)));
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
 * According to command line options prepare SNMP Get | GetNext | GetBulk PDU.
 * Wait for a response and print it.
 */
int
main(int argc, char ** argv)
{
	struct snmp_toolinfo *tool;
	struct snmp_client *client_context;
	struct snmp_pdu req, resp;
	struct sockaddr_in addr;
	int fd;
	u_char * buf = NULL;
	char * s_addr;
	char * s_oid;

	s_addr = (argc > 1) ? argv[1] : "16.127.73.182";
	s_oid  = (argc > 2) ? argv[2] : "1.3.6.1.4.1.11.2.3.9.1.1.7.0";

	tool = snmptool_init(NULL);
	if (tool == NULL)
		return (1);
	client_context = tool->client;

	SET_NUMERIC(*tool);
	client_context->version = SNMP_V1;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	addr.sin_family = PF_INET;
	addr.sin_port = htons(161);
	inet_pton(PF_INET, s_addr, &addr.sin_addr);
	connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (snmp_fd_open(client_context, fd, NULL, NULL)) {
	    snmp_tool_freeall(tool);
	    err(1, "Failed to open SNMP session");
	}

	if (snmp_object_add(tool, snmptest_parse_oid, s_oid) < 0) {
		snmp_tool_freeall(tool);
		return (1);
	}

	snmp_pdu_create(client_context, &req, GET_PDUTYPE(*tool));

	if (snmp_pdu_add_bindings(tool, NULL, snmpget_add_vbind, &req) <= 0) {
		warnx("ADD bindings");
		goto err_exit;
	}

	if (snmp_dialog(client_context, &req, &resp) < 0)
		warn("SNMP dialog");
	else if (snmp_parse_resp(client_context, &resp, &req) >= 0 /* SNMP_ERR_NOERROR */) {
		if ((buf = snmp_oct2tc(SNMP_STRING,
			resp.bindings[0].v.octetstring.len,
			resp.bindings[0].v.octetstring.octets)) != NULL) {
			fprintf(stdout, "%s\n", buf);
			free(buf);
		} else
			warnx("snmp_oct2tc");
	} else
		snmp_output_err_resp(tool, &resp);
	snmp_pdu_free(&resp);

	if (snmp_dialog(client_context, &req, &resp) < 0)
		warn("SNMP dialog");
	else if (snmp_parse_resp(client_context, &resp, &req) >= 0 /* SNMP_ERR_NOERROR */) {
		if ((buf = snmp_oct2tc(SNMP_STRING,
			resp.bindings[0].v.octetstring.len,
			resp.bindings[0].v.octetstring.octets)) != NULL) {
			fprintf(stdout, "%s\n", buf);
			free(buf);
		} else
			warnx("snmp_oct2tc");
	} else
		snmp_output_err_resp(tool, &resp);
	snmp_pdu_free(&resp);

err_exit:
	snmp_tool_freeall(tool);

	return (0);
}
