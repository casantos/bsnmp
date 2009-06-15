/* 
 * Copyright (C) 2004
 * 	Hartmut Brandt.
 * 	All rights reserved.
 * 
 * Author: Harti Brandt <harti@freebsd.org>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Begemot: bsnmp/gensnmpdef/gensnmpdef.c,v 1.3 2004/08/06 08:46:45 brandt Exp $
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#if defined(HAVE_ERR_H)
#include <err.h>
#endif
#include <assert.h>
#include <smi.h>

static const char usgtxt[] =
"Usage: gensnmpdef [-h] [-c <cut>] MIB [MIB ...]\n"
"Options:\n"
"  -c	specify the number of initial sub-oids to cut from the oids\n"
"  -h	print this help\n"
"MIBs are searched according to the libsmi(3) search rules and can\n"
"be specified either by path or module name\n";

static SmiNode *last_node;
static u_int cut = 3;

static void print_node(SmiNode *n, u_int level);

static void
save_node(SmiNode *n)
{
	if (n != NULL)
		last_node = n;
}

static void
pindent(u_int level)
{
	if (level >= cut)
		printf("%*s", (level - cut) * 2, "");
}

static void
print_name(SmiNode *n)
{
	char *p;

	for (p = n->name; *p != '\0'; p++) {
		if (*p == '-')
			printf("_");
		else
			printf("%c", *p);
	}
}

static u_int
close_node(u_int n, u_int level)
{
	while (n--) {
		pindent(level);
		level--;
		if (level >= cut)
			printf(")\n");
	}
	return (level);
}

static u_int
open_node(const SmiNode *n, u_int level, SmiNode **last)
{
	SmiNode *n1;
	u_int i;

	if (*last != NULL) {
		for (i = 0; i < (*last)->oidlen - 1; i++) {
			if (i >= n->oidlen) {
				level = close_node((*last)->oidlen -
				    n->oidlen, level);
				break;
			}
			if ((*last)->oid[i] != n->oid[i])
				break;
		}
		if (i < (*last)->oidlen - 1)
			level = close_node((*last)->oidlen - 1 - i,
			    level - 1) + 1;
	}

	while (level < n->oidlen - 1) {
		if (level >= cut) {
			pindent(level);
			printf("(%u", n->oid[level]);
			n1 = smiGetNodeByOID(level + 1, n->oid);
			printf(" ");
			print_name(n1);
			printf("\n");
		}
		level++;
	}
	return (level);
}

static const char *const type_names[] = {
	[SMI_BASETYPE_UNKNOWN] =	"UNKNOWN_TYPE",
	[SMI_BASETYPE_INTEGER32] =	"INTEGER",
	[SMI_BASETYPE_OCTETSTRING] =	"OCTETSTRING",
	[SMI_BASETYPE_OBJECTIDENTIFIER] =	"OID",
	[SMI_BASETYPE_UNSIGNED32] =	"UNSIGNED32",
	[SMI_BASETYPE_INTEGER64] =	"INTEGER64",
	[SMI_BASETYPE_UNSIGNED64] =	"UNSIGNED64",
	[SMI_BASETYPE_FLOAT32] =	"FLOAT32",
	[SMI_BASETYPE_FLOAT64] =	"FLOAT64",
	[SMI_BASETYPE_FLOAT128] =	"FLOAT128",
	[SMI_BASETYPE_ENUM] =	"INTEGER",
	[SMI_BASETYPE_BITS] =	"BITS",
};

static const char *const type_map[] = {
	"Gauge32",	"GAUGE",
	"Gauge",	"GAUGE",
	"TimeTicks",	"TIMETICKS",
	"Counter32",	"COUNTER",
	"Counter",	"COUNTER",
	"Counter64",	"COUNTER64",
	"Integer32",	"INTEGER32",
	"IpAddress",	"IPADDRESS",
	NULL
};

static void
print_type(SmiNode *n)
{
	SmiType *type;
	u_int m;

	type = smiGetNodeType(n);
	assert(type != NULL);

	if (type->name != NULL) {
		for (m = 0; type_map[m] != NULL; m += 2)
			if (strcmp(type_map[m], type->name) == 0) {
				printf("%s", type_map[m + 1]);
				return;
			}
	}
	printf("%s", type_names[type->basetype]);
}

static void
print_access(SmiAccess a)
{
	if (a == SMI_ACCESS_READ_ONLY)
		printf(" GET");
	else if (a == SMI_ACCESS_READ_WRITE)
		printf(" GET SET");
}

static void
print_scalar(SmiNode *n, u_int level)
{
	SmiNode *p;

	assert (n->nodekind == SMI_NODEKIND_SCALAR);

	save_node(n);

	pindent(level);
	printf("(%u ", n->oid[level]);
	print_name(n);
	printf(" ");
	print_type(n);

	/* generate the operation from the parent node name */
	p = smiGetParentNode(n);
	printf(" op_%s", p->name);

	print_access(n->access);
	
	printf(")\n");
}

static void
print_notification(SmiNode *n, u_int level)
{

	assert (n->nodekind == SMI_NODEKIND_NOTIFICATION);

	save_node(n);

	pindent(level);
	printf("(%u ", n->oid[level]);
	print_name(n);
	printf(" OID");

	printf(" op_%s)\n", n->name);
}

static void
print_col(SmiNode *n, u_int level)
{
	assert (n->nodekind == SMI_NODEKIND_COLUMN);

	save_node(n);

	pindent(level);
	printf("(%u ", n->oid[level]);
	print_name(n);
	printf(" ");
	print_type(n);
	print_access(n->access);
	printf(")\n");
}

static void
print_index(SmiNode *row)
{
	SmiElement *e;

	e = smiGetFirstElement(row);
	while (e != NULL) {
		printf(" ");
		print_type(smiGetElementNode(e));
		e = smiGetNextElement(e);
	}
}

static void
print_table(SmiNode *n, u_int level)
{
	SmiNode *row, *col, *rel;

	assert (n->nodekind == SMI_NODEKIND_TABLE);

	save_node(n);

	pindent(level);
	printf("(%u ", n->oid[level]);
	print_name(n);
	printf("\n");

	row = smiGetFirstChildNode(n);
	if (row->nodekind != SMI_NODEKIND_ROW)
		errx(1, "%s: kind %u, not row", __func__, row->nodekind);

	save_node(n);

	pindent(level + 1);
	printf("(%u ", row->oid[level + 1]);
	print_name(row);
	printf(" :");

	/* index */
	rel = smiGetRelatedNode(row);
	switch (row->indexkind) {

	  case SMI_INDEX_INDEX:
		print_index(row);
		break;

	  case SMI_INDEX_AUGMENT:
		if (rel == NULL)
			errx(1, "%s: cannot find augemented table", row->name);
		print_index(rel);
		break;

	  default:
		errx(1, "%s: cannot handle index kind %u", row->name,
		    row->indexkind);
	}

	printf(" op_%s", n->name);
	printf("\n");

	col = smiGetFirstChildNode(row);
	while (col != NULL) {
		print_col(col, level + 2);
		col = smiGetNextChildNode(col);
	}
	pindent(level + 1);
	printf(")\n");

	pindent(level);
	printf(")\n");
}

static void
print_it(SmiNode *n, u_int level)
{
	switch (n->nodekind) {

	  case SMI_NODEKIND_NODE:
		print_node(n, level);
		break;

	  case SMI_NODEKIND_SCALAR:
		print_scalar(n, level);
		break;

	  case SMI_NODEKIND_TABLE:
		print_table(n, level);
		break;

	  case SMI_NODEKIND_COMPLIANCE:
	  case SMI_NODEKIND_GROUP:
		save_node(n);
		break;

	  case SMI_NODEKIND_NOTIFICATION:
		print_notification(n, level);
		break;

	  default:
		errx(1, "cannot handle %u nodes", n->nodekind);
	}
}

static void
print_node(SmiNode *n, u_int level)
{
	assert (n->nodekind == SMI_NODEKIND_NODE);

	save_node(n);

	pindent(level);
	printf("(%u ", n->oid[level]);
	print_name(n);
	printf("\n");

	n = smiGetFirstChildNode(n);
	while (n != NULL) {
		print_it(n, level + 1);
		n = smiGetNextChildNode(n);
	}
	pindent(level);
	printf(")\n");
}

int
main(int argc, char *argv[])
{
	int opt;
	int flags;
	SmiModule **mods;
	char *name;
	SmiNode *n, *last;
	u_int level;
	long u;
	char *end;

	smiInit(NULL);

	while ((opt = getopt(argc, argv, "c:h")) != -1)
		switch (opt) {

		  case 'c':
			errno = 0;
			u = strtol(optarg, &end, 10);
			if (errno != 0)
				err(1, "argument to -c");
			if (*end != '\0')
				err(1, "%s: not a number", optarg);
			if (u < 0 || u > 5)
				err(1, "%s: out of range", optarg);
			cut = (u_int)u;
			break;

		  case 'h':
			fprintf(stderr, usgtxt);
			exit(0);
		}

	argc -= optind;
	argv += optind;

	flags = smiGetFlags();
	flags |= SMI_FLAG_ERRORS;
	smiSetFlags(flags);

	mods = malloc(sizeof(mods[0]) * argc);
	if (mods == NULL)
		err(1, NULL);

	for (opt = 0; opt < argc; opt++) {
		if ((name = smiLoadModule(argv[opt])) == NULL)
			err(1, "%s: cannot load", argv[opt]);
		mods[opt] = smiGetModule(name);
	}
	level = 0;
	last = NULL;
	for (opt = 0; opt < argc; opt++) {
		n = smiGetFirstNode(mods[opt], SMI_NODEKIND_ANY);
		for (;;) {
			level = open_node(n, level, &last);
			print_it(n, level);
			last = n;

			if (last_node == NULL ||
			    (n = smiGetNextNode(last_node, SMI_NODEKIND_ANY))
			    == NULL)
				break;
		}
	}
	level = close_node(last->oidlen - 1, level - 1);
	return (0);
}