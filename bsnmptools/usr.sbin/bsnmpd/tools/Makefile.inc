# $FreeBSD$
# Author: Shteryana Shopova <soc-shteryana@freebsd.org>

BINDIR?=	/usr/bin

CFLAGS+=	-I${.CURDIR}/../../../../lib/libbsnmptools/libbsnmptools
LDFLAGS+=	-L${.OBJDIR}/../../../../lib/libbsnmptools/libbsnmptools

