###############################################################################
#
# Generic
#
###############################################################################

MKDIR := mkdir -p

OBJ_DIR := obj
BIN_DIR := bin
LIB_DIR := lib

LOCAL_CFLAGS := \
	-fpic -fPIC -DHAVE_ERR_H -DHAVE_GETADDRINFO -DHAVE_STDINT_H -D__unused="" \
	-fstrict-aliasing -Wall -Werror -Wno-unused-parameter -I include -I .

###############################################################################
#
# BSNMP library
#
###############################################################################

BSNMP_LIB_DIR := bsnmp/lib

BSNMP_LIB_OBJS := $(OBJ_DIR)/asn1.o $(OBJ_DIR)/snmp.o $(OBJ_DIR)/support.o
BSNMP_AGENT_OBJS := $(OBJ_DIR)/snmpagent.o
BSNMP_CLIENT_OBJS := $(OBJ_DIR)/snmpclient.o
BSNMP_OBJS := $(BSNMP_LIB_OBJS) $(BSNMP_AGENT_OBJS) $(BSNMP_CLIENT_OBJS)

BSNMP_LIB := $(LIB_DIR)/libbsnmp.so
BSNMP_LDFLAGS := -L $(LIB_DIR) -lbsnmp

BSNMP_AGENT_LIB_FILE := $(LIB_DIR)/libbsnmpagent.so
BSNMP_CLIENT_LIB_FILE := $(LIB_DIR)/libbsnmpclient.so

ifeq ($(MAKECMDGOALS),split)
BSNMP_AGENT_LIB := $(BSNMP_AGENT_LIB_FILE)
BSNMP_CLIENT_LIB := $(BSNMP_CLIENT_LIB_FILE)
BSNMP_CLIENT_LDFLAGS := -lbsnmpclient
BSNMP_AGENT_LDFLAGS := -lbsnmpagent
else
BSNMP_AGENT_LIB :=
BSNMP_CLIENT_LIB :=
BSNMP_CLIENT_LDFLAGS :=
BSNMP_AGENT_LDFLAGS :=
endif

BSNMP_LIBS := $(BSNMP_LIB) $(BSNMP_AGENT_LIB) $(BSNMP_CLIENT_LIB)

$(OBJ_DIR)/%.d: $(BSNMP_LIB_DIR)/%.c
	$(MKDIR) $(OBJ_DIR)
	$(CC) -MM -MG $< -MT "$(OBJ_DIR)/$*.o $(OBJ_DIR)/$*.d" -MF $@

$(OBJ_DIR)/%.o: $(BSNMP_LIB_DIR)/%.c $(OBJ_DIR)/%.d
	$(CC) -c $(CFLAGS) $(LOCAL_CFLAGS) $< -o $@

###############################################################################
#
# BSNMP tools library
#
###############################################################################

TOOLS_LIB_DIR := bsnmptools/lib/libbsnmptools/libbsnmptools

TOOLS_CFLAGS := -I $(TOOLS_LIB_DIR)
TOOLS_LIB_OBJS := $(OBJ_DIR)/bsnmpimport.o $(OBJ_DIR)/bsnmpmap.o $(OBJ_DIR)/bsnmptc.o $(OBJ_DIR)/bsnmptools.o
TOOLS_LIB := $(LIB_DIR)/libbsnmptools.so
TOOLS_LDFLAGS := $(BSNMP_LDFLAGS) $(BSNMP_CLIENT_LDFLAGS) -lbsnmptools

$(OBJ_DIR)/%.d: $(TOOLS_LIB_DIR)/%.c
	$(MKDIR) $(OBJ_DIR)
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) -MM -MG $< -MT "$(OBJ_DIR)/$*.o $(OBJ_DIR)/$*.d" -MF $@

$(OBJ_DIR)/%.o: $(TOOLS_LIB_DIR)/%.c $(OBJ_DIR)/%.d
	$(CC) -c $(CFLAGS) $(LOCAL_CFLAGS) $< -o $@

###############################################################################
#
# Utilities
#
###############################################################################

#
# bsnmpget
#

BSNMPGET_DIR = bsnmptools/usr.sbin/bsnmpd/tools/bsnmpget
BSNMPGET_OBJS := $(OBJ_DIR)/bsnmpget.o
BSNMPGET := $(BIN_DIR)/bsnmpget

$(OBJ_DIR)/%.d: $(BSNMPGET_DIR)/%.c
	$(MKDIR) $(OBJ_DIR)
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) -MM -MG $< -MT "$(OBJ_DIR)/$*.o $(OBJ_DIR)/$*.d" -MF $@

$(OBJ_DIR)/%.o: $(BSNMPGET_DIR)/%.c $(OBJ_DIR)/%.d
	$(CC) -c $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) $< -o $@

#
# bsnmpset
#

BSNMPSET_DIR = bsnmptools/usr.sbin/bsnmpd/tools/bsnmpset
BSNMPSET_OBJS := $(OBJ_DIR)/bsnmpset.o
BSNMPSET := $(BIN_DIR)/bsnmpset

$(OBJ_DIR)/%.d: $(BSNMPSET_DIR)/%.c
	$(MKDIR) $(OBJ_DIR)
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) -MM -MG $< -MT "$(OBJ_DIR)/$*.o $(OBJ_DIR)/$*.d" -MF $@

$(OBJ_DIR)/%.o: $(BSNMPSET_DIR)/%.c $(OBJ_DIR)/%.d
	$(CC) -c $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) $< -o $@

#
# bsnmpwalk
#

BSNMPWALK_DIR = bsnmptools/usr.sbin/bsnmpd/tools/bsnmpwalk
BSNMPWALK_OBJS := $(OBJ_DIR)/bsnmpwalk.o
BSNMPWALK := $(BIN_DIR)/bsnmpwalk

$(OBJ_DIR)/%.d: $(BSNMPWALK_DIR)/%.c
	$(MKDIR) $(OBJ_DIR)
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) -MM -MG $< -MT "$(OBJ_DIR)/$*.o $(OBJ_DIR)/$*.d" -MF $@

$(OBJ_DIR)/%.o: $(BSNMPWALK_DIR)/%.c $(OBJ_DIR)/%.d
	$(CC) -c $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) $< -o $@

#
# bsnmpwalk
#

BSNMPTEST_DIR = test
BSNMPTEST_OBJS := $(OBJ_DIR)/bsnmptest.o
BSNMPTEST := $(BIN_DIR)/bsnmptest

$(OBJ_DIR)/%.d: $(BSNMPTEST_DIR)/%.c
	$(MKDIR) $(OBJ_DIR)
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) -MM -MG $< -MT "$(OBJ_DIR)/$*.o $(OBJ_DIR)/$*.d" -MF $@

$(OBJ_DIR)/%.o: $(BSNMPTEST_DIR)/%.c $(OBJ_DIR)/%.d
	$(CC) -c $(CFLAGS) $(LOCAL_CFLAGS) $(TOOLS_CFLAGS) $< -o $@

###############################################################################
#
# Build targets
#
###############################################################################

OBJS = $(BSNMP_OBJS) $(TOOLS_LIB_OBJS) $(BSNMPGET_OBJS) $(BSNMPSET_OBJS) $(BSNMPWALK_OBJS) $(BSNMPTEST_OBJS)
DEPENDS := $(OBJS:.o=.d)

#
# Use the "split" rule if you want separate libraries for agent and client
#
ifeq ($(MAKECMDGOALS),split)
split::
	@if [ -e $(BSNMP_LIB) -a ! \( -e $(BSNMP_AGENT_LIB) -o -e $(BSNMP_CLIENT_LIB) \) ]; then \
		echo rm -f $(BSNMP_LIB); \
		rm -f $(BSNMP_LIB); \
	fi
split:: all
else
all::
	@if [ -e $(BSNMP_AGENT_LIB_FILE) -o -e $(BSNMP_CLIENT_LIB_FILE) ]; then \
		echo rm -f $(BSNMP_LIB) $(BSNMP_AGENT_LIB_FILE) $(BSNMP_CLIENT_LIB_FILE); \
		rm -f $(BSNMP_LIB) $(BSNMP_AGENT_LIB_FILE) $(BSNMP_CLIENT_LIB_FILE); \
	fi
endif

ifeq ($(MAKECMDGOALS),debug)
CFLAGS := -g
debug:: all
endif

all::   $(BIN_DIR) $(OBJ_DIR) $(LIB_DIR) $(DEPENDS) $(BSNMP_LIBS) $(TOOLS_LIB) $(BSNMPGET) $(BSNMPSET) $(BSNMPWALK) $(BSNMPTEST)

$(BIN_DIR):
	$(MKDIR) $(BIN_DIR)

$(OBJ_DIR):
	$(MKDIR) $(OBJ_DIR)

$(LIB_DIR):
	$(MKDIR) $(LIB_DIR)

#
# BSNMP library
#

ifeq ($(MAKECMDGOALS),split)
$(BSNMP_LIB): $(BSNMP_LIB_OBJS)
	$(CC) -shared -o $@ $(BSNMP_LIB_OBJS)

$(BSNMP_AGENT_LIB): $(BSNMP_AGENT_OBJS)
	$(CC) -shared -o $@ $(BSNMP_AGENT_OBJS)

$(BSNMP_CLIENT_LIB): $(BSNMP_CLIENT_OBJS)
	$(CC) -shared -o $@ $(BSNMP_CLIENT_OBJS)
else
$(BSNMP_LIB): $(BSNMP_OBJS)
	$(CC) -shared -o $@ $(BSNMP_OBJS)
endif

#
# BSNMP tools library
#

$(TOOLS_LIB): $(TOOLS_LIB_OBJS) $(BSNMP_LIB) $(BSNMP_CLIENT_LIB)
	$(CC) -shared -o $@ $(TOOLS_LIB_OBJS) $(BSNMP_LDFLAGS) $(BSNMP_CLIENT_LDFLAGS)

#
# Utilities
#

$(BSNMPGET): $(BSNMPGET_OBJS) $(TOOLS_LIB) $(BSNMP_LIB) $(BSNMP_CLIENT_LIB)
	$(CC) -o $@ $(BSNMPGET_OBJS) $(TOOLS_LDFLAGS)

$(BSNMPSET): $(BSNMPSET_OBJS) $(TOOLS_LIB) $(BSNMP_LIB) $(BSNMP_CLIENT_LIB)
	$(CC) -o $@ $(BSNMPSET_OBJS) $(TOOLS_LDFLAGS)

$(BSNMPWALK): $(BSNMPWALK_OBJS) $(TOOLS_LIB) $(BSNMP_LIB) $(BSNMP_CLIENT_LIB)
	$(CC) -o $@ $(BSNMPWALK_OBJS) $(TOOLS_LDFLAGS)

$(BSNMPTEST): $(BSNMPTEST_OBJS) $(TOOLS_LIB) $(BSNMP_LIB) $(BSNMP_CLIENT_LIB)
	$(CC) -o $@ $(BSNMPTEST_OBJS) $(TOOLS_LDFLAGS)

clean:
	rm -f -r $(BIN_DIR)/* $(OBJ_DIR)/* $(LIB_DIR)/*

ifneq ($(MAKECMDGOALS),clean)
include $(DEPENDS)
endif
