#******************************************************************************
#  Begemot SNMP port for the Android platform
#******************************************************************************

LOCAL_PATH := $(call my-dir)

DATA_DIR := /etc/bsnmp

BUILD_CFLAGS := -fstrict-aliasing -Wall -Werror -Wno-unused-parameter \
	-DHAVE_GETADDRINFO -DHAVE_STDINT_H -DHAVE_STRLCPY \
	-DDEFSDIR=\"$(DATA_DIR)\" -DNO_LOCAL_DEFS_DIR \
	"-D__printflike(x,y)=" "-D__dead2="

#DEBUG_CFLAGS := -g
DEBUG_CFLAGS :=

#OPT_CFLAGS := -O3
OPT_CFLAGS := -O2

#*******************************************************************************
#
# Libraries
#
#*******************************************************************************

#
# bsnmp library
#
include $(CLEAR_VARS)
BSNMP_LIB_SNMPAGENT_C := # bsnmp/lib/snmpagent.c	# don't need the agent
LOCAL_SRC_FILES := \
	bsnmp/lib/asn1.c \
	$(BSNMP_LIB_SNMPAGENT_C) \
	bsnmp/lib/snmp.c \
	bsnmp/lib/snmpclient.c \
	bsnmp/lib/support.c
LOCAL_CFLAGS += -fPIC $(BUILD_CFLAGS) $(DEBUG_CFLAGS) $(OPT_CFLAGS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_MODULE := libbsnmp
include $(BUILD_SHARED_LIBRARY)

#
# bsnmptools library (needed by clients)
#
include $(CLEAR_VARS)

BSNMP_TOOLS_LIBDIR := bsnmptools/lib/libbsnmptools/libbsnmptools
LOCAL_SRC_FILES := \
	$(BSNMP_TOOLS_LIBDIR)/bsnmpimport.c \
	$(BSNMP_TOOLS_LIBDIR)/bsnmpmap.c \
	$(BSNMP_TOOLS_LIBDIR)/bsnmptc.c \
	$(BSNMP_TOOLS_LIBDIR)/bsnmptools.c
LOCAL_CFLAGS += -fPIC $(BUILD_CFLAGS) $(DEBUG_CFLAGS) $(OPT_CFLAGS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := libbsnmp
LOCAL_MODULE := libbsnmptools
include $(BUILD_SHARED_LIBRARY)

#*******************************************************************************
#
# Data files
#
#*******************************************************************************

include $(CLEAR_VARS)
LOCAL_MODULE := tree.def
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)$(DATA_DIR)
LOCAL_SRC_FILES := bsnmp/snmpd/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := mibII_tree.def
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)$(DATA_DIR)
LOCAL_SRC_FILES := bsnmp/snmp_mibII/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)

#*******************************************************************************
#
# Utilities
#
#*******************************************************************************

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bsnmptools/usr.sbin/bsnmpd/tools/bsnmpget/bsnmpget.c
LOCAL_CFLAGS += $(BUILD_CFLAGS) $(DEBUG_CFLAGS) $(OPT_CFLAGS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include $(LOCAL_PATH)/$(BSNMP_TOOLS_LIBDIR)
LOCAL_MODULE := bsnmpget
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_SHARED_LIBRARIES := libbsnmp libbsnmptools
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bsnmptools/usr.sbin/bsnmpd/tools/bsnmpset/bsnmpset.c
LOCAL_CFLAGS += $(BUILD_CFLAGS) $(DEBUG_CFLAGS) $(OPT_CFLAGS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include $(LOCAL_PATH)/$(BSNMP_TOOLS_LIBDIR)
LOCAL_MODULE := bsnmpset
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_SHARED_LIBRARIES := libbsnmp libbsnmptools
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := bsnmptools/usr.sbin/bsnmpd/tools/bsnmpwalk/bsnmpwalk.c
LOCAL_CFLAGS += $(BUILD_CFLAGS) $(DEBUG_CFLAGS) $(OPT_CFLAGS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include $(LOCAL_PATH)/$(BSNMP_TOOLS_LIBDIR)
LOCAL_MODULE := bsnmpwalk
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_SHARED_LIBRARIES := libbsnmp libbsnmptools
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := test/bsnmptest.c
LOCAL_CFLAGS += $(BUILD_CFLAGS) $(DEBUG_CFLAGS) $(OPT_CFLAGS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include $(LOCAL_PATH)/$(BSNMP_TOOLS_LIBDIR)
LOCAL_MODULE := bsnmptest
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_SHARED_LIBRARIES := libbsnmp libbsnmptools
include $(BUILD_EXECUTABLE)
