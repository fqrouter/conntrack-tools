LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := src/conntrack.c \
    extensions/libct_proto_tcp.c \
    extensions/libct_proto_udp.c \
    extensions/libct_proto_unknown.c

LOCAL_STATIC_LIBRARIES:=libnflink libmnl libnetfilter_conntrack

LOCAL_MODULE:=conntrack
LOCAL_CFLAGS := -O2 -std=gnu99 -g \
	-I$(LOCAL_PATH)/../libnfnetlink/include \
	-I$(LOCAL_PATH)/../libnetfilter_conntrack/include \
	-I$(LOCAL_PATH)/../libmnl/include \
	-I$(LOCAL_PATH)/include

include $(BUILD_EXECUTABLE)
