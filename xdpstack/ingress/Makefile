XDP_TARGETS  := xdp_prog_kern2
USER_TARGETS := xdp_user2

COMMON_DIR := ../common


EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h

COMMON_OBJS := $(COMMON_DIR)/common_user_bpf_xdp.o

CFLAGS += $(shell pkg-config --cflags libdpdk)

LDLIBS += ai_engine.o $(shell pkg-config --libs libdpdk) -L/home/omarm/nips/TensorRT-8.6.1.6/lib -lnvinfer -lcudart -lxgboost -lstdc++

include $(COMMON_DIR)/common.mk

ai_engine.o: ai_engine.cpp
	g++ -O3 -Wall -Wno-deprecated-declarations -fPIC -I/usr/local/cuda/include -I/home/omarm/nips/TensorRT-8.6.1.6/include -c $< -o $@

$(USER_TARGETS): ai_engine.o