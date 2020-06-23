# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020, Intel Corporation

EXE := fcs_client

SRC_DIR := src
OBJ_DIR := obj
FITSRC_DIR := fitsrc
FITOBJ_DIR := fitobj
NETTLE_SRC_DIR := nettle/src
NETTLE_OBJ_DIR := nettle_obj

SRC := $(wildcard ${SRC_DIR}/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

FITSRC := $(wildcard ${FITSRC_DIR}/*.c)
FITOBJ := $(FITSRC:$(FITSRC_DIR)/%.c=$(FITOBJ_DIR)/%.o)

NETTLE_SRC := $(wildcard ${NETTLE_SRC_DIR}/*.c)
NETTLE_OBJ := $(NETTLE_SRC:$(NETTLE_SRC_DIR)/%.c=$(NETTLE_OBJ_DIR)/%.o)

CPP_FLAGS := -Iinclude -Iinclude/uboot -Iinclude/tools -Iinclude/libfdt -Iinclude/linux -Inettle/include -DUSE_HOSTCC
CFLAGS := -Wall

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) $(FITOBJ) $(NETTLE_OBJ)
	$(CROSS_COMPILE)gcc $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CROSS_COMPILE)gcc $(CPP_FLAGS) $(CFLAGS) -c $< -o $@

$(FITOBJ_DIR)/%.o: $(FITSRC_DIR)/%.c | $(FITOBJ_DIR)
	$(CROSS_COMPILE)gcc $(CPP_FLAGS) $(CFLAGS) -c $< -o $@

$(NETTLE_OBJ_DIR)/%.o: $(NETTLE_SRC_DIR)/%.c | $(NETTLE_OBJ_DIR)
	$(CROSS_COMPILE)gcc $(CPP_FLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir $@

$(FITOBJ_DIR):
	mkdir $@

$(NETTLE_OBJ_DIR):
	mkdir $@

clean:
	rm -fr $(OBJ) $(FITOBJ) $(NETTLE_OBJ) fcs_client
