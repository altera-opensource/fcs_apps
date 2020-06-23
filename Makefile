# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020, Intel Corporation

EXE := fcs_prepare

SRC_DIR := src
OBJ_DIR := obj
NETTLE_SRC_DIR := nettle/src
NETTLE_OBJ_DIR := nettle_obj

SRC := $(wildcard ${SRC_DIR}/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

NETTLE_SRC := $(wildcard ${NETTLE_SRC_DIR}/*.c)
NETTLE_OBJ := $(NETTLE_SRC:$(NETTLE_SRC_DIR)/%.c=$(NETTLE_OBJ_DIR)/%.o)

CPP_FLAGS := -Iinclude -Inettle/include
CFLAGS := -Wall
LDFLAGS := -static

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) $(NETTLE_OBJ)
	gcc $(LDFLAGS) $^ $(LDLIBS) -o $@

#$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(NETTLE_SRC_DIR)/%.c | $(OBJ_DIR)
#	gcc $(CPP_FLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	gcc $(CPP_FLAGS) $(CFLAGS) -c $< -o $@

$(NETTLE_OBJ_DIR)/%.o: $(NETTLE_SRC_DIR)/%.c | $(NETTLE_OBJ_DIR)
	gcc $(CPP_FLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir $@

$(NETTLE_OBJ_DIR):
	mkdir $@

clean:
	rm -fr $(OBJ) $(NETTLE_OBJ) fcs_prepare
