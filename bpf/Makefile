# Copyright Authors of Cilium
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

DOCKER ?= docker
BUILDER ?= hybridnet-bpf-builder:dev

include ./Makefile.bpf

BUILD_PERMUTATIONS ?= ""
LIB := $(shell find $(ROOT_DIR)/bpf -name '*.h')

BPF = police.o edt.o

all: $(BPF)

edt.o: edt.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

edt.ll: edt.c
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

police.o: police.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

police.ll: police.c
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

builder:
	$(DOCKER) build -t $(BUILDER) -f bpf_builder/Dockerfile .


# docker run --rm -it -v /Users/hhy/go/src/github.com/hhyasdf/hybridnet/:/go/src/github.com/hhyasdf/hybridnet/ hybridnet-bpf-builder:dev bash -c "cd /go/src/github.com/hhyasdf/hybridnet/bpf/ && export ROOT_DIR=/go/src/github.com/hhyasdf/hybridnet/ && export CLANG=clang-14 && make"