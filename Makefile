CC       ?= cc
CFLAGS   ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS ?= -D_GNU_SOURCE -Isrc -MMD -MP
LDLIBS   ?= -lcrypt

IMAGE    ?= ubuntu:24.04
ARTIFACT ?= build/disk.qcow2
SSH_KEY  ?= $(HOME)/.ssh/id_ed25519

SYFT_VERSION  ?= v1.51.1
GRYPE_VERSION ?= v0.118.0
COSIGN_VERSION ?= v2.4.1
ORAS_VERSION   ?= 1.2.0

SRCS := $(wildcard src/*.c src/core/*.c src/convert/*.c src/custody/*.c)
OBJS := $(SRCS:src/%.c=obj/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all clean demo tools loop-check cdb

all: c2vm

c2vm: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -rf obj/ c2vm build/ output/
	rm -f lab/*.raw lab/*.qcow2 lab/*.vmdk lab/*.ova
	-@$(MAKE) --no-print-directory loop-check

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

-include $(DEPS)

cdb:
	bear -- $(MAKE) -B

demo: c2vm
	./c2vm build $(IMAGE) --format qcow2
	./c2vm scan $(ARTIFACT)

tools:
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
	  | sh -s -- -b $(HOME)/.local/bin $(SYFT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
	  | sh -s -- -b $(HOME)/.local/bin $(GRYPE_VERSION)
	curl -sSfLo $(HOME)/.local/bin/cosign \
	  https://github.com/sigstore/cosign/releases/download/$(COSIGN_VERSION)/cosign-linux-amd64
	chmod +x $(HOME)/.local/bin/cosign
	curl -sSfL https://github.com/oras-project/oras/releases/download/v$(ORAS_VERSION)/oras_$(ORAS_VERSION)_linux_amd64.tar.gz \
	  | tar -xz -C $(HOME)/.local/bin oras

loop-check:
	@losetup --list --noheadings --output NAME,BACK-FILE \
	  | awk -v d="$(CURDIR)/" \
	    'length(d) > 1 && index($$2, d) == 1 { print "leaked: " $$1 " -> " $$2; f=1 } \
	     END { if (f) { print "detach with: sudo losetup -d <dev>"; exit 1 } }'
