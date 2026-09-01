CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS ?= -D_GNU_SOURCE -Isrc
IMAGE ?= ubuntu:24.04
ARTIFACT ?= build/disk.qcow2

SRCS := c2vm.c src/run.c src/cleanup.c src/build.c src/ova.c src/boottest.c src/json.c src/scan.c src/sbom.c src/diff.c src/vuln.c src/cve.c
OBJS := $(SRCS:.c=.o)
LDLIBS ?= -lcrypt

SYFT_VERSION ?= v1.51.1
GRYPE_VERSION ?= v0.118.0

.PHONY: all clean demo loop-check tools

all: c2vm

c2vm: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJS): src/run.h src/cleanup.h src/build.h src/ova.h src/boottest.h src/json.h src/scan.h src/sbom.h src/diff.h src/vuln.h src/cve.h

demo: c2vm
	./c2vm build $(IMAGE) --format qcow2
	./c2vm scan $(ARTIFACT)

clean:
	rm -f c2vm
	rm -rf build/ output/
	rm -f lab/*.raw lab/*.qcow2 lab/*.vmdk lab/*.ova
	-@$(MAKE) --no-print-directory loop-check

loop-check:
	@losetup --list --noheadings --output NAME,BACK-FILE \
	  | awk -v d="$(CURDIR)/" \
	    'length(d) > 1 && index($$2, d) == 1 { print "leaked: " $$1 " -> " $$2; f=1 } \
	     END { if (f) { print "detach with: sudo losetup -d <dev>"; exit 1 } }'

tools:
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
	  | sh -s -- -b $(HOME)/.local/bin $(SYFT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
	  | sh -s -- -b $(HOME)/.local/bin $(GRYPE_VERSION)