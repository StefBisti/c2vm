CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
IMAGE ?= ubuntu:24.04
ARTIFACT ?= build/disk.qcow2

.PHONY: all clean demo loop-check

all: c2vm

c2vm: c2vm.c
	$(CC) $(CFLAGS) -o $@ $<

demo: c2vm
	./c2vm build $(IMAGE) --format qcow2
	./c2vm scan $(ARTIFACT)

clean:
	rm -f c2vm
	rm -rf build/ output/
	rm -f lab/*.raw lab/*.qcow2 lab/*.vmdk lab/*.ova
	-@$(MAKE) --no-print-directory loop-check

# Reports only. Detaching is a decision you make, not a side effect.
loop-check:
	@losetup --list --noheadings --output NAME,BACK-FILE \
	  | awk -v d="$(CURDIR)/" \
	    'length(d) > 1 && index($$2, d) == 1 { print "leaked: " $$1 " -> " $$2; f=1 } \
	     END { if (f) { print "detach with: sudo losetup -d <dev>"; exit 1 } }'