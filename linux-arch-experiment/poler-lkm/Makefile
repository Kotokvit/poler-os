# ============================================================================
# POLER-OS Crypto — Linux Kernel Module Makefile
# ============================================================================

obj-m += poler_lkm.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod poler_lkm.ko

uninstall:
	sudo rmmod poler_lkm

test: install
	cat /proc/poler
	sudo chmod 666 /dev/poler

.PHONY: all clean install uninstall test
