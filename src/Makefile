obj-m += ramdisk_module.o

all:
	make -C /lib/modules/`uname -r`/build SUBDIRS=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build SUBDIRS=$(PWD) clean
	ls | grep -v '.c\|.h\|Makefile\|README' | xargs rm