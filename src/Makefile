obj-m += ramdisk_module.o

all:
	make -C /lib/modules/`uname -r`/build SUBDIRS=$(PWD) modules
	gcc -Wall ramdisk_module.c -o ramdisk_module
clean:
	make -C /lib/modules/`uname -r`/build SUBDIRS=$(PWD) clean
	ls | grep -v '.c\|Makefile\|README' | xargs rm -rf