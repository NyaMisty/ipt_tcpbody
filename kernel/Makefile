ifneq ($(KERNELRELEASE),)

obj-m += xt_TCPBODY.o
xt_TCPBODY-y := xt_TBODY.o

else

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

all:	modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install INSTALL_MOD_PATH=$(DESTDIR)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

endif
