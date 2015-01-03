ifneq ($(KERNELRELEASE),)
	ccflags-y	:= -DPRINTK_DEBUG
	obj-m	:= nfhook.o
else
	KSRC	:=/lib/modules/`uname -r`/build
	PWD	:=`pwd`
	#CFLAGS-nfhook.o	:= -DPRINTK_DEBUG
	ccflags-y	:= -DPRINTK_DEBUG
all:
	$(MAKE) -C $(KSRC) M=$(PWD) modules
clean:
	$(MAKE) -C $(KSRC) M=$(PWD) clean
endif
