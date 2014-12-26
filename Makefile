obj-m	:= nfhook.o
KSRC	:=/lib/modules/`uname -r`/build
PWD	:=`pwd`

all:
	$(MAKE)  -C $(KSRC) M=$(PWD) modules
	
clean:
	$(MAKE) -C $(KSRC) M=$(PWD) clean
