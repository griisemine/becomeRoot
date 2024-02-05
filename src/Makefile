KDIR :=/lib/modules/$(shell uname -r)/build

kbuild:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean