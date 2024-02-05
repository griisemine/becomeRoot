DIRBUILD := $(PWD)/build
DIRBIN := $(PWD)/bin

all:
	cd src && make kbuild
	mkdir -p $(DIRBUILD)
	mkdir -p $(DIRBIN)
	mv -f src/*.o $(DIRBUILD)/
	mv -f src/*.mod $(DIRBUILD)/
	mv -f src/*.symvers $(DIRBUILD)/
	mv -f src/*.order $(DIRBUILD)/
	mv -f src/*.mod.* $(DIRBUILD)/
	mv -f src/.*.cmd $(DIRBUILD)/
	mv -f src/*.ko $(DIRBIN)/

clean:
	cd src && make clean
	rm -f $(DIRBUILD)/* || true
	rm -f $(DIRBUILD)/.* || true
	rm -f $(DIRBIN)/*.ko
