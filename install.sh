make clean && make all
sudo rm -r /dev/becomeRoot || true
sudo rmmod becomeroot || true
sudo insmod bin/becomeroot.ko
