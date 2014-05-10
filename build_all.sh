#make clean
make -j6
make dist
make dist-xen
make dist-tools
sudo make install

