make clean
make -j8
make dist -j8
make dist-xen -j8
make dist-tools -j8
sudo make install

