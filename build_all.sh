#make clean
make -j16
make dist -j16
make dist-xen -j16
make dist-tools -j16
sudo make install
git commit -am "hetero"
git push origin master
#./copy.sh

