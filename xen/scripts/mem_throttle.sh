#!/bin/bash

# Usage:

# To throttle memory node 1 (0 is fast node)
# $./mem_throttle.sh 1 

# To disable memory throttle
# $./mem_throttle.sh

if [ $1 ]
	then
sudo setpci -s 3f:04.3 0x48.L=0x2
sudo setpci -s 3f:05.3 0x48.L=0x2
sudo setpci -s 3f:06.3 0x48.L=0x2
sudo setpci -s 3f:04.3 0x84.L=0xff0f
sudo setpci -s 3f:05.3 0x84.L=0xff0f
sudo setpci -s 3f:06.3 0x84.L=0xff0f
else
sudo setpci -s 3f:04.3 0x48.L=0x0
sudo setpci -s 3f:05.3 0x48.L=0x0
sudo setpci -s 3f:06.3 0x48.L=0x0

fi

