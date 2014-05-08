#!/bin/bash

# Usage:

# To throttle each core by 50% (0-5)
# $./cpu_throttle.sh 1 

# To disable CPU throttle
# $./mem_throttle.sh

if [ $1 ]
	then
wrmsr -p 0 0x19ah 24
wrmsr -p 1 0x19ah 24
wrmsr -p 2 0x19ah 24
wrmsr -p 3 0x19ah 24
wrmsr -p 4 0x19ah 24
wrmsr -p 5 0x19ah 24
else
wrmsr -p 0 0x19ah 2
wrmsr -p 1 0x19ah 2
wrmsr -p 2 0x19ah 2
wrmsr -p 3 0x19ah 2
wrmsr -p 4 0x19ah 2
wrmsr -p 5 0x19ah 2
fi
