#!/bin/sh

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

DEBUG_MODE=0

	echo "-----> Building using cmake with DEBUG"
	cd ../..
	rm -r build
	set -e
	mkdir build
	cd build
if [ $DEBUG_MODE -eq 1 ]
then
	cmake .. -DENABLE_DEBUG=1
else
	cmake ..
fi
	make
	cd ..

echo "-----> Installing"
set +e
sudo rm /lib/liboptigatrust*.so > /dev/null
sudo cp -r ./lib/*so /lib/
