# A PKCS#11 Interface implementation for OPTIGA™ Trust M

PKCS #11 is a Public-Key Cryptography Standard that defines a standard method to
access cryptographic services from tokens/ devices such as hardware security
modules (HSM), smart cards, etc. In this project we intend to use a OPTIGA™ Trust M device
as the cryptographic token.

# Setting up Linux environment on Raspberry Pi 3

Install the build dependendencies for the system:

## Update the system

	$ sudo apt-get update
## Install cmake

	$ sudo apt-get install cmake
## Install CUnit library for assert in system test

	$ sudo apt-get install libcunit1-dev

## Install openSSL library used for PAL crypto operations

	$ sudo apt-get install libssl-dev

## Install pThread installation

	$ sudo apt-get install libpthread-stubs0-dev



## Enable the I2C interafce to communicate with OPTIGA™ Trust M:

	$ sudo raspi-config

* Navigate to Interfacing Options.
* Select P5 I2C and hit enter.
* When the window to enable the I2C interface is appeared select yes.
* Finish the configuration window.


# Hardware connection between OPTIGA™ Trust M and Raspberry Pi 3

Below table shows the I2C connection between the OPTIGA™ Trust M and Raspberry Pi 3.

| No       			| Description		| Pin #    | Pin Description |
| :-------------: | :----------: | :-----------: | :-----------: |
| 1| I2C SCL  | 5 |SCL1, I2C    |
| 2| I2C SDA   | 3 | SDA1, I2C    |
| 3| RST   | 11 | GPIO 17 |
| 4| VCC   | 13 | GPIO 27  |
| 5| GND   | 9 | GND    |

# Building System Test Project for PKCS#11

## Get the latest version of PKCS#11 implementation with OPTIGA™ Trust M

	$ git clone --recursive https://github.com/Infineon/pkcs11-optiga-trust-m

Note: Enable recursive option for git clone as optiga-trust-m is a sub-module.

## Build PKCS#11 library with OPTIGA™ Trust M
* Create a directory with name **build** at *cloned_repo*

		$ mkdir build
* Navigate inside build folder and type cmake ..

		$ cd build
		$ cmake ..

* Build the project

		$ make
	
	Note: After build is successful a directory with name **lib** gets created at *cloned_repo*.	


## Build test project
* Navigate to folder *cloned_repo*/test/projects/raspberry_pi3/

		$ cd test/projects/raspberry_pi3/

* Create a directory with name **lib**

		$ mkdir lib

* Copy compiled liboptigatrust-i2c-linux-pkcs11.so to /lib/

		$ sudo cp -r ../../../lib/*so /lib/

* Build the project:	

		$ make

# Running Test 

On the directory location *cloned_repo*/test/projects/raspberry_pi3/, run command

	$ sudo ./lib/OPTIGA_Trust_M_PKCS11_Test


This will trigger the system test to start running and populates the system test result on console.

Note : To run any specific test cases enable/disable the test cases under test folder at location *cloned_repo*/test/test/test_holder_pkcs11.c





