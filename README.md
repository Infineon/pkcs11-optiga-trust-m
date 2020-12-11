# A PKCS#11 Interface implementation for </br>OPTIGA™ Trust M

PKCS #11 is a Public-Key Cryptography Standard that defines a standard method to
access cryptographic services from tokens/ devices such as hardware security
modules (HSM), smart cards, etc. In this project we intend to use a OPTIGA™ Trust M device
as the cryptographic token.

# Setting up Linux environment on Raspberry Pi 3

Install the build dependendencies for the system:

1. Update the system

    ```console
    $ sudo apt-get update
    ```
2. PKCS11 dependencies
    ```console
    $ sudo apt-get install cmake libssl-dev libusb-1.0-0-dev
    ```	
3. CUnit based system test dependencies
    ```console
    $ sudo apt-get install libcunit1-dev libpthread-stubs0-dev
    ```
4. Enable the I2C interface to communicate with OPTIGA™ Trust M (optional)
    ```console
    $ sudo raspi-config
    ```
    * Navigate to Interfacing Options.
    * Select P5 I2C and hit enter.
    * When the window to enable the I2C interface is appeared select yes.
    * Finish the configuration window.


# Hardware connection between OPTIGA™ Trust M and Raspberry Pi 3

This APpNote does support two hardware types:

1. USB Dongle. In this case you just need to plug it into one of available USB slots on your Raspberry Pi board
2. I2C Connection
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

	$ sudo ./lib/OPTIGA_Trust_M_PKCS11_Test_usbdongle

if you use one of Trust M USB dongles, otherwise

	$ sudo ./lib/OPTIGA_Trust_M_PKCS11_Test_i2c


This will trigger the system test to start running and populates the system test result on console. It usually takes around 26 seconds to cmplete all testcases, please be aware that no extra messages will be displayed during this time. YOu can find a generic test execution output below:

```console
pi@raspberrypi:~/git/pkcs11-optiga-trust-m/test/projects/raspberry_pi3 $ sudo ./lib/OPTIGA_Trust_M_PKCS11_Test_usbdongle

 Added GAD_optiga_pkcs_11_system_test_cases_Tests Suite to the CUnit Registry.


     CUnit - A unit testing framework for C - Version 2.1-3
     http://cunit.sourceforge.net/



Run Summary:    Type  Total    Ran Passed Failed Inactive
              suites      1      1    n/a      0        0
               tests     56     56     56      0        0
             asserts    369    369    369      0      n/a

Elapsed time =   26.820 seconds
```

Note : To run any specific test cases enable/disable the test cases under test folder at location *cloned_repo*/test/test/test_holder_pkcs11.c





