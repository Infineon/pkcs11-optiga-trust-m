<!--
SPDX-FileCopyrightText: 2024 Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

## Build test project
* Create a directory with name **lib**
  
``` console
  	$ mkdir lib
```

* Copy compiled liboptigatrust-i2c-linux-pkcs11.so to /lib/

``` console
  	$ sudo cp -r ../../../lib/*so /lib/
```

* Build the project:	

``` console
  	$ make
```

# Running Test 

On the directory location *cloned_repo*/test/projects/raspberry_pi3/, run command

	$ sudo ./lib/OPTIGA_Trust_M_PKCS11_Test_usbdongle

if you use one of Trust M USB dongles, otherwise

	$ sudo ./lib/OPTIGA_Trust_M_PKCS11_Test_i2c


This will trigger the system test to start running and populates the system test result on console. It usually takes around 26 seconds to complete all testcases, please be aware that no extra messages will be displayed during this time. You can find a generic test execution output below:

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





