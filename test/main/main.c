#include <stdio.h>
#include <CUnit/CUnit.h>
#include "CUnit/Console.h"
#include "c_unit_helper.h"


/** @revision
*	0.01 | 28-Apr-14 | Main is very thin layer | Manish Kanchan
*/

void main(int argc, char *argv[])
{
    char * pszVariantName = NULL;
	do
	{
		pszVariantName = "/home/pi/pkcs11/projects/raspberry_pi3/cunit_result";

		if(0 != InitialiseTest())
			break;
		
		StartUnitTests(pszVariantName);
	}while(0);
}