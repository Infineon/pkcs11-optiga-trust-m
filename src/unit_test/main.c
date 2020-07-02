#include <stdio.h>
#include <CUnit/CUnit.h>
#include "CUnit/Console.h"
#include "c_unit_helper.h"

#include "optiga/comms/optiga_comms.h"
#include "optiga/cmd/optiga_cmd.h"

/** @revision
*	0.01 | 28-Apr-14 | Main is very thin layer | Manish Kanchan
*/

#ifndef IFX_I2C_ASYNC
//optiga_comms_t optiga_comms = {0};
#endif

void main(int argc, char *argv[])
{
    char_t* pszVariantName = NULL;
	do
	{
		pszVariantName = "/home/pi/pkcs11/projects/raspberry_pi3/cunit_result";

		if(0 != InitialiseTest())
			break;
		StartUnitTests(pszVariantName);
	}while(0);
}