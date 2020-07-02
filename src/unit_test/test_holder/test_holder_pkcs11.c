#include "c_unit_helper.h"
/////////////////////include test cases prototyping here/////////////////////
//function prototyping

//Cmd Lib:Get Data
INCLUDE(prvBeforeRunningTests)
INCLUDE(AFQP_InitializeFinalize)
INCLUDE(AFQP_GenerateRandom)
INCLUDE(AFQP_GenerateKeyPairEC)
INCLUDE(ut_generate_keypair_sign_verify_rsa)

//not built file were, None
void make_it_fail()
{
	CU_FAIL("All test in this exe need to be modified due to async and optiga changes");
}
//creates suites
int CreateTestSuite(int (*fptrCUHelper)(sTestSuite_d*,int))
{
	int status = 0;
	do
	{
		/////////////////////Add test cases in respective suites/////////////////////
		START_SUITE(optiga_pkcs_init_deinit)//name of the suite
			//ADDTEST(prvBeforeRunningTests)
			//ADDTEST(AFQP_InitializeFinalize)
			//ADDTEST(AFQP_GenerateRandom)
			ADDTEST(AFQP_GenerateKeyPairEC)
			ADDTEST(ut_generate_keypair_sign_verify_rsa)
        END_SUITE
        
		/////////////////////////////////////////////////////////////////////////////
		/////////////////////////////Add new test suites/////////////////////////////
		//include suite here
		sTestSuite_d setOfSuitesTB[]=
		{
			ADDSUITE(optiga_pkcs_init_deinit)
		};
		/////////////////////////////////////////////////////////////////////////////

		//call cunit helper to add suites to registry
		status = fptrCUHelper(setOfSuitesTB,sizeof(setOfSuitesTB)/sizeof(sTestSuite_d));
	}while(0);

	return status;
}


