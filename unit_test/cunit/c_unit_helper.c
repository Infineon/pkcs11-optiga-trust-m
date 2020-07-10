#include "c_unit_helper.h"
#include "optiga/common/optiga_lib_types.h"
#include "string.h"

/** @revision
*	0.01 | 28-Apr-14 | Created and initial version | Manish Kanchan
*/
/**
* \copyright Copyright (c) 2014 Infineon AG. This software is the confidential
* and proprietary information of Infineon AG. All rights reserved.
*
* \author Infineon AG
*
* \file CUnithelper.c
*
* \brief This file defines the framework for adding suite to cunit.
*/
#define HEXLOADED "Hexloaded.txt"
#define SUITERUNCOMPLETE "SuiteRunComplete.txt"

/**
* Creates test suite. This is specifically defined in the file which implements test cases
* \param[in] fptrCUHelper function pointer 
*/
extern int CreateTestSuite(int (*fptrCUHelper)(sTestSuite_d*,int));

/**
* Adds test suite to registry
* \param[in] pSetOfSuite Set of suites
* \param[in] numberOfSuites number of suites
*/
int AddTestSuites(sTestSuite_d* pSetOfSuite,int numberOfSuites )
{
	int suiteAddition = 0xFF;
	int count = 0;
	psTestSuite_d psTestSuite = NULL;
	psTestCase_d psTestCase = NULL;
	CU_pSuite pSuite = NULL;

	if(NULL == pSetOfSuite)
		return suiteAddition;

	while(count < numberOfSuites)
	{	
		psTestSuite = pSetOfSuite + count;
		//adding suite to test registry
		pSuite = CU_add_suite(psTestSuite->suiteName, NULL, NULL);
		if(NULL == pSuite)
		{
			printf("\n Not able to add %s Suite to the CUnit Registry.\n",psTestSuite->suiteName);
			suiteAddition = 0xFF;
		}
		else
		{
			printf("\n Added %s Suite to the CUnit Registry.\n",psTestSuite->suiteName);
			psTestCase = psTestSuite->psTestCase;
			while(psTestCase->testFuncPtr != NULL)
			{
				if(NULL==CU_add_test(pSuite,psTestCase->testName,psTestCase->testFuncPtr))
				{
						printf("\n Not able to add Test cases %s to the test suite %s. \n",psTestCase->testName,psTestSuite->suiteName);
						break;
				}
				psTestCase ++;				
			}
			suiteAddition = 0;
		}
		pSuite = NULL;
		count++;		
	};
	return suiteAddition;
}



/**
* Initialize cunit test framework
*/
int InitialiseTest()
{
	int status = 0;
	do
	{
		if(CUE_SUCCESS != CU_initialize_registry())
		{
			printf("\n Not able to Initialize the CUnit Registry. \n");
			break;
		}
		status = CreateTestSuite(AddTestSuites);
		if(CUE_SUCCESS != status)
		{
			printf("\n Not able to add test suite the CUnit Registry. \n");
			CU_cleanup_registry();
			break;
		}
	}while(0);		
	return status;
}


/**
* Starts Unit test execution
*/
void StartUnitTests(char *outputFileName)
{

	if(AUTOMATION == 1)
	{
		CU_set_output_filename(outputFileName);    //Output file name
		CU_list_tests_to_file();
		CU_automated_run_tests();
	}
	else
	{
		CU_set_output_filename(outputFileName);
		CU_console_run_tests();
	}
	CU_cleanup_registry();
}

//prints log number
void LogNumber(uint16_t wLoopNumber)
{
	char_t buffer[50];
	sprintf(buffer,"Failed in loop : %d\n",wLoopNumber);
	CU_FAIL(buffer);
}

