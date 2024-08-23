#ifndef _CUNIT_HELPER_H_
#define _CUNIT_HELPER_H_

#ifdef WIN32
#include <stdio.h>
#endif
#include <CUnit/Automated.h>
#include <CUnit/CUnit.h>
#include <CUnit/Console.h>
#include <ctype.h>
//#include "Utilities.h"
//#include "optiga/common/optiga_lib_types.h"

/** @revision
*	0.01 | 28-Apr-14 | Created and initial version | Manish Kanchan
*/

// Copyright (c) 2014 Infineon AG. This software is the confidential
// SPDX-FileCopyrightText: 2024 Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#ifdef _DEBUG
#define AUTOMATION 0
#else
#define AUTOMATION 0
#endif

/**
 * \brief   Structure defining a test case
*/
typedef struct sTestCase_d {
    char *testName;  ///test case name
    CU_TestFunc testFuncPtr;  ///test function
} sTestCase_d, *psTestCase_d;

/**
 * \brief   Structure defining a test suite
*/
typedef struct sTestSuite_d {
    char *suiteName;  ///test suite name
    psTestCase_d psTestCase;  ///test attached to a suite
} sTestSuite_d, *psTestSuite_d;

/**
 * \brief   Structure defining a test framework
*/
typedef struct sFrameWork_d {
    psTestSuite_d *ppsSuiteList;  ///test suite list
    int suiteCount;  ///number of suites
    char *reportName;  //name of the test report
} sFrameWork_d, *psFrameWork_d;

///Start suite array
#define START_SUITE(n) sTestCase_d n[] = {
///End suite array
#define END_SUITE \
    { NULL, NULL } \
    } \
    ;

///Adds test to suites array
#define ADDTEST(n) {#n, (CU_TestFunc)n},

///Adds test case to a suite
#define ADDSUITE(n) {"GAD_" #n "_Tests", (psTestCase_d)n},

///Include for function that return void and take no parameters: Test functions
#define INCLUDE(n) void n();

///Extended assert to compare byte arrays
#define CU_EXT_ASSERT_ARRAY(actual, expected, length) \
    { \
        if (CompareArray(actual, expected, length)) { \
            CU_PASS("Array are equal"); \
        } else { \
            CU_FAIL("Array not equal"); \
        } \
    }

///Adds test suite to registry
int AddTestSuites(sTestSuite_d *pSetOfSuite, int numberOfSuites);

///Initialize cunit test framework
int InitialiseTest();

///Starts test execution
void StartTests(int argc, char *argv[], char *outputFileName);

///Starts Unit test execution
void StartUnitTests(char *outputFileName);

//prints log number
void LogNumber(unsigned short wLoopNumber);

#define CU_EXT_LOG_LOOP(loop) \
    { LogNumber(loop); }

#define CU_EXT_ASSERT(exp, act) \
    { \
        CU_ASSERT(exp == act) \
        if (act != exp) { \
            printf("Return Value is =%d", act); \
            break; \
        } \
    }

#endif
