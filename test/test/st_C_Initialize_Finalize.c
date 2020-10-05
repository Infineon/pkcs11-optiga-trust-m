#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"
#include "c_unit_helper.h"

/**
 * This program contains integration test for C_Initialize and C_Finalize.
 * C_Initialize initializes the Cryptoki library.
 * C_Finalize is called to indicate that an application is finished with the Cryptoki library.
 */

// Test the 4 states and additional error case of:
//   http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
// Section 5.4
void st_c_initialize_finalize_valid_001() {
    
	CK_VOID_PTR pInitArgs = NULL_PTR;
	CK_RV rv;

	do 
	{	
		rv = C_Initialize (&pInitArgs);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_Initialize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		rv = C_Finalize(NULL);
		if (rv != CKR_OK) {
				printf("C_Finalize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;	
		}		
	} while(0);

}

void st_c_initialize_invalid_002() {

	CK_VOID_PTR pInitArgs = NULL_PTR;
	CK_RV rv;
		
	do 
	{	
		rv = C_Initialize (&pInitArgs);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_Initialize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		rv = C_Initialize (&pInitArgs);
		CU_ASSERT_EQUAL( CKR_CRYPTOKI_ALREADY_INITIALIZED, rv );	
		if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			printf("C_Initialize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}	
		
		rv = C_Finalize(NULL);
		CU_ASSERT_EQUAL( CKR_OK, rv );		
		if (rv != CKR_OK) {
				printf("C_Finalize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;	
		}	

	} while(0);	

}

void st_c_finalize_invalid_003() {

	CK_VOID_PTR pInitArgs = NULL_PTR;
	CK_RV rv;
	
	do 
	{	
		rv = C_Initialize (&pInitArgs);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_Initialize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		rv = C_Finalize((void *)0xDEADBEEF);
		CU_ASSERT_EQUAL( CKR_ARGUMENTS_BAD, rv );		
		if (rv != CKR_ARGUMENTS_BAD) {
				printf("C_Finalize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;	
		}	

		rv = C_Finalize(NULL);
		CU_ASSERT_EQUAL( CKR_OK, rv );		
		if (rv != CKR_OK) {
				printf("C_Finalize failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;	
		}			
	} while(0);	

}