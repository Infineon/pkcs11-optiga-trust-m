#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11_optiga_trustm.h"
#include "c_unit_helper.h"

extern void st_c_test_initialize();
extern void st_c_test_deinitialize();

/**
 * This program contains integration test for C_Initialize and C_Finalize.
 * C_Initialize initializes the Cryptoki library.
 * C_Finalize is called to indicate that an application is finished with the Cryptoki library.
 */

// Test the 4 states and additional error case of:
//   http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
// Section 5.10
void st_c_digest_init_update_final_valid_001() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
	
    CK_BYTE data[] = "Hello World This is My First Digest Message";
	CK_BYTE hash[32];
    CK_ULONG hashlen = sizeof(hash);
	

	st_c_test_initialize();	
	
	do 
	{	
		
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// C_DigestInit
		rv = C_DigestInit(hSession, &smech);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestUpdate
		rv = C_DigestUpdate(hSession, data, sizeof(data));
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestUpdate failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestFinal
		rv = C_DigestFinal(hSession, hash, &hashlen);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestFinal failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}	
			
		// Close Session
		rv = C_CloseSession(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_CloseSession failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

	} while(0);
		
	st_c_test_deinitialize();
		
}

void st_c_digest_update_final_invalid_002() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
	
    CK_BYTE data[] = "Hello World This is My First Digest Message";
	CK_BYTE hash[32];
    CK_ULONG hashlen = sizeof(hash);
	

	st_c_test_initialize();	
	
	do 
	{	
		
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// C_DigestUpdate
		rv = C_DigestUpdate(hSession, data, sizeof(data));
		CU_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, rv );	
		if (rv != CKR_OPERATION_NOT_INITIALIZED) {
			printf("C_DigestUpdate failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
			
		// Close Session
		rv = C_CloseSession(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_CloseSession failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

	} while(0);
		
	st_c_test_deinitialize();
		
}

void st_c_digest_init_update_final_invalid_buffer_small_003() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
	
    CK_BYTE data[] = "Hello World This is My First Digest Message";
	CK_BYTE hash[31];
    CK_ULONG hashlen = sizeof(hash);
	

	st_c_test_initialize();	
	
	do 
	{	
		
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// C_DigestInit
		rv = C_DigestInit(hSession, &smech);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestUpdate
		rv = C_DigestUpdate(hSession, data, sizeof(data));
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestUpdate failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestFinal
		rv = C_DigestFinal(hSession, hash, &hashlen);
		CU_ASSERT_EQUAL( CKR_BUFFER_TOO_SMALL, rv );	
		if (rv != CKR_BUFFER_TOO_SMALL) {
			printf("C_DigestFinal failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}	
			
		// Close Session
		rv = C_CloseSession(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_CloseSession failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

	} while(0);
		
	st_c_test_deinitialize();
		
}

void st_c_digest_init_mechanism_invalid_004() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_MECHANISM smech = {
        .mechanism = CKM_AES_CBC,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
	
    CK_BYTE data[] = "Hello World This is My First Digest Message";
	CK_BYTE hash[32];
    CK_ULONG hashlen = sizeof(hash);
	

	st_c_test_initialize();	
	
	do 
	{	
		
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// C_DigestInit
		rv = C_DigestInit(hSession, &smech);
		CU_ASSERT_EQUAL( CKR_MECHANISM_INVALID, rv );	
		if (rv != CKR_MECHANISM_INVALID) {
			printf("C_DigestInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}		
		
		// Close Session
		rv = C_CloseSession(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_CloseSession failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

	} while(0);
		
	st_c_test_deinitialize();
		
}

void st_c_digest_init_update_final_terminates_valid_005() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
	
    CK_BYTE data[] = "Hello World This is My First Digest Message";
	CK_BYTE hash[32];
    CK_ULONG hashlen = sizeof(hash);
	

	st_c_test_initialize();	
	
	do 
	{	
		
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// C_DigestInit
		rv = C_DigestInit(hSession, &smech);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestUpdate
		rv = C_DigestUpdate(hSession, data, sizeof(data));
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestUpdate failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestFinal with CKR_BUFFER_TOO_SMALL and it wont terminate active digest operation
		hashlen = hashlen - 1;
		rv = C_DigestFinal(hSession, hash, &hashlen);
		CU_ASSERT_EQUAL( CKR_BUFFER_TOO_SMALL, rv );	
		if (rv != CKR_BUFFER_TOO_SMALL) {
			printf("C_DigestFinal failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}	
		
		// C_DigestFinal gives digest back
		hashlen = hashlen + 1;
		rv = C_DigestFinal(hSession, hash, &hashlen);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestFinal failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}	
		
		// Close Session
		rv = C_CloseSession(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_CloseSession failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

	} while(0);
		
	st_c_test_deinitialize();
		
}

void st_c_digest_init_operation_active_invalid_006() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_MECHANISM smech = {
        .mechanism = CKM_SHA256,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
	
    CK_BYTE data[] = "Hello World This is My First Digest Message";
	CK_BYTE hash[32];
    CK_ULONG hashlen = sizeof(hash);
	

	st_c_test_initialize();	
	
	do 
	{	
		
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// C_DigestInit
		rv = C_DigestInit(hSession, &smech);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestUpdate
		rv = C_DigestUpdate(hSession, data, sizeof(data));
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestUpdate failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestInit
		rv = C_DigestInit(hSession, &smech);
		CU_ASSERT_EQUAL( CKR_OPERATION_ACTIVE, rv );	
		if (rv != CKR_OPERATION_ACTIVE) {
			printf("C_DigestInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// C_DigestFinal
		rv = C_DigestFinal(hSession, hash, &hashlen);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_DigestFinal failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}	
			
		// Close Session
		rv = C_CloseSession(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_CloseSession failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

	} while(0);
		
	st_c_test_deinitialize();
		
}