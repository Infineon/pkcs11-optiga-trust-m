#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"
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
// Section 5.14
void st_c_get_attribute_value_valid_001() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;
    CK_KEY_TYPE xKeyType;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_CLASS xClass;
    CK_BYTE xEcPoint[ 256 ] = { 0 };
    CK_BYTE xPrivateKeyBuffer[ 32 ] = { 0 };
    CK_BYTE xEcParams[ 11 ] = { 0 };
	CK_BYTE ec_params_p256[] = pkcs11DER_ENCODED_OID_P256; /* prime256v1 */

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
	CK_UTF8CHAR label[] = pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;	
	CK_UTF8CHAR label_pub[] = pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS;	
    CK_BYTE ec_params[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };
CK_KEY_TYPE KeyType = CKK_EC;	
    CK_ATTRIBUTE pub[] = {	
	
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },
        {CKA_TOKEN,   &true, sizeof(true)},       
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
		{CKA_LABEL, label_pub, strlen( label_pub )}
	
    };

    CK_ATTRIBUTE priv[] = {
		
        //{CKA_ID, id, strlen( id)},
        { CKA_KEY_TYPE, &KeyType,          sizeof( KeyType )                            },		
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},
        {CKA_LABEL, label, strlen( label )},
		
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_EC_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	
	
	st_c_test_initialize();	
	
	do 
	{			
		rv = C_GetFunctionList( &function_list );
		CU_ASSERT_EQUAL( CKR_OK, rv );
		if( rv != CKR_OK )
		{
			printf("C_GetFunctionList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;
		}
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		rv = C_GenerateKeyPair(
				hSession,             &mech,
            pub, sizeof( pub ) / sizeof( CK_ATTRIBUTE ),
            priv, sizeof( priv ) / sizeof( CK_ATTRIBUTE ),
            &pubkey, &privkey);

		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		/* Check that correct object class retrieved. */
		xTemplate.type = CKA_CLASS;
		xTemplate.pValue = NULL;
		xTemplate.ulValueLen = 0;
		rv = function_list->C_GetAttributeValue( hSession, pubkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		CU_ASSERT_EQUAL( sizeof( CK_OBJECT_CLASS ), xTemplate.ulValueLen );		
		
		xTemplate.pValue = &xClass;
		rv = function_list->C_GetAttributeValue( hSession, pubkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_OK, rv);
		CU_ASSERT_EQUAL( CKO_PUBLIC_KEY, xClass);

		/* Check that both keys are stored as EC Keys. */
		xTemplate.type = CKA_KEY_TYPE;
		xTemplate.pValue = &xKeyType;
		xTemplate.ulValueLen = sizeof( CK_KEY_TYPE );
		rv = function_list->C_GetAttributeValue( hSession, privkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		CU_ASSERT_EQUAL( sizeof( CK_KEY_TYPE ), xTemplate.ulValueLen);
		CU_ASSERT_EQUAL( CKK_EC, xKeyType);


		rv = function_list->C_GetAttributeValue( hSession, pubkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		CU_ASSERT_EQUAL( sizeof( CK_KEY_TYPE ), xTemplate.ulValueLen );
		CU_ASSERT_EQUAL( CKK_EC, xKeyType );


		/* Check that correct curve retrieved for private key. */
		xTemplate.type = CKA_EC_PARAMS;
		xTemplate.pValue = xEcParams;
		xTemplate.ulValueLen = sizeof( xEcParams );
		rv = function_list->C_GetAttributeValue( hSession, privkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		CU_ASSERT_EQUAL( sizeof( ec_params_p256 ), xTemplate.ulValueLen);
		CU_ASSERT_NSTRING_EQUAL( ec_params_p256, xEcParams, xTemplate.ulValueLen );


		/* Check that the private key cannot be retrieved. */
		xTemplate.type = CKA_VALUE;
		xTemplate.pValue = xPrivateKeyBuffer;
		xTemplate.ulValueLen = sizeof( xPrivateKeyBuffer );
		rv = function_list->C_GetAttributeValue( hSession, privkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_ATTRIBUTE_SENSITIVE, rv);
		//TEST_ASSERT_EACH_EQUAL_INT8_MESSAGE( 0, xPrivateKeyBuffer, sizeof( xPrivateKeyBuffer ));

		/* Check that public key point can be retrieved for public key. */
		xTemplate.type = CKA_EC_POINT;
		xTemplate.pValue = xEcPoint;
		xTemplate.ulValueLen = sizeof( xEcPoint );
		rv = function_list->C_GetAttributeValue( hSession, pubkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		
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

void st_c_get_attribute_value_invalid_002() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;
    CK_KEY_TYPE xKeyType;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_CLASS xClass;
    CK_BYTE xEcPoint[ 256 ] = { 0 };
    CK_BYTE xPrivateKeyBuffer[ 32 ] = { 0 };
    CK_BYTE xEcParams[ 11 ] = { 0 };
	CK_BYTE ec_params_p256[] = pkcs11DER_ENCODED_OID_P256; /* prime256v1 */

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
	CK_UTF8CHAR label[] = pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;	
	CK_UTF8CHAR label_pub[] = pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS;	
    CK_BYTE ec_params[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07
    };
CK_KEY_TYPE KeyType = CKK_EC;	
    CK_ATTRIBUTE pub[] = {	
	
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },
        {CKA_TOKEN,   &true, sizeof(true)},       
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
		{CKA_LABEL, label_pub, strlen( label_pub )}
	
    };

    CK_ATTRIBUTE priv[] = {
		
        //{CKA_ID, id, strlen( id)},
        { CKA_KEY_TYPE, &KeyType,          sizeof( KeyType )                            },		
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},
        {CKA_LABEL, label, strlen( label )},
		
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_EC_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	
	
	st_c_test_initialize();	
	
	do 
	{			
		rv = C_GetFunctionList( &function_list );
		CU_ASSERT_EQUAL( CKR_OK, rv );
		if( rv != CKR_OK )
		{
			printf("C_GetFunctionList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;
		}
		// Open Session
		rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_OpenSession failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		rv = C_GenerateKeyPair(
				hSession,             &mech,
            pub, sizeof( pub ) / sizeof( CK_ATTRIBUTE ),
            priv, sizeof( priv ) / sizeof( CK_ATTRIBUTE ),
            &pubkey, &privkey);

		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		/* Check that correct object class retrieved. */
		xTemplate.type = 0xff;
		xTemplate.pValue = NULL;
		xTemplate.ulValueLen = 0;
		rv = function_list->C_GetAttributeValue( hSession, pubkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_ATTRIBUTE_TYPE_INVALID, rv );		
		
		xTemplate.type = CKA_CLASS;		
		xTemplate.ulValueLen = 0;
		xTemplate.pValue = &xClass;
		rv = function_list->C_GetAttributeValue( hSession, pubkey, &xTemplate, 1 );
		CU_ASSERT_EQUAL( CKR_BUFFER_TOO_SMALL, rv);

		/* Check that both keys are stored as EC Keys. */
		xTemplate.type = CKA_KEY_TYPE;
		xTemplate.pValue = &xKeyType;
		xTemplate.ulValueLen = sizeof( CK_KEY_TYPE );
		rv = function_list->C_GetAttributeValue( hSession, privkey, &xTemplate, 0 );
		CU_ASSERT_EQUAL( CKR_DATA_INVALID, rv );	

		xTemplate.type = CKA_EC_POINT;
		xTemplate.pValue = xEcPoint;
		xTemplate.ulValueLen = sizeof( xEcPoint );
		rv = function_list->C_GetAttributeValue( hSession, pubkey, NULL, 1 );
		CU_ASSERT_EQUAL( CKR_DATA_INVALID, rv );	
		
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
