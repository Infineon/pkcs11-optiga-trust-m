#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11_optiga_trustm.h"
#include "c_unit_helper.h"


void st_c_test_find_objects_info_valid_001(void)
{
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;
    CK_KEY_TYPE xKeyType;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_CLASS xClass;
	CK_ULONG ulObjectCount;
    

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
	CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;	
	CK_UTF8CHAR label_pub[] = LABEL_DEVICE_PUBLIC_KEY_FOR_TLS;	
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
	
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_ATTRIBUTE tmpl[] = {
							  //{CKA_CLASS, &key_class, sizeof(key_class)},
							  //{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
							  {CKA_LABEL, label_pub, strlen( label_pub )},
						  };
    CK_ATTRIBUTE tmp2[] = {
							  //{CKA_CLASS, &key_class, sizeof(key_class)},
							  //{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
							  {CKA_LABEL, label, strlen( label )},
						  };						  
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
		
		rv = C_FindObjectsInit(hSession, &tmpl, 2);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsInit failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
	
		rv = C_FindObjects(hSession, &pubkey, 1, &ulObjectCount);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjects failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
		CU_ASSERT_EQUAL( ulObjectCount, 1 );
		
		rv = C_FindObjectsFinal(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsFinal failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		rv = C_FindObjectsInit(hSession, &tmp2, 2);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsInit failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
	
		rv = C_FindObjects(hSession, &privkey, 1, &ulObjectCount);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjects failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
		CU_ASSERT_EQUAL( ulObjectCount, 1 );
		
		rv = C_FindObjectsFinal(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsFinal failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
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

void st_c_test_find_objects_init_invalid_002(void)
{
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;
    CK_KEY_TYPE xKeyType;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_CLASS xClass;
	CK_ULONG ulObjectCount;
    

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
	CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;	
	CK_UTF8CHAR label_pub[] = LABEL_DEVICE_PUBLIC_KEY_FOR_TLS;	
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
	
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_ATTRIBUTE tmpl[] = {
							  {CKA_CLASS, &key_class, sizeof(key_class)},
							  
						  };
    CK_ATTRIBUTE tmp2[] = {
							  {CKA_CLASS, &key_class, sizeof(key_class)},
							  
						  };						  
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
		
		rv = C_FindObjectsInit(hSession, &tmpl, 2);
		CU_ASSERT_EQUAL( CKR_TEMPLATE_INCOMPLETE, rv );	
		if (rv != CKR_TEMPLATE_INCOMPLETE) {
			printf("C_FindObjectsInit failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
	

		rv = C_FindObjectsInit(hSession, &tmp2, 2);
		CU_ASSERT_EQUAL( CKR_TEMPLATE_INCOMPLETE, rv );	
		if (rv != CKR_TEMPLATE_INCOMPLETE) {
			printf("C_FindObjectsInit failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
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

void st_c_test_find_objects_invalid_003(void)
{
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;
    CK_KEY_TYPE xKeyType;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_CLASS xClass;
	CK_ULONG ulObjectCount;
    

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
	CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;	
	CK_UTF8CHAR label_pub[] = LABEL_DEVICE_PUBLIC_KEY_FOR_TLS;	
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
	
	CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_ATTRIBUTE tmpl[] = {
							  {CKA_LABEL, label_pub, strlen( label_pub )},
						  };
    CK_ATTRIBUTE tmp2[] = {
							  {CKA_LABEL, label, strlen( label )},
						  };						  
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
		
	
		rv = C_FindObjects(hSession, &pubkey, 1, &ulObjectCount);
		CU_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, rv );	
		if (rv != CKR_OPERATION_NOT_INITIALIZED) {
			printf("C_FindObjects failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		rv = C_FindObjectsFinal(hSession);
		CU_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, rv );	
		if (rv != CKR_OPERATION_NOT_INITIALIZED) {
			printf("C_FindObjectsFinal failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		rv = C_FindObjectsInit(hSession, &tmpl, 2);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsInit failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
	
		rv = C_FindObjects(hSession, &pubkey, 0, &ulObjectCount);
		CU_ASSERT_EQUAL( CKR_ARGUMENTS_BAD, rv );	
		if (rv != CKR_ARGUMENTS_BAD) {
			printf("C_FindObjects failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		
		rv = C_FindObjectsFinal(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsFinal failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		rv = C_FindObjectsInit(hSession, &tmpl, 2);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsInit failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
	
		rv = C_FindObjects(hSession, &pubkey, 1, NULL);
		CU_ASSERT_EQUAL( CKR_ARGUMENTS_BAD, rv );	
		if (rv != CKR_ARGUMENTS_BAD) {
			printf("C_FindObjects failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		
		rv = C_FindObjectsFinal(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsFinal failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}	

		rv = C_FindObjectsInit(hSession, &tmpl, 2);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsInit failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}
	
		rv = C_FindObjects(hSession, NULL, 1, &ulObjectCount);
		CU_ASSERT_EQUAL( CKR_ARGUMENTS_BAD, rv );	
		if (rv != CKR_ARGUMENTS_BAD) {
			printf("C_FindObjects failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
			break;		
		}

		
		rv = C_FindObjectsFinal(hSession);
		CU_ASSERT_EQUAL( CKR_OK, rv );	
		if (rv != CKR_OK) {
			printf("C_FindObjectsFinal failed with Response Code :%lx at line Number : %d\n",rv, __LINE__);
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
