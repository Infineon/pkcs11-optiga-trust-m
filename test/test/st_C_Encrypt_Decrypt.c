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
// Section 5.8
void st_c_encrypt_decrypt_rsa_1024_valid_001() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[128] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		
		// Encrypt_Init
		rv = C_EncryptInit(hSession, &mech, pubkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_EncryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// Encrypt message
		plaintext_len = sizeof(plaintext);
		ciphertext_len = 128;
		rv = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		CU_ASSERT_EQUAL( ciphertext_len, 128 );					
		if (ciphertext_len != 128) {
			printf("C_Encrypt ciphertext_len mismatch:%x at line Number : %d\n",ciphertext_len, __LINE__);
			break;		
		}

		// Decrypt_Init
		rv = C_DecryptInit(hSession, &mech, privkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_DecryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// Decrypt message
		rv = C_Decrypt(hSession, ciphertext, ciphertext_len, deciphertext, &deciphertext_len);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

		CU_ASSERT_EQUAL( deciphertext_len, plaintext_len );					
		if (deciphertext_len != plaintext_len) {
			printf("C_Decrypt deciphertext_len mismatch:%x at line Number : %d\n",deciphertext_len, __LINE__);
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

void st_c_encrypt_decrypt_rsa_2048_valid_002() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 2048;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[256] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		
		// Encrypt_Init
		rv = C_EncryptInit(hSession, &mech, pubkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_EncryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// Encrypt message
		plaintext_len = sizeof(plaintext);
		ciphertext_len = 256;
		rv = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		CU_ASSERT_EQUAL( ciphertext_len, 256 );					
		if (ciphertext_len != 256) {
			printf("C_Encrypt ciphertext_len mismatch:%x at line Number : %d\n",ciphertext_len, __LINE__);
			break;		
		}

		// Decrypt_Init
		rv = C_DecryptInit(hSession, &mech, privkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_DecryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// Decrypt message
		rv = C_Decrypt(hSession, ciphertext, ciphertext_len, deciphertext, &deciphertext_len);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

		CU_ASSERT_EQUAL( deciphertext_len, plaintext_len );					
		if (deciphertext_len != plaintext_len) {
			printf("C_Decrypt deciphertext_len mismatch:%x at line Number : %d\n",ciphertext_len, __LINE__);
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

void st_c_encrypt_init_ck_encrypt_false_invalid_003() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &false, sizeof(false)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[128] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		
		// Encrypt_Init
		rv = C_EncryptInit(hSession, &mech, pubkey);
		CU_ASSERT_EQUAL( CKR_KEY_FUNCTION_NOT_PERMITTED, rv );			
		if (rv != CKR_KEY_FUNCTION_NOT_PERMITTED) {
			printf("C_EncryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
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


void st_c_encrypt_rsa_1024_invalid_without_init_004() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[128] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		
		// Encrypt message
		plaintext_len = sizeof(plaintext);
		ciphertext_len = 128;
		rv = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
		CU_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, rv );			
		if (rv != CKR_OPERATION_NOT_INITIALIZED) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}


		CU_ASSERT_EQUAL( deciphertext_len, plaintext_len );					
		if (ciphertext_len != 128) {
			printf("C_Decrypt deciphertext_len mismatch:%x at line Number : %d\n",ciphertext_len, __LINE__);
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

void st_c_decrypt_rsa_1024_invalid_without_init_005() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[128] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		
		// Encrypt_Init
		rv = C_EncryptInit(hSession, &mech, pubkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_EncryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// Encrypt message
		plaintext_len = sizeof(plaintext);
		ciphertext_len = 128;
		rv = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		CU_ASSERT_EQUAL( ciphertext_len, 128 );					
		if (ciphertext_len != 128) {
			printf("C_Encrypt ciphertext_len mismatch:%x at line Number : %d\n",ciphertext_len, __LINE__);
			break;		
		}

		// Decrypt message
		rv = C_Decrypt(hSession, ciphertext, ciphertext_len, deciphertext, &deciphertext_len);
		CU_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, rv );			
		if (rv != CKR_OPERATION_NOT_INITIALIZED) {
			printf("C_Decrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
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

void st_c_encrypt_rsa_1024_invalid_buffer_low_006() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[128] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		
		// Encrypt_Init
		rv = C_EncryptInit(hSession, &mech, pubkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_EncryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// Encrypt message
		plaintext_len = sizeof(plaintext);
		ciphertext_len = 127;
		rv = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
		CU_ASSERT_EQUAL( CKR_BUFFER_TOO_SMALL, rv );			
		if (rv != CKR_BUFFER_TOO_SMALL) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
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

void st_c_decrypt_init_ck_decrypt_false_invalid_007() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &false, sizeof(false)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[128] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		// Encrypt_Init
		rv = C_EncryptInit(hSession, &mech, pubkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_EncryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// Encrypt message
		plaintext_len = sizeof(plaintext);
		ciphertext_len = 128;
		rv = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		CU_ASSERT_EQUAL( ciphertext_len, 128 );					
		if (ciphertext_len != 128) {
			printf("C_Encrypt ciphertext_len mismatch:%x at line Number : %d\n",ciphertext_len, __LINE__);
			break;		
		}

		// Decrypt_Init
		rv = C_DecryptInit(hSession, &mech, privkey);
		CU_ASSERT_EQUAL( CKR_KEY_FUNCTION_NOT_PERMITTED, rv );			
		if (rv != CKR_KEY_FUNCTION_NOT_PERMITTED) {
			printf("C_DecryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
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

void st_c_encrypt_decrypt_rsa_1024_invalid_len_range_008() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
	CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 }; //65537 in BN
    CK_UTF8CHAR pub_label[] = pkcs11configLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS; // "0xF1E0"
	CK_UTF8CHAR priv_label[] = pkcs11configLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS; // "0xE0FC"	
	CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof (exp)},
		//{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}
    };

    CK_ATTRIBUTE priv[] = {
        { CKA_KEY_TYPE,  &KeyType,         sizeof( KeyType )                           },		
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN,   &true, sizeof(true)},		
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };
	
    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0
    };
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;	

    CK_BYTE plaintext[] = {
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
        'm', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'i', 's', 'c', 'o', 'o', 'l',
    };
    CK_BYTE ciphertext[128] = { 0 };
    CK_BYTE deciphertext[sizeof(plaintext)] = { 0 };
	
    CK_ULONG plaintext_len;
	CK_ULONG ciphertext_len;
	CK_ULONG deciphertext_len = sizeof(deciphertext);

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
		
		// Encrypt_Init
		rv = C_EncryptInit(hSession, &mech, pubkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_EncryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		
		// Encrypt message
		plaintext_len = sizeof(plaintext);
		ciphertext_len = 128;
		rv = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_Encrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}
		CU_ASSERT_EQUAL( ciphertext_len, 128 );					
		if (ciphertext_len != 128) {
			printf("C_Encrypt ciphertext_len mismatch:%x at line Number : %d\n",ciphertext_len, __LINE__);
			break;		
		}

		// Decrypt_Init
		rv = C_DecryptInit(hSession, &mech, privkey);
		CU_ASSERT_EQUAL( CKR_OK, rv );			
		if (rv != CKR_OK) {
			printf("C_DecryptInit failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;		
		}

		// Decrypt message
		ciphertext_len = 127;
		rv = C_Decrypt(hSession, ciphertext, ciphertext_len, deciphertext, &deciphertext_len);
		CU_ASSERT_EQUAL( CKR_ENCRYPTED_DATA_LEN_RANGE, rv );			
		if (rv != CKR_ENCRYPTED_DATA_LEN_RANGE) {
			printf("C_Decrypt failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
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