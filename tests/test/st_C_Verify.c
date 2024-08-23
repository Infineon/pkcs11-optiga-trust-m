// SPDX-FileCopyrightText: 2024 Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c_unit_helper.h"
#include "pkcs11_optiga_trustm.h"

extern void st_c_test_initialize();
extern void st_c_test_deinitialize();

/**
 * This program contains integration test for C_Initialize and C_Finalize.
 * C_Initialize initializes the Cryptoki library.
 * C_Finalize is called to indicate that an application is finished with the Cryptoki library.
 */

// Test the 4 states and additional error case of:
//   http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
// Section 5.11
void st_c_verify_ecc_valid_001() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label_priv[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;  // 0xE0F1
    CK_UTF8CHAR label_pub[] = LABEL_DEVICE_PUBLIC_KEY_FOR_TLS;  // 0xF1D2
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label_pub, strlen(label_pub)}

    };

    CK_ATTRIBUTE priv[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        //{CKA_ID, id, strlen( id)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label_priv, strlen(label_priv)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_ECDSA, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();

    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_VerifyInit(hSession, &mechSign, pubkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_VerifyInit failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_verify_ecc_invalid_no_verifyinit_002() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label_priv[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    CK_UTF8CHAR label_pub[] = LABEL_DEVICE_PUBLIC_KEY_FOR_TLS;
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label_pub, strlen(label_pub)}

    };

    CK_ATTRIBUTE priv[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        //{CKA_ID, id, strlen( id)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label_priv, strlen(label_priv)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_ECDSA, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();

    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, siglen);
        CU_ASSERT_EQUAL(CKR_OPERATION_NOT_INITIALIZED, rv);
        if (rv != CKR_OPERATION_NOT_INITIALIZED) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_verify_ecc_invalid_sign_len_invalid_003() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label_priv[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    CK_UTF8CHAR label_pub[] = LABEL_DEVICE_PUBLIC_KEY_FOR_TLS;
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label_pub, strlen(label_pub)}

    };

    CK_ATTRIBUTE priv[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        //{CKA_ID, id, strlen( id)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label_priv, strlen(label_priv)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_ECDSA, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();

    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_VerifyInit(hSession, &mechSign, pubkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_VerifyInit failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, siglen - 1);
        CU_ASSERT_EQUAL(CKR_SIGNATURE_LEN_RANGE, rv);
        if (rv != CKR_SIGNATURE_LEN_RANGE) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_verify_ecc_invalid_sign_invalid_004() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label_priv[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    CK_UTF8CHAR label_pub[] = LABEL_DEVICE_PUBLIC_KEY_FOR_TLS;
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label_pub, strlen(label_pub)}

    };

    CK_ATTRIBUTE priv[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        //{CKA_ID, id, strlen( id)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label_priv, strlen(label_priv)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_ECDSA, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];
    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();

    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_VerifyInit(hSession, &mechSign, pubkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_VerifyInit failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig - 1, siglen);
        CU_ASSERT_EQUAL(CKR_SIGNATURE_INVALID, rv);
        if (rv != CKR_SIGNATURE_INVALID) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_verify_rsa_1024_valid_001() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = {0x01, 0x00, 0x01};  //65537 in BN
    CK_UTF8CHAR pub_label[] = LABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS;  // "0xF1E0"
    CK_UTF8CHAR priv_label[] = LABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS;  // "0xE0FC"
    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_RSA;

    CK_ATTRIBUTE pub[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof(exp)},
        //{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}};

    CK_ATTRIBUTE priv[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, priv_label, sizeof(priv_label)}};

    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_RSA_PKCS, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();
    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_VerifyInit(hSession, &mechSign, pubkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_VerifyInit failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_verify_rsa_2048_valid_002() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 2048;
    CK_BYTE exp[] = {0x01, 0x00, 0x01};  //65537 in BN
    CK_UTF8CHAR pub_label[] = LABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS;  // "0xF1E0"
    CK_UTF8CHAR priv_label[] = LABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS;  // "0xE0FC"
    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_RSA;

    CK_ATTRIBUTE pub[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof(exp)},
        //{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}};

    CK_ATTRIBUTE priv[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_RSA_PKCS, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();
    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_VerifyInit(hSession, &mechSign, pubkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_VerifyInit failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_verify_rsa_1024_invalid_no_verify_init_003() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = {0x01, 0x00, 0x01};  //65537 in BN
    CK_UTF8CHAR pub_label[] = LABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS;  // "0xF1E0"
    CK_UTF8CHAR priv_label[] = LABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS;  // "0xE0FC"
    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_RSA;

    CK_ATTRIBUTE pub[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof(exp)},
        //{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}};

    CK_ATTRIBUTE priv[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_RSA_PKCS, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();
    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, siglen);
        CU_ASSERT_EQUAL(CKR_OPERATION_NOT_INITIALIZED, rv);
        if (rv != CKR_OPERATION_NOT_INITIALIZED) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_verify_rsa_1024_invalid_sign_invalid_004() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-rsa";
    CK_ULONG bits = 1024;
    CK_BYTE exp[] = {0x01, 0x00, 0x01};  //65537 in BN
    CK_UTF8CHAR pub_label[] = LABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS;  // "0xF1E0"
    CK_UTF8CHAR priv_label[] = LABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS;  // "0xE0FC"
    CK_BYTE sha256_msg_hash[] = {0xcd, 0xd8, 0x92, 0x1d, 0xf0, 0xcd, 0x29, 0xba, 0x4b, 0x8b, 0x87,
                                 0x12, 0x15, 0x07, 0x46, 0xdf, 0xb1, 0x91, 0x50, 0x81, 0xf7, 0xd4,
                                 0x9b, 0xd5, 0x67, 0x58, 0xae, 0x5a, 0xa3, 0x2e, 0x47, 0x0d};
    CK_ULONG siglen = 0;
    CK_KEY_TYPE KeyType = CKK_RSA;

    CK_ATTRIBUTE pub[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof(exp)},
        //{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}};

    CK_ATTRIBUTE priv[] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, priv_label, sizeof(priv_label)},
    };

    CK_MECHANISM mech = {
        .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .pParameter = NULL,
        .ulParameterLen = 0};

    CK_MECHANISM mechSign = {.mechanism = CKM_RSA_PKCS, .pParameter = NULL, .ulParameterLen = 0};

    CK_BYTE sig[1024];

    CK_OBJECT_HANDLE pubkey;
    CK_OBJECT_HANDLE privkey;

    st_c_test_initialize();
    do {
        // Open Session
        rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_OpenSession failed with Response Code :%lx at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_GenerateKeyPair(
            hSession,
            &mech,
            pub,
            sizeof(pub) / sizeof(CK_ATTRIBUTE),
            priv,
            sizeof(priv) / sizeof(CK_ATTRIBUTE),
            &pubkey,
            &privkey
        );

        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        // Init the signal
        rv = C_SignInit(hSession, &mechSign, privkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_SignInit failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Sign the digest
        siglen = sizeof(sig);

        /* Call C_Sign for size */
        rv = C_Sign(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig, &siglen);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf("C_Sign failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        rv = C_VerifyInit(hSession, &mechSign, pubkey);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_VerifyInit failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        rv = C_Verify(hSession, sha256_msg_hash, sizeof(sha256_msg_hash), sig - 1, siglen);
        CU_ASSERT_EQUAL(CKR_SIGNATURE_INVALID, rv);
        if (rv != CKR_SIGNATURE_INVALID) {
            printf("C_Verify failed with Response Code :%x at line Number : %d\n", rv, __LINE__);
            break;
        }

        // Close Session
        rv = C_CloseSession(hSession);
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_CloseSession failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}