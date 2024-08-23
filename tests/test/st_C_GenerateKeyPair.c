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
// Section 5.14
void st_c_generate_keypair_ecc_p_256_valid_001() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label, strlen(label)}

    };

    CK_ATTRIBUTE priv[] = {

        //{CKA_ID, id, strlen( id)},
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, strlen(label)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

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

void st_c_generate_keypair_ecc_p_384_valid_002() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    //MBEDTLS_OID_EC_GRP_SECP384R1
    CK_BYTE ec_params[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label, strlen(label)}

    };

    CK_ATTRIBUTE priv[] = {

        //{CKA_ID, id, strlen( id)},
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, strlen(label)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

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

void st_c_generate_keypair_ecc_p_521_valid_003() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    CK_BYTE ec_params[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label, strlen(label)}

    };

    CK_ATTRIBUTE priv[] = {

        //{CKA_ID, id, strlen( id)},
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, strlen(label)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

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

void st_c_generate_keypair_ecc_invalid_004() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_KEY_TYPE KeyType = CKK_RSA;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_LABEL, label, strlen(label)}

    };

    CK_ATTRIBUTE priv[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        //{CKA_ID, id, strlen( id)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, strlen(label)},

    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

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

        CU_ASSERT_EQUAL(CKR_ATTRIBUTE_VALUE_INVALID, rv);
        if (rv != CKR_ATTRIBUTE_VALUE_INVALID) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

        KeyType = CKK_EC;
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

void st_c_generate_keypair_ecc_invalid_missing_attribute_005() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_RV rv;

    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE id[] = "p11-templ-key-id-ecc";
    //CK_UTF8CHAR label[] = "p11-templ-key-label-ecc";
    CK_UTF8CHAR label[] = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_KEY_TYPE KeyType = CKK_EC;
    CK_ATTRIBUTE pub[] = {

        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        //{CKA_ID, id, strlen(id)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_LABEL, label, strlen(label)}};

    CK_ATTRIBUTE priv[] = {

        //{CKA_ID, id, strlen( id)},
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, strlen(label)},
    };

    CK_MECHANISM mech = {.mechanism = CKM_EC_KEY_PAIR_GEN, .pParameter = NULL, .ulParameterLen = 0};

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

        CU_ASSERT_EQUAL(CKR_TEMPLATE_INCONSISTENT, rv);
        if (rv != CKR_TEMPLATE_INCONSISTENT) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
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

void st_c_generate_keypair_rsa_1024_valid_001() {
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

void st_c_generate_keypair_rsa_2048_valid_002() {
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

void st_c_generate_keypair_rsa_1024_invalid_003() {
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
    CK_KEY_TYPE KeyType = CKK_EC;

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

        CU_ASSERT_EQUAL(CKR_ATTRIBUTE_VALUE_INVALID, rv);
        if (rv != CKR_ATTRIBUTE_VALUE_INVALID) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
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

void st_c_generate_keypair_rsa_1024_invalid_missing_attribute_004() {
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
    CK_KEY_TYPE KeyType = CKK_RSA;

    CK_ATTRIBUTE pub[6] = {
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        //{CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, exp, sizeof(exp)},
        //{CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, pub_label, sizeof(pub_label)}};

    CK_ATTRIBUTE priv[6] = {
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

        CU_ASSERT_EQUAL(CKR_TEMPLATE_INCONSISTENT, rv);
        if (rv != CKR_TEMPLATE_INCONSISTENT) {
            printf(
                "C_GenerateKeyPair failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
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