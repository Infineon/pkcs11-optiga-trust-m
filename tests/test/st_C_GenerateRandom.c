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
// Section 5.4
void st_c_generate_random_valid_001() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_BYTE pRandomData_val[100] = {0};
    CK_BYTE_PTR pRandomData = pRandomData_val;
    CK_RV rv;

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
        rv = C_GenerateRandom(hSession, pRandomData, sizeof(pRandomData));
        CU_ASSERT_EQUAL(CKR_OK, rv);
        if (rv != CKR_OK) {
            printf(
                "C_GenerateRandom failed with Response Code :%x at line Number : %d\n",
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

void st_c_generate_random_invalid_002() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_BYTE pRandomData_val[100] = {0};
    CK_BYTE_PTR pRandomData = pRandomData_val;
    CK_RV rv;

    st_c_test_initialize();

    do {
        rv = C_GenerateRandom(hSession, pRandomData, sizeof(pRandomData));
        CU_ASSERT_EQUAL(CKR_SESSION_HANDLE_INVALID, rv);
        if (rv != CKR_SESSION_HANDLE_INVALID) {
            printf(
                "C_GenerateRandom failed with Response Code :%x at line Number : %d\n",
                rv,
                __LINE__
            );
            break;
        }

    } while (0);

    st_c_test_deinitialize();
}

void st_c_generate_random_invalid_003() {
    CK_SLOT_ID slot_id = 1;
    CK_SESSION_HANDLE hSession;
    CK_BYTE pRandomData_val[100] = {0};
    CK_BYTE_PTR pRandomData = NULL;
    CK_RV rv;

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

        rv = C_GenerateRandom(hSession, pRandomData, sizeof(pRandomData));
        CU_ASSERT_EQUAL(CKR_ARGUMENTS_BAD, rv);
        if (rv != CKR_ARGUMENTS_BAD) {
            printf(
                "C_GenerateRandom failed with Response Code :%x at line Number : %d\n",
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