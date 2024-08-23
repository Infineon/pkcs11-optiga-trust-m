// Copyright (c) 2020 Infineon Technologies AG
// SPDX-FileCopyrightText: 2024 Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

/**
 * @file pkcs11_trustm.c
 * @brief OPTIGA(TM) Trust M -based PKCS#11 implementation for software keys. This
 * file deviates from the FreeRTOS style standard for some function names and
 * data types in order to maintain compliance with the PKCS #11 standard.
 */

/* C runtime includes. */
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

/* OPTIGA(TM) Trust M Includes */
#include "ecdsa_utils.h"
#include "ifx_i2c/ifx_i2c_config.h"
#include "optiga_crypt.h"
#include "optiga_util.h"
#include "pal/pal_i2c.h"
#include "pal/pal_ifx_i2c_config.h"
#include "pal/pal_os_event.h"
#include "pal/pal_os_lock.h"
#include "pkcs11_optiga_trustm.h"

#ifndef USE_OPTIGA_SHA
#include "mbedtls/sha256.h"
#endif

#ifdef __linux__
#include <semaphore.h>
static sem_t semaphore; /* Semaphore that protects write operations to the objects array. */
static uint8_t sem_initialized = 0;
#else
//Platgorm specific header file
#endif

#define LIBRARY_MANUFACTURER "Infineon Technologies"
#define LIBRARY_DESCRIPTION "OPTIGA Trust M"

#define LIBRARY_VERSION_MAJOR 2
#define LIBRARY_VERSION_MINOR 24

#define FIRMWARE_VERSION_MAJOR 3
#define FIRMWARE_VERSION_MINOR 0

#define HARDWARE_VERSION_MAJOR 1
#define HARDWARE_VERSION_MINOR 0

#define SERIAL_NUMBER "12345678"  // !!! Fix Me

/*************************************************
 * @brief Cryptoki module attribute definitions.
 */
#ifdef PKCS11_SUPPORT_RSA
#define PKCS11_MAX_SLOTS 6
#else
#define PKCS11_MAX_SLOTS 4
#endif

#define PKCS11_MAX_MECHANISMS 30
#define MAX_SESSIONS 4
#define PKCS11_SLOT_MAX_OBJECTS 4

#define MAX_NUM_OBJECTS \
    21 /* also defined in pkcs11_optiga_trustm.h. Repeated here to ensure the same value */

#define pkcs11NO_OPERATION ((CK_MECHANISM_TYPE)0xFFFFFFFFF)

/* The size of the buffer malloc'ed for the exported public key in C_GenerateKeyPair */
#define pkcs11OBJECT_CERTIFICATE_MAX_SIZE 1728
#define MAX_PUBLIC_KEY_SIZE 100
#define MAX_DELAY 50

// Value of Operational state
#define LCSO_STATE_CREATION (0x01)
// Value of Operational state
#define LCSO_STATE_OPERATIONAL (0x07)

#define PKCS_ENCRYPT_ENABLE (1 << 0)
#define PKCS_DECRYPT_ENABLE (1 << 1)
#define PKCS_SIGN_ENABLE (1 << 2)
#define PKCS_VERIFY_ENABLE (1 << 3)
#define PKCS_WRAP_ENABLE (1 << 4)
#define PKCS_UNWRAP_ENABLE (1 << 5)
#define PKCS_DERIVE_ENABLE (1 << 6)

//Currently set to Creation state(defualt value). At the real time/customer side this needs to be LCSO_STATE_OPERATIONAL (0x07)
#define FINAL_LCSO_STATE (LCSO_STATE_CREATION)

uint8_t header_p256[] =
    {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
uint8_t header_p384[] =
    {0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
uint8_t header_p521[] =
    {0x30, 0x81, 0x9B, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
uint8_t header_BP256[] = {
    0x30,
    0x5A,  // SEQUENCE
    0x30,
    0x14,  //SEQUENCE
    0x06,
    0x07,  // OID:1.2.840.10045.2.1
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x02,
    0x01};
uint8_t header_BP384[] = {
    0x30,
    0x7A,  // SEQUENCE
    0x30,
    0x14,  //SEQUENCE
    0x06,
    0x07,  // OID:1.2.840.10045.2.1
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x02,
    0x01};
uint8_t header_BP512[] = {
    0x30,
    0x81,
    0x9B,  // SEQUENCE
    0x30,
    0x14,  //SEQUENCE
    0x06,
    0x07,  // OID:1.2.840.10045.2.1
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x02,
    0x01};

uint8_t ec_param_p256[] = pkcs11DER_ENCODED_OID_P256;
uint8_t ec_param_p384[] = pkcs11DER_ENCODED_OID_P384;
uint8_t ec_param_p521[] = pkcs11DER_ENCODED_OID_P521;
uint8_t ec_param_BP256[] = pkcs11DER_ENCODED_OID_BP256;
uint8_t ec_param_BP384[] = pkcs11DER_ENCODED_OID_BP384;
uint8_t ec_param_BP512[] = pkcs11DER_ENCODED_OID_BP512;

/**************************************************************************************
 * @brief Objects
 */
typedef struct pkcs11_object_t {
    //  CK_OBJECT_HANDLE logical_object_handle;     /* 1,2,... */
    CK_SLOT_ID slot_id;
    CK_BYTE text_label[MAX_LABEL_LENGTH + 1]; /* Object Label text "0xE0E0" */
    CK_LONG physical_oid; /* Object's physical Optiga Trust M address*/
    CK_OBJECT_CLASS object_class; /* CKO_CERTIFICATE, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY */
    CK_KEY_TYPE key_type; /* Key type: ECC or RSA */
    uint16_t
        obj_size_key_alg; /* Object max data size or key algorithm identifier (ECC 0x03..0x16) */
} pkcs11_object_t;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * @brief Global objects list
 */
typedef struct pkcs11_object_list {
    optiga_crypt_t *optiga_crypt_instance;
    optiga_util_t *optiga_util_instance;
    optiga_lib_status_t optiga_lib_status;
    pkcs11_object_t objects[MAX_NUM_OBJECTS];
} pkcs11_object_list;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * @brief Shared library instance context
 */
typedef struct pkcs11_context_struct {
    CK_BBOOL is_initialized;
    pkcs11_object_list object_list;
    //!!!    uint16_t certificate_oid;
    //!!!    uint16_t private_key_oid;
} pkcs11_context_struct;

static pkcs11_context_struct pkcs11_context;

/**************************************************************************************
                Logical object numbers (sequential from 1 to 21)
***************************************************************************************/
enum eObjectHandles {
    eInvalidHandle = 0, /* According to PKCS #11 spec, 0 is never a valid object handle. */
    ObjectHandle_Slot0_Certificate,  // 1
    ObjectHandle_Slot0_PrivateKey,  // 2
    ObjectHandle_Slot0_PublicKey,  // 3

    ObjectHandle_Slot1_Certificate,  // 4
    ObjectHandle_Slot1_PrivateKey,  // 5
    ObjectHandle_Slot1_PublicKey,  // 6

    ObjectHandle_Slot2_Certificate,  // 7
    ObjectHandle_Slot2_PrivateKey,  // 8
    ObjectHandle_Slot2_PublicKey,  // 9

    ObjectHandle_Slot3_Certificate,  // 10
    ObjectHandle_Slot3_PrivateKey,  // 11
    ObjectHandle_Slot3_PublicKey,  // 12

    ObjectHandle_Slot4_Certificate,  // 13
    ObjectHandle_Slot4_PrivateKey,  // 14
    ObjectHandle_Slot4_PublicKey,  // 15

    ObjectHandle_Slot5_Certificate,  // 16
    ObjectHandle_Slot5_PrivateKey,  // 17
    ObjectHandle_Slot5_PublicKey,  // 18

    ObjectHandle_TrustAnchor1_Certificate,  // 19
    ObjectHandle_TrustAnchor2_Certificate,  // 20
    ObjectHandle_CodeSigning_Certificate,  // 21
};

#define OPTIGA_CERTIFICATE_SIZE pkcs11OBJECT_CERTIFICATE_MAX_SIZE
#define OPTIGA_PUBLIC_KEY_SIZE 1500
#define OPTIGA_PRIVATE_KEY_SIZE 0

#define BUSY_WAIT_TIME_OUT \
    6000  // Note: This value must be at least 4000, any value smaller might encounter premature exit while waiting response from Trust M
#define MAX_RSA_KEY_GEN_TIME 62000  // Note: RSA key gen time can very from 7s to 60s

/**************************************************************************************
    Mapping of logical object numbers (see enum above) to:
    - slot number (0,1,2,3,4,5,6)
    - Object labels (text representation: "Cert", "PrvKey", "PubKey" or "0xE0E8" )
    - physical Optiga addresses (OIDs) 
    - slot type - ECC or RSA (same for private/pub keys and certificate in this slot)
    - maximum object (cert, pub or private key) physical memory size 
***************************************************************************************/
#define LABEL_CERT "Cert"
#define LABEL_PRVK "PrvKey"
#define LABEL_PUBK "PubKey"

#ifndef PKCS11_SUPPORT_RSA  // Mapping for 4 ECC slots and 2 RSA slots
static pkcs11_object_t optiga_objects_list[MAX_NUM_OBJECTS + 1] = {
    {
        0,
        "",
        0,
        0,
        0,
        0,
    },
    {0, LABEL_CERT, 0xE0E0, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 1  - Slot 0 (ECC)
    {0, LABEL_PRVK, 0xE0F0, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 2
    {0, LABEL_PUBK, 0xE0E8, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 3

    {1, LABEL_CERT, 0xE0E1, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 4  - Slot 1 (ECC)
    {1, LABEL_PRVK, 0xE0F1, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 5
    {1, LABEL_PUBK, 0xE0E9, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 6

    {2, LABEL_CERT, 0xE0E2, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 7  - Slot 2 (ECC)
    {2, LABEL_PRVK, 0xE0F2, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 8
    {2, LABEL_PUBK, 0xF1E0, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 9

    {3, LABEL_CERT, 0xE0E3, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 10 - Slot 3 (ECC)
    {3, LABEL_PRVK, 0xE0F3, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 11
    {3, LABEL_PUBK, 0xF1E1, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 12
    // Objects below should not be used - they overlap with slots 0-3
    {4,
     LABEL_CERT,
     0xE0E2,
     CKO_CERTIFICATE,
     CKK_RSA,
     OPTIGA_CERTIFICATE_SIZE},  // 13 - Slot 4 (RSA)
    {4, LABEL_PRVK, 0xE0FC, CKO_PRIVATE_KEY, CKK_RSA, OPTIGA_PRIVATE_KEY_SIZE},  // 14
    {4, LABEL_PUBK, 0xF1E0, CKO_PUBLIC_KEY, CKK_RSA, OPTIGA_PUBLIC_KEY_SIZE},  // 15

    {5,
     LABEL_CERT,
     0xE0E3,
     CKO_CERTIFICATE,
     CKK_RSA,
     OPTIGA_CERTIFICATE_SIZE},  // 16 - Slot 5 (RSA)
    {5, LABEL_PRVK, 0xE0FD, CKO_PRIVATE_KEY, CKK_RSA, OPTIGA_PRIVATE_KEY_SIZE},  // 17
    {5, LABEL_PUBK, 0xF1E1, CKO_PUBLIC_KEY, CKK_RSA, OPTIGA_PUBLIC_KEY_SIZE},  // 18

    {6, "0xE0E8", 0xE0E8, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 19 - Trust anchors
    {6, "0xE0E9", 0xE0E9, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 20
    {6, "0xE0EF", 0xE0EF, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 21
};
#endif

#ifdef PKCS11_SUPPORT_RSA  // Mapping for 4 ECC slots and 2 RSA slots
static pkcs11_object_t optiga_objects_list[MAX_NUM_OBJECTS + 1] = {
    {
        0,
        "",
        0,
        0,
        0,
        0,
    },
    {0, LABEL_CERT, 0xE0E0, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 1  - Slot 0 (ECC)
    {0, LABEL_PRVK, 0xE0F0, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 2
    {0, LABEL_PUBK, 0xF1D0, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 3

    {1, LABEL_CERT, 0xE0E1, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 4  - Slot 1 (ECC)
    {1, LABEL_PRVK, 0xE0F1, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 5
    {1, LABEL_PUBK, 0xF1D1, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 6

    {2, LABEL_CERT, 0xE0E2, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 7  - Slot 2 (ECC)
    {2, LABEL_PRVK, 0xE0F2, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 8
    {2, LABEL_PUBK, 0xF1D2, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 9

    {3, LABEL_CERT, 0xE0E3, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 10 - Slot 3 (ECC)
    {3, LABEL_PRVK, 0xE0F3, CKO_PRIVATE_KEY, CKK_EC, OPTIGA_PRIVATE_KEY_SIZE},  // 11
    {3, LABEL_PUBK, 0xF1D3, CKO_PUBLIC_KEY, CKK_EC, OPTIGA_PUBLIC_KEY_SIZE},  // 12

    {4,
     LABEL_CERT,
     0xE0E2,
     CKO_CERTIFICATE,
     CKK_RSA,
     OPTIGA_CERTIFICATE_SIZE},  // 13 - Slot 4 (RSA)
    {4, LABEL_PRVK, 0xE0FC, CKO_PRIVATE_KEY, CKK_RSA, OPTIGA_PRIVATE_KEY_SIZE},  // 14
    {4, LABEL_PUBK, 0xF1E0, CKO_PUBLIC_KEY, CKK_RSA, OPTIGA_PUBLIC_KEY_SIZE},  // 15

    {5,
     LABEL_CERT,
     0xE0E3,
     CKO_CERTIFICATE,
     CKK_RSA,
     OPTIGA_CERTIFICATE_SIZE},  // 16 - Slot 5 (RSA)
    {5, LABEL_PRVK, 0xE0FD, CKO_PRIVATE_KEY, CKK_RSA, OPTIGA_PRIVATE_KEY_SIZE},  // 17
    {5, LABEL_PUBK, 0xF1E1, CKO_PUBLIC_KEY, CKK_RSA, OPTIGA_PUBLIC_KEY_SIZE},  // 18

    {6, "0xE0E8", 0xE0E8, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 19 - Trust anchors
    {6, "0xE0E9", 0xE0E9, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 20
    {6, "0xE0EF", 0xE0EF, CKO_CERTIFICATE, CKK_EC, OPTIGA_CERTIFICATE_SIZE},  // 21
};
#endif

typedef struct _MECHANISM_INFO {
    CK_MECHANISM_TYPE xType;
    CK_MECHANISM_INFO xInfo;
} MECHANISM_INFO;

typedef struct _SLOTS_LIST {
    CK_SLOT_ID slot_id;
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR tokenLabel[32];

    uint16_t objects_number;
    enum eObjectHandles logical_object_handle
        [PKCS11_SLOT_MAX_OBJECTS + 1]; /* int: sequential object number - 1,2,...*/

    uint16_t mechanisms_number;
    MECHANISM_INFO mechanisms_list[PKCS11_MAX_MECHANISMS + 1];
} SLOTS_LIST;

/**************************************************************************************
    PKCS#11 slots/tokens and mechanisms info. 
    Mapping of slots to logical object numbers (see enum above)
***************************************************************************************/
static SLOTS_LIST supported_slots_mechanisms_list[PKCS11_MAX_SLOTS + 1] = {
    {
        0,  // ======================== Slot 0 - ECC ========================
        "Slot0",
        "Token0",
        3,  // Number of objects in slot
        {
            // Optiga OID list associated with this slot
            ObjectHandle_Slot0_Certificate,  // Default: Optiga Trust M Certificate OID
            ObjectHandle_Slot0_PrivateKey,  // Default: Optiga Trust M Private key OID
            ObjectHandle_Slot0_PublicKey,  // Default: Optiga Trust M Public key (Arbitrary object) OID
        },
        2,  // Number of supported ECC mechanisms
        {CKM_ECDSA, 256, 521, CKF_SIGN | CKF_VERIFY, CKM_SHA256, 256, 256, CKF_DIGEST},
    },
    {
        1,  // ======================== Slot 1 - ECC ========================
        "Slot1",
        "Token1",
        3,  // Number of objects in slot
        {
            // Optiga OID list associated with this slot
            ObjectHandle_Slot1_Certificate,  // Default: Optiga Trust M Certificate OID
            ObjectHandle_Slot1_PrivateKey,  // Default: Optiga Trust M Private key OID
            ObjectHandle_Slot1_PublicKey,  // Default: Optiga Trust M Public key (Arbitrary object) OID
        },
        3,  // Number of supported ECC mechanisms
        {CKM_EC_KEY_PAIR_GEN,
         256,
         521,
         CKF_GENERATE_KEY_PAIR,
         CKM_ECDSA,
         256,
         521,
         CKF_SIGN | CKF_VERIFY,
         CKM_SHA256,
         256,
         256,
         CKF_DIGEST},
    },
    {
        2,  // ======================== Slot 2 - ECC ========================
        "Slot2",
        "Token2",
        3,  // Number of objects in slot
        {
            // Optiga OID list associated with this slot
            ObjectHandle_Slot2_Certificate,  // Default: Optiga Trust M Certificate OID - shared with slot 4
            ObjectHandle_Slot2_PrivateKey,  // Default: Optiga Trust M Private key OID
            ObjectHandle_Slot2_PublicKey,  // Default: Optiga Trust M Public key (Arbitrary object) OID
        },
        3,  // Number of supported ECC mechanisms
        {CKM_EC_KEY_PAIR_GEN,
         256,
         521,
         CKF_GENERATE_KEY_PAIR,
         CKM_ECDSA,
         256,
         521,
         CKF_SIGN | CKF_VERIFY,
         CKM_SHA256,
         256,
         256,
         CKF_DIGEST},
    },
    {
        3,  // ======================== Slot 3 - ECC ========================
        "Slot3",
        "Token3",
        3,  // Number of objects in slot
        {
            // Optiga OID list associated with this slot
            ObjectHandle_Slot3_Certificate,  // Default: Optiga Trust M Certificate OID - shared with slot 5
            ObjectHandle_Slot3_PrivateKey,  // Default: Optiga Trust M Private key OID
            ObjectHandle_Slot3_PublicKey,  // Default: Optiga Trust M Public key (Arbitrary object) OID
        },
        3,  // Number of supported ECC mechanisms
        {CKM_EC_KEY_PAIR_GEN,
         256,
         521,
         CKF_GENERATE_KEY_PAIR,
         CKM_ECDSA,
         256,
         521,
         CKF_SIGN | CKF_VERIFY,
         CKM_SHA256,
         256,
         256,
         CKF_DIGEST},
    },
#ifdef PKCS11_SUPPORT_RSA
    {
        4,  // ======================== Slot 4 - RSA ========================
        "Slot4",
        "Token4",
        3,  // Number of objects in slot
        {
            // Optiga OID list associated with this slot
            ObjectHandle_Slot2_Certificate,  // Default: Optiga Trust M Certificate OID - shared with slot 2
            ObjectHandle_Slot4_PrivateKey,  // Default: Optiga Trust M Private key OID
            ObjectHandle_Slot4_PublicKey,  // Default: Optiga Trust M Public key (Arbitrary object) OID
        },
        2,  // Number of supported RSA mechanisms
        {CKM_RSA_PKCS_KEY_PAIR_GEN,
         1024,
         2048,
         CKF_GENERATE_KEY_PAIR,
         CKM_RSA_PKCS,
         1024,
         2048,
         CKF_SIGN | CKF_VERIFY | CKA_ENCRYPT | CKA_DECRYPT},
    },
    {
        5,  // ======================== Slot 5 - RSA ========================
        "Slot5",
        "Token5",
        3,  // Number of objects in slot
        {
            // Optiga OID list associated with this slot
            ObjectHandle_Slot3_Certificate,  // Default: Optiga Trust M Certificate OID - shared with slot 3
            ObjectHandle_Slot5_PrivateKey,  // Default: Optiga Trust M Private key OID
            ObjectHandle_Slot5_PublicKey,  // Default: Optiga Trust M Public key (Arbitrary object) OID
        },
        2,  // Number of supported RSA mechanisms
        {CKM_RSA_PKCS_KEY_PAIR_GEN,
         1024,
         2048,
         CKF_GENERATE_KEY_PAIR,
         CKM_RSA_PKCS,
         1024,
         2048,
         CKF_SIGN | CKF_VERIFY | CKA_ENCRYPT | CKA_DECRYPT},
    },
#endif
};

/********************************************************************************************
 * @brief Sessions
 */
typedef struct optiga_sha256_ctx_t {
    uint8_t hash_ctx_buff[209];
    optiga_hash_context_t hash_ctx;
} optiga_sha256_ctx_t;

typedef struct pkcs11_session {
    CK_SLOT_ID slot_id;
    CK_ULONG state;
    CK_BBOOL opened;
    CK_MECHANISM_TYPE operation_in_progress;
    CK_BBOOL find_object_init;
    uint16_t find_object_counter;
    CK_OBJECT_CLASS find_object_class;
    CK_LONG find_object_id;
    CK_BYTE find_object_label
        [MAX_LABEL_LENGTH + 1]; /* String representation of label. +1 for the null terminator. */
    uint8_t find_object_length;
    CK_MECHANISM_TYPE verify_mechanism;
    uint16_t verify_key_oid;
    CK_MECHANISM_TYPE
    sign_mechanism; /* Mechanism of the sign operation in progress. Set during C_SignInit. */
    CK_ULONG signature_size;
    CK_OBJECT_HANDLE key_object_handle; /* 1,2,... */
    uint16_t sign_key_oid;
    CK_BBOOL sign_init_done;
    CK_BBOOL verify_init_done;
    CK_BBOOL encrypt_init_done;
    CK_BBOOL decrypt_init_done;
#ifdef USE_OPTIGA_SHA
    optiga_sha256_ctx_t sha256_ctx;
#else
    mbedtls_sha256_context sha256_ctx;
#endif
    CK_ULONG rsa_key_size;
    //  CK_ULONG ec_key_size;
    uint16_t key_alg_id;
    uint16_t encryption_key_oid;
    uint16_t decryption_key_oid;
    CK_ULONG key_template_enabled;
} pkcs11_session_t, *p_pkcs11_session_t;

p_pkcs11_session_t pxSessions[MAX_SESSIONS + 1];

pal_os_lock_t optiga_mutex;

/*************************************************
 * @brief Helper definitions.

    Macro executed at the beginning of each PKCS#11 function not using a session.
    - Checks if pkcs11 module is initialized. 
      If not, opens log file, logs an error and exits function with CKR_CRYPTOKI_NOT_INITIALIZED
    - Logs Entry message 
**************************************************/
#define PKCS11_MODULE_INITIALIZED \
    CK_RV xResult = CKR_OK; \
    if (pkcs11_context.is_initialized != CK_TRUE) { \
        LOGOPEN \
        PKCS11_PRINT("ERROR: CKR_CRYPTOKI_NOT_INITIALIZED\r\n"); \
        return CKR_CRYPTOKI_NOT_INITIALIZED; \
    }

/**************
    Macro executed at the beginning of each PKCS#11 function using a session.
    - Same as PKCS11_MODULE_INITIALIZED (see above)
    + Checks if session has started. If not, logs an error and exits function with CKR_SESSION_HANDLE_INVALID
    + writes "TRACE: Enter Function. Session: xx" message to the log file.
**************/
#define PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession) \
    PKCS11_MODULE_INITIALIZED \
    if ((p_pkcs11_session_t)xSession == NULL) \
        return CKR_SESSION_HANDLE_INVALID; \
    if (((p_pkcs11_session_t)xSession)->opened != CK_TRUE) { \
        PKCS11_PRINT("ERROR: %s: Invalid session or session not opened\r\n", __func__); \
        return CKR_SESSION_CLOSED; \
    } \
    p_pkcs11_session_t pxSession = get_session_pointer(xSession); \
    if (pxSession == NULL) { \
        PKCS11_PRINT("ERROR: %s: Invalid session handle\r\n", __func__); \
        return CKR_SESSION_HANDLE_INVALID; \
    } \
    PKCS11_DEBUG("TRACE: Enter %s. Session: 0x%X\r\n", __func__, pxSession);

/**************
    Macro dumping PKCS#11 function TEMPLATE parameters to the log file.
 **************/
#define PKCS11_PRINT_TEMPLATE(pxTemplate, ulCount) \
    { \
        int i; \
        for (i = 0; i < ulCount; i++) { \
            if (pxTemplate[i].pValue != NULL) { \
                char message[200]; \
                sprintf( \
                    message, \
                    "TRACE: %s: Template: 0x%08X Value: ", \
                    __func__, \
                    pxTemplate[i].type \
                ); \
                HEXDUMP(message, pxTemplate[i].pValue, pxTemplate[i].ulValueLen); \
            } \
        } \
    }

/**************
    Macro dumping PKCS#11 function MECHANISM parameters to the log file.
 **************/
#define PKCS11_PRINT_MECHANISM(pxMechanism) \
    { \
        if (pxMechanism != NULL) { \
            PKCS11_DEBUG("TRACE: %s: Mechanism: 0x%X\r\n", __func__, pxMechanism->mechanism); \
            if (pxMechanism->ulParameterLen != 0) { \
                HEXDUMP("Parameters:", pxMechanism->pParameter, pxMechanism->ulParameterLen); \
            } \
        } \
    }

/**************
    Macro dumping PKCS#11 function KEY parameters to the log file.
 **************/
#define PKCS11_PRINT_KEY(strKeyName, xKey) \
    { PKCS11_DEBUG("TRACE: %s: %s: 0x%X\r\n", __func__, strKeyName, xKey); }

/*-------------------------------------------------------------------------
   Initialize Semaphores
  -------------------------------------------------------------------------*/
void Semaphore_Initialize() {
#ifdef USE_SEMAPHORES
    int xResult = 0;
    if (sem_initialized == 1)
        return;
#ifdef __linux__
    xResult = sem_init(&semaphore, 0, 1);
#else
        //Platform specific semaphore implementation
#endif
    if (xResult != 0) {
        PKCS11_PRINT("ERROR: C_Initialize: sem_init failed. Returned: 0x%X\r\n", (int)xResult);
        return;
    }
    sem_timeout.tv_sec = 0;
    sem_timeout.tv_nsec = 0xffff;
    sem_initialized = 1;
#endif
}
/*-------------------------------------------------------------------------
   Shutdown/Destroy Semaphores
  -------------------------------------------------------------------------*/
void Semaphore_Shutdown() {
#ifdef USE_SEMAPHORES
#ifdef __linux__
    if (sem_initialized == 1)
        sem_destroy(&semaphore);
#endif
    sem_initialized = 0;
#endif
}
/*-------------------------------------------------------------------------
   Wait until Semaphore released (with timeout)
  -------------------------------------------------------------------------*/
int Semaphore_Wait() {
    int32_t get_semaphore = 0;
#ifdef USE_SEMAPHORES
#ifdef __linux__
    get_semaphore = sem_timedwait(&semaphore, &sem_timeout);
    if (get_semaphore != 0) {
        PKCS11_PRINT(
            "ERROR: Semaphore_Wait: sem_timedwait failed. Returned: 0x%X\r\n",
            (int)get_semaphore
        );
        return CKR_CANT_LOCK;
    }
#endif
#endif
    return get_semaphore;
}
/*-------------------------------------------------------------------------
   Release Semaphore
  -------------------------------------------------------------------------*/
void Semaphore_Release() {
#ifdef USE_SEMAPHORES
#ifdef __linux__
    sem_post(&semaphore);
#endif
#endif
}
/*-----------------------------------------------------------*/
//lint --e{818} suppress "argument "context" is not used in the sample provided"
static void optiga_callback(void *pvContext, optiga_lib_status_t xReturnStatus) {
    optiga_lib_status_t *xInstanceStatus = (optiga_lib_status_t *)pvContext;

    if (NULL != xInstanceStatus) {
        *xInstanceStatus = xReturnStatus;
    }
}
/**********************************************************************
 * @brief Start Optiga communication timeout
 **********************************************************************/
void trustm_TimerStart() {
    pkcs11_context.object_list.optiga_lib_status = OPTIGA_LIB_BUSY;
}
/**********************************************************************
 * @brief Wait while Optiga is busy
 **********************************************************************/
void trustm_WaitForCompletion(uint16_t time_ms) {
    unsigned long count;
    for (count = 0; count < time_ms; count++) {
        if (pkcs11_context.object_list.optiga_lib_status != OPTIGA_LIB_BUSY)
            return;
        usleep(1000);  // Sleep for 1 ms
    }
}
/**********************************************************************
 * @brief Check Optiga function return code and wait while Optiga is busy
 **********************************************************************/
void trustm_CheckStatus_WaitForCompletion(
    optiga_lib_status_t *optiga_lib_return,
    uint16_t time_ms,
    char *func_name
) {
    if (OPTIGA_LIB_SUCCESS == *optiga_lib_return) {
        trustm_WaitForCompletion(time_ms);
        *optiga_lib_return = pkcs11_context.object_list.optiga_lib_status;
    }
    if (OPTIGA_LIB_SUCCESS != *optiga_lib_return) {
        PKCS11_PRINT(
            "ERROR: Optiga Trust M function '%s' failed. Error: 0x%X\r\n",
            func_name,
            *optiga_lib_return
        );
    }
}
/**********************************************************************
 * @brief Enable or disable Shielded Connection for UTIL and CRYPT
 * @param OPTIGA_COMMS_NO_PROTECTION or OPTIGA_COMMS_FULL_PROTECTION
 **********************************************************************/
void trustm_util_ShieldedConnection(uint8_t enable) {
#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
    PKCS11_DEBUG("%s UTIL Shielded Connection\r\n", enable ? "Enable" : "Disable");

    OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(pkcs11_context.object_list.optiga_util_instance, enable);
    OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(
        pkcs11_context.object_list.optiga_util_instance,
        OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET
    );
#endif
}
void trustm_crypt_ShieldedConnection(uint8_t enable) {
#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
    PKCS11_DEBUG("%s CRYPT Shielded Connection\r\n", enable ? "Enable" : "Disable");

    OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(
        pkcs11_context.object_list.optiga_crypt_instance,
        enable
    );
    OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(
        pkcs11_context.object_list.optiga_crypt_instance,
        OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET
    );
#endif
}
/**************************************************************************
    Read data from OPTIGA object
 **************************************************************************/
CK_RV optiga_trustm_read_data(
    uint16_t oid,
    uint16_t offset,
    uint8_t *data,
    uint16_t *pulDataSize,
    uint8_t shielded
) {
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;

    trustm_TimerStart();
    trustm_util_ShieldedConnection(shielded);  // Enable Shielded Connection

    optiga_lib_return = optiga_util_read_data(
        pkcs11_context.object_list.optiga_util_instance,
        oid,
        offset,
        data,
        pulDataSize
    );
    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_util_read_data"
    );

    if (0x8008 == optiga_lib_return)  // In case the read was ok, but no data inside
    {
        *pulDataSize = 0;
        return OPTIGA_UTIL_SUCCESS;
    }
    PKCS11_PRINT("OPTIGA Read Data(0x%04X)\r\n", oid);
    HEXDUMP("Data: ", data, *pulDataSize);
    return optiga_lib_return;
}
/**************************************************************************
    Read metadata from OPTIGA object
 **************************************************************************/
CK_RV optiga_trustm_read_metadata(
    uint16_t oid,
    uint8_t *metadata,
    int metadatasize,
    uint8_t shielded
) {
    uint16_t bytes_to_read = metadatasize;
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;

    trustm_TimerStart();
    trustm_util_ShieldedConnection(shielded);  // Enable Shielded Connection

    optiga_lib_return = optiga_util_read_metadata(
        pkcs11_context.object_list.optiga_util_instance,
        oid,
        metadata,
        &bytes_to_read
    );
    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_util_read_metadata"
    );

    PKCS11_PRINT("OPTIGA Read Metadata(0x%04X)\r\n", oid);
    HEXDUMP("Data: ", metadata, bytes_to_read);
    return optiga_lib_return;
}

/**************************************************************************/
#ifdef PKCS11_SUPPORT_RSA
CK_RV set_valid_rsa_signature_scheme(
    CK_MECHANISM_TYPE mechanism_type,
    optiga_rsa_signature_scheme_t *rsa_signature_scheme
) {
    CK_RV return_status = CKR_OK;
    switch (mechanism_type) {
        case CKM_RSA_PKCS:
            *rsa_signature_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
            break;
        case CKM_SHA256_RSA_PKCS:
            *rsa_signature_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
            break;
        case CKM_SHA384_RSA_PKCS:
            *rsa_signature_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA384;
            break;
        case CKM_SHA512_RSA_PKCS:
            *rsa_signature_scheme = OPTIGA_RSASSA_PKCS1_V15_SHA512;
            break;
        default:
            return_status = CKR_MECHANISM_INVALID;
    }
    return return_status;
}
#endif
/**************************************************************************
    Sign data in OPTIGA using private key in provided OID
 **************************************************************************/
CK_RV optiga_trustm_sign_data(
    CK_MECHANISM_TYPE sign_mechanism,
    uint16_t key_alg_id,
    uint16_t oid,
    uint8_t *pucData,
    int ulDataLen,
    CK_BYTE_PTR pucSignature,
    CK_ULONG xSignatureLength
) {
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    /* Signature Length + 3x2 bytes reserved for DER tags */
    uint8_t ecSignature[pkcs11ECDSA_P521_SIGNATURE_LENGTH + 3 + 3];
    uint16_t ecSignatureLength = sizeof(ecSignature);
    optiga_rsa_signature_scheme_t rsa_signature_scheme = 0;

    HEXDUMP("TRACE: C_Sign...: Signing data: ", pucData, ulDataLen);

    trustm_TimerStart();
    trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

    if (sign_mechanism == CKM_ECDSA) {
        PKCS11_DEBUG("TRACE: C_Sign...(ECC): OID: 0x%X. KeyType: 0x%X\r\n", oid, key_alg_id);
        optiga_lib_return = optiga_crypt_ecdsa_sign(
            pkcs11_context.object_list.optiga_crypt_instance,
            pucData,
            ulDataLen,
            oid,
            ecSignature,
            &ecSignatureLength
        );

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_crypt_ecdsa_sign"
        );
        /* Reformat from DER encoded to 64-byte R & S components. Example:
                   00000000  AB 20 21 DC 56 13 CF 6E 01 D7 3F 3A 2D 09 07 46  . !.V..n..?:-..F
                   00000010  BA BA D3 2E 83 B8 5B D6 16 99 4A 40 85 77 B5 C0  ......[...J@.w..
                   00000020  48 F8 A8 1A C5 BB F2 E6 B8 3A 33 76 97 22 21 67  H........:3v."!g
                   00000030  F1 A9 31 CF AF AC DD EE 7A 74 AF 17 C5 D8 18 5B  ..1.....zt.....[
       */
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT(
                "ERROR: C_Sign...(ECC): 'optiga_crypt_sign' failed. Returned: 0x%04X\r\n",
                (int)optiga_lib_return
            );
            return optiga_lib_return;
        }
        asn1_to_ecdsa_rs(ecSignature, ecSignatureLength, pucSignature, xSignatureLength);
    }
#ifdef SUPPORT_RSA
    else if (CKR_OK == set_valid_rsa_signature_scheme(sign_mechanism, &rsa_signature_scheme)) {
        PKCS11_DEBUG(
            "TRACE: C_Sign...(RSA): OID: 0x%X. Signature scheme: 0x%X\r\n",
            oid,
            rsa_signature_scheme
        );
        optiga_lib_return = optiga_crypt_rsa_sign(
            pkcs11_context.object_list.optiga_crypt_instance,
            rsa_signature_scheme,
            pucData,
            ulDataLen,
            oid,
            pucSignature,
            (uint16_t *)pulSignatureLen,
            0x0000
        );
        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_crypt_rsa_sign"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT(
                "ERROR: C_Sign...(RSA): 'optiga_crypt_sign' failed. Returned: 0x%04X\r\n",
                (int)optiga_lib_return
            );
            return optiga_lib_return;
        }
    }
#endif
    else {
        PKCS11_PRINT("ERROR: C_Sign...: Wrong mechanism: 0x%X\r\n", sign_mechanism);
        return OPTIGA_UTIL_ERROR;
    }
    /* Example of a returned signature 
        * 0x000000: 02 20 38 0f 56 c8 90 53 18 9d 8f 58 b4 46 35 a0 . 8.V..S...X.F5.
        * 0x000010: d7 07 63 ef 9f a2 30 64 93 e4 3d bf 7b db 57 a1 ..c...0d..=.{.W.
        * 0x000020: b6 d7 02 20 4f 5e 3a db 6b 1a eb ac 66 9a 15 69 ... O^:.k...f..i
        * 0x000030: 0d 7d 46 5b 44 72 40 06 a5 7b 06 84 0f d7 6e 0f .}F[Dr@..{....n.
        * 0x000040: 4b 45 7f 50                                     KE.P
        */
    HEXDUMP("TRACE: C_Sign...: Signature: ", pucSignature, xSignatureLength);
    return optiga_lib_return;
}

/**************************************************************************
 * @brief Translates text label ("0xE0E0") into an object handle (1,2...)
 *
 * Port-specific object handle retrieval.
 *
 * @param[in] pLabel         Pointer to the textual label of the object
 *                           who's handle should be found. Ex., "0xE0E0"
 * @param[out] plOptigaOid   Pointer to a long containing Optiga physical address (0xE0E0)
 *
 * @return The object handle if operation was successful.
 * Returns CK_INVALID_HANDLE if unsuccessful.
 **************************************************************************/
CK_OBJECT_HANDLE find_object_by_label(CK_SLOT_ID slot_id, char *pLabel, CK_LONG *plOptigaOid) {
    uint16_t obj;
    for (obj = 1; obj < MAX_NUM_OBJECTS; obj++) {
        if (strncasecmp(pLabel, (char *)optiga_objects_list[obj].text_label, MAX_LABEL_LENGTH) == 0
            && optiga_objects_list[obj].slot_id == slot_id) {
            if (plOptigaOid != NULL) {
                *plOptigaOid = optiga_objects_list[obj].physical_oid;
            }
            return obj;
        }
    }
    PKCS11_PRINT(
        "ERROR: find_object_by_label: Object Label '%s' not found in Slot %d\r\n",
        pLabel,
        (int)slot_id
    );
    return CK_INVALID_HANDLE;
}
/**************************************************************************
 * @brief Translates Optiga object ID (0xE0E1) into an object handle (1,2...)
 *
 * @param[in] oid            Optiga object ID (0xE0E1)
 * @param[out] plOptigaOid   Pointer to a long containing Optiga physical address (0xE0E0)
 *
 * @return The object handle if operation was successful.
 * Returns CK_INVALID_HANDLE if unsuccessful.
 **************************************************************************/
CK_OBJECT_HANDLE find_object_by_id(CK_LONG oid, CK_LONG *plOptigaOid) {
    uint16_t obj;
    for (obj = 1; obj < MAX_NUM_OBJECTS; obj++)
        if (oid == optiga_objects_list[obj].physical_oid) {
            if (plOptigaOid != NULL) {
                *plOptigaOid = optiga_objects_list[obj].physical_oid;
            }
            return obj;
        }
    PKCS11_PRINT("ERROR: find_object_by_id: Invalid object ID: 0x%X\r\n", oid);
    return CK_INVALID_HANDLE;
}
/**************************************************************************
 * @brief Searches the PKCS #11 module's object list for handle and provides OID
 *
 * @param[in]  xAppHandle    The logical handle of the object being searched (1,2,...)
 * @param[out] plOptigaOid   Pointer to a long containing Optiga physical address (0xE0E0)
 *
 * @return     xPalHandle    The logical handle of the object (1,2,...) if found
 *                           Returns CK_INVALID_HANDLE if unsuccessful.
 **************************************************************************/
CK_OBJECT_HANDLE find_object_by_handle(CK_OBJECT_HANDLE xAppHandle, CK_LONG *plOptigaOid) {
    if (xAppHandle == 0 || xAppHandle >= MAX_NUM_OBJECTS) {
        PKCS11_PRINT(
            "ERROR: find_object_by_handle: Wrong object handle: %d. Min: 1, Max: %d\r\n",
            (int)xAppHandle,
            MAX_NUM_OBJECTS
        );
        return CK_INVALID_HANDLE;
    }
    if (plOptigaOid != NULL) {
        *plOptigaOid = optiga_objects_list[xAppHandle].physical_oid;
    }
    return xAppHandle;
}
/*************************************************************************
 * @brief Cleanup after get_object_value().
 *
 * @param[in] pucData       The buffer to free.
 *                          (*ppucData from get_object_value())
 **************************************************************************/
void get_object_value_cleanup(uint8_t *pucData) {
    if (pucData != NULL)
        free(pucData);
}
/*************************************************************************
 * @brief Gets the value of an object from Optiga, by logical handle.
 *
 * Port-specific file access for cryptographic information.
 *
 * This call dynamically allocates the buffer which object value
 * data is copied into.  get_object_value_cleanup()
 * should be called after each use to free the dynamically allocated
 * buffer.
 *
 * @sa get_object_value_cleanup
 *
 * @param[in] object_handle The logical object handle 1,2,... 
 * @param[out] ppucData     Pointer to buffer for the data
 * @param[out] pulDataSize  Pointer to data size (in bytes) returned
 *
 * @return CKR_OK if operation was successful.  CKR_KEY_HANDLE_INVALID if
 * no such object handle was found, CKR_DEVICE_ERROR if memory for
 * buffer could not be allocated, CKR_FUNCTION_FAILED for device driver
 * error.
 **************************************************************************/
long get_object_value(CK_OBJECT_HANDLE object_handle, uint8_t **ppucData, uint16_t *pulDataSize) {
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    CK_LONG lOptigaOid;
    uint16_t offset;

    *ppucData = NULL;
    *pulDataSize = 0;

    lOptigaOid = optiga_objects_list[object_handle].physical_oid; /* Get Optiga address/oid */

    // We need to allocate a buffer for a certificate/certificate chain
    // This data is later should be freed with get_object_value_cleanup
    *ppucData = malloc(pkcs11OBJECT_CERTIFICATE_MAX_SIZE);
    if (NULL == *ppucData) {
        PKCS11_PRINT("ERROR: %s: memory allocation error\r\n", __func__);
        return CKR_DEVICE_ERROR;
    }
    *pulDataSize =
        optiga_objects_list[object_handle].obj_size_key_alg;  // pkcs11OBJECT_CERTIFICATE_MAX_SIZE;

    if (optiga_objects_list[object_handle].object_class == CKO_CERTIFICATE)
        offset = 9;
    else
        offset = 0;

    optiga_lib_return = optiga_trustm_read_data(
        lOptigaOid,
        offset,
        *ppucData,
        pulDataSize,
        OPTIGA_COMMS_FULL_PROTECTION
    );
    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
        PKCS11_PRINT("ERROR: optiga_trustm_read_data (OID: 0x%04X) failed.\r\n", lOptigaOid);
        get_object_value_cleanup(*ppucData);
        *ppucData = NULL;
        return CKR_DEVICE_ERROR;
    }
    if (*pulDataSize == 0) {
        get_object_value_cleanup(*ppucData);
        *ppucData = NULL;
        return CKR_OK;
    }
    return CKR_OK;
}
/*-------------------------------------------------------------------------------
    Decodes ASN.1 BER TLV tag's length.
    Input: 
        buf  pointer to the tag
        i    pointer to the index containing offset in tags array
    Output: 
        Upon exit index points to TLV data
    Returns tag's length. 
  -------------------------------------------------------------------------------*/
int GetBERlen(uint8_t *buf, int *i) {
    uint8_t b;
    switch (buf[++(*i)]) {
        case 0x81:
            (*i)++;
            return (int)buf[(*i)++];
        case 0x82:
            (*i)++;
            b = buf[(*i)++];
            return (int)(b * 256 + buf[(*i)++]);
        default:
            return (int)buf[(*i)++];
    }
    return 0;
}
/*-------------------------------------------------------------------------------
    Search TLV data in data array (search one level only). 
    Input: 
        parray  pointer to the tag
        tag     tag to search
    Output: 
        plen    pointer to the integer where the length of found TLV will be returned
    Returns pointer to the found TLV
 -------------------------------------------------------------------------------*/
uint8_t *Find_TLV_Tag(uint8_t *parray, uint8_t tag, int *plen) {
    int ind = 0, arraylen, dlen;
    if (parray == NULL)
        return NULL;
    if (plen != NULL)
        *plen = 0;
    arraylen = GetBERlen(parray, &ind) + ind;  // Get ASN.1 encoded length of the found object

    for (; ind < arraylen; ind += dlen) {
        if (parray[ind] == tag) {  // Compare with tag we are looking for
            if (plen != NULL)
                *plen = arraylen - ind;
            return parray + ind;  // Return pointer to the Tag
        }
        if ((dlen = GetBERlen(parray, &ind)) == 0)
            return NULL;  // Wrong tag's length
    }
    return NULL;
}
/*-------------------------------------------------------------------------------
    Search DER TLV data array, find tag 03, remove preceeding data
 -------------------------------------------------------------------------------*/
int find_public_key_in_der(uint8_t *der) {
    if (der[0] == 0x30)  // DER header tag present in the object data
    {
        int iPubKeyLen;
        uint8_t *pPubKey = Find_TLV_Tag(der, 0x03, &iPubKeyLen);  // Get pointer to Tag 0x03 value
        if (pPubKey != NULL && iPubKeyLen != 0)
            memmove(der, pPubKey, iPubKeyLen);  // Remove header from the DER public key encoding
        return iPubKeyLen;
    }
    return 0;
}
/*************************************************************************
 * @brief Finds first available session handle and allocate memory for 
 * the session handle structure. Track all handles and allocated memory.
 **************************************************************************/
p_pkcs11_session_t new_session_pointer() {
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (pxSessions[i] == NULL) {
            pxSessions[i] = (p_pkcs11_session_t)malloc(sizeof(struct pkcs11_session));
            if (NULL == pxSessions[i]) {
                PKCS11_PRINT("ERROR: %s: memory allocation error\r\n", __func__);
                return NULL;
            }
            /* Zero out the session structure */
            memset(pxSessions[i], 0, sizeof(pkcs11_session_t));
            return pxSessions[i];
        }
    }
    return NULL;
}
/*************************************************************************
 * @brief Maps an opaque caller session handle into its internal state structure.
 *************************************************************************/
p_pkcs11_session_t get_session_pointer(CK_SESSION_HANDLE xSession) {
    return (p_pkcs11_session_t
    )xSession; /*lint !e923 Allow casting integer type to pointer for handle. */
}
/*************************************************************************
 * @brief Finds and deallocates session(s) structure
   if xSession = NULL - closes all sessions
 *************************************************************************/
void free_session_pointer(CK_SESSION_HANDLE xSession) {
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if ((p_pkcs11_session_t)xSession == NULL || (p_pkcs11_session_t)xSession == pxSessions[i]) {
            free(pxSessions[i]);
            pxSessions[i] = NULL;
        }
    }
}
/*************************************************************************
 * PKCS#11 module implementation.
 * @brief PKCS#11 interface functions implemented by this Cryptoki module.
 *************************************************************************/
static CK_FUNCTION_LIST prvP11FunctionList = {
    {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    NULL, /*C_InitPIN*/
    NULL, /*C_SetPIN*/
    C_OpenSession,
    C_CloseSession,
    NULL, /*C_CloseAllSessions, - implemented, but not supported by OpenSC pkcs11-spy based on PKCS#11 ver.2.11 */
    NULL, /*C_GetSessionInfo*/
    NULL, /*C_GetOperationState*/
    NULL, /*C_SetOperationState*/
    C_Login,
    C_Logout,
    C_CreateObject,
    NULL, /*C_CopyObject*/
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    NULL, /*C_SetAttributeValue*/
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    NULL, /* C_DigestKey*/
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    NULL, /*C_SignFinal, */
    NULL, /*C_SignRecoverInit*/
    NULL, /*C_SignRecover*/
    C_VerifyInit,
    C_Verify,
    NULL, /* C_VerifyUpdate,*/
    NULL, /* C_VerifyFinal,*/
    NULL, /*C_VerifyRecoverInit*/
    NULL, /*C_VerifyRecover*/
    NULL, /*C_DigestEncryptUpdate*/
    NULL, /*C_DecryptDigestUpdate*/
    NULL, /*C_SignEncryptUpdate*/
    NULL, /*C_DecryptVerifyUpdate*/
    NULL, /*C_GenerateKey*/
    C_GenerateKeyPair,
    NULL, /*C_WrapKey*/
    NULL, /*C_UnwrapKey*/
    NULL, /*C_DeriveKey*/
    NULL, /*C_SeedRandom*/
    C_GenerateRandom,
    NULL, /*C_GetFunctionStatus*/
    NULL, /*C_CancelFunction*/
    NULL /*C_WaitForSlotEvent*/
};
/**************************************************************************
    !!!JC  ATTENTION:  NOT TESTED YET     
 **************************************************************************/
optiga_lib_status_t pair_host_and_optiga_using_pre_shared_secret(void) {
    uint16_t bytes_to_read;
    uint8_t platform_binding_secret[64];
    uint8_t platform_binding_secret_metadata[44];
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    pal_status_t pal_return_status;

    /* Platform Binding Shared Secret (0xE140) Metadata to be updated */

    const uint8_t platform_binding_shared_secret_metadata_final[] = {
        //Metadata to be updated
        0x20,
        0x17,
        // LcsO
        0xC0,
        0x01,
        FINAL_LCSO_STATE,  // Refer Macro to see the value or some more notes
        // Change/Write Access tag
        0xD0,
        0x07,
        // This allows updating the binding secret during the runtime using shielded connection
        // If not required to update the secret over the runtime, set this to NEV and
        // update Metadata length accordingly
        0xE1,
        0xFC,
        LCSO_STATE_OPERATIONAL,  // LcsO < Operational state
        0xFE,
        0x20,
        0xE1,
        0x40,
        // Read Access tag
        0xD1,
        0x03,
        0xE1,
        0xFC,
        LCSO_STATE_OPERATIONAL,  // LcsO < Operational state
        // Execute Access tag
        0xD3,
        0x01,
        0x00,  // Always
        // Data object Type
        0xE8,
        0x01,
        0x22,  // Platform binding secret type
    };

    PKCS11_DEBUG("TRACE: Enter pair_host_and_optiga_using_pre_shared_secret\r\n");
    do {
        /**
         * 1. Initialize the protection level and protocol version for the instances
         */
        trustm_util_ShieldedConnection(OPTIGA_COMMS_NO_PROTECTION
        );  // Initialize Shielded Connection (disable)
        trustm_crypt_ShieldedConnection(OPTIGA_COMMS_NO_PROTECTION);

        /**
         * 2. Read Platform Binding Shared secret (0xE140) data object metadata from OPTIGA
         *    using optiga_util_read_metadata.
         */
        optiga_lib_return = optiga_trustm_read_metadata(
            0xE140,
            platform_binding_secret_metadata,
            sizeof(platform_binding_secret_metadata),
            OPTIGA_COMMS_NO_PROTECTION
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT("ERROR: pair_host_and_optiga_using_pre_shared_secret failed.\r\n");
            break;
        }
        HEXDUMP(
            "Object 0xE140 metadata: ",
            platform_binding_secret_metadata,
            sizeof(platform_binding_secret_metadata)
        );

        /**
         * 3. Validate LcsO in the metadata.
         *    Skip the rest of the procedure if LcsO is greater than or equal to operational state(0x07)
         */
        if (platform_binding_secret_metadata[4] >= LCSO_STATE_OPERATIONAL) {
            // The LcsO is already greater than or equal to operational state
            break;
        }
        /**
         * 4. Generate Random using optiga_crypt_random
         *       - Specify the Random type as TRNG
         *    a. The maximum supported size of secret is 64 bytes.
         *       The minimum recommended is 32 bytes.
         *    b. If the host platform doesn't support random generation,
         *       use OPTIGA to generate the maximum size chosen.
         *       else choose the appropriate length of random to be generated by OPTIGA
         *
         */
        trustm_TimerStart();
        optiga_lib_return = optiga_crypt_random(
            pkcs11_context.object_list.optiga_crypt_instance,
            OPTIGA_RNG_TYPE_TRNG,
            platform_binding_secret,
            sizeof(platform_binding_secret)
        );

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_crypt_random"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT("ERROR: pair_host_and_optiga_using_pre_shared_secret failed.\r\n");
            break;
        }
        HEXDUMP("Random PBS: ", platform_binding_secret, sizeof(platform_binding_secret));
        /**
         * 5. Generate random on Host
         *    If the host platform doesn't support, skip this step
         */

        /**
         * 6. Write random(secret) to OPTIGA platform Binding shared secret data object (0xE140)
         */
        trustm_TimerStart();
        trustm_util_ShieldedConnection(OPTIGA_COMMS_NO_PROTECTION);

        optiga_lib_return = optiga_util_write_data(
            pkcs11_context.object_list.optiga_util_instance,
            0xE140,
            OPTIGA_UTIL_ERASE_AND_WRITE,
            0,
            platform_binding_secret,
            sizeof(platform_binding_secret)
        );

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_util_write_data(platform_binding_secret)"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT("ERROR: pair_host_and_optiga_using_pre_shared_secret failed.\r\n");
            break;
        }
        PKCS11_DEBUG("TRACE: PBS written to 0xE140\r\n");

        /**
         * 7. Write/store the random(secret) on the Host platform
         */
        pal_return_status = pal_os_datastore_write(
            OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID,
            platform_binding_secret,
            sizeof(platform_binding_secret)
        );
        if (PAL_STATUS_SUCCESS != pal_return_status) {
            PKCS11_PRINT(
                "ERROR: pair_host_and_optiga_using_pre_shared_secret: 'pal_os_datastore_write' failed. Error: %d\r\n",
                pal_return_status
            );
            break;
        }
        PKCS11_DEBUG("TRACE: PBS saved to datastore\r\n");

        /**
         * 8. Update metadata of OPTIGA Platform Binding shared secret data object (0xE140)
         */
        trustm_TimerStart();
        trustm_util_ShieldedConnection(OPTIGA_COMMS_NO_PROTECTION);

        optiga_lib_return = optiga_util_write_metadata(
            pkcs11_context.object_list.optiga_util_instance,
            0xE140,
            platform_binding_shared_secret_metadata_final,
            sizeof(platform_binding_shared_secret_metadata_final)
        );

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_util_write_metadata"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT("ERROR: pair_host_and_optiga_using_pre_shared_secret failed.\r\n");
            break;
        }
        PKCS11_DEBUG("TRACE: Metadata written to 0xE140 - Operational life cycle\r\n");
        optiga_lib_return = OPTIGA_LIB_SUCCESS;
    } while (FALSE);
    return optiga_lib_return;
}
/**************************************************************************
          Optiga Trust M hardware initialization 
 **************************************************************************/
CK_RV optiga_trustm_initialize(void) {
    CK_RV xResult = CKR_OK, res;
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    pal_status_t pal_status;
    uint16_t dOptigaOID;
    static uint8_t host_pair_done = 1;
    pal_os_lock_acquire(&optiga_mutex);
    PKCS11_DEBUG("TRACE: Enter optiga_trustm_initialize\r\n");
    do {
        if ((pal_status = pal_gpio_init(&optiga_reset_0)) != PAL_STATUS_SUCCESS) {
            PKCS11_PRINT(
                "ERROR: C_Initialize: pal_gpio_init(RESET) failed. Error: %d\r\n",
                pal_status
            );
            return CKR_FUNCTION_FAILED;
        }
        if ((pal_status = pal_gpio_init(&optiga_vdd_0)) != PAL_STATUS_SUCCESS) {
            PKCS11_PRINT(
                "ERROR: C_Initialize: pal_gpio_init(VDD) failed. Error: %d\r\n",
                pal_status
            );
            goto init_error3;
        }
        /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
        PKCS11_DEBUG("TRACE: C_Initialize: optiga_crypt_create\r\n");
        pkcs11_context.object_list.optiga_crypt_instance =
            optiga_crypt_create(0, optiga_callback, &pkcs11_context.object_list.optiga_lib_status);

        if (NULL == pkcs11_context.object_list.optiga_crypt_instance) {
            PKCS11_PRINT("ERROR: C_Initialize: 'optiga_crypt_create' failed\r\n");
            xResult = CKR_FUNCTION_FAILED;
            goto init_error2;
        }

        PKCS11_DEBUG("TRACE: C_Initialize: optiga_util_create\r\n");
        pkcs11_context.object_list.optiga_util_instance =
            optiga_util_create(0, optiga_callback, &pkcs11_context.object_list.optiga_lib_status);

        if (NULL == pkcs11_context.object_list.optiga_util_instance) {
            PKCS11_PRINT("ERROR: C_Initialize: 'optiga_util_create' failed\r\n");
            xResult = CKR_FUNCTION_FAILED;
            goto init_error1;
        }
        /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
        trustm_TimerStart();
        PKCS11_DEBUG("TRACE: C_Initialize: optiga_util_open_application\r\n");
        optiga_lib_return =
            optiga_util_open_application(pkcs11_context.object_list.optiga_util_instance, 0);

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_util_open_application"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT(
                "ERROR: C_Initialize: optiga_util_open_application failed. Returned: 0x%04X\r\n",
                (int)optiga_lib_return
            );
            xResult = CKR_FUNCTION_FAILED;
            goto init_error0;
        }
        /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
        /* else
        {
            #ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
            if(host_pair_done)
            {
                xResult = pair_host_and_optiga_using_pre_shared_secret();
                if (OPTIGA_LIB_SUCCESS != xResult)
                {
                    PKCS11_PRINT("ERROR: PKCS#11: 'pair_host_and_optiga_using_pre_shared_secret' failed. Status: 0x%04X\r\n", xResult);
                    xResult = CKR_FUNCTION_FAILED;
                    break;
                }
                host_pair_done = 0;
            }
            #endif
        } */
    } while (0);

    PKCS11_DEBUG("TRACE: Exit optiga_trustm_initialize. Result: 0x%04X\r\n", (int)xResult);
    return xResult;

init_error0:
    res = optiga_util_destroy(pkcs11_context.object_list.optiga_util_instance);
    if (OPTIGA_LIB_SUCCESS != res) {
        PKCS11_PRINT(
            "ERROR: optiga_trustm_deinitialize: optiga_util_destroy failed. Error: 0x%X\r\n",
            res
        );
    }
init_error1:
    res = optiga_crypt_destroy(pkcs11_context.object_list.optiga_crypt_instance);
    if (OPTIGA_LIB_SUCCESS != res) {
        PKCS11_PRINT(
            "ERROR: optiga_trustm_deinitialize: optiga_crypt_destroy failed. Error: 0x%X\r\n",
            res
        );
    }
init_error2:
    if (pal_gpio_deinit(&optiga_vdd_0) != PAL_STATUS_SUCCESS) {
        PKCS11_PRINT("ERROR: optiga_trustm_deinitialize: pal_gpio_init(VDD) failed\r\n");
    }
init_error3:
    if (pal_gpio_deinit(&optiga_reset_0) != PAL_STATUS_SUCCESS) {
        PKCS11_PRINT("ERROR: optiga_trustm_deinitialize: pal_gpio_init(RESET) failed\r\n");
    }
    return xResult;
}
/**************************************************************************
          Optiga Trust M hardware de-initialization 
 **************************************************************************/
CK_RV optiga_trustm_deinitialize(void) {
    CK_RV xResult = CKR_OK, res;
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    pal_status_t pal_status;
    PKCS11_DEBUG("TRACE: Enter optiga_trustm_deinitialize\r\n");
    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
    trustm_TimerStart();
    optiga_lib_return =
        optiga_util_close_application(pkcs11_context.object_list.optiga_util_instance, 0);

    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_util_close_application"
    );
    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
        PKCS11_PRINT(
            "ERROR: optiga_trustm_deinitialize: optiga_util_close_application failed. Returned: 0x%04X\r\n",
            (int)optiga_lib_return
        );
        xResult = CKR_FUNCTION_FAILED;
    }
    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
    //Destroy the instances after the completion of usecase
    res = optiga_crypt_destroy(pkcs11_context.object_list.optiga_crypt_instance);
    if (OPTIGA_LIB_SUCCESS != res) {
        PKCS11_PRINT(
            "ERROR: optiga_trustm_deinitialize: optiga_crypt_destroy failed. Error: 0x%X\r\n",
            res
        );
        xResult = CKR_FUNCTION_FAILED;
    }

    res = optiga_util_destroy(pkcs11_context.object_list.optiga_util_instance);
    if (OPTIGA_LIB_SUCCESS != res) {
        PKCS11_PRINT(
            "ERROR: optiga_trustm_deinitialize: optiga_util_destroy failed. Error: 0x%X\r\n",
            res
        );
        xResult = CKR_FUNCTION_FAILED;
    }
    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
    if (pal_gpio_deinit(&optiga_reset_0) != PAL_STATUS_SUCCESS) {
        PKCS11_PRINT("ERROR: optiga_trustm_deinitialize: pal_gpio_init(RESET) failed\r\n");
        xResult = CKR_FUNCTION_FAILED;
    }

    if (pal_gpio_deinit(&optiga_vdd_0) != PAL_STATUS_SUCCESS) {
        PKCS11_PRINT("ERROR: optiga_trustm_deinitialize: pal_gpio_init(VDD) failed\r\n");
        xResult = CKR_FUNCTION_FAILED;
    }
    pal_os_lock_release(&optiga_mutex);
    PKCS11_DEBUG("TRACE: Exit optiga_trustm_deinitialize. Result: 0x%04X\r\n", (int)xResult);
    return xResult;
}
/**************************************************************************
    Certificates on OPTIGA Trust are stored with certificate identifiers/tags, 
    which are 9 bytes long
 **************************************************************************/
static uint8_t append_optiga_certificate_tags(
    uint16_t xCertWithoutTagsLength,
    uint8_t *pxCertTags,
    uint16_t xCertTagsLength
) {
    char t1[3], t2[3], t3[3];
    int xCalc = xCertWithoutTagsLength, xCalc1 = 0, xCalc2 = 0;
    uint8_t ret = 0;
    do {
        if ((pxCertTags == NULL) || (xCertWithoutTagsLength == 0) || (xCertTagsLength != 9)) {
            break;
        }
        if (xCalc > 0xFF) {
            xCalc1 = xCalc >> 8;
            xCalc = xCalc % 0x100;
            if (xCalc1 > 0xFF) {
                xCalc2 = xCalc1 >> 8;
                xCalc1 = xCalc1 % 0x100;
            }
        }
        t3[0] = xCalc2;
        t3[1] = xCalc1;
        t3[2] = xCalc;
        xCalc = xCertWithoutTagsLength + 3;
        if (xCalc > 0xFF) {
            xCalc1 = xCalc >> 8;
            xCalc = xCalc % 0x100;
            if (xCalc1 > 0xFF) {
                xCalc2 = xCalc1 >> 8;
                xCalc1 = xCalc1 % 0x100;
            }
        }
        t2[0] = xCalc2;
        t2[1] = xCalc1;
        t2[2] = xCalc;
        xCalc = xCertWithoutTagsLength + 6;
        if (xCalc > 0xFF) {
            xCalc1 = xCalc >> 8;
            xCalc = xCalc % 0x100;
            if (xCalc1 > 0xFF) {
                xCalc2 = xCalc1 >> 8;
                xCalc1 = xCalc1 % 0x100;
            }
        }
        t1[0] = 0xC0;
        t1[1] = xCalc1;
        t1[2] = xCalc;

        for (int i = 0; i < 3; i++) {
            pxCertTags[i] = t1[i];
        }
        for (int i = 0; i < 3; i++) {
            pxCertTags[i + 3] = t2[i];
        }
        for (int i = 0; i < 3; i++) {
            pxCertTags[i + 6] = t3[i];
        }
        ret = 1;
    } while (0);
    return ret;
}
/**************************************************************************
 * Write a certificate to a given cert object (e.g. E0E8)
 * using optiga_util_write_data.
 *
 * We do create here another instance, as the certificate slot is shared bz all isntances
 *
 * Use Erase and Write (OPTIGA_UTIL_ERASE_AND_WRITE) option,
 * to clear the remaining data in the object
 **************************************************************************/
static optiga_lib_status_t
upload_certificate(long lOptigaOid, uint8_t *pucData, uint32_t ulDataSize) {
    const uint8_t xTagsLength = 9;
    uint8_t pxCertTags[xTagsLength];
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;

    if ((0 != lOptigaOid) && (USHRT_MAX > lOptigaOid) && (USHRT_MAX > ulDataSize)) {
        // Certificates on OPTIGA Trust are stored with certificate identifiers -> tags, which are 9 bytes long
        if (append_optiga_certificate_tags(ulDataSize, pxCertTags, xTagsLength)) {
            PKCS11_DEBUG("TRACE: upload_certificate: Object: 0x%04X\r\n", (int)lOptigaOid);
            HEXDUMP("Tags: ", pxCertTags, xTagsLength);
            HEXDUMP("Data: ", pucData, ulDataSize);

            trustm_TimerStart();
            trustm_util_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION
            );  // Enable Shielded Connection

            optiga_lib_return = optiga_util_write_data(
                pkcs11_context.object_list.optiga_util_instance,
                (uint16_t)lOptigaOid,
                OPTIGA_UTIL_ERASE_AND_WRITE,
                0,
                pxCertTags,
                9
            );

            trustm_CheckStatus_WaitForCompletion(
                &optiga_lib_return,
                BUSY_WAIT_TIME_OUT,
                "optiga_util_write_data(certificate tags)"
            );
            if (OPTIGA_LIB_SUCCESS == optiga_lib_return) {
                trustm_TimerStart();
                trustm_util_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION
                );  // Enable Shielded Connection

                optiga_lib_return = optiga_util_write_data(
                    pkcs11_context.object_list.optiga_util_instance,
                    (uint16_t)lOptigaOid,
                    OPTIGA_UTIL_WRITE_ONLY,
                    xTagsLength,
                    pucData,
                    ulDataSize
                );

                trustm_CheckStatus_WaitForCompletion(
                    &optiga_lib_return,
                    BUSY_WAIT_TIME_OUT,
                    "optiga_util_write_data(certificate data)"
                );
            }
        }
    }
    return optiga_lib_return;
}
/**************************************************************************
 Public keys on OPTIGA Trust are stored in DER format. Add header including:
    OID 1.2.840.10045.2.1 = EC Public Key 
    EC algorithm OID: prime256v1 (1.2.840.10045.3.1.7)
 **************************************************************************/
#define CONCATENATE_DER(header, ec_param) \
    len = sizeof(header); \
    memcpy(pxBuffer, header, len); \
    memcpy(pxBuffer + len, ec_param, sizeof(ec_param)); \
    len += sizeof(ec_param); \
    memcpy(pxBuffer + len, pxTags, uTagsLength); \
    len += uTagsLength;

static uint16_t append_public_key_der_tags(
    uint16_t key_alg,
    uint8_t *pxTags,
    uint16_t uTagsLength,
    uint8_t *pxBuffer
) {
    uint16_t len;

    switch (key_alg) {
        case OPTIGA_ECC_CURVE_NIST_P_256:
            CONCATENATE_DER(header_p256, ec_param_p256)
            pxBuffer[1] = (uint8_t)len - 2;  // Set tags length
            break;
        case OPTIGA_ECC_CURVE_NIST_P_384:
            CONCATENATE_DER(header_p384, ec_param_p384)
            pxBuffer[1] = (uint8_t)len - 2;  // Set tags length
            break;
        case OPTIGA_ECC_CURVE_NIST_P_521:
            CONCATENATE_DER(header_p521, ec_param_p521)
            pxBuffer[1] = 0x81;
            pxBuffer[2] = (uint8_t)len - 3;  // Set tags length '81 XX'
            break;
        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
            CONCATENATE_DER(header_BP256, ec_param_BP256)
            pxBuffer[1] = (uint8_t)len - 2;  // Set tags length
            break;
        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
            CONCATENATE_DER(header_BP384, ec_param_BP384)
            pxBuffer[1] = (uint8_t)len - 2;  // Set tags length
            break;
        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
            CONCATENATE_DER(header_BP512, ec_param_BP512)
            pxBuffer[1] = 0x81;
            pxBuffer[2] = (uint8_t)len - 3;  // Set tags length '81 XX'
            break;
    }
    return len;
}
/**************************************************************************
 * Write a public key to an arbitrary data object
 * Note: You might need to lock the data object here. see optiga_util_write_metadata()
 *
 * Use Erase and Write (OPTIGA_UTIL_ERASE_AND_WRITE) option,
 * to clear the remaining data in the object
 **************************************************************************/
static optiga_lib_status_t
upload_public_key(long lOptigaOid, uint16_t key_alg, uint8_t *pucData, uint32_t ulDataSize) {
    uint8_t *pucPubKeyDer;
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;

    if ((0 != lOptigaOid) && (USHRT_MAX >= lOptigaOid) && (USHRT_MAX >= ulDataSize)) {
#ifdef DEBUG
        PKCS11_DEBUG("Writing public key object 0x%04X\r\n", (int)lOptigaOid);
        HEXDUMP("Pub.key: ", pucData, ulDataSize);
#endif
        pucPubKeyDer = malloc(ulDataSize + sizeof(ec_param_p521) + 30);
        if (pucPubKeyDer == NULL) {
            PKCS11_PRINT("ERROR: %s: memory allocation error\r\n", __func__);
            return OPTIGA_UTIL_ERROR;
        }

        ulDataSize = append_public_key_der_tags(key_alg, pucData, ulDataSize, pucPubKeyDer);
        HEXDUMP("ASN1 DER: ", pucPubKeyDer, ulDataSize);

        trustm_TimerStart();
        trustm_util_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);  // Enable Shielded Connection

        optiga_lib_return = optiga_util_write_data(
            pkcs11_context.object_list.optiga_util_instance,
            (uint16_t)lOptigaOid,
            OPTIGA_UTIL_ERASE_AND_WRITE,
            0,
            pucPubKeyDer,
            ulDataSize
        );
        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_util_write_data(public key)"
        );
        free(pucPubKeyDer);
    }
    return optiga_lib_return;
}
/**************************************************************************
    !!!JC  ATTENTION:  NOT TESTED YET. 
 **************************************************************************/
CK_RV destroy_object(CK_OBJECT_HANDLE xAppHandle) {
    char *pcTempLabel = NULL;
    size_t xLabelLength = 0;
    uint32_t ulObjectLength = 0;
    CK_RV xResult = CKR_OK;
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    CK_BBOOL xFreeMemory = CK_FALSE;
    CK_BYTE_PTR pxObject = NULL;
    CK_OBJECT_HANDLE xPalHandle;
    CK_OBJECT_HANDLE xAppHandle2;
    CK_LONG lOptigaOid = 0;

    xPalHandle = find_object_by_handle(xAppHandle, &lOptigaOid);
    if (xPalHandle == CK_INVALID_HANDLE)
        return xPalHandle;

    switch (xPalHandle) {
        case ObjectHandle_Slot1_PrivateKey:
        case ObjectHandle_Slot2_PrivateKey:
        case ObjectHandle_Slot3_PrivateKey:  // Old: 0xE0F1 LABEL_DEVICE_PRIVATE_KEY_FOR_TLS (ECC)
        {
            CK_BYTE pucDumbData[68];
            uint16_t ucDumbDataLength = 68;

            trustm_TimerStart();
            trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

            optiga_lib_return = optiga_crypt_ecc_generate_keypair(
                pkcs11_context.object_list.optiga_crypt_instance,
                OPTIGA_ECC_CURVE_NIST_P_256,
                (uint8_t)OPTIGA_KEY_USAGE_SIGN,
                FALSE,
                &lOptigaOid,
                pucDumbData,
                &ucDumbDataLength
            );

            trustm_CheckStatus_WaitForCompletion(
                &optiga_lib_return,
                BUSY_WAIT_TIME_OUT,
                "optiga_crypt_ecc_generate_keypair"
            );
            if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
                PKCS11_PRINT("ERROR: destroy_object: Failed to invalidate a keypair\r\n");
                xResult = CKR_FUNCTION_FAILED;
            }
        } break;

        case ObjectHandle_Slot1_Certificate:  // 0xE0E1
        case ObjectHandle_Slot1_PublicKey:  // 0xF1D1
        case ObjectHandle_Slot2_Certificate:  // 0xE0E2 Old: LABEL_DEVICE_CERTIFICATE_FOR_TLS (DevicePublicKey RSA)
        case ObjectHandle_Slot2_PublicKey:  // 0xF1D2 Old: LABEL_DEVICE_PUBLIC_KEY_FOR_TLS (DevicePublicKey ECC)
        case ObjectHandle_Slot3_Certificate:  // 0xE0E3
        case ObjectHandle_Slot3_PublicKey:  // 0xF1D3
        case ObjectHandle_Slot4_Certificate:  // 0xE0E2
        case ObjectHandle_Slot4_PublicKey:  // 0xF1E0
        case ObjectHandle_Slot5_Certificate:  // 0xE0E3
        case ObjectHandle_Slot5_PublicKey:  // 0xF1E1
        case ObjectHandle_CodeSigning_Certificate:  // 0xE0EF Old: LABEL_CODE_VERIFICATION_KEY
        {
            // Erase the object
            CK_BYTE pucData[] = {0};

            trustm_TimerStart();
            trustm_util_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION
            );  // Enable Shielded Connection

            optiga_lib_return = optiga_util_write_data(
                pkcs11_context.object_list.optiga_util_instance,
                (uint16_t)lOptigaOid,
                OPTIGA_UTIL_ERASE_AND_WRITE,
                0,  // Offset
                pucData,
                1
            );
            trustm_CheckStatus_WaitForCompletion(
                &optiga_lib_return,
                BUSY_WAIT_TIME_OUT,
                "optiga_util_write_data"
            );
            if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
                PKCS11_PRINT("ERROR: destroy_object: Failed to erase object\r\n");
                xResult = CKR_FUNCTION_FAILED;
            } else {
                PKCS11_DEBUG("destroy_object: OID: 0x%X\r\n", lOptigaOid);
                //!!!JC                    find_object_in_list_by_label( ( uint8_t * ) pcTempLabel, strlen( ( char * ) pcTempLabel ), &xPalHandle, &xAppHandle2 );
                //
                //                    if( xPalHandle != CK_INVALID_HANDLE )
                //                    {
                //                        xResult = delete_object_from_list( xAppHandle2 );
                //                    }
            }
        } break;
        default:
            break;
    }
    return xResult;
}
/**************************************************************************/
size_t get_signature_size(int key_type) {
    switch (key_type) {
        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
        case OPTIGA_ECC_CURVE_NIST_P_256:
            return pkcs11ECDSA_P256_SIGNATURE_LENGTH;

        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
        case OPTIGA_ECC_CURVE_NIST_P_384:
            return pkcs11ECDSA_P384_SIGNATURE_LENGTH;

        case OPTIGA_ECC_CURVE_NIST_P_521:
            return pkcs11ECDSA_P521_SIGNATURE_LENGTH;
        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
            return pkcs11ECDSA_BP512_SIGNATURE_LENGTH;
    }
    return 0;
}
/**************************************************************************/
size_t get_key_size(int key_type) {
    switch (key_type) {
        case OPTIGA_ECC_CURVE_NIST_P_256:
        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
            return pkcs11EC_P256_PUBLIC_KEY_LENGTH;  // 0x44 = 68 = 64 + 4
        case OPTIGA_ECC_CURVE_NIST_P_384:
        case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
            return pkcs11EC_P384_PUBLIC_KEY_LENGTH;  // 0x64 = 100 = 96 + 4
        case OPTIGA_ECC_CURVE_NIST_P_521:
            return pkcs11EC_P521_PUBLIC_KEY_LENGTH;  // 0x89 = 137 = 128 + 5
            //    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1: return ???
    }
    return 0;
}
/**************************************************************************/
CK_ULONG check_valid_rsa_signature_scheme(CK_MECHANISM_TYPE mechanism_type, CK_ULONG key_size) {
    switch (mechanism_type) {
        case CKM_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            if (key_size == 0)
                return 1;  // In case key_size is not required
            return (key_size == pkcs11RSA_2048_MODULUS_BITS) ? pkcs11RSA_2048_SIGNATURE_LENGTH
                                                             : pkcs11RSA_1024_SIGNATURE_LENGTH;
    }
    return 0;
}
/**************************************************************************/
CK_ULONG check_signature_scheme_get_signature_size(
    p_pkcs11_session_t pxSession,
    CK_MECHANISM_TYPE mechanism_type,
    CK_OBJECT_HANDLE priv_key_handle,  // Private key object handle (1,2,...)
    CK_OBJECT_HANDLE pub_key_handle
)  // Public key object handle (1,2,...)
{
    CK_ULONG lSignatureSize = 0;
    uint8_t metadata[64];
    uint8_t *pAlg;
    optiga_lib_status_t optiga_lib_return;

    if (pub_key_handle != 0 && priv_key_handle == 0)
        priv_key_handle =
            pub_key_handle
            - 1;  // Assumption that private key in slots table is followed by public key
    if (mechanism_type == CKM_ECDSA) {
        if (pxSession->key_alg_id == 0) {
            if (priv_key_handle != 0 && priv_key_handle < MAX_NUM_OBJECTS) {
                if (optiga_objects_list[priv_key_handle].obj_size_key_alg
                    != 0)  // Check if metadata has been read before (cached)
                {
                    pxSession->key_alg_id =
                        optiga_objects_list[priv_key_handle]
                            .obj_size_key_alg;  // Use key_size to store alg id byte
                } else {
                    optiga_lib_return = optiga_trustm_read_metadata(
                        optiga_objects_list[priv_key_handle].physical_oid,
                        metadata,
                        sizeof(metadata),
                        OPTIGA_COMMS_FULL_PROTECTION
                    );
                    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
                        PKCS11_PRINT(
                            "ERROR: check_signature_scheme_get_signature_size (OID: 0x%04X) failed.\r\n",
                            optiga_objects_list[priv_key_handle].physical_oid
                        );
                        return 0;
                    }
                    /*
                    Private key metadata:                                         Alg 
                    0xE0F1: (NIST256) 20 11 C0 01 01 D0 03 E1 FC 07 D3 01 00 E0 01 03 E1 01 10
                    0xE0F2: (NIST384) 20 11 C0 01 01 D0 03 E1 FC 07 D3 01 00 E0 01 04 E1 01 10
                    0xE0F3: (NIST521) 20 11 C0 01 01 D0 03 E1 FC 07 D3 01 00 E0 01 05 E1 01 10 
                    */
                    pAlg = Find_TLV_Tag(
                        metadata,
                        0xE0,
                        NULL
                    );  // Get Tag E0 value (one byte) = key algorithm
                    pxSession->key_alg_id = pAlg[2];
                    optiga_objects_list[priv_key_handle].obj_size_key_alg =
                        pxSession->key_alg_id;  // Use key_size to store alg id byte
                }
            } else {
                PKCS11_PRINT("ERROR: Unknown EC key handle: 0x%X\r\n", priv_key_handle);
                return 0;
            }
        }
        if ((lSignatureSize = get_signature_size((int)pxSession->key_alg_id)) == 0) {
            PKCS11_PRINT("ERROR: Unsupported EC key type 0x%X \r\n", pxSession->key_alg_id);
            return 0;
        }
    }
#ifdef PKCS11_SUPPORT_RSA
    else {
        lSignatureSize = check_valid_rsa_signature_scheme(mechanism_type, rsa_key_size);
        switch (mechanism_type) {
            case CKM_RSA_PKCS:
            case CKM_SHA256_RSA_PKCS:
            case CKM_SHA384_RSA_PKCS:
            case CKM_SHA512_RSA_PKCS:
                if (key_size == 0)
                    lSignatureSize = 1;  // In case key_size is not required
                if (key_size == pkcs11RSA_2048_MODULUS_BITS)
                    lSignatureSize = pkcs11RSA_2048_SIGNATURE_LENGTH;
                else
                    lSignatureSize = pkcs11RSA_1024_SIGNATURE_LENGTH;
        }
        if (lSignatureSize == 0) {
            PKCS11_PRINT("ERROR: Unsupported signature mechanism 0x%X \r\n", mechanism_type);
            return 0;
        }
    }
#endif
    return lSignatureSize;
}
/**************************************************************************/
CK_BBOOL check_bool_attribute(CK_ATTRIBUTE *pxAttribute, char *strTemplate, char *strAttr) {
    CK_BBOOL xBool;
    memcpy(&xBool, pxAttribute->pValue, sizeof(CK_BBOOL));
    PKCS11_DEBUG("TRACE: %s: %s: %d\r\n", strTemplate, strAttr, xBool);
    return xBool;
}
/**************************************************************************/
CK_RV check_and_copy_attribute(
    CK_OBJECT_HANDLE xObject,
    char *attr_name,
    CK_ATTRIBUTE_PTR pxTemplate,
    CK_ULONG iAttrib,
    void *pxObjectValue,
    uint32_t ulLength
) {
    if (pxTemplate[iAttrib].pValue == NULL) {
        pxTemplate[iAttrib].ulValueLen = ulLength;
    } else if (pxTemplate[iAttrib].ulValueLen < ulLength) {
        PKCS11_PRINT(
            "ERROR: Attribute: Reserved buffer too small: %d, should be at least %d\r\n",
            pxTemplate[iAttrib].ulValueLen,
            ulLength
        );
        return CKR_BUFFER_TOO_SMALL;
    } else {
#ifdef DEBUG
        sprintf(debug_message, "Object: %d Attribute: %s: ", (int)xObject, attr_name);
        HEXDUMP(debug_message, pxObjectValue, ulLength);
#endif
        memcpy(pxTemplate[iAttrib].pValue, pxObjectValue, ulLength);
        pxTemplate[iAttrib].ulValueLen = ulLength;
    }
    return CKR_OK;
}
/**************************************************************************/
CK_RV check_and_copy_bool_attribute(
    CK_OBJECT_HANDLE xObject,
    char *attr_name,
    CK_ATTRIBUTE_PTR pxTemplate,
    CK_ULONG iAttrib,
    CK_BBOOL xAttribute
) {
    return check_and_copy_attribute(
        xObject,
        attr_name,
        pxTemplate,
        iAttrib,
        (void *)&xAttribute,
        sizeof(CK_BBOOL)
    );
}
/**************************************************************************/
CK_RV check_and_copy_bit_attribute(
    CK_OBJECT_HANDLE xObject,
    char *attr_name,
    CK_ATTRIBUTE_PTR pxTemplate,
    CK_ULONG iAttrib,
    CK_ULONG ul_key_template,
    CK_ULONG ul_bitmask
) {
    CK_BBOOL xAttribute;
    if ((ul_key_template & ul_bitmask) != 0)
        xAttribute = CK_TRUE;
    else
        xAttribute = CK_FALSE;

    return check_and_copy_bool_attribute(xObject, attr_name, pxTemplate, iAttrib, xAttribute);
}
/**************************************************************************
 * @brief Verifies certificate template
 *
 * @param[in] pxTemplate    The pointer to the template
 * @param[in] ulCount       Items in template
 * @param[out] ppxLabel
 *
 * @return  CKR_OK - the template if good. Error code if unsuccessful
 **************************************************************************/
CK_RV verify_certificate_template(
    CK_ATTRIBUTE_PTR pxTemplate,
    CK_ULONG ulCount,
    CK_ATTRIBUTE_PTR *ppxLabel,
    CK_BYTE_PTR *ppxCertificateValue,
    CK_ULONG *pxCertificateLength
) {
    CK_RV xResult = CKR_OK;
    CK_CERTIFICATE_TYPE xCertificateType = 0; /* = CKC_X_509; */
    uint32_t ulIndex = 0;
    CK_ATTRIBUTE xAttribute;

    /* Search for the pointer to the certificate VALUE. */
    for (ulIndex = 0; ulIndex < ulCount; ulIndex++) {
        xAttribute = pxTemplate[ulIndex];

        switch (xAttribute.type) {
            case (CKA_VALUE):
                HEXDUMP(
                    "TRACE: C_CreateObject: CKA_VALUE: ",
                    xAttribute.pValue,
                    xAttribute.ulValueLen
                );
                *ppxCertificateValue = xAttribute.pValue;
                *pxCertificateLength = xAttribute.ulValueLen;
                break;

            case (CKA_LABEL):
                if (xAttribute.ulValueLen < MAX_LABEL_LENGTH && xAttribute.ulValueLen != 0) {
                    *ppxLabel = &pxTemplate[ulIndex];
                    PKCS11_DEBUG("TRACE: C_CreateObject: CKA_LABEL: %s\r\n", *ppxLabel);
                } else {
                    PKCS11_PRINT(
                        "WARNING: C_CreateObject: Wrong CKA_LABEL size: %d\r\n",
                        xAttribute.ulValueLen
                    );
                    xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                }
                break;

            case (CKA_CERTIFICATE_TYPE):
                memcpy(&xCertificateType, xAttribute.pValue, sizeof(CK_CERTIFICATE_TYPE));
                PKCS11_DEBUG(
                    "TRACE: C_CreateObject: CKA_CERTIFICATE_TYPE: 0x%X\r\n",
                    xCertificateType
                );
                //                if( xCertificateType != CKC_X_509 )
                //                {
                //                    xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                //                }
                break;

            default: /* Ignore unknown or previously processed attributes */
                break;
        }
    }
    if (*ppxCertificateValue == NULL || *pxCertificateLength == 0) {
        PKCS11_PRINT("ERROR: C_CreateObject: Template incomplete. CKA_VALUE missing\r\n");
        xResult = CKR_TEMPLATE_INCOMPLETE;
    }
    return xResult;
}

#define PKCS11_INVALID_KEY_TYPE ((CK_KEY_TYPE)0xFFFFFFFF)
/**************************************************************************

 **************************************************************************/
CK_KEY_TYPE get_key_type(CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount) {
    CK_KEY_TYPE xKeyType = PKCS11_INVALID_KEY_TYPE;
    uint32_t ulIndex;
    CK_ATTRIBUTE xAttribute;

    for (ulIndex = 0; ulIndex < ulCount; ulIndex++) {
        xAttribute = pxTemplate[ulIndex];

        if (xAttribute.type == CKA_KEY_TYPE) {
            memcpy(&xKeyType, xAttribute.pValue, sizeof(CK_KEY_TYPE));
            break;
        }
    }
    return xKeyType;
}
/**************************************************************************

 **************************************************************************/
void get_label(CK_ATTRIBUTE_PTR *ppxLabel, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount) {
    CK_ATTRIBUTE xAttribute;
    uint32_t ulIndex;

    *ppxLabel = NULL;

    for (ulIndex = 0; ulIndex < ulCount; ulIndex++) {
        xAttribute = pxTemplate[ulIndex];

        if (xAttribute.type == CKA_LABEL) {
            *ppxLabel = &pxTemplate[ulIndex];
            break;
        }
    }
}
/**************************************************************************

 **************************************************************************/
CK_RV verify_private_key_template(
    CK_SESSION_HANDLE xSession,
    CK_MECHANISM_TYPE xMechanism,
    CK_ATTRIBUTE_PTR *ppxLabel,
    CK_ATTRIBUTE_PTR pxTemplate,
    CK_ULONG ulTemplateLength
) {
#define LABEL (1U)
#define PRIVATE (1U << 1)
#define SIGN (1U << 2)
#define DECRYPT (1U << 3)

    CK_ATTRIBUTE xAttribute;
    CK_KEY_TYPE xKeyType;
    CK_ULONG ulIndex;
    uint32_t received_attribute = 0;
    uint32_t ec_expected_attribute[] = {(LABEL | PRIVATE | SIGN), (PRIVATE | SIGN)};
    uint32_t rsa_expected_attribute[] = {
        (LABEL | PRIVATE | SIGN | DECRYPT),
        (LABEL | PRIVATE | DECRYPT),
        (LABEL | PRIVATE | SIGN)};
    uint32_t *pExpected_attribute;
    int expected_attributes_size;

    p_pkcs11_session_t session = get_session_pointer(xSession);

    if (xMechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
        xKeyType = CKK_RSA;
    else if (xMechanism == CKM_EC_KEY_PAIR_GEN || xMechanism == CKM_ECDSA_KEY_PAIR_GEN)
        xKeyType = CKK_EC;

    /* If LABEL not received or received NULL, use hardcoded label associated with the slot */
    *ppxLabel = NULL;

    for (ulIndex = 0; ulIndex < ulTemplateLength; ulIndex++) {
        xAttribute = pxTemplate[ulIndex];

        switch (xAttribute.type) {
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_LABEL): {
                if (xAttribute.ulValueLen != 0) /* If calling client provides label - use it */
                {
                    *ppxLabel = &pxTemplate[ulIndex];
                    PKCS11_DEBUG("TRACE: PrivateKeyTemplate: CKA_LABEL: %s\r\n", *ppxLabel);
                } else {
                    PKCS11_PRINT("WARNING: PrivateKeyTemplate: CKA_LABEL is empty\r\n");
                }
                received_attribute |= LABEL;
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_TOKEN): {
                if (check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_TOKEN")
                    != CK_TRUE) {
                    PKCS11_PRINT(
                        "WARNING: PrivateKeyTemplate: Only token key generation is supported. \r\n"
                    );
                    //!!!JC             return CKR_ATTRIBUTE_VALUE_INVALID;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_KEY_TYPE): {
                memcpy(&xKeyType, xAttribute.pValue, sizeof(CK_ULONG));
                if ((xKeyType != CKK_EC) && (xKeyType != CKK_RSA)) {
                    PKCS11_PRINT(
                        "ERROR: PrivateKeyTemplate: Only EC and RSA key pair generation is supported. \r\n"
                    );
                    return CKR_TEMPLATE_INCONSISTENT;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_PRIVATE): {
                if (check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_PRIVATE")
                    != CK_TRUE) {
                    PKCS11_PRINT(
                        "ERROR: PrivateKeyTemplate: Generating private keys that are not marked private is not supported. \r\n"
                    );
                    return CKR_TEMPLATE_INCONSISTENT;
                }
                received_attribute |= PRIVATE;
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_SIGN): {
                if (check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_SIGN")
                    != CK_TRUE) {
                    PKCS11_PRINT(
                        "WARNING: PrivateKeyTemplate: Generating private key that is not marked CKA_SIGN\r\n"
                    );
                }
                session->key_template_enabled |= PKCS_SIGN_ENABLE;
                received_attribute |= SIGN;
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_DECRYPT): {
                if (check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_DECRYPT")
                    != CK_TRUE) {
                    PKCS11_PRINT(
                        "WARNING: PrivateKeyTemplate: Generating private key that is not marked CKA_DECRYPT\r\n"
                    );
                }
                session->key_template_enabled |= PKCS_DECRYPT_ENABLE;
                received_attribute |= DECRYPT;
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case CKA_CLASS: {
                check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_CLASS");
            } break;
            case CKA_ID: {
                check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_ID");
            } break;
            case CKA_UNWRAP: {
                check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_UNWRAP");
            } break;
            case CKA_DERIVE: {
                check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_DERIVE");
            } break;
            case CKA_SENSITIVE: {
                check_bool_attribute(&xAttribute, "PrivateKeyTemplate", "CKA_SENSITIVE");
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            default: {
                PKCS11_PRINT(
                    "ERROR: PrivateKeyTemplate: CKA attribute not supported: 0x%X\r\n",
                    xAttribute.type
                );
                return CKR_TEMPLATE_INCONSISTENT;
            } break;
        }
    }

    if (xKeyType == CKK_EC) {
        pExpected_attribute = ec_expected_attribute;
        expected_attributes_size = sizeof(ec_expected_attribute) / sizeof(uint32_t);
        PKCS11_DEBUG("TRACE: PrivateKeyTemplate: KeyType: CKK_EC\r\n");
    } else if (xKeyType == CKK_RSA) {
        pExpected_attribute = rsa_expected_attribute;
        expected_attributes_size = sizeof(rsa_expected_attribute) / sizeof(uint32_t);
        PKCS11_DEBUG("TRACE: PrivateKeyTemplate: KeyType: RSA\r\n");
    } else {
        PKCS11_PRINT("ERROR: PrivateKeyTemplate: CKA_KEY_TYPE not ECC or RSA. \r\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    for (ulIndex = 0; ulIndex < expected_attributes_size; ulIndex++) {
        if ((received_attribute & pExpected_attribute[ulIndex]) == pExpected_attribute[ulIndex]) {
            return CKR_OK;
        }
    }
    PKCS11_PRINT(("ERROR: PrivateKeyTemplate: Template inconsistent\r\n"));
    return CKR_TEMPLATE_INCONSISTENT;
}
/**************************************************************************

 **************************************************************************/
CK_RV verify_public_key_template(
    CK_SESSION_HANDLE xSession,
    CK_ATTRIBUTE_PTR *ppxLabel,
    CK_ATTRIBUTE_PTR pxTemplate,
    CK_ULONG ulTemplateLength,
    uint8_t *pxPublicKey,
    uint32_t *pulKeySize
) {
#define LABEL (1U)
#define EC_PARAMS (1U << 1)
#define VERIFY (1U << 2)
#define ENCRYPT (1U << 3)
#define MODULUS (1U << 4)
#define EXPONENT (1U << 5)

    CK_ATTRIBUTE xAttribute;
    CK_RV xResult = CKR_OK;
    CK_ULONG modulus_bits;
    CK_BYTE exp_bits[] = {0x01, 0x00, 0x01};
    CK_KEY_TYPE xKeyType;
    int lCompare;
    CK_ULONG ulIndex;
    uint32_t received_attribute = 0;
    uint32_t ec_expected_attribute[] = {(LABEL | EC_PARAMS /* |VERIFY */), (EC_PARAMS)};
    uint32_t rsa_expected_attribute[] = {
        (LABEL | ENCRYPT | VERIFY | MODULUS | EXPONENT),
        (LABEL | ENCRYPT | MODULUS | EXPONENT),
        (LABEL | VERIFY | MODULUS | EXPONENT),
    };
    uint32_t *pExpected_attribute;
    int expected_attributes_size;

    p_pkcs11_session_t session = get_session_pointer(xSession);

    xKeyType = get_key_type(pxTemplate, ulTemplateLength);
    //    if (xMechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
    //        xKeyType = CKK_RSA;
    //    else if (xMechanism == CKM_EC_KEY_PAIR_GEN || xMechanism == CKM_ECDSA_KEY_PAIR_GEN)
    //        xKeyType = CKK_EC;

    for (ulIndex = 0; ulIndex < ulTemplateLength; ulIndex++) {
        xAttribute = pxTemplate[ulIndex];

        switch (xAttribute.type) {
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_LABEL): {
                if (xAttribute.ulValueLen != 0) /* If calling client provides label - use it */
                {
                    *ppxLabel = &pxTemplate[ulIndex];
                    PKCS11_DEBUG("TRACE: PublicKeyTemplate: CKA_LABEL: %s\r\n", *ppxLabel);
                } else /* If not - use hardcoded label associated with the slot */
                {
                    PKCS11_PRINT("WARNING: PublicKeyTemplate: CKA_LABEL is empty\r\n");
                    *ppxLabel = NULL;
                }
                received_attribute |= LABEL;
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_KEY_TYPE): {
                memcpy(&xKeyType, xAttribute.pValue, sizeof(CK_KEY_TYPE));

                if ((xKeyType != CKK_EC) && (xKeyType != CKK_RSA)) {
                    PKCS11_PRINT((
                        "ERROR: PublicKeyTemplate: Only EC and RSA key pair generation is supported. \r\n"
                    ));
                    return CKR_TEMPLATE_INCONSISTENT;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_EC_PARAMS): {
                xKeyType = CKK_EC;
                if (0 == memcmp(ec_param_p256, xAttribute.pValue, sizeof(ec_param_p256))) {
                    session->key_alg_id =
                        OPTIGA_ECC_CURVE_NIST_P_256;  // session->ec_key_size = 0x44;
                    PKCS11_PRINT("TRACE: PublicKeyTemplate: CKA_EC_PARAMS: ECC NIST P-256\r\n");
                    received_attribute |= EC_PARAMS;
                } else if (0 == memcmp(ec_param_p384, xAttribute.pValue, sizeof(ec_param_p384))) {
                    session->key_alg_id =
                        OPTIGA_ECC_CURVE_NIST_P_384;  // session->ec_key_size = 0x64;
                    PKCS11_PRINT("TRACE: PublicKeyTemplate: CKA_EC_PARAMS: ECC NIST P-384\r\n");
                    received_attribute |= EC_PARAMS;
                } else if (0 == memcmp(ec_param_p521, xAttribute.pValue, sizeof(ec_param_p521))) {
                    session->key_alg_id =
                        OPTIGA_ECC_CURVE_NIST_P_521;  // session->ec_key_size = 0x89;
                    PKCS11_PRINT("TRACE: PublicKeyTemplate: CKA_EC_PARAMS: ECC NIST P-512\r\n");
                    received_attribute |= EC_PARAMS;
                } else if (0 == memcmp(ec_param_BP256, xAttribute.pValue, sizeof(ec_param_BP256))) {
                    session->key_alg_id = OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1;
                    PKCS11_PRINT("TRACE: PublicKeyTemplate: CKA_EC_PARAMS: ECC BP P-256\r\n");
                    received_attribute |= EC_PARAMS;
                } else if (0 == memcmp(ec_param_BP384, xAttribute.pValue, sizeof(ec_param_BP384))) {
                    session->key_alg_id = OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1;
                    PKCS11_PRINT("TRACE: PublicKeyTemplate: CKA_EC_PARAMS: ECC BP P-384\r\n");
                    received_attribute |= EC_PARAMS;
                } else if (0 == memcmp(ec_param_BP512, xAttribute.pValue, sizeof(ec_param_BP512))) {
                    session->key_alg_id = OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1;
                    PKCS11_PRINT("TRACE: PublicKeyTemplate: CKA_EC_PARAMS: ECC BP P-512\r\n");
                    received_attribute |= EC_PARAMS;
                } else {
                    HEXDUMP(
                        "ERROR: PublicKeyTemplate: Unsupported EC curve: ",
                        xAttribute.pValue,
                        xAttribute.ulValueLen
                    );
                    return CKR_TEMPLATE_INCONSISTENT;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_EC_POINT): {
                if (pxPublicKey == NULL || pulKeySize == 0)  // Ignore if not requested
                    break;
                if (*pulKeySize > (xAttribute.ulValueLen - 2)) {
                    /* The first 2 bytes are for ASN1 type/length encoding. */
                    memcpy(
                        pxPublicKey,
                        ((uint8_t *)(xAttribute.pValue) + 2),
                        (xAttribute.ulValueLen - 2)
                    );
                    *pulKeySize = xAttribute.ulValueLen - 2;
                } else {
                    xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_VERIFY): {
                if (check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_VERIFY")
                    != CK_TRUE) {
                    PKCS11_PRINT(
                        "ERROR: PublicKeyTemplate: Generating public keys that cannot verify is not supported\r\n"
                    );
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                session->key_template_enabled |= PKCS_VERIFY_ENABLE;
                received_attribute |= VERIFY;
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_TOKEN): {
                if (check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_TOKEN")
                    != CK_TRUE) {
                    PKCS11_PRINT(
                        ("WARNING: PublicKeyTemplate: Only token key generation is supported. \r\n")
                    );
                    //!!!JC             return CKR_TEMPLATE_INCONSISTENT;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_ENCRYPT): {
                if (check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_ENCRYPT")
                    == CK_TRUE) {
                    session->key_template_enabled |= PKCS_ENCRYPT_ENABLE;
                    received_attribute |= ENCRYPT;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_MODULUS_BITS): {
                memcpy(&modulus_bits, xAttribute.pValue, sizeof(CK_ULONG));
                PKCS11_DEBUG(
                    "TRACE: PublicKeyTemplate: CKA_MODULUS_BITS: %d\r\n",
                    (int)modulus_bits
                );
                if (modulus_bits != 0) {
                    session->rsa_key_size = modulus_bits;
                    received_attribute |= MODULUS;
                }
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case (CKA_PUBLIC_EXPONENT): {
                HEXDUMP(
                    "TRACE: PublicKeyTemplate: CKA_PUBLIC_EXPONENT: ",
                    xAttribute.pValue,
                    xAttribute.ulValueLen
                );
                if (0 != memcmp(exp_bits, xAttribute.pValue, sizeof(exp_bits))) {
                    PKCS11_PRINT(
                        "ERROR: PublicKeyTemplate: CKA_PUBLIC_EXPONENT in input template inconsistent\r\n"
                    );
                    return CKR_TEMPLATE_INCONSISTENT;
                }
                received_attribute |= EXPONENT;
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            case CKA_CLASS: {
                check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_CLASS");
            } break;
            case CKA_ID: {
                check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_ID");
            } break;
            case CKA_PRIVATE: {
                check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_PRIVATE");
            } break;
            case CKA_WRAP: {
                check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_WRAP");
            } break;
            case CKA_DERIVE: {
                check_bool_attribute(&xAttribute, "PublicKeyTemplate", "CKA_DERIVE");
            } break;
            /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            default: {
                PKCS11_PRINT(
                    "WARNING: PublicKeyTemplate: CKA attribute not supported: 0x%X\r\n",
                    xAttribute.type
                );
                //              return CKR_TEMPLATE_INCONSISTENT;
            } break;
        }
    }

    if (xKeyType == CKK_EC) {
        pExpected_attribute = ec_expected_attribute;
        expected_attributes_size = sizeof(ec_expected_attribute) / sizeof(uint32_t);
        PKCS11_DEBUG("TRACE: PublicKeyTemplate: KeyType: CKK_EC\r\n");
    } else if (xKeyType == CKK_RSA) {
        pExpected_attribute = rsa_expected_attribute;
        expected_attributes_size = sizeof(rsa_expected_attribute) / sizeof(uint32_t);
        PKCS11_DEBUG("TRACE: PublicKeyTemplate: KeyType: RSA\r\n");
    } else {
        PKCS11_PRINT("ERROR: PublicKeyTemplate: CKA_KEY_TYPE not ECC or RSA. \r\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    for (ulIndex = 0; ulIndex < expected_attributes_size; ulIndex++) {
        if ((received_attribute & pExpected_attribute[ulIndex]) == pExpected_attribute[ulIndex]) {
            return CKR_OK;
        }
    }
    PKCS11_PRINT(("ERROR: PublicKeyTemplate: Template inconsistent\r\n"));
    return CKR_TEMPLATE_INCONSISTENT;
}
/**************************************************************************
    Get object CLASS from template     
 **************************************************************************/
CK_RV get_object_class(CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount, CK_OBJECT_CLASS *pxClass) {
    CK_RV xResult = CKR_TEMPLATE_INCOMPLETE;
    uint32_t ulIndex = 0;

    /* Search template for class attribute. */
    for (ulIndex = 0; ulIndex < ulCount; ulIndex++) {
        CK_ATTRIBUTE xAttribute = pxTemplate[ulIndex];

        if (xAttribute.type == CKA_CLASS) {
            memcpy(pxClass, xAttribute.pValue, sizeof(CK_OBJECT_CLASS));
            xResult = CKR_OK;
            break;
        }
    }
    return xResult;
}
/**************************************************************************
 * @brief Provides import and storage of a single client certificate.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(CK_SESSION_HANDLE xSession,
 CK_ATTRIBUTE_PTR pxTemplate,
 CK_ULONG ulCount,
 CK_OBJECT_HANDLE_PTR pxObject) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    CK_OBJECT_CLASS xClass;
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    CK_ATTRIBUTE_PTR pxLabel = NULL;
    CK_BYTE_PTR pxCertificateValue = NULL;
    CK_ULONG xCertificateLength = 0;
    uint8_t pxPublicKey[MAX_PUBLIC_KEY_SIZE];
    uint32_t ulKeySize = MAX_PUBLIC_KEY_SIZE;
    CK_KEY_TYPE xKeyType;

    if (NULL == pxTemplate || NULL == pxObject) /* Check parameters */
        return CKR_ARGUMENTS_BAD;

    PKCS11_PRINT_TEMPLATE(pxTemplate, ulCount)

    xResult = get_object_class(pxTemplate, ulCount, &xClass);
    if (xResult == CKR_OK) {
        switch (xClass) {
            case CKO_DATA:
            case CKO_CERTIFICATE:
                xResult = verify_certificate_template(
                    pxTemplate,
                    ulCount,
                    &pxLabel,
                    &pxCertificateValue,
                    &xCertificateLength
                );
                if (xResult == CKR_OK) {
                    if (pxLabel
                        == NULL) /* Client doesn't provide LABEL - use hardcode Optiga public key OID for a specified slot */
                    {
                        xPalHandle = supported_slots_mechanisms_list[pxSession->slot_id]
                                         .logical_object_handle[0];  // Certificate object
                    } else {
                        xPalHandle =
                            find_object_by_label(pxSession->slot_id, pxLabel->pValue, NULL);
                        if (xPalHandle == CK_INVALID_HANDLE) {
                            return CKR_OBJECT_HANDLE_INVALID;
                        }
                    }
                    PKCS11_DEBUG(
                        "INFO: C_CreateObject: Certificate. Label: '%s'\r\n",
                        optiga_objects_list[xPalHandle].text_label
                    );

                    if (xCertificateLength
                        > optiga_objects_list[xPalHandle]
                              .obj_size_key_alg)  // pkcs11OBJECT_CERTIFICATE_MAX_SIZE
                    {
                        PKCS11_PRINT(
                            "ERROR: C_CreateObject: certificate size (%d) exceeds %s object size %d\r\n",
                            xCertificateLength,
                            optiga_objects_list[xPalHandle].text_label,
                            optiga_objects_list[xPalHandle].obj_size_key_alg
                        );
                        return CKR_DATA_LEN_RANGE;
                    }

                    if (upload_certificate(
                            optiga_objects_list[xPalHandle].physical_oid,
                            pxCertificateValue,
                            xCertificateLength
                        )
                        != OPTIGA_LIB_SUCCESS) {
                        PKCS11_PRINT(
                            "ERROR: C_CreateObject: upload_certificate to object 0x%04X failed\r\n",
                            (int)optiga_objects_list[xPalHandle].physical_oid
                        );
                        return CKR_DEVICE_ERROR;
                    }
                }
                break;

            case CKO_PRIVATE_KEY:
                PKCS11_PRINT("ERROR: C_CreateObject: Private key injection not supported\r\n");
                return CKR_FUNCTION_NOT_SUPPORTED;

            case CKO_PUBLIC_KEY:
                xKeyType = get_key_type(pxTemplate, ulCount);
                if (xKeyType == CKK_EC) {
                    get_label(&pxLabel, pxTemplate, ulCount);
                    xResult = verify_public_key_template(
                        xSession,
                        &pxLabel,
                        pxTemplate,
                        ulCount,
                        pxPublicKey,
                        &ulKeySize
                    );
                } else {
                    PKCS11_PRINT("ERROR: C_CreateObject: Invalid key type %d\r\n", xKeyType);
                    return CKR_TEMPLATE_INCONSISTENT;
                }
                if (xResult == CKR_OK) {
                    xPalHandle = find_object_by_label(pxSession->slot_id, pxLabel->pValue, NULL);
                    if (xPalHandle == CK_INVALID_HANDLE)
                        return CKR_OBJECT_HANDLE_INVALID;

                    if (upload_public_key(
                            pxSession->key_alg_id,
                            optiga_objects_list[xPalHandle].physical_oid,
                            pxPublicKey,
                            ulKeySize
                        )
                        != OPTIGA_LIB_SUCCESS) {
                        PKCS11_PRINT(
                            "ERROR: C_CreateObject: upload_public_key to object %s failed\r\n",
                            optiga_objects_list[xPalHandle].text_label
                        );
                        return CKR_DEVICE_ERROR;
                    }
                }
                break;

            default:
                PKCS11_PRINT("ERROR: C_CreateObject: CLASS 0x%X not supported\r\n", xClass);
                return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    *pxObject = xPalHandle;
    return xResult;
}
/**************************************************************************
 * @brief Free resources attached to an object handle.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE xObject) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    (void)xObject;
    xResult = destroy_object(xObject);
    return xResult;
}
/**************************************************************************
 * @brief Initialize the Cryptoki module for use.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pvInitArgs) {
    /*lint !e9072 It's OK to have different parameter name. */
    (void)(pvInitArgs);

    CK_RV xResult = CKR_OK;
    LOGOPEN
    PKCS11_DEBUG("TRACE: C_Initialize\r\n");
    PKCS11_DEBUG(
        "%s %s PKCS#11 library ver.%d.%d\r\n",
        LIBRARY_MANUFACTURER,
        LIBRARY_DESCRIPTION,
        LIBRARY_VERSION_MAJOR,
        LIBRARY_VERSION_MINOR
    );

    /* Ensure that the FreeRTOS heap is used. */
    //        CRYPTO_ConfigureHeap();

    if (pkcs11_context.is_initialized != CK_TRUE) {
        memset(
            &pkcs11_context,
            0,
            sizeof(pkcs11_context)
        );  // Clean up all context including .is_initialized flag
        Semaphore_Initialize();
        /*
         *   Reset OPTIGA(TM) Trust M and open an application on it
         */
        xResult = optiga_trustm_initialize();
        if (xResult != CKR_OK) {
            xResult = optiga_trustm_initialize(); /* try initialization one more time */
        }
        if (xResult == CKR_OK) {
            pkcs11_context.is_initialized = CK_TRUE;
        } else {
            Semaphore_Shutdown();
        }
    } else {
        xResult = CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    return xResult;
}
/**************************************************************************
 * @brief Un-initialize the Cryptoki module.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pvReserved) {
    PKCS11_MODULE_INITIALIZED
    PKCS11_DEBUG("TRACE: Enter %s\r\n", __func__);

    if (NULL != pvReserved) {
        xResult = CKR_ARGUMENTS_BAD;
    } else {
        xResult = optiga_trustm_deinitialize();
        Semaphore_Shutdown();

        pkcs11_context.is_initialized = CK_FALSE;
    }
    LOGCLOSE
    return xResult;
}
/**************************************************************************
 * @brief Copy src string to destination without terminating zero
 **************************************************************************/
void strcpy_bp(char *dst, const char *src, size_t dstsize) {
    memset((char *)dst, ' ', dstsize);
    if (src) {
        size_t src_len = strlen(src);

        if (src_len > dstsize) { /* string will be truncated */
            memcpy((char *)dst, src, dstsize);
        } else {
            memcpy((char *)dst, src, src_len);
        }
    }
}
/**************************************************************************
 * @brief Query the general info about Cryptoki:
      CK_VERSION    cryptokiVersion;        Cryptoki interface ver 
      CK_UTF8CHAR   manufacturerID[32];     blank padded 
      CK_FLAGS      flags;                  must be zero 
      CK_UTF8CHAR   libraryDescription[32]; blank padded 
      CK_VERSION    libraryVersion;         version of library 
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO *pInfo) {
    PKCS11_MODULE_INITIALIZED

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = (CK_BYTE)CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = (CK_BYTE)CRYPTOKI_VERSION_MINOR;

    strcpy_bp(pInfo->manufacturerID, LIBRARY_MANUFACTURER, sizeof(pInfo->manufacturerID));
    strcpy_bp(pInfo->libraryDescription, LIBRARY_DESCRIPTION, sizeof(pInfo->libraryDescription));

    pInfo->libraryVersion.major = LIBRARY_VERSION_MAJOR;
    pInfo->libraryVersion.minor = LIBRARY_VERSION_MINOR;
    return CKR_OK;
}
/**************************************************************************
 * @brief Query the list of interface function pointers.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppxFunctionList) {
    CK_RV xResult = CKR_OK;

    LOGOPEN
    PKCS11_DEBUG("TRACE: %s\r\n", __func__);

    if (NULL == ppxFunctionList) {
        xResult = CKR_ARGUMENTS_BAD;
    } else {
        *ppxFunctionList = &prvP11FunctionList;
    }
    return xResult;
}
/**************************************************************************
 * @brief Query the list of slots. A single default slot is implemented.
 * used to obtain a list of slots in the system. 
 *  tokenPresent indicates whether the list obtained includes only those 
 *	       slots with a token present (CK_TRUE), or all slots (CK_FALSE); 
 *  pulCount points to the location that receives the number of slots.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)
(CK_BBOOL xTokenPresent, CK_SLOT_ID_PTR pxSlotList, CK_ULONG_PTR pulCount) {
    PKCS11_MODULE_INITIALIZED

    uint32_t ulSlot = 0;
    /* Since the implementation of PKCS#11 does not depend
     * on a physical token, this parameter is ignored. */
    (void)(xTokenPresent);

    if (NULL == pulCount) {
        return CKR_ARGUMENTS_BAD;
    } else if (NULL == pxSlotList) {
        *pulCount = PKCS11_MAX_SLOTS;
    } else {
        if (0u == *pulCount) {
            PKCS11_PRINT("ERROR: C_GetSlotList: Reserved output buffer has zero size\r\n");
            return CKR_BUFFER_TOO_SMALL;
        } else {
            if (*pulCount > PKCS11_MAX_SLOTS) {
                *pulCount = PKCS11_MAX_SLOTS;
            }
            for (; ulSlot < *pulCount; ulSlot++) {
                pxSlotList[ulSlot] = supported_slots_mechanisms_list[ulSlot].slot_id;
            }
        }
    }
    return CKR_OK;
}
/**************************************************************************
 * @brief Query slot info. 
 * Obtains information about a particular slot in the system. 
 *  slotID is the ID of the slot
 *  pInfo points to the location that receives the slot information
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    PKCS11_MODULE_INITIALIZED

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(CK_SLOT_INFO));

    strcpy_bp(
        (char *)pInfo->slotDescription,
        (char *)supported_slots_mechanisms_list[slotID].slotDescription,
        sizeof(pInfo->slotDescription)
    );
    strcpy_bp((char *)pInfo->manufacturerID, LIBRARY_MANUFACTURER, sizeof(pInfo->manufacturerID));

    pInfo->flags =
        CKF_TOKEN_PRESENT  // 0x00000001 True if a token is present in the slot (e.g., a device is in the reader)
        //  | CKF_REMOVABLE_DEVICE           // 0x00000002 True if the reader supports removable devices
        | CKF_HW_SLOT  // 0x00000004 True if the slot is a hardware slot, as opposed to a software slot implementing a soft token
        ;

    pInfo->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
    pInfo->hardwareVersion.minor = HARDWARE_VERSION_MINOR;

    pInfo->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
    pInfo->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;

    return CKR_OK;
}
/**************************************************************************
  @brief Returns token information to a CK_TOKEN_INFO structure:
      CK_UTF8CHAR   label[32];            blank padded 
      CK_UTF8CHAR   manufacturerID[32];   blank padded 
      CK_UTF8CHAR   model[16];            blank padded 
      CK_CHAR       serialNumber[16];     blank padded 
      CK_FLAGS      flags;                see below 
      CK_ULONG      ulMaxSessionCount;    max open sessions
      CK_ULONG      ulSessionCount;       sess. now open
      CK_ULONG      ulMaxRwSessionCount;  max R/W sessions
      CK_ULONG      ulRwSessionCount;     R/W sess. now open
      CK_ULONG      ulMaxPinLen;          in bytes
      CK_ULONG      ulMinPinLen;          in bytes
      CK_ULONG      ulTotalPublicMemory;  in bytes
      CK_ULONG      ulFreePublicMemory;   in bytes
      CK_ULONG      ulTotalPrivateMemory; in bytes
      CK_ULONG      ulFreePrivateMemory;  in bytes
      CK_VERSION    hardwareVersion;      version of hardware
      CK_VERSION    firmwareVersion;      version of firmware
      CK_CHAR       utcTime[16];          time 
 
  @return CKR_OK.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    PKCS11_MODULE_INITIALIZED

    if (slotID >= PKCS11_MAX_SLOTS) {
        return CKR_SLOT_ID_INVALID;
    }
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));

    strcpy_bp(
        (char *)pInfo->label,
        (char *)supported_slots_mechanisms_list[slotID].tokenLabel,
        sizeof(pInfo->label)
    );
    strcpy_bp((char *)pInfo->manufacturerID, LIBRARY_MANUFACTURER, sizeof(pInfo->manufacturerID));
    strcpy_bp((char *)pInfo->model, LIBRARY_DESCRIPTION, sizeof(pInfo->model));
    strcpy_bp((char *)pInfo->serialNumber, SERIAL_NUMBER, sizeof(pInfo->serialNumber));

    pInfo->flags =
        CKF_RNG  // the token has its own random number generator
        //  | CKF_WRITE_PROTECTED              // the token is write-protected (see below)
        //  | CKF_LOGIN_REQUIRED               // there are some cryptographic functions that a user MUST be logged in to perform
        //  | CKF_USER_PIN_INITIALIZED         // the normal user’s PIN has been initialized
        //  | CKF_RESTORE_KEY_NOT_NEEDED       // a successful save of a session’s cryptographic operations state always contains all keys needed to restore the state of the session
        //  | CKF_CLOCK_ON_TOKEN               // token has its own hardware clock
        //  | CKF_PROTECTED_AUTHENTICATION_PATH// token has a "protected authentication path", whereby a user can log into the token without passing a PIN through the Cryptoki library
        //  | CKF_DUAL_CRYPTO_OPERATIONS       // a single session with the token can perform dual cryptographic operations (see Section 5.12)
        | CKF_TOKEN_INITIALIZED  // the token has been initialized using C_InitToken or an equivalent mechanism outside the scope of this standard. Calling C_InitToken when this flag is set will cause the token to be reinitialized.
        //  | CKF_SECONDARY_AUTHENTICATION     // the token supports secondary authentication for private key objects. (Deprecated; new implementations MUST NOT set this flag)
        //  | CKF_USER_PIN_COUNT_LOW           // an incorrect user login PIN has been entered at least once since the last successful authentication.
        //  | CKF_USER_PIN_FINAL_TRY           // supplying an incorrect user PIN will cause it to become locked.
        //  | CKF_USER_PIN_LOCKED              // the user PIN has been locked. User login to the token is not possible.
        //  | CKF_USER_PIN_TO_BE_CHANGED       // the user PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
        //  | CKF_SO_PIN_COUNT_LOW             // an incorrect SO login PIN has been entered at least once since the last successful authentication.
        //  | CKF_SO_PIN_FINAL_TRY             // supplying an incorrect SO PIN will cause it to become locked.
        //  | CKF_SO_PIN_LOCKED                // the SO PIN has been locked. SO login to the token is not possible.
        //  | CKF_SO_PIN_TO_BE_CHANGED         // the SO PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
        //  | CKF_ERROR_STATE                  // the token failed a FIPS 140-2 self-test and entered an error state.
        ;

    pInfo->ulMaxSessionCount = MAX_SESSIONS;

    pInfo->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
    pInfo->hardwareVersion.minor = HARDWARE_VERSION_MINOR;

    pInfo->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
    pInfo->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;
    return CKR_OK;
}
/**************************************************************************
  @brief This function obtains a list of mechanism types supported by a token.
 
  \param[in]  xSlotID         ID of the token’s slot.
  \param[in]  pMechanismList  if NULL, then returns in *pulCount the number of mechanisms.
                              If not, then *pulCount contains the number of mechanisms to return.
  \param[out] pInfo	          points to the location that receives the number of mechanisms.
 
  @return CKR_OK if the mechanism is supported. Otherwise, CKR_MECHANISM_INVALID.
 **************************************************************************/
CK_RV C_GetMechanismList(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount
) {
    PKCS11_MODULE_INITIALIZED
    uint32_t ulMech = 0;

    if (slotID >= PKCS11_MAX_SLOTS) {
        return CKR_SLOT_ID_INVALID;
    }
    if (NULL == pulCount) {
        return CKR_ARGUMENTS_BAD;
    }
    if (NULL == pMechanismList) {
        *pulCount = supported_slots_mechanisms_list[slotID].mechanisms_number;
    } else {
        if (0u == *pulCount) {
            PKCS11_PRINT("ERROR: C_GetMechanismList: Reserved output buffer has zero size\r\n");
            return CKR_BUFFER_TOO_SMALL;
        } else {
            if (*pulCount > supported_slots_mechanisms_list[slotID].mechanisms_number) {
                *pulCount = supported_slots_mechanisms_list[slotID].mechanisms_number;
            }
            for (; ulMech < *pulCount; ulMech++) {
                pMechanismList[ulMech] =
                    supported_slots_mechanisms_list[slotID].mechanisms_list[ulMech].xType;
            }
        }
    }
    return CKR_OK;
}
/**************************************************************************
 * @brief This function obtains information about a particular
 * mechanism possibly supported by a token.
 *
 *  \param[in]  xSlotID         This parameter is unused in this port.
 *  \param[in]  type            The cryptographic capability for which support
 *                              information is being queried.
 *  \param[out] pInfo           Algorithm sizes and flags for the requested
 *                              mechanism, if supported.
 *
 * @return CKR_OK if the mechanism is supported. Otherwise, CKR_MECHANISM_INVALID.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
    PKCS11_MODULE_INITIALIZED
    uint32_t ulMech = 0;

    if (slotID >= PKCS11_MAX_SLOTS) {
        return CKR_SLOT_ID_INVALID;
    }
    /* Look for the requested mechanism in the above table. */
    for (; ulMech < supported_slots_mechanisms_list[slotID].mechanisms_number; ulMech++) {
        if (supported_slots_mechanisms_list[slotID].mechanisms_list[ulMech].xType == type) {
            /* The mechanism is supported. Copy out the details and exit */
            memcpy(
                pInfo,
                &(supported_slots_mechanisms_list[slotID].mechanisms_list[ulMech].xInfo),
                sizeof(CK_MECHANISM_INFO)
            );
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}
/**************************************************************************
 * @brief This function is not implemented for this port.
 *
 * C_InitToken() is only implemented for compatibility with other ports.
 * All inputs to this function are ignored, and calling this
 * function on this port does not add any security.
 *
 * @return CKR_OK.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
    PKCS11_MODULE_INITIALIZED

        /* Avoid compiler warnings about unused variables. */
        (void) slotID;
    (void)pPin;
    (void)ulPinLen;
    (void)pLabel;

    return CKR_OK;
}
/**************************************************************************
 * @brief Start a session for a cryptographic command sequence.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(CK_SLOT_ID xSlotID,
 CK_FLAGS xFlags,
 CK_VOID_PTR pvApplication,
 CK_NOTIFY xNotify,
 CK_SESSION_HANDLE_PTR pxSession) {
    PKCS11_MODULE_INITIALIZED

    p_pkcs11_session_t pxSessionObj = NULL;

    (void)(pvApplication);
    (void)(xNotify);
    /* Check that the PKCS #11 module is initialized. */
    if (pkcs11_context.is_initialized != CK_TRUE) {
        xResult = CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    /* Check arguments. */
    if (NULL == pxSession) {
        xResult = CKR_ARGUMENTS_BAD;
    }
    /* For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set. */
    if (0 == (CKF_SERIAL_SESSION & xFlags)) {
        xResult = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    /*
     * Make space for the context.
     */
    if (CKR_OK == xResult) {
        pxSessionObj = new_session_pointer();
        if (pxSessionObj == NULL) {
            PKCS11_PRINT("ERROR: C_OpenSession: Not enough memory for the session\r\n");
            xResult = CKR_SESSION_COUNT;
        }
    }
    if (CKR_OK == xResult) {
        /*
         * Assign the session.
         */
        pxSessionObj->slot_id = xSlotID;
        pxSessionObj->state =
            0u != (xFlags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
        pxSessionObj->opened = CK_TRUE;

        /*
         * Return the session.
         */
        *pxSession = (CK_SESSION_HANDLE
        )pxSessionObj; /*lint !e923 Allow casting pointer to integer type for handle. */
    }
    /*
     *   Initialize the operation in progress.
     */
    if (CKR_OK == xResult) {
        pxSessionObj->operation_in_progress = pkcs11NO_OPERATION;
    }
    if ((NULL != pxSessionObj) && (CKR_OK != xResult)) {
        free(pxSessionObj);
    }
    return xResult;
}
/**************************************************************************
 * @brief Terminate a session and release resources.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE xSession) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    free_session_pointer(xSession);
    return xResult;
}
/**************************************************************************
 * @brief Terminate all sessions and release resources.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSession)(CK_SESSION_HANDLE xSession) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    free_session_pointer((CK_SESSION_HANDLE)NULL);
    return xResult;
}
/**************************************************************************
     THIS FUNCTION IS NOT IMPLEMENTED
     If login capability is required, implement it here.
     Defined for compatibility with other PKCS #11 ports.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Login)
(CK_SESSION_HANDLE xSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    return CKR_OK;
}
/**************************************************************************
     THIS FUNCTION IS NOT IMPLEMENTED
     If login capability is required, implement it here.
     Defined for compatibility with other PKCS #11 ports.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE xSession) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    return CKR_OK;
}
/**************************************************************************
 * @brief Query the size of the specified cryptographic object.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE xObject, CK_ULONG_PTR pulSize) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;

    /* Find object by logical handle */
    xPalHandle = find_object_by_handle(xObject, NULL);
    if (xPalHandle == CK_INVALID_HANDLE) {
        PKCS11_PRINT("ERROR: C_GetObjectSize: Object 0x%X not found\r\n", (int)xObject);
        return CKR_DATA_INVALID;
    }

    switch (optiga_objects_list[xPalHandle].object_class) {
        case CKO_CERTIFICATE:
            *pulSize = optiga_objects_list[xPalHandle].obj_size_key_alg;
            break;
        case CKO_PUBLIC_KEY:
            *pulSize = optiga_objects_list[xPalHandle].obj_size_key_alg;
            break;
        case CKO_PRIVATE_KEY:
            *pulSize = get_key_size(optiga_objects_list[xPalHandle].obj_size_key_alg);
            break;
        default:
            PKCS11_PRINT(
                "ERROR: C_GetObjectSize: Wrong object class 0x%X\r\n",
                optiga_objects_list[xPalHandle].object_class
            );
            return CKR_DATA_INVALID;
    }
    return CKR_OK;
}
/**************************************************************************
 * @brief Query the value of the specified cryptographic object attribute.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(CK_SESSION_HANDLE xSession, CK_OBJECT_HANDLE xObject, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount
) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    CK_BBOOL xIsPrivate = CK_TRUE;
    CK_BBOOL xIsLocal = CK_FALSE;
    CK_ULONG iAttrib;
    CK_KEY_TYPE xPkcsKeyType = (CK_KEY_TYPE)~0;
    CK_OBJECT_CLASS xClass;
    uint8_t *pxObjectValue = NULL;
    uint16_t ulLength = 0;
    uint8_t *temp_ec_value = NULL;
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    uint8_t *pcLabel = NULL;
    CK_CERTIFICATE_TYPE xType;
    uint8_t bOptigaOid[2];
    CK_BBOOL xAttribute;

    if (NULL == pxTemplate || 0 == ulCount) {
        PKCS11_PRINT("ERROR: C_GetAttributeValue: Bad arguments. xResult = %d\r\n", (int)xResult);
        return CKR_ARGUMENTS_BAD;
    }
    //  PKCS11_DEBUG("TRACE: C_GetAttributeValue: Object: %d\r\n", (int)xObject);

    /* Find object by logical handle */
    xPalHandle = find_object_by_handle(xObject, NULL);
    if (xPalHandle == CK_INVALID_HANDLE) {
        PKCS11_PRINT("ERROR: C_GetAttributeValue: Object 0x%X not found\r\n", (int)xObject);
        return CKR_DATA_INVALID;
    }
    /* Get object class */
    switch (xPalHandle) {
        case ObjectHandle_Slot0_Certificate:
        case ObjectHandle_Slot1_Certificate:
        case ObjectHandle_Slot2_Certificate:  // Old: DeviceCertificate ECC
        case ObjectHandle_Slot3_Certificate:
        case ObjectHandle_Slot4_Certificate:  // Old: DeviceCertificate RSA
        case ObjectHandle_Slot5_Certificate:
        case ObjectHandle_TrustAnchor1_Certificate:
        case ObjectHandle_TrustAnchor2_Certificate:
        case ObjectHandle_CodeSigning_Certificate:
            xIsLocal = CK_FALSE;
            xIsPrivate = CK_FALSE;
            xClass = CKO_CERTIFICATE;
            break;
            /* - - - - - - - - - - - - - - - - - - */
        case ObjectHandle_Slot0_PublicKey:
            xIsLocal = CK_FALSE;
            xIsPrivate = CK_FALSE;
            xClass = CKO_PUBLIC_KEY;
            break;
        case ObjectHandle_Slot1_PublicKey:
        case ObjectHandle_Slot2_PublicKey:  // Old: DevicePublicKey ECC
        case ObjectHandle_Slot3_PublicKey:
        case ObjectHandle_Slot4_PublicKey:  // Old: DevicePublicKey RSA
        case ObjectHandle_Slot5_PublicKey:
            xIsLocal = CK_TRUE;
            xIsPrivate = CK_FALSE;
            xClass = CKO_PUBLIC_KEY;
            break;
            /* - - - - - - - - - - - - - - - - - - */
        case ObjectHandle_Slot0_PrivateKey:
            xIsLocal = CK_FALSE;
            xIsPrivate = CK_TRUE;
            xClass = CKO_PRIVATE_KEY;
            break;
        case ObjectHandle_Slot1_PrivateKey:  // Old: DevicePrivateKey ECC
        case ObjectHandle_Slot2_PrivateKey:
        case ObjectHandle_Slot3_PrivateKey:
        case ObjectHandle_Slot4_PrivateKey:  // Old: DevicePublicKey RSA
        case ObjectHandle_Slot5_PrivateKey:
            xIsLocal = CK_TRUE;
            xIsPrivate = CK_TRUE;
            xClass = CKO_PRIVATE_KEY;
            break;
    }

    for (iAttrib = 0; iAttrib < ulCount /*!JC && CKR_OK == xResult */; iAttrib++) {
        pxTemplate[iAttrib].ulValueLen = CK_UNAVAILABLE_INFORMATION;

        switch (pxTemplate[iAttrib].type) {
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_CLASS:
                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_CLASS",
                    pxTemplate,
                    iAttrib,
                    (void *)&xClass,
                    sizeof(CK_OBJECT_CLASS)
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_ID: /* !JC: PKCS11 base spec 2.40: CKA_ID Key identifier for key (default empty) - may be different from LABEL */
                // Note: use little-endian 2 bytes as object ID. Ex., 0xF0, 0xE0
                // Command line: pkcs11-tool --id E0F0"
                bOptigaOid[0] = (optiga_objects_list[xPalHandle].physical_oid >> 8) & 0x00FF;
                bOptigaOid[1] = optiga_objects_list[xPalHandle].physical_oid & 0x00FF;

                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_ID",
                    pxTemplate,
                    iAttrib,
                    (void *)bOptigaOid,
                    2
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_LABEL:
                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_LABEL",
                    pxTemplate,
                    iAttrib,
                    (void *)optiga_objects_list[xPalHandle].text_label,
                    strlen((char *)optiga_objects_list[xPalHandle].text_label)
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_VALUE:
                if (xClass == CKO_PRIVATE_KEY) {
                    PKCS11_PRINT(
                        "WARNING: C_GetAttributeValue: CKA_VALUE not supported for private key objects\r\n"
                    );
                    xResult = CKR_ATTRIBUTE_SENSITIVE;
                    break;
                }
                PKCS11_DEBUG(
                    "TRACE: C_GetAttributeValue: CKA_VALUE: Getting object: %d from Optiga\r\n",
                    (int)xObject
                );
                xResult = get_object_value(
                    xPalHandle,
                    &pxObjectValue,
                    &ulLength
                ); /* Read object from Optiga to a buffer - allocates dynamic memory */
                if (CKR_OK != xResult) {
                    PKCS11_PRINT(
                        "ERROR: C_GetAttributeValue: Get object %d value from Optiga failed with error 0x%X\r\n",
                        (int)xObject,
                        (int)xResult
                    );
                    goto get_object_exit;
                }
                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_VALUE",
                    pxTemplate,
                    iAttrib,
                    (void *)pxObjectValue,
                    ulLength
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_EC_POINT:
                if (xClass != CKO_PUBLIC_KEY) {
                    PKCS11_PRINT(
                        "ERROR: C_GetAttributeValue: EC_POINT supported only for public key objects\r\n"
                    );
                    xResult = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
                }
                PKCS11_DEBUG(
                    "TRACE: C_GetAttributeValue: CKA_EC_POINT: Getting object: %d from Optiga\r\n",
                    (int)xObject
                );
                xResult = get_object_value(
                    xPalHandle,
                    &pxObjectValue,
                    &ulLength
                ); /* Read object from Optiga to a buffer - allocates dynamic memory */
                if (CKR_OK != xResult) {
                    PKCS11_PRINT(
                        "ERROR: C_GetAttributeValue: Get public key %d EC_POINT from Optiga failed with error 0x%X\r\n",
                        (int)xObject,
                        (int)xResult
                    );
                    goto get_object_exit;
                }
                if (pxObjectValue[0] == 0x30)  // DER header tag present in the object data
                {
                    int iPubKeyLen;
                    uint8_t *pPubKey = Find_TLV_Tag(
                        pxObjectValue,
                        0x03,
                        &iPubKeyLen
                    );  // Get pointer to Tag 0x03 value
                    if (pPubKey != NULL && iPubKeyLen != 0) {
                        ulLength = iPubKeyLen + 2;
                        memmove(
                            pxObjectValue,
                            pPubKey,
                            ulLength
                        );  // Remove header from the DER public key encoding
                    }
                } else if (pxObjectValue[0] == 0)
                    ulLength =
                        67;  // Pub key not written (ex., Slot 0 IFX provisioned - default - EC 256 bit - all zero bytes)
                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_VALUE",
                    pxTemplate,
                    iAttrib,
                    (void *)pxObjectValue,
                    ulLength
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_CERTIFICATE_TYPE:
                xType = CKC_VENDOR_DEFINED;
                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_CERTIFICATE_TYPE",
                    pxTemplate,
                    iAttrib,
                    (void *)&xType,
                    sizeof(CK_CERTIFICATE_TYPE)
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_KEY_TYPE:
                xPkcsKeyType = optiga_objects_list[xPalHandle].key_type;
                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_KEY_TYPE",
                    pxTemplate,
                    iAttrib,
                    (void *)&xPkcsKeyType,
                    sizeof(CK_KEY_TYPE)
                );
                break;
                /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
                //        case CKA_ALLOWED_MECHANISMS: // A list of mechanisms allowed to be used with this key.
                //            break;
                /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
                //        case CKA_SUBJECT: // DER-encoding of the key subject name
                //            break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_ALWAYS_AUTHENTICATE:
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_ALWAYS_AUTHENTICATE",
                    pxTemplate,
                    iAttrib,
                    CK_FALSE
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_TOKEN:
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_TOKEN",
                    pxTemplate,
                    iAttrib,
                    CK_TRUE
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_PRIVATE:
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_PRIVATE",
                    pxTemplate,
                    iAttrib,
                    xIsPrivate
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_SENSITIVE:
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_SENSITIVE",
                    pxTemplate,
                    iAttrib,
                    xIsPrivate
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_ALWAYS_SENSITIVE:
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_ALWAYS_SENSITIVE",
                    pxTemplate,
                    iAttrib,
                    xIsPrivate
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_EXTRACTABLE:
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_EXTRACTABLE",
                    pxTemplate,
                    iAttrib,
                    !xIsPrivate
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_NEVER_EXTRACTABLE:
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_NEVER_EXTRACTABLE",
                    pxTemplate,
                    iAttrib,
                    xIsPrivate
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_LOCAL:  // CK_TRUE if key was generated locally with a C_GenerateKey or C_GenerateKeyPair
                xResult = check_and_copy_bool_attribute(
                    xObject,
                    "CKA_LOCAL",
                    pxTemplate,
                    iAttrib,
                    xIsLocal
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_ENCRYPT:
                xResult = check_and_copy_bit_attribute(
                    xObject,
                    "CKA_ENCRYPT",
                    pxTemplate,
                    iAttrib,
                    pxSession->key_template_enabled,
                    PKCS_ENCRYPT_ENABLE
                );
                break;
            case CKA_DECRYPT:
                xResult = check_and_copy_bit_attribute(
                    xObject,
                    "CKA_DECRYPT",
                    pxTemplate,
                    iAttrib,
                    pxSession->key_template_enabled,
                    PKCS_DECRYPT_ENABLE
                );
                break;
            case CKA_SIGN:
                xResult = check_and_copy_bit_attribute(
                    xObject,
                    "CKA_SIGN",
                    pxTemplate,
                    iAttrib,
                    pxSession->key_template_enabled,
                    PKCS_SIGN_ENABLE
                );
                break;
            case CKA_VERIFY:
                xResult = check_and_copy_bit_attribute(
                    xObject,
                    "CKA_VERIFY",
                    pxTemplate,
                    iAttrib,
                    pxSession->key_template_enabled,
                    PKCS_VERIFY_ENABLE
                );
                break;
            case CKA_WRAP:
                xResult = check_and_copy_bit_attribute(
                    xObject,
                    "CKA_WRAP",
                    pxTemplate,
                    iAttrib,
                    pxSession->key_template_enabled,
                    PKCS_WRAP_ENABLE
                );
                break;
            case CKA_UNWRAP:
                xResult = check_and_copy_bit_attribute(
                    xObject,
                    "CKA_UNWRAP",
                    pxTemplate,
                    iAttrib,
                    pxSession->key_template_enabled,
                    PKCS_UNWRAP_ENABLE
                );
                break;
            case CKA_DERIVE:
                xResult = check_and_copy_bit_attribute(
                    xObject,
                    "CKA_DERIVE",
                    pxTemplate,
                    iAttrib,
                    pxSession->key_template_enabled,
                    PKCS_DERIVE_ENABLE
                );
                break;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_EC_PARAMS:
                switch ((int)pxSession->key_alg_id) {
                    case 0:
                        //!!!JC ToDo: If ECC key length unknown, need to read it from Optiga metadata.
                        PKCS11_PRINT("ERROR: C_GetAttributeValue: EC key size unknown\r\n");
                        xResult = CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                    case OPTIGA_ECC_CURVE_NIST_P_256:
                        temp_ec_value = ec_param_p256;
                        ulLength = sizeof(ec_param_p256);
                        break;
                    case OPTIGA_ECC_CURVE_NIST_P_384:
                        temp_ec_value = ec_param_p384;
                        ulLength = sizeof(ec_param_p384);
                        break;
                    case OPTIGA_ECC_CURVE_NIST_P_521:
                        temp_ec_value = ec_param_p256;
                        ulLength = sizeof(ec_param_p256);
                        break;
                    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
                        temp_ec_value = ec_param_BP256;
                        ulLength = sizeof(ec_param_BP256);
                        break;
                    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
                        temp_ec_value = ec_param_BP384;
                        ulLength = sizeof(ec_param_BP384);
                        break;
                    case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
                        temp_ec_value = ec_param_BP512;
                        ulLength = sizeof(ec_param_BP512);
                        break;
                    default:
                        PKCS11_PRINT(
                            "ERROR: C_GetAttributeValue: Invalid EC key type: 0x%X\r\n",
                            (int)pxSession->key_alg_id
                        );
                        goto get_object_exit;
                }
                xResult = check_and_copy_attribute(
                    xObject,
                    "CKA_EC_PARAMS",
                    pxTemplate,
                    iAttrib,
                    (void *)temp_ec_value,
                    ulLength
                );
                break;
                /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#ifdef PKCS11_SUPPORT_RSA
            case CKA_MODULUS: /* ToDo */
            case CKA_MODULUS_BITS: /* ToDo */
            case CKA_PUBLIC_EXPONENT: /* ToDo */
                return CKR_ATTRIBUTE_TYPE_INVALID;
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            case CKA_PRIVATE_EXPONENT:
            case CKA_PRIME_1:
            case CKA_PRIME_2:
            case CKA_EXPONENT_1:
            case CKA_EXPONENT_2:
            case CKA_COEFFICIENT:
                return CKR_ATTRIBUTE_SENSITIVE;
#endif
            /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
            default:
                if ((unsigned int)(pxTemplate[iAttrib].type) >= 0x800) {
                    xResult = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
                }
                PKCS11_PRINT(
                    "WARNING: C_GetAttributeValue: Unknown attribute 0x%X ignored, returned FALSE\r\n",
                    (int)(pxTemplate[iAttrib].type)
                );
                pxTemplate[iAttrib].pValue = CK_FALSE;
                pxTemplate[iAttrib].ulValueLen =
                    sizeof(CK_BBOOL);  // Ignore unknown attributes, return FALSE
        }
    }
    //  PKCS11_PRINT_TEMPLATE(pxTemplate, ulCount)

get_object_exit:
    get_object_value_cleanup(pxObjectValue); /* Free the buffer where object was stored. */
    return xResult;
}
/**************************************************************************
 * @brief Begin an enumeration sequence for the objects of the specified type.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(CK_SESSION_HANDLE xSession, CK_ATTRIBUTE_PTR pxTemplate, CK_ULONG ulCount) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    uint32_t ulIndex;
    uint8_t byteID[10];
    CK_ATTRIBUTE xAttribute;

    PKCS11_DEBUG(
        "TRACE: C_FindObjectsInit: Slot: %d. Template: 0x%X, Count:%d\r\n",
        (int)pxSession->slot_id,
        pxTemplate,
        ulCount
    );

    pxSession->find_object_class = CKO_VENDOR_DEFINED;  // Not defined
    pxSession->find_object_id = 0;
    pxSession->find_object_length = 0;
    pxSession->find_object_counter = 0;

    /* Check inputs. */
    if (pxSession->find_object_init != CK_FALSE) {
        pxSession->find_object_init = CK_FALSE;
        PKCS11_PRINT("ERROR: C_FindObjectsInit: Find object operation already in progress. \r\n");
        return CKR_OPERATION_ACTIVE;
    } else if (NULL == pxTemplate || ulCount == 0) /* No template provided - start object search and return all objects */
    {
        PKCS11_DEBUG("TRACE: C_FindObjectsInit: No template provided. Search all objects\r\n");
        pxSession->find_object_init = CK_TRUE;
        return CKR_OK;
    } else if (pxTemplate->ulValueLen > MAX_LABEL_LENGTH) {
        PKCS11_PRINT("ERROR: C_FindObjectsInit: Invalid object label in template.\r\n");
        return CKR_ARGUMENTS_BAD;
    }
    PKCS11_PRINT_TEMPLATE(pxTemplate, ulCount)

    /* Search template contains one or more attribites - CKA_CLASS, CKA_LABEL, CKA_ID */
    pxSession->find_object_init = CK_FALSE;
    for (ulIndex = 0; ulIndex < ulCount; ulIndex++) {
        xAttribute = pxTemplate[ulIndex];
        switch (xAttribute.type) {
            case CKA_CLASS:  // Search by CLASS
                if (xAttribute.ulValueLen != sizeof(CK_OBJECT_CLASS)) {
                    HEXDUMP(
                        "ERROR: C_FindObjectsInit: Invalid object CLASS in template: ",
                        xAttribute.pValue,
                        xAttribute.ulValueLen
                    );
                    return CKR_ARGUMENTS_BAD;
                }
                memcpy(byteID, xAttribute.pValue, xAttribute.ulValueLen);
                pxSession->find_object_class = (CK_OBJECT_CLASS)byteID[0];
                pxSession->find_object_init = CK_TRUE;

                PKCS11_DEBUG(
                    "TRACE: C_FindObjectsInit: Search by CLASS: 0x%X\r\n",
                    pxSession->find_object_class
                );
                break;

            case CKA_LABEL:  // Search by LABEL
                memcpy(pxSession->find_object_label, xAttribute.pValue, xAttribute.ulValueLen);
                pxSession->find_object_length = xAttribute.ulValueLen;
                pxSession->find_object_init = CK_TRUE;

                HEXDUMP(
                    "TRACE: C_FindObjectsInit: Search by LABEL: ",
                    xAttribute.pValue,
                    xAttribute.ulValueLen
                );
                break;

            case CKA_ID:  // Search by ID
                if (xAttribute.ulValueLen > sizeof(byteID))
                    xAttribute.ulValueLen = sizeof(byteID);
                memcpy(byteID, xAttribute.pValue, xAttribute.ulValueLen);

                if (xAttribute.ulValueLen == 2)
                    pxSession->find_object_id =
                        byteID[0] * 256 + byteID[1];  // 2 bytes big endian oid
                else if (xAttribute.ulValueLen == 4)
                    pxSession->find_object_id =
                        byteID[2] * 256 + byteID[3];  // 4 bytes big endian oid
                if (pxSession->find_object_id == 0) {
                    HEXDUMP(
                        "ERROR: C_FindObjectsInit: Invalid object ID in template: ",
                        xAttribute.pValue,
                        xAttribute.ulValueLen
                    );
                    return CKR_ARGUMENTS_BAD;
                }
                pxSession->find_object_init = CK_TRUE;

                PKCS11_DEBUG(
                    "TRACE: C_FindObjectsInit: Search by ID: 0x%X\r\n",
                    pxSession->find_object_id
                );
                break;

            default:
                PKCS11_WARNING_PRINT(
                    "WARNING: Unknown search attribute: 0x%X\r\n",
                    (int)xAttribute.type
                );
        }
    }
    if (pxSession->find_object_init != CK_TRUE) {
        PKCS11_PRINT("ERROR: C_FindObjectsInit: Template incomplete\r\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }
    return CKR_OK;
}
/**************************************************************************
 * @brief Query the objects of the requested type.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(CK_SESSION_HANDLE xSession,
 CK_OBJECT_HANDLE_PTR pxObject,
 CK_ULONG ulMaxObjectCount,
 CK_ULONG_PTR pulObjectCount) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);

    CK_BYTE_PTR pcObjectValue = NULL;
    uint32_t xObjectLength = 0;
    CK_BBOOL xIsPrivate = CK_TRUE;
    CK_BYTE xByte = 0;
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    uint16_t uObjCount;

    PKCS11_DEBUG(
        "TRACE: C_FindObjects: Slot: %d. Counter: %d MaxCount:%d\r\n",
        (int)pxSession->slot_id,
        pxSession->find_object_counter,
        ulMaxObjectCount
    );
    /*
     * Check parameters.
     */
    if ((CKR_OK != xResult) || (NULL == pxObject) || (NULL == pulObjectCount)) {
        PKCS11_PRINT(
            "ERROR: C_FindObjects: No template provided by the caller: CKR_ARGUMENTS_BAD\r\n"
        );
        return CKR_ARGUMENTS_BAD;
    }
    if (pxSession->find_object_init == CK_FALSE) {
        PKCS11_PRINT("ERROR: C_FindObjects: Wrong session: CKR_OPERATION_NOT_INITIALIZED\r\n");
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    *pulObjectCount = 0;
    if (0u == ulMaxObjectCount) {
        PKCS11_PRINT("ERROR: C_FindObjects: No objects in this session\r\n");
        return CKR_ARGUMENTS_BAD;
    }

    /*- - - - - - - - - object ID provided in search template - - - - - - - - - */
    if (pxSession->find_object_id != 0) {
        xPalHandle =
            find_object_by_id(pxSession->find_object_id, NULL); /* find specific object by ID */
        if (xPalHandle == CK_INVALID_HANDLE) {
            *pxObject = CK_INVALID_HANDLE;
            *pulObjectCount = 0;
            PKCS11_PRINT(
                "ERROR: C_FindObjects: Object ID = 0x%X not found\r\n",
                pxSession->find_object_id
            );
            return CKR_OBJECT_HANDLE_INVALID;
        } else {
            *pxObject = xPalHandle;
            *pulObjectCount = 1;
            PKCS11_DEBUG(
                "TRACE: C_FindObjects: Object found: %s\r\n",
                optiga_objects_list[xPalHandle].text_label
            );
            return CKR_OK;
        }
    }
    /*- - - - - - - - - object LABEL provided in search template - - - - - - - - - */
    else if (pxSession->find_object_length != 0) {
        xPalHandle = find_object_by_label(
            pxSession->slot_id,
            (char *)pxSession->find_object_label,
            NULL
        ); /* find specific object by label */
        if (xPalHandle == CK_INVALID_HANDLE) {
            *pxObject = CK_INVALID_HANDLE;
            *pulObjectCount = 0;
            PKCS11_PRINT(
                "ERROR: C_FindObjects: Slot: %d, Label: %s: Object not found\r\n",
                pxSession->slot_id,
                (char *)pxSession->find_object_label
            );
            return CKR_OBJECT_HANDLE_INVALID;
        } else {
            *pxObject = xPalHandle;
            *pulObjectCount = 1;
            PKCS11_DEBUG(
                "TRACE: C_FindObjects: Object found: %s\r\n",
                optiga_objects_list[xPalHandle].text_label
            );
            return CKR_OK;
        }
    }
    /*- - - - - - - - - no label or ID provided, find all objects in this slot - - - - - - - - - */
    else {
        for (uObjCount = 0; pxSession->find_object_counter < PKCS11_SLOT_MAX_OBJECTS;
             pxSession->find_object_counter++) {
            xPalHandle = supported_slots_mechanisms_list[pxSession->slot_id]
                             .logical_object_handle[pxSession->find_object_counter];
            if (xPalHandle == 0)
                break;
            /* Check if searching for a specific CLASS (Cert, private or public) */
            if (pxSession->find_object_class != CKO_VENDOR_DEFINED
                && pxSession->find_object_class != optiga_objects_list[xPalHandle].object_class)
                continue;

            *pxObject = xPalHandle;
            pxObject += sizeof(CK_OBJECT_HANDLE);
            (*pulObjectCount)++;
            PKCS11_DEBUG(
                "TRACE: C_FindObjects: Object found: %s\r\n",
                optiga_objects_list[xPalHandle].text_label
            );
            if (++uObjCount >= ulMaxObjectCount) {
                pxSession->find_object_counter++;
                return CKR_OK;
            }
        }
        /* Find complete, no more objects for this slot */
        *pxObject = CK_INVALID_HANDLE;
        *pulObjectCount = 0;
        return CKR_OK;
    }
}
/**************************************************************************
 * @brief Terminate object enumeration.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE xSession) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);

    if (pxSession->find_object_init == CK_FALSE) {
        PKCS11_PRINT("ERROR: C_FindObjects: Wrong session: CKR_OPERATION_NOT_INITIALIZED\r\n");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    pxSession->find_object_class = CKO_VENDOR_DEFINED;
    pxSession->find_object_id = 0;
    pxSession->find_object_counter = 0;
    pxSession->find_object_length = 0;
    pxSession->find_object_init = CK_FALSE;
    return CKR_OK;
}
/**************************************************************************
 * @ brief Generate a new public - private key pair.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(CK_SESSION_HANDLE xSession,
 CK_MECHANISM_PTR pxMechanism,
 CK_ATTRIBUTE_PTR pxPublicKeyTemplate,
 CK_ULONG ulPublicKeyAttributeCount,
 CK_ATTRIBUTE_PTR pxPrivateKeyTemplate,
 CK_ULONG ulPrivateKeyAttributeCount,
 CK_OBJECT_HANDLE_PTR pxPublicKey,
 CK_OBJECT_HANDLE_PTR pxPrivateKey) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    uint8_t *pucPublicKeyDer = NULL;
    uint16_t ucPublicKeyBitLength = 0;
    uint16_t ucPublicKeyDerLength = 0;
    uint16_t asn1_header_size;
    CK_MECHANISM_TYPE xMechanism = pxMechanism->mechanism;

    CK_ATTRIBUTE_PTR pxPrivateLabel = NULL;
    CK_ATTRIBUTE_PTR pxPublicLabel = NULL;

    CK_OBJECT_HANDLE xPalPublic = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPalPrivate = CK_INVALID_HANDLE;

    long lOptigaOid_private = 0;
    long lOptigaOid_public = 0;

    optiga_rsa_key_type_t rsa_key_type = 0;
    uint8_t key_usage;
    long optiga_timeout = BUSY_WAIT_TIME_OUT;

    do {
        PKCS11_DEBUG("TRACE: C_GenerateKeyPair: session: 0x%p\r\n", (void *)pxSession);

        if (pxSession->slot_id >= PKCS11_MAX_SLOTS) {
            PKCS11_PRINT(
                "ERROR: C_GenerateKeyPair: Invalid SlotID 0x%X for session 0x%p\r\n",
                (int)pxSession->slot_id,
                (void *)pxSession
            );
            return CKR_SLOT_ID_INVALID;
        }
        PKCS11_DEBUG("TRACE: C_GenerateKeyPair: Slot: %d\r\n", (int)pxSession->slot_id);

        if ((CKM_EC_KEY_PAIR_GEN != xMechanism) && (CKM_RSA_PKCS_KEY_PAIR_GEN != xMechanism)) {
            PKCS11_PRINT(
                "ERROR: C_GenerateKeyPair: Invalid mechanism - not RSA or ECC: 0x%X\r\n",
                (int)xMechanism
            );
            return CKR_MECHANISM_PARAM_INVALID;
        }
        PKCS11_PRINT_MECHANISM(pxMechanism)
        PKCS11_PRINT_KEY("Public Key object", pxPublicKey)
        PKCS11_PRINT_KEY("Private Key object", pxPrivateKey)
        PKCS11_PRINT_TEMPLATE(pxPrivateKeyTemplate, ulPrivateKeyAttributeCount)

        /*======================= Verify received private key template =======================*/
        xResult = verify_private_key_template(
            xSession,
            xMechanism,
            &pxPrivateLabel,
            pxPrivateKeyTemplate,
            ulPrivateKeyAttributeCount
        );
        if (xResult != CKR_OK) {
            break;
        }
        if (pxPrivateLabel != NULL) {
            xPalPrivate = find_object_by_label(
                pxSession->slot_id,
                (char *)pxPrivateLabel->pValue,
                &lOptigaOid_private
            );
        } else /* Client doesn't provide PRIVATE LABEL - use hardcode Optiga private key OID for a specified slot */
        {
            xPalPrivate = supported_slots_mechanisms_list[pxSession->slot_id]
                              .logical_object_handle[1];  // Private key object
            lOptigaOid_private =
                optiga_objects_list[xPalPrivate].physical_oid;  // Optiga private key physical OID
        }
        PKCS11_DEBUG(
            "INFO: C_GenerateKeyPair: Optiga private key: Label: '%s' OID: 0x%04X\r\n",
            optiga_objects_list[xPalPrivate].text_label,
            (unsigned int)lOptigaOid_private
        );

        PKCS11_PRINT_TEMPLATE(pxPublicKeyTemplate, ulPublicKeyAttributeCount)
        /*======================= Verify received public key template =======================*/
        xResult = verify_public_key_template(
            xSession,
            &pxPublicLabel,
            pxPublicKeyTemplate,
            ulPublicKeyAttributeCount,
            NULL,
            0
        );
        if (xResult != CKR_OK) {
            break;
        }
        if (pxPublicLabel
            != NULL) /* Client doesn't provide PUBLIC LABEL - use hardcode Optiga public key OID for a specified slot */
        {
            xPalPublic = find_object_by_label(
                pxSession->slot_id,
                (char *)pxPublicLabel->pValue,
                &lOptigaOid_public
            );
        } else {
            xPalPublic = supported_slots_mechanisms_list[pxSession->slot_id]
                             .logical_object_handle[2];  // Public key object
            lOptigaOid_public =
                optiga_objects_list[xPalPublic].physical_oid;  // Optiga public key physical OID
        }
        PKCS11_DEBUG(
            "INFO: C_GenerateKeyPair: Optiga public key: Label: '%s' OID: 0x%04X\r\n",
            optiga_objects_list[xPalPublic].text_label,
            (unsigned int)lOptigaOid_public
        );

        /*========================= Call Optiga Trust M functions =========================*/
        if (0 != lOptigaOid_private) {
            /* For the public key, the OPTIGA library will return the standard 65 
                      bytes of uncompressed curve points plus a 3-byte tag. The latter will 
                       be intentionally overwritten below. */
            trustm_TimerStart();
            trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

            if (xMechanism
                == CKM_EC_KEY_PAIR_GEN) { /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
                ucPublicKeyBitLength = get_key_size(pxSession->key_alg_id);
                pucPublicKeyDer = malloc(ucPublicKeyBitLength);
                if (pucPublicKeyDer == NULL) {
                    PKCS11_PRINT("ERROR: %s: memory allocation error\r\n", __func__);
                    xResult = CKR_HOST_MEMORY;
                    break;
                }
                PKCS11_DEBUG(
                    "TRACE: C_GenerateKeyPair(EC): Enter optiga_crypt_ecc_generate_keypair. Key size(bytes): %d. Key type: %d\r\n",
                    ucPublicKeyBitLength,
                    (int)pxSession->key_alg_id
                );

                // pxSession->key_alg_id:
                //    0x03  OPTIGA_ECC_CURVE_NIST_P_256         Generate elliptic curve key based on NIST P256.
                //    0x04  OPTIGA_ECC_CURVE_NIST_P_384         Generate elliptic curve key based on NIST P384.
                //    0x05  OPTIGA_ECC_CURVE_NIST_P_521         Generate elliptic curve key based on ECC NIST P521.
                //    0x13  OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1	Generate elliptic curve key based on ECC Brainpool 256R1.
                //    0x15  OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1	Generate elliptic curve key based on ECC Brainpool 384R1.
                //    0x16  OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1	Generate elliptic curve key based on ECC Brainpool 512R1.

                optiga_lib_return = optiga_crypt_ecc_generate_keypair(
                    pkcs11_context.object_list.optiga_crypt_instance,
                    pxSession->key_alg_id,
                    (uint8_t)OPTIGA_KEY_USAGE_SIGN
                    //                                                            | OPTIGA_KEY_USAGE_AUTHENTICATION
                    //                                                            | OPTIGA_KEY_USAGE_KEY_AGREEMENT
                    //                                                            | OPTIGA_KEY_USAGE_ENCRYPTION
                    ,
                    FALSE,
                    &lOptigaOid_private,
                    pucPublicKeyDer,
                    &ucPublicKeyBitLength
                );

                PKCS11_DEBUG(
                    "TRACE: C_GenerateKeyPair(EC): Exit optiga_crypt_ecc_generate_keypair. Result: 0x%X. Key size(bytes): %d\r\n",
                    optiga_lib_return,
                    ucPublicKeyBitLength
                );
                ucPublicKeyDerLength = ucPublicKeyBitLength;
            } else /* if ( xMechanism == CKM_RSA_PKCS_KEY_PAIR_GEN ) */
            { /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
                ucPublicKeyBitLength = pxSession->rsa_key_size;
                pucPublicKeyDer = malloc(
                    pxSession->rsa_key_size + 100
                );  // JC:  Add more bytes for ASN.1 encoding of the RSA key
                    // ASN.1 header for RSA2048: 03 82 01 0F 00 30 82 01 0A 02 82 01 01 00
                if (pucPublicKeyDer == NULL) {
                    PKCS11_PRINT("ERROR: %s: memory allocation error\r\n", __func__);
                    xResult = CKR_HOST_MEMORY;
                    break;
                }

                if ((pxSession->key_template_enabled & PKCS_ENCRYPT_ENABLE)
                    && (pxSession->key_template_enabled & PKCS_DECRYPT_ENABLE)) {
                    key_usage = OPTIGA_KEY_USAGE_ENCRYPTION;
                }

                if ((pxSession->key_template_enabled & PKCS_SIGN_ENABLE)
                    && (pxSession->key_template_enabled & PKCS_VERIFY_ENABLE)) {
                    key_usage |= OPTIGA_KEY_USAGE_SIGN;
                }
                if (pxSession->rsa_key_size == pkcs11RSA_2048_MODULUS_BITS) {
                    rsa_key_type = OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;
                    asn1_header_size =
                        14;  // !!!JC FixMe: Parse ASN.1 header after optiga_crypt_rsa_generate_keypair
                } else {
                    rsa_key_type = OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;
                    asn1_header_size =
                        11;  // !!!JC FixMe: Parse ASN.1 header after optiga_crypt_rsa_generate_keypair
                }
                PKCS11_DEBUG(
                    "TRACE: C_GenerateKeyPair(RSA): Enter optiga_crypt_rsa_generate_keypair. Key size(bits): %d. Key type: %d\r\n",
                    ucPublicKeyBitLength,
                    (int)rsa_key_type
                );

                optiga_lib_return = optiga_crypt_rsa_generate_keypair(
                    pkcs11_context.object_list.optiga_crypt_instance,
                    rsa_key_type,
                    key_usage,
                    FALSE,
                    &lOptigaOid_private,
                    pucPublicKeyDer,
                    &ucPublicKeyBitLength
                );

                PKCS11_DEBUG(
                    "TRACE: C_GenerateKeyPair(RSA): Exit optiga_crypt_rsa_generate_keypair. Key size(bits): %d\r\n",
                    ucPublicKeyBitLength
                );
                ucPublicKeyDerLength =
                    ucPublicKeyBitLength / 8 + asn1_header_size;  // Bits -> bytes

                optiga_timeout = MAX_RSA_KEY_GEN_TIME;  // RSA keygen can take up to 60 sec
            } /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
            trustm_CheckStatus_WaitForCompletion(
                &optiga_lib_return,
                optiga_timeout,
                "optiga_crypt_rsa_generate_keypair"
            );
            if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
                xResult = CKR_FUNCTION_FAILED;
                break;
            }
            PKCS11_DEBUG("TRACE: C_GenerateKeyPair: Keypair generated successfully\r\n");
        } else {
            PKCS11_PRINT("ERROR: Wrong Optiga OID \r\n");
            xResult = CKR_FUNCTION_FAILED;
            break;
        }

        PKCS11_DEBUG(
            "TRACE: C_GenerateKeyPair: Public key generated (len=%d)\r\n",
            ucPublicKeyDerLength
        );
        HEXDUMP("", pucPublicKeyDer, ucPublicKeyDerLength);
        /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
        if (xResult == CKR_OK) {
            if (upload_public_key(
                    lOptigaOid_public,
                    pxSession->key_alg_id,
                    pucPublicKeyDer,
                    ucPublicKeyDerLength
                )
                != OPTIGA_LIB_SUCCESS) {
                PKCS11_PRINT(
                    "ERROR: C_GenerateKeyPair: upload_public_key to object %s failed\r\n",
                    optiga_objects_list[xPalPublic].text_label
                );
                xResult = CKR_DEVICE_ERROR;
                break;
            } else {
                PKCS11_DEBUG(
                    "TRACE: C_GenerateKeyPair: Public key object %d saved (len=%d)\r\n",
                    (int)xPalPublic,
                    ucPublicKeyDerLength
                );
                *pxPublicKey = xPalPublic;
                *pxPrivateKey = xPalPrivate;
            }
        } else {
            xResult = CKR_GENERAL_ERROR;
            break;
        }
    } while (0);

    /* Clean up - deallocate memory */
    if (NULL != pucPublicKeyDer) {
        free(pucPublicKeyDer);
    }
    return xResult;
}
/**************************************************************************
 * @brief Begin creating a digital signature.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
(CK_SESSION_HANDLE xSession, CK_MECHANISM_PTR pxMechanism, CK_OBJECT_HANDLE xKey) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    CK_OBJECT_HANDLE xPalHandle;
    long lOptigaOid = 0;

    if (NULL == pxMechanism) {
        PKCS11_PRINT("ERROR: C_SignInit: Mechanism not provided in parameters\r\n");
        return CKR_ARGUMENTS_BAD;
    }
    PKCS11_PRINT_MECHANISM(pxMechanism)
    PKCS11_PRINT_KEY("Private Key object", xKey)

    /* Retrieve key value from storage. */
    xPalHandle = find_object_by_handle(xKey, &lOptigaOid);
    if (xPalHandle == CK_INVALID_HANDLE) {
        PKCS11_PRINT("ERROR: C_SignInit: Object 0x%X not found\r\n", (int)xKey);
        return CKR_KEY_HANDLE_INVALID;
    }
    pxSession->key_object_handle = xPalHandle;
    pxSession->sign_key_oid = (uint16_t)lOptigaOid;

    /* Check that the mechanism and key type are compatible, supported.  Update the signature length. */
    if ((pxSession->signature_size = check_signature_scheme_get_signature_size(
             pxSession,
             pxMechanism->mechanism,
             xPalHandle,
             0
         ))
        == 0) {
        PKCS11_PRINT("ERROR: C_SignInit: Invalid mechanism: 0x%X\r\n", pxMechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    } else {
        pxSession->sign_mechanism = pxMechanism->mechanism;
        PKCS11_DEBUG(
            "TRACE: C_SignInit: Mechanism: 0x%X(parameters:%d). Key algorithm: 0x%X\r\n",
            pxMechanism->mechanism,
            pxMechanism->ulParameterLen,
            pxSession->key_alg_id
        );
        pxSession->sign_init_done = TRUE;
    }
    return CKR_OK;
}
/**************************************************************************
 * @brief Performs a digital signature operation.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(CK_SESSION_HANDLE xSession,
 CK_BYTE_PTR pucData,
 CK_ULONG ulDataLen,
 CK_BYTE_PTR pucSignature,
 CK_ULONG_PTR pulSignatureLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;

    if (TRUE != pxSession->sign_init_done) {
        PKCS11_PRINT("ERROR: C_Sign: Operation not initialized by C_SignInit\r\n");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (NULL == pulSignatureLen || 0 == ulDataLen) {
        PKCS11_PRINT("ERROR: C_Sign: Wrong arguments: pulSignatureLen or ulDataLen is null\r\n");
        return CKR_ARGUMENTS_BAD;
    }

    /* Caller trying to determine the length of the buffer needed to hold the signature */
    if (*pulSignatureLen == 0) {
        *pulSignatureLen = pxSession->signature_size;
        return CKR_OK;
    }

    /* Check that the signature buffer is long enough. */
    if (*pulSignatureLen < pxSession->signature_size) {
        PKCS11_PRINT(
            "ERROR: C_Sign: Signature buffer too small: %d, should be at least %d\r\n",
            *pulSignatureLen,
            pxSession->signature_size
        );
        return CKR_BUFFER_TOO_SMALL;
    }
    if (0 == pxSession->sign_key_oid) {
        PKCS11_PRINT("ERROR: C_Sign: Wrong OID was provided in C_SignInit\r\n");
        return CKR_ARGUMENTS_BAD;
    }

    optiga_lib_return = optiga_trustm_sign_data(
        pxSession->sign_mechanism,
        pxSession->key_alg_id,
        pxSession->sign_key_oid,
        pucData,
        ulDataLen,
        pucSignature,
        pxSession->signature_size
    );
    if (optiga_lib_return != OPTIGA_LIB_SUCCESS)
        return CKR_FUNCTION_FAILED;
    *pulSignatureLen = pxSession->signature_size;
    pxSession->sign_mechanism = pkcs11NO_OPERATION;
    return xResult;
}
/**************************************************************************
    C_SignUpdate                                     !!! NOT SUPPORTED
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR part, CK_ULONG part_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    HEXDUMP("TRACE: C_SignUpdate - NOT IMPLEMENTED !!!: Data: ", part, part_len);
    return CKR_FUNCTION_NOT_SUPPORTED;
}
/**************************************************************************
    C_SignFinal                                     !!! NOT SUPPORTED
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    PKCS11_DEBUG("TRACE: C_SignFinal - NOT IMPLEMENTED !!!\r\n");
    return CKR_OK;
}
/**************************************************************************
 * @brief Begin a digital signature verification.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)
(CK_SESSION_HANDLE xSession, CK_MECHANISM_PTR pxMechanism, CK_OBJECT_HANDLE xKey) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    uint8_t *pxLabel = NULL;
    size_t xLabelLength = 0;
    CK_LONG lOptigaOid = 0;

    do {
        if (NULL == pxMechanism) {
            PKCS11_PRINT("ERROR: C_VerifyInit: Mechanism not provided in parameters\r\n");
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        PKCS11_PRINT_MECHANISM(pxMechanism)
        PKCS11_PRINT_KEY("Public Key object", xKey)

        /* Retrieve key value from storage. */
        xPalHandle = find_object_by_handle(xKey, &lOptigaOid);
        if (xPalHandle == CK_INVALID_HANDLE) {
            PKCS11_PRINT("ERROR: C_VerifyInit: Object 0x%X not found\r\n", (int)xKey);
            return CKR_KEY_HANDLE_INVALID;
        }
        pxSession->verify_key_oid = (uint16_t)lOptigaOid;
        pxSession->key_object_handle = xPalHandle;

        /* Check that the mechanism and key type are compatible, supported. */
        if (check_signature_scheme_get_signature_size(
                pxSession,
                pxMechanism->mechanism,
                0,
                xPalHandle
            )
            == 0) {
            xResult = CKR_MECHANISM_INVALID;
            break;
        } else {
            pxSession->verify_mechanism = pxMechanism->mechanism;
            PKCS11_DEBUG(
                "TRACE: C_VerifyInit: Mechanism: 0x%X(parameters:%d). Key algorithm: 0x%X\r\n",
                pxMechanism->mechanism,
                pxMechanism->ulParameterLen,
                pxSession->key_alg_id
            );
        }
        pxSession->verify_init_done = TRUE;
    } while (0);
    return xResult;
}
/**************************************************************************
 * @brief Verifies a digital signature.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Verify)
(CK_SESSION_HANDLE xSession,
 CK_BYTE_PTR pucData,
 CK_ULONG ulDataLen,
 CK_BYTE_PTR pucSignature,
 CK_ULONG ulSignatureLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    uint8_t temp[2048];
    uint16_t tempLen = 2048;
    public_key_from_host_t xPublicKeyDetails = {0};
    optiga_rsa_signature_scheme_t rsa_signature_scheme = 0;
    CK_ULONG xSignatureLength = 0;
    /* (R component ) + (S component ) + DER tags 3 bytes max each*/
    CK_BYTE pubASN1Signature[pkcs11ECDSA_P521_SIGNATURE_LENGTH + 0x03 + 0x03];
    CK_ULONG pubASN1SignatureLength = sizeof(pubASN1Signature);

    do {
        if (TRUE != pxSession->verify_init_done) {
            PKCS11_PRINT("ERROR: C_Verify: Operation not initialized by C_VerifyInit\r\n");
            xResult = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }
        /* Check parameters. */
        if (NULL == pucData || ulDataLen == 0) {
            PKCS11_PRINT("ERROR: C_Verify: data is NULL\r\n");
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        if (NULL == pucSignature || ulSignatureLen == 0) {
            PKCS11_PRINT("ERROR: C_Verify: signature is NULL\r\n");
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        HEXDUMP("TRACE: C_Verify: Data:      ", pucData, ulDataLen);
        HEXDUMP("TRACE: C_Verify: Signature: ", pucSignature, ulSignatureLen);

        /* Update the signature length. */
        xSignatureLength = check_signature_scheme_get_signature_size(
            pxSession,
            pxSession->verify_mechanism,
            0,
            pxSession->key_object_handle
        );
        if (xSignatureLength == 0) {
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        /* Check that the signature size is correct. */
        if (ulSignatureLen != xSignatureLength) {
            PKCS11_PRINT(
                "ERROR: C_Verify: Incorrect EC signature length provided in parameters: %d, expected: %d\r\n",
                ulSignatureLen,
                xSignatureLength
            );
            xResult = CKR_SIGNATURE_LEN_RANGE;
            break;
        }

        /* Check that the signature and data are the expected length.
         * These PKCS #11 mechanism expect data to be pre-hashed/formatted. */
        if (pxSession->verify_mechanism == CKM_ECDSA) {
            if (ulDataLen > (xSignatureLength / 2))  //!!! only support up to the 256/384/512 bit
            {
                PKCS11_PRINT("ERROR: C_Verify: Wrong EC data length: %d\r\n", ulDataLen);
                xResult = CKR_DATA_LEN_RANGE;
                break;
            }
            /* Convert RS format to ASN.1 */
            if (!ecdsa_rs_to_asn1_integers(
                    &pucSignature[0],
                    &pucSignature[xSignatureLength / 2],
                    (size_t)(xSignatureLength / 2),
                    pubASN1Signature,
                    (size_t *)&pubASN1SignatureLength
                )) {
                PKCS11_PRINT(
                    "ERROR: C_Verify: Failed to convert EC signature (%d bytes) from RS to ASN.1 format\r\n",
                    xSignatureLength
                );
                xResult = CKR_SIGNATURE_INVALID;
                break;
            }
        }

        /*- - - - - - - -  Read public key from Optiga - - - - - - - - */
        optiga_lib_return = optiga_trustm_read_data(
            pxSession->verify_key_oid,
            0,
            temp,
            &tempLen,
            OPTIGA_COMMS_FULL_PROTECTION
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return || tempLen == 0) {
            PKCS11_PRINT("ERROR: C_Verify: Failed to extract Public Key from Optiga\r\n");
            return CKR_DEVICE_ERROR;
        }
        tempLen = find_public_key_in_der(temp);
        HEXDUMP("Pub.Key: ", temp, tempLen);

        /*- - - - - - - - Perform an ECDSA verification. - - - - - - - - */
        trustm_TimerStart();
        trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

        if (pxSession->verify_mechanism == CKM_ECDSA) {
            xPublicKeyDetails.public_key = temp;
            xPublicKeyDetails.length = tempLen;
            xPublicKeyDetails.key_type = pxSession->key_alg_id;

            optiga_lib_return = optiga_crypt_ecdsa_verify(
                pkcs11_context.object_list.optiga_crypt_instance,
                pucData,
                ulDataLen,
                pubASN1Signature,
                pubASN1SignatureLength,
                OPTIGA_CRYPT_HOST_DATA,
                &xPublicKeyDetails
            );

            trustm_CheckStatus_WaitForCompletion(
                &optiga_lib_return,
                BUSY_WAIT_TIME_OUT,
                "optiga_crypt_ecdsa_verify"
            );
        }
#ifdef PKCS11_SUPPORT_RSA
        else if (CKR_OK == set_valid_rsa_signature_scheme(pxSession->verify_mechanism, &rsa_signature_scheme)) {
            xPublicKeyDetails.public_key = temp;
            xPublicKeyDetails.length = tempLen;
            xPublicKeyDetails.key_type =
                (pxSession->rsa_key_size == pkcs11RSA_2048_MODULUS_BITS
                     ? OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL
                     : OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL);

            optiga_lib_return = optiga_crypt_rsa_verify(
                pkcs11_context.object_list.optiga_crypt_instance,
                rsa_signature_scheme,
                pucData,
                ulDataLen,
                pucSignature,
                ulSignatureLen,
                OPTIGA_CRYPT_HOST_DATA,
                &xPublicKeyDetails,
                0x0000
            );

            trustm_CheckStatus_WaitForCompletion(
                &optiga_lib_return,
                BUSY_WAIT_TIME_OUT,
                "optiga_crypt_rsa_verify"
            );
        }
#endif
        else {
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT("ERROR: C_Verify: Failed to verify the signature\r\n");
            xResult = CKR_SIGNATURE_INVALID;
            break;
        }
    } while (0);
    /* Return the signature verification result. */
    if (xResult != CKR_OK) {
        PKCS11_PRINT("CK_RV ERROR:%#010lX\r\n", xResult);
        xResult = CKR_SIGNATURE_INVALID;
    }
    return xResult;
}
/**************************************************************************
    C_VerifyUpdate                                  !!! NOT SUPPORTED
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR part, CK_ULONG part_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    HEXDUMP("TRACE: C_VerifyUpdate - NOT IMPLEMENTED !!!: Data: ", part, part_len);
    return CKR_OK;
}
/**************************************************************************
    C_VerifyFinal                                   !!! NOT SUPPORTED
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR signature, CK_ULONG signature_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    PKCS11_DEBUG("TRACE: C_VerifyFinal - NOT IMPLEMENTED !!!\r\n");
    return CKR_OK;
}
/**************************************************************************
 * @brief Generate cryptographically random bytes.
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR pucRandomData, CK_ULONG ulRandomLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    // this is to truncate random numbers to the required length, as OPTIGA(TM) Trust can generate
    // values starting from 8 bytes
    CK_BYTE xRandomBuf4SmallLengths[8];
    CK_ULONG xBuferSwitcherLength = ulRandomLen;
    CK_BYTE_PTR pxBufferSwitcher = pucRandomData;

    do {
        if (xResult != CKR_OK) {
            break;
        }
        if ((NULL == pucRandomData) || (ulRandomLen == 0)) {
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        if (xBuferSwitcherLength < sizeof(xRandomBuf4SmallLengths)) {
            pxBufferSwitcher = xRandomBuf4SmallLengths;
            xBuferSwitcherLength = sizeof(xRandomBuf4SmallLengths);
        }

        trustm_TimerStart();
        trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

        optiga_lib_return = optiga_crypt_random(
            pkcs11_context.object_list.optiga_crypt_instance,
            OPTIGA_RNG_TYPE_TRNG,
            pxBufferSwitcher,
            xBuferSwitcherLength
        );

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_crypt_random"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT(
                "ERROR: Failed to generate random value %d bytes long\r\n",
                xBuferSwitcherLength
            );
            xResult = CKR_SIGNATURE_INVALID;
            break;
        }

        if (pxBufferSwitcher == xRandomBuf4SmallLengths) {
            memcpy(pucRandomData, xRandomBuf4SmallLengths, ulRandomLen);
            HEXDUMP("TRACE: C_GenerateRandom: Random: ", pucRandomData, ulRandomLen);
        }
    } while (0);
    return xResult;
}
/**************************************************************************
    C_EncryptInit                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)
(CK_SESSION_HANDLE xSession, CK_MECHANISM_PTR pxMechanism, CK_OBJECT_HANDLE xKey) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    uint8_t *pxLabel = NULL;
    size_t xLabelLength = 0;
    CK_LONG lOptigaOid = 0;

    do {
        if (!(pxSession->key_template_enabled & PKCS_ENCRYPT_ENABLE)) {
            xResult = CKR_KEY_FUNCTION_NOT_PERMITTED;
            break;
        }
        if (NULL == pxMechanism) {
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        PKCS11_PRINT_MECHANISM(pxMechanism)
        PKCS11_PRINT_KEY("Key object", xKey)

        /* Retrieve key value from storage. */
        xPalHandle = find_object_by_handle(xKey, &lOptigaOid);
        if (xPalHandle == CK_INVALID_HANDLE) {
            PKCS11_PRINT("ERROR: C_EncryptInit: Object 0x%X not found\r\n", (int)xKey);
            PKCS11_PRINT(
                "ERROR: C_EncryptInit: Unable to retrieve value of public key for encryption\r\n"
            );
            return CKR_KEY_HANDLE_INVALID;
        }
        pxSession->encryption_key_oid = (uint16_t)lOptigaOid;

        //        find_object_by_handle( xKey, &xPalHandle, &pxLabel, &xLabelLength );
        //
        //        if( xPalHandle != CK_INVALID_HANDLE )
        //        {
        //            lOptigaOid = strtol((char*)pxLabel, &xEnd, 16);
        //
        //            if (0 != lOptigaOid)
        //            {
        //                pxSession->encryption_key_oid = (uint16_t) lOptigaOid;
        //            }
        //            else
        //            {
        //                PKCS11_PRINT("ERROR: Unable to retrieve value of public key for encryption %d. \r\n", xResult);
        //                xResult = CKR_ARGUMENTS_BAD;
        //                break;
        //            }
        //        }
        //        else
        //        {
        //            xResult = CKR_KEY_HANDLE_INVALID;
        //        }
        pxSession->encrypt_init_done = TRUE;

    } while (0);
    return xResult;
}
/**************************************************************************
    C_Encrypt                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)
(CK_SESSION_HANDLE xSession,
 CK_BYTE_PTR pxData,
 CK_ULONG ulDataLen,
 CK_BYTE_PTR pxEncryptedData,
 CK_ULONG_PTR pxulEncryptedDataLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    uint8_t temp[2048];
    uint16_t tempLen = sizeof(temp);
    uint8_t key_type;
    uint16_t key_size_bytes = pxSession->rsa_key_size / 8;
    public_key_from_host_t xPublicKeyDetails = {0};

    HEXDUMP("TRACE: C_Encrypt: Data: ", pxData, ulDataLen);
    do {
        if (FALSE == pxSession->encrypt_init_done) {
            PKCS11_PRINT(
                "ERROR: C_Encrypt: Encryption operation not initialized (C_EncryptInit)\r\n"
            );
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        key_type = (uint8_t
        )(pxSession->rsa_key_size == pkcs11RSA_2048_MODULUS_BITS
              ? OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL
              : OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL);

        if (((key_type == OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL)
             && (ulDataLen > ((pkcs11RSA_1024_MODULUS_BITS / 8) - 11)))
            || ((key_type == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
                && (ulDataLen > ((pkcs11RSA_2048_MODULUS_BITS / 8) - 11)))) {
            return CKR_ARGUMENTS_BAD;
        }

        /* Caller trying to determine the length of the buffer needed to hold the signature */
        if (*pxulEncryptedDataLen == 0) {
            *pxulEncryptedDataLen = key_size_bytes;
            return CKR_OK;
        }

        if (*pxulEncryptedDataLen < key_size_bytes) {
            PKCS11_PRINT(
                "ERROR: C_Encrypt: Reserved output buffer too small: %d, should be at least %d\r\n",
                *pxulEncryptedDataLen,
                key_size_bytes
            );
            return CKR_BUFFER_TOO_SMALL;
        }

        /*- - - - - - - -  Read Public key from Optiga - - - - - - - - */
        optiga_lib_return = optiga_trustm_read_data(
            pxSession->encryption_key_oid,
            0,
            temp,
            &tempLen,
            OPTIGA_COMMS_FULL_PROTECTION
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT("ERROR: C_Encrypt: Failed to extract Public Key from Optiga\r\n");
            return CKR_DEVICE_ERROR;
        }

        trustm_TimerStart();
        trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

        xPublicKeyDetails.public_key = temp;
        xPublicKeyDetails.length = tempLen;
        xPublicKeyDetails.key_type = key_type;

        optiga_lib_return = optiga_crypt_rsa_encrypt_message(
            pkcs11_context.object_list.optiga_crypt_instance,
            OPTIGA_RSAES_PKCS1_V15,
            pxData,
            ulDataLen,
            NULL,
            0,
            OPTIGA_CRYPT_HOST_DATA,
            &xPublicKeyDetails,
            pxEncryptedData,
            (uint16_t *)pxulEncryptedDataLen
        );

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_crypt_rsa_encrypt_message"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT(("ERROR: Failed to encrypt value \r\n"));
            xResult = CKR_ENCRYPTED_DATA_INVALID;
            break;
        }
    } while (0);
    return xResult;
}
/**************************************************************************
    C_EncryptUpdate                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)
(CK_SESSION_HANDLE xSession,
 CK_BYTE_PTR part,
 CK_ULONG part_len,
 CK_BYTE_PTR encrypted_part,
 CK_ULONG_PTR encrypted_part_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    HEXDUMP("TRACE: C_EncryptUpdate - NOT IMPLEMENTED !!!: Data: ", part, part_len);
    return CKR_OK;
}
/**************************************************************************
    C_EncryptFinal                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR last_encrypted_part, CK_ULONG_PTR last_encrypted_part_len
) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    PKCS11_DEBUG("TRACE: C_EncryptFinal - NOT IMPLEMENTED !!!\r\n");
    return CKR_OK;
}
/**************************************************************************
    C_DecryptInit                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)
(CK_SESSION_HANDLE xSession, CK_MECHANISM *pxMechanism, CK_OBJECT_HANDLE xKey) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    CK_LONG lOptigaOid = 0;

    do {
        if (!(pxSession->key_template_enabled & PKCS_DECRYPT_ENABLE)) {
            xResult = CKR_KEY_FUNCTION_NOT_PERMITTED;
            break;
        }
        if (NULL == pxMechanism) {
            xResult = CKR_ARGUMENTS_BAD;
            break;
        }
        PKCS11_PRINT_MECHANISM(pxMechanism)
        PKCS11_PRINT_KEY("Key object", xKey)

        /* Retrieve key value from storage. */
        xPalHandle = find_object_by_handle(xKey, &lOptigaOid);
        if (xPalHandle == CK_INVALID_HANDLE) {
            PKCS11_PRINT("ERROR: C_DecryptInit: Object 0x%X not found\r\n", (int)xKey);
            PKCS11_PRINT(
                "ERROR: C_DecryptInit: Unable to retrieve value of private key for decryption\r\n"
            );
            return CKR_KEY_HANDLE_INVALID;
        }
        pxSession->decryption_key_oid = (uint16_t)lOptigaOid;
        pxSession->decrypt_init_done = TRUE;
    } while (0);
    return xResult;
}
/**************************************************************************
    C_Decrypt                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)
(CK_SESSION_HANDLE xSession,
 CK_BYTE_PTR encrypted_data,
 CK_ULONG encrypted_data_len,
 CK_BYTE_PTR data,
 CK_ULONG_PTR data_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    uint8_t key_type;
    uint16_t key_size_bytes = pxSession->rsa_key_size / 8;

    HEXDUMP("TRACE: C_Decrypt: Data: ", encrypted_data, encrypted_data_len);
    do {
        if (FALSE == pxSession->decrypt_init_done) {
            PKCS11_PRINT(
                "ERROR: C_Decrypt: Decryption operation not initialized (C_DecryptInit)\r\n"
            );
            return CKR_OPERATION_NOT_INITIALIZED;
        }

        //JC!!!        key_type = (uint8_t)(pxSession->rsa_key_size == pkcs11RSA_2048_MODULUS_BITS ?
        //                                                      OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL :
        //                                                      OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL);
        if (key_size_bytes != encrypted_data_len) {
            return CKR_ENCRYPTED_DATA_LEN_RANGE;
        }

        /* Caller trying to determine the length of the buffer needed to hold the signature */
        if (*data_len == 0) {
            *data_len = key_size_bytes;
            return CKR_OK;
        }

        if (*data_len < key_size_bytes) {
            PKCS11_PRINT(
                "ERROR: C_Decrypt: Reserved output buffer too small: %d, should be at least %d\r\n",
                *data_len,
                key_size_bytes
            );
            return CKR_BUFFER_TOO_SMALL;
        }

        trustm_TimerStart();
        trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

        optiga_lib_return = optiga_crypt_rsa_decrypt_and_export(
            pkcs11_context.object_list.optiga_crypt_instance,
            OPTIGA_RSAES_PKCS1_V15,
            encrypted_data,
            encrypted_data_len,
            NULL,
            0,
            pxSession->decryption_key_oid,
            data,
            (uint16_t *)data_len
        );

        trustm_CheckStatus_WaitForCompletion(
            &optiga_lib_return,
            BUSY_WAIT_TIME_OUT,
            "optiga_crypt_rsa_decrypt_and_export"
        );
        if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
            PKCS11_PRINT("ERROR: C_Decrypt: Failed to decrypt value\r\n");
            xResult = CKR_ENCRYPTED_DATA_INVALID;
            break;
        }
    } while (0);
    return xResult;
}
/**************************************************************************
    C_DecryptUpdate                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)
(CK_SESSION_HANDLE xSession,
 CK_BYTE_PTR encrypted_part,
 CK_ULONG encrypted_part_len,
 CK_BYTE_PTR part,
 CK_ULONG_PTR part_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    HEXDUMP(
        "TRACE: C_DecryptUpdate - NOT IMPLEMENTED !!!: Data: ",
        encrypted_part,
        encrypted_part_len
    );
    return CKR_OK;
}
/**************************************************************************
    C_DecryptFinal                                 !!!JC  NOT CHECKED YET
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    PKCS11_DEBUG("TRACE: C_DecryptFinal - NOT IMPLEMENTED !!!\r\n");
    return CKR_OK;
}
/**************************************************************************
    C_DigestInit                        Only SHA256 supported
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE xSession, CK_MECHANISM_PTR pMechanism) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    int lib_return = OPTIGA_UTIL_ERROR;
    PKCS11_PRINT_MECHANISM(pMechanism)

    if (pMechanism->mechanism != CKM_SHA256) {
        PKCS11_PRINT("ERROR: C_DigestInit: Mechanism not supported\r\n");
        return CKR_MECHANISM_INVALID;
    }
#ifdef USE_OPTIGA_SHA
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    pxSession->sha256_ctx.hash_ctx.context_buffer = pxSession->sha256_ctx.hash_ctx_buff;
    pxSession->sha256_ctx.hash_ctx.context_buffer_length =
        sizeof(pxSession->sha256_ctx.hash_ctx_buff);
    pxSession->sha256_ctx.hash_ctx.hash_algo = OPTIGA_HASH_TYPE_SHA_256;

    //Hash start
    trustm_TimerStart();
    trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

    optiga_lib_return = optiga_crypt_hash_start(
        pkcs11_context.object_list.optiga_crypt_instance,
        &pxSession->sha256_ctx.hash_ctx
    );

    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_crypt_hash_start"
    );
    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
        PKCS11_PRINT(
            "ERROR: C_DigestInit: Failed in optiga_crypt_hash_start. Error: 0x%X\r\n",
            optiga_lib_return
        );
        return CKR_FUNCTION_FAILED;
    }
#else
    mbedtls_sha256_init(&pxSession->sha256_ctx);
    if ((lib_return = mbedtls_sha256_starts_ret(&pxSession->sha256_ctx, 0)) != 0) {
        PKCS11_PRINT(
            "ERROR: C_DigestInit: Failed in mbedtls_sha256_starts_ret. Error: 0x%X\r\n",
            lib_return
        );
        return CKR_FUNCTION_FAILED;
    }

#endif
    pxSession->operation_in_progress = pMechanism->mechanism;
    return xResult;
}
/**************************************************************************
    C_DigestUpdate                      Only SHA256 supported
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    int lib_return = OPTIGA_UTIL_ERROR;

    if (pxSession->operation_in_progress != CKM_SHA256) {
        PKCS11_PRINT("ERROR: C_DigestUpdate: Digest operation not initialized\r\n");
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    HEXDUMP("TRACE: C_DigestUpdate: Data: ", pPart, ulPartLen);
#ifdef USE_OPTIGA_SHA
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    hash_data_from_host_t hash_data_host;
    hash_data_host.buffer = pPart;
    hash_data_host.length = ulPartLen;

    trustm_TimerStart();
    trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

    optiga_lib_return = optiga_crypt_hash_update(
        pkcs11_context.object_list.optiga_crypt_instance,
        &pxSession->sha256_ctx.hash_ctx,
        OPTIGA_CRYPT_HOST_DATA,
        &hash_data_host
    );

    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_crypt_hash_update"
    );
    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
        PKCS11_PRINT(
            "ERROR: C_DigestUpdate: Failed in optiga_crypt_hash_update. Error: 0x%X\r\n",
            optiga_lib_return
        );
        return CKR_FUNCTION_FAILED;
    }
#else
    if ((lib_return = mbedtls_sha256_update_ret(&pxSession->sha256_ctx, pPart, ulPartLen)) != 0) {
        PKCS11_PRINT(
            "ERROR: C_DigestUpdate: Failed in mbedtls_sha256_update_ret. Error: 0x%X\r\n",
            lib_return
        );
        return CKR_FUNCTION_FAILED;
    }
#endif
    return CKR_OK;
}
/**************************************************************************
    C_DigestFinal                   Only SHA256 supported
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(CK_SESSION_HANDLE xSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    int lib_return = OPTIGA_UTIL_ERROR;

    if (pxSession->operation_in_progress != CKM_SHA256) {
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        PKCS11_PRINT("ERROR: C_DigestFinal: Digest operation not initialized\r\n");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (pDigest == NULL) {
        *pulDigestLen = pkcs11SHA256_DIGEST_LENGTH; /* Supply the required buffer size. */
        return CKR_OK;
    }
    if (*pulDigestLen < pkcs11SHA256_DIGEST_LENGTH) {
        PKCS11_PRINT(
            "ERROR: C_DigestFinal: Reserved output buffer too small: %d, should be at least %d\r\n",
            *pulDigestLen,
            pkcs11SHA256_DIGEST_LENGTH
        );
        return CKR_BUFFER_TOO_SMALL;
    }

#ifdef USE_OPTIGA_SHA
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    trustm_TimerStart();
    trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

    optiga_lib_return = optiga_crypt_hash_finalize(
        pkcs11_context.object_list.optiga_crypt_instance,
        &pxSession->sha256_ctx.hash_ctx,
        pDigest
    );

    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_crypt_hash_finalize"
    );
    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
        PKCS11_PRINT(
            "ERROR: C_DigestFinal: Failed in optiga_crypt_hash_finalize. Error: 0x%X\r\n",
            optiga_lib_return
        );
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        return CKR_FUNCTION_FAILED;
    }
#else
    if ((lib_return = mbedtls_sha256_finish_ret(&pxSession->sha256_ctx, pDigest)) != 0) {
        PKCS11_PRINT(
            "ERROR: C_DigestFinal: Failed in mbedtls_sha256_finish_ret. Error: 0x%X\r\n",
            lib_return
        );
        mbedtls_sha256_free(&pxSession->sha256_ctx);
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        return CKR_FUNCTION_FAILED;
    }
    mbedtls_sha256_free(&pxSession->sha256_ctx);
#endif
    pxSession->operation_in_progress = pkcs11NO_OPERATION;
    *pulDigestLen = pkcs11SHA256_DIGEST_LENGTH;
    HEXDUMP("Digest: ", pDigest, *pulDigestLen);
    return CKR_OK;
}

/**************************************************************************
    C_Digest                              Only SHA256 supported
     Uses MbedTLS software library
        mbedtls_sha256_context sha256_ctx;
        mbedtls_sha256_init(&sha256_ctx);
        mbedtls_sha256_starts_ret(&sha256_ctx, 0);
        mbedtls_sha256_update_ret(&sha256_ctx, message, message_len);
        mbedtls_sha256_finish_ret(&sha256_ctx, digest);
        mbedtls_sha256_free(&sha256_ctx);

     Can also use openssl
        sha256_ctx sha256;
        sha256_init(&sha256);
        const int bufsize = 32768;
        char* buffer = malloc(bufsize);
        int bytesread = 0;
        if(!buffer) return -1;
        while((bytesread = fread(buffer, 1, bufsize, fp)))
            sha256_update(&sha256, buffer, bytesread);
        sha256_final(digest, &sha256);
 **************************************************************************/
CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(CK_SESSION_HANDLE xSession,
 CK_BYTE_PTR pData,
 CK_ULONG ulDataLen,
 CK_BYTE_PTR pDigest,
 CK_ULONG_PTR pulDigestLen) {
    PKCS11_MODULE_INITIALIZED_AND_SESSION_VALID(xSession);
    int lib_return = OPTIGA_UTIL_ERROR;

    if (pxSession->operation_in_progress != CKM_SHA256) {
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        PKCS11_PRINT("ERROR: C_Digest: Digest operation not initialized\r\n");
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (pDigest == NULL) {
        *pulDigestLen = pkcs11SHA256_DIGEST_LENGTH; /* Supply the required buffer size. */
        return CKR_OK;
    }
    if (*pulDigestLen < pkcs11SHA256_DIGEST_LENGTH) {
        PKCS11_PRINT(
            "ERROR: C_Digest: Reserved output buffer too small: %d, should be at least %d\r\n",
            *pulDigestLen,
            pkcs11SHA256_DIGEST_LENGTH
        );
        return CKR_BUFFER_TOO_SMALL;
    }

    HEXDUMP("TRACE: C_Digest: Data: ", pData, ulDataLen);
#ifdef USE_OPTIGA_SHA
    optiga_lib_status_t optiga_lib_return = OPTIGA_UTIL_ERROR;
    hash_data_from_host_t hash_data_host;
    hash_data_host.buffer = pData;
    hash_data_host.length = ulDataLen;

    trustm_TimerStart();
    trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

    optiga_lib_return = optiga_crypt_hash_update(
        pkcs11_context.object_list.optiga_crypt_instance,
        &pxSession->sha256_ctx.hash_ctx,
        OPTIGA_CRYPT_HOST_DATA,
        &hash_data_host
    );

    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_crypt_hash_update"
    );
    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
        PKCS11_PRINT(
            "ERROR: C_Digest: Failed in optiga_crypt_hash_update. Error: 0x%X\r\n",
            optiga_lib_return
        );
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        return CKR_FUNCTION_FAILED;
    }
    // hash finalize
    trustm_TimerStart();
    trustm_crypt_ShieldedConnection(OPTIGA_COMMS_FULL_PROTECTION);

    optiga_lib_return = optiga_crypt_hash_finalize(
        pkcs11_context.object_list.optiga_crypt_instance,
        &pxSession->sha256_ctx.hash_ctx,
        pDigest
    );

    trustm_CheckStatus_WaitForCompletion(
        &optiga_lib_return,
        BUSY_WAIT_TIME_OUT,
        "optiga_crypt_hash_finalize"
    );
    if (OPTIGA_LIB_SUCCESS != optiga_lib_return) {
        PKCS11_PRINT(
            "ERROR: C_Digest: Failed in optiga_crypt_hash_finalize. Error: 0x%X\r\n",
            optiga_lib_return
        );
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        return CKR_FUNCTION_FAILED;
    }

#else
    if ((lib_return = mbedtls_sha256_update_ret(&pxSession->sha256_ctx, pData, ulDataLen)) != 0) {
        PKCS11_PRINT(
            "ERROR: C_Digest: Failed in mbedtls_sha256_update_ret. Error: 0x%X\r\n",
            lib_return
        );
        mbedtls_sha256_free(&pxSession->sha256_ctx);
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        return CKR_FUNCTION_FAILED;
    }
    if ((lib_return = mbedtls_sha256_finish_ret(&pxSession->sha256_ctx, pDigest)) != 0) {
        PKCS11_PRINT(
            "ERROR: C_Digest: Failed in mbedtls_sha256_finish_ret. Error: 0x%X\r\n",
            lib_return
        );
        mbedtls_sha256_free(&pxSession->sha256_ctx);
        pxSession->operation_in_progress = pkcs11NO_OPERATION;
        return CKR_FUNCTION_FAILED;
    }
    mbedtls_sha256_free(&pxSession->sha256_ctx);
#endif
    pxSession->operation_in_progress = pkcs11NO_OPERATION;
    *pulDigestLen = pkcs11SHA256_DIGEST_LENGTH;
    HEXDUMP("Digest: ", pDigest, *pulDigestLen);
    return CKR_OK;
}
