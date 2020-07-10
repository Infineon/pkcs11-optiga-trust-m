/*
 * FreeRTOS PKCS #11 V2.0.3
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* Standard includes. */
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "aws_dev_mode_key_provisioning.h"
#include "mbedtls/x509_crt.h"

/* mbedTLS includes. */
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "c_unit_helper.h"
typedef uint8_t BaseType_t;
typedef enum
{
    eNone,                /* Device is not provisioned.  All credentials have been destroyed. */
    eRsaTest,             /* Provisioned using the RSA test credentials located in this file. */
    eEllipticCurveTest,   /* Provisioned using EC test credentials located in this file. */
    eClientCredential,    /* Provisioned using the credentials in aws_clientcredential_keys. */
    eGeneratedEc,         /* Provisioned using elliptic curve generated on device.  Private key unknown.  No corresponding certificate. */
    eGeneratedRsa,
    eDeliberatelyInvalid, /* Provisioned using credentials that are meant to trigger an error condition. */
    eStateUnknown         /* State of the credentials is unknown. */
} CredentialsProvisioned_t;

/* PKCS #11 Globals.
 * These are used to reduce setup and tear down calls, and to
 * prevent memory leaks in the case of TEST_PROTECT() actions being triggered. */
CK_SESSION_HANDLE xGlobalSession;
CK_FUNCTION_LIST_PTR pxGlobalFunctionList;
CredentialsProvisioned_t xCurrentCredentials = eStateUnknown;

/* Function Prototypes. */
CK_RV prvBeforeRunningTests( void );
void prvAfterRunningTests_NoObject( void );
void prvAfterRunningTests_Object( void );



static CK_RV prvDestroyTestCredentials( void )
{
    CK_RV xResult = CKR_OK;

    CK_BYTE * pxPkcsLabels[] =
    {
        ( CK_BYTE * ) pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
        ( CK_BYTE * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
        ( CK_BYTE * ) pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
        #if ( pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
            ( CK_BYTE * ) pkcs11testLABEL_CODE_VERIFICATION_KEY,
            ( CK_BYTE * ) pkcs11testLABEL_JITP_CERTIFICATE,
            ( CK_BYTE * ) pkcs11testLABEL_ROOT_CERTIFICATE
        #endif
    };
    CK_OBJECT_CLASS xClass[] =
    {
        CKO_CERTIFICATE,
        CKO_PRIVATE_KEY,
        CKO_PUBLIC_KEY,
        #if ( pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
            CKO_PUBLIC_KEY,
            CKO_CERTIFICATE,
            CKO_CERTIFICATE
        #endif
    };

    xResult = xDestroyProvidedObjects( xGlobalSession,
                                       pxPkcsLabels,
                                       xClass,
                                       sizeof( xClass ) / sizeof( CK_OBJECT_CLASS ) );

    return xResult;
}

CK_RV prvBeforeRunningTests( void )
{
    CK_RV xResult;

    /* Initialize the function list */
    xResult = C_GetFunctionList( &pxGlobalFunctionList );

    if( xResult == CKR_OK )
    {
        /* Close the last session if it was not closed already. */
        pxGlobalFunctionList->C_Finalize( NULL );
    }

    return xResult;
}

/* If no changes to PKCS #11 objects have been made during the test,
 *  just make sure that the PKCS #11 module is initialized and in a good state.
 */
void prvAfterRunningTests_NoObject( void )
{
    xInitializePKCS11();
}

/* If these tests may have manipulated the PKCS #11 objects
 * (private key, public keys and/or certificates), run this routine afterwards
 * to make sure that credentials are in a good state for the other test groups. */
void prvAfterRunningTests_Object( void )
{
    /* Check if the test label is the same as the run-time label. */

    /* If labels are the same, then we are assuming that this device does not
     * have a secure element. */
    if( ( 0 == strcmp( pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) ) &&
        ( 0 == strcmp( pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS ) ) )
    {
        /* Delete the old device private key and certificate, if that
         * operation is supported by this port. Replace
         * them with known-good AWS IoT credentials. */
        xDestroyDefaultCryptoObjects( xGlobalSession );

        /* Re-provision the device with default certs
         * so that subsequent tests are not changed. */
        vDevModeKeyProvisioning();
        xCurrentCredentials = eClientCredential;
    }

    /* If the labels are different, then test credentials
     * and application credentials are stored in separate
     * slots which were not modified, so nothing special
     * needs to be done. */
}



/* Assumes that device is already provisioned at time of calling. */
void prvFindObjectTest( void )
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    CK_OBJECT_HANDLE xTestObjectHandle;

    /* Happy Path - Find a previously created object. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            CKO_PRIVATE_KEY,
                                            &xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( 0, xPrivateKeyHandle );

    /*         TODO: Add the code sign key and root ca. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                            CKO_PUBLIC_KEY,
                                            &xPublicKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xPublicKeyHandle );


    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            CKO_CERTIFICATE,
                                            &xCertificateHandle );

    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( 0, xCertificateHandle);

    /* Try to find an object that has never been created. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            ( const char * ) "This label doesn't exist",
                                            CKO_PUBLIC_KEY,
                                            &xTestObjectHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CK_INVALID_HANDLE, xTestObjectHandle);

    /* Destroy the private key and try to find it. */
    xCurrentCredentials = eStateUnknown;
    xResult = pxGlobalFunctionList->C_DestroyObject( xGlobalSession, xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            CKO_PRIVATE_KEY,
                                            &xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xPrivateKeyHandle );

    /* Make sure the certificate can still be found. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            CKO_CERTIFICATE,
                                            &xCertificateHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xCertificateHandle );

    xResult = pxGlobalFunctionList->C_DestroyObject( xGlobalSession, xCertificateHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            CKO_CERTIFICATE,
                                            &xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( 0, xPrivateKeyHandle);
}


void AFQP_StartFinish_FirstTest(void)
{
    CK_RV xResult;

    /* Finalize the PKCS #11 module to get it in a known state.
     * Set up the PKCS #11 function list pointer. */
    xResult = prvBeforeRunningTests();

    /* prvBeforeRunningTests finalizes the PKCS #11 modules so that tests will start
     * in a known state.  It is OK if the module was not previously initialized. */
    if( xResult == CKR_CRYPTOKI_NOT_INITIALIZED )
    {
        xResult = CKR_OK;
    }

    CU_ASSERT_EQUAL( CKR_OK, xResult);
}

/*-----------------------------------------------------------*/

void AFQP_GetFunctionList(void)
{
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;

    CU_ASSERT_EQUAL( CKR_ARGUMENTS_BAD, C_GetFunctionList( NULL ) );

    CU_ASSERT_EQUAL( CKR_OK, C_GetFunctionList( &pxFunctionList ) );

    /* Ensure that pxFunctionList was changed by C_GetFunctionList. */
    CU_ASSERT_NOT_EQUAL( NULL, pxFunctionList );
}

uint8_t TEST_PROTECT(void) {return 1;}

void AFQP_InitializeFinalize(void)
{
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_RV xResult;

    xResult = C_GetFunctionList( &pxFunctionList );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( NULL, pxFunctionList);

    xResult = xInitializePKCS11();
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    if( TEST_PROTECT() )
    {
        /* Call initialize a second time.  Since this call may be made many times,
         * it is important that PKCS #11 implementations be tolerant of multiple calls. */
        xResult = xInitializePKCS11();
        CU_ASSERT_EQUAL( CKR_CRYPTOKI_ALREADY_INITIALIZED, xResult);

        /* C_Finalize should fail if pReserved isn't NULL. */
        xResult = pxFunctionList->C_Finalize( ( CK_VOID_PTR ) 0x1234 );
        CU_ASSERT_EQUAL( CKR_ARGUMENTS_BAD, xResult );
    }

    xResult = pxFunctionList->C_Finalize( NULL );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* Call Finalize a second time.  Since finalize may be called multiple times,
     * it is important that the PKCS #11 module is tolerant of multiple calls. */
    xResult = pxFunctionList->C_Finalize( NULL );
    CU_ASSERT_EQUAL( CKR_CRYPTOKI_NOT_INITIALIZED, xResult);
}

void AFQP_GetSlotList(void)
{
    CK_RV xResult;
    CK_SLOT_ID * pxSlotId = NULL;
    CK_ULONG xSlotCount = 0;
    CK_ULONG xExtraSlotCount = 0;

    xResult = xInitializePKCS11();
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    if( TEST_PROTECT() )
    {
        /* The Happy Path. */

        /* When a NULL slot pointer is passed in,
         *  the number of slots should be updated. */
        xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, NULL, &xSlotCount );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        //TEST_ASSERT_GREATER_THAN_MESSAGE( 0);

        /* Allocate memory to receive the list of slots, plus one extra. */
        pxSlotId = malloc( sizeof( CK_SLOT_ID ) * ( xSlotCount + 1 ) );
        CU_ASSERT_EQUAL( NULL, pxSlotId);

        /* Call C_GetSlotList again to receive all slots with tokens present. */
        xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xSlotCount );
        CU_ASSERT_EQUAL( CKR_OK, xResult);

        /* Note: Being able to use the slot to open a session will be  tested
         * in the C_OpenSession tests. */

        /* Off the happy path. */
        xExtraSlotCount = xSlotCount + 1;

        /* Make sure that number of slots returned is updated when extra buffer room exists. */
        xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xExtraSlotCount );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( xSlotCount, xExtraSlotCount);

        /* Claim that the buffer to receive slots is too small. */
        xSlotCount = 0;
        xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xSlotCount );
        CU_ASSERT_EQUAL( CKR_BUFFER_TOO_SMALL, xResult);
    }

    if( pxSlotId != NULL )
    {
        free( pxSlotId );
    }

    xResult = pxGlobalFunctionList->C_Finalize( NULL );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
}

extern CK_RV xGetSlotList( CK_SLOT_ID ** ppxSlotId,
                           CK_ULONG * pxSlotCount );
void AFQP_OpenSessionCloseSession(void)
{
    CK_SLOT_ID_PTR pxSlotId = NULL;
    CK_SLOT_ID xSlotId = 0;
    CK_ULONG xSlotCount = 0;
    CK_SESSION_HANDLE xSession = 0;
    CK_BBOOL xSessionOpen = CK_FALSE;
    CK_RV xResult = CKR_OK;

    xResult = xInitializePKCS11();
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    if( TEST_PROTECT() )
    {
        xResult = xGetSlotList( &pxSlotId,
                                &xSlotCount );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        xSlotId = pxSlotId[ pkcs11testSLOT_NUMBER ];
        free( pxSlotId ); /* xGetSlotList allocates memory. */
        //TEST_ASSERT_GREATER_THAN( 0, xSlotCount );


        xResult = pxGlobalFunctionList->C_OpenSession( xSlotId,
                                                       CKF_SERIAL_SESSION, /* This flag is mandatory for PKCS #11 legacy reasons. */
                                                       NULL,               /* Application defined pointer. */
                                                       NULL,               /* Callback function. */
                                                       &xSession );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        xSessionOpen = CK_TRUE;
    }

    if( xSessionOpen )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xSession );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    }

    pxGlobalFunctionList->C_Finalize( NULL );


    /* Negative tests */

    /* Try to open a session without having initialized the module. */
    xResult = pxGlobalFunctionList->C_OpenSession( xSlotId,
                                                   CKF_SERIAL_SESSION, /* This flag is mandatory for PKCS #11 legacy reasons. */
                                                   NULL,               /* Application defined pointer. */
                                                   NULL,               /* Callback function. */
                                                   &xSession );
    CU_ASSERT_EQUAL( CKR_CRYPTOKI_NOT_INITIALIZED, xResult);
}

/*--------------------------------------------------------*/
/*-------------- Capabilities Tests --------------------- */
/*--------------------------------------------------------*/

void AFQP_Capabilities(void)
{
    CK_RV xResult = 0;
    CK_ULONG xSlotCount = 0;
    CK_SLOT_ID_PTR pxSlotId = NULL;
    CK_MECHANISM_INFO MechanismInfo = { 0 };
    CK_BBOOL xSupportsKeyGen = CK_FALSE;

    /* Determine the number of slots. */
    xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, NULL, &xSlotCount );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* Allocate memory to receive the list of slots, plus one extra. */
    pxSlotId = malloc( sizeof( CK_SLOT_ID ) * xSlotCount );
    CU_ASSERT_EQUAL( NULL, pxSlotId);

    /* Call C_GetSlotList again to receive all slots with tokens present. */
    xResult = pxGlobalFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, &xSlotCount );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* Check for RSA PKCS #1 signing support. */
    xResult = pxGlobalFunctionList->C_GetMechanismInfo( pxSlotId[ 0 ], CKM_RSA_PKCS, &MechanismInfo );
    CU_ASSERT_TRUE( CKR_OK == xResult || CKR_MECHANISM_INVALID == xResult );

    if( CKR_OK == xResult )
    {
        CU_ASSERT_TRUE( 0 != ( CKF_SIGN & MechanismInfo.flags ) );

        CU_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11RSA_2048_MODULUS_BITS &&
                          MechanismInfo.ulMinKeySize <= pkcs11RSA_2048_MODULUS_BITS );

        /* Check for pre-padded signature verification support. This is required
         * for round-trip testing. */
        xResult = pxGlobalFunctionList->C_GetMechanismInfo( pxSlotId[ 0 ], CKM_RSA_X_509, &MechanismInfo );
        CU_ASSERT_TRUE( CKR_OK == xResult );

        CU_ASSERT_TRUE( 0 != ( CKF_VERIFY & MechanismInfo.flags ) );

        CU_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11RSA_2048_MODULUS_BITS &&
                          MechanismInfo.ulMinKeySize <= pkcs11RSA_2048_MODULUS_BITS );

        /* Check consistency with static configuration. */
        #if ( 0 == pkcs11testRSA_KEY_SUPPORT )
            printf( "Static and runtime configuration for key generation support are inconsistent." );
        #endif

        printf( ( "The PKCS #11 module supports RSA signing.\r\n" ) );
    }

    /* Check for ECDSA support, if applicable. */
    xResult = pxGlobalFunctionList->C_GetMechanismInfo( pxSlotId[ 0 ], CKM_ECDSA, &MechanismInfo );
    CU_ASSERT_TRUE( CKR_OK == xResult || CKR_MECHANISM_INVALID == xResult );

    if( CKR_OK == xResult )
    {
        CU_ASSERT_TRUE( 0 != ( ( CKF_SIGN | CKF_VERIFY ) & MechanismInfo.flags ) );

        CU_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11ECDSA_P256_KEY_BITS &&
                          MechanismInfo.ulMinKeySize <= pkcs11ECDSA_P256_KEY_BITS );

        /* Check consistency with static configuration. */
        #if ( 0 == pkcs11testEC_KEY_SUPPORT )
            printf( "Static and runtime configuration for key generation support are inconsistent." );
        #endif

        printf( ( "The PKCS #11 module supports ECDSA.\r\n" ) );
    }

    /* Check for elliptic-curve key generation support. */
    xResult = pxGlobalFunctionList->C_GetMechanismInfo( pxSlotId[ 0 ], CKM_EC_KEY_PAIR_GEN, &MechanismInfo );
    CU_ASSERT_TRUE( CKR_OK == xResult || CKR_MECHANISM_INVALID == xResult );

    if( CKR_OK == xResult )
    {
        CU_ASSERT_TRUE( 0 != ( CKF_GENERATE_KEY_PAIR & MechanismInfo.flags ) );

        CU_ASSERT_TRUE( MechanismInfo.ulMaxKeySize >= pkcs11ECDSA_P256_KEY_BITS &&
                          MechanismInfo.ulMinKeySize <= pkcs11ECDSA_P256_KEY_BITS );

        xSupportsKeyGen = CK_TRUE;
        printf( ( "The PKCS #11 module supports elliptic-curve key generation.\r\n" ) );
    }

    /* SHA-256 support is required. */
    xResult = pxGlobalFunctionList->C_GetMechanismInfo( pxSlotId[ 0 ], CKM_SHA256, &MechanismInfo );
    CU_ASSERT_TRUE( CKR_OK == xResult );
    CU_ASSERT_TRUE( 0 != ( CKF_DIGEST & MechanismInfo.flags ) );

    /* Check for consistency between static configuration and runtime key
     * generation settings. */
    if( CK_TRUE == xSupportsKeyGen )
    {
        #if ( 0 == pkcs11testGENERATE_KEYPAIR_SUPPORT )
            printf( "Static and runtime configuration for key generation support are inconsistent." );
        #endif
    }
    else
    {
        #if ( 1 == pkcs11testGENERATE_KEYPAIR_SUPPORT )
            printf( "Static and runtime configuration for key generation support are inconsistent." );
        #endif
    }

    /* Report on static configuration for key import support. */
    #if ( 1 == pkcs11testIMPORT_PRIVATE_KEY_SUPPORT )
        printf( ( "The PKCS #11 module supports private key import.\r\n" ) );
    #endif
}

/*--------------------------------------------------------*/
/*-------------- No Object Tests ------------------------ */
/*--------------------------------------------------------*/

static CK_BYTE x896BitInput[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

static CK_BYTE xSha256HashOf896BitInput[] =
{
    0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
    0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1
};

void AFQP_Digest(void)
{
    CK_RV xResult = 0;

    CK_MECHANISM xDigestMechanism;

    CK_BYTE xDigestResult[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_ULONG xDigestLength = 0;


    /* Hash with SHA256 */
    xDigestMechanism.mechanism = CKM_SHA256;

    xResult = pxGlobalFunctionList->C_DigestInit( xGlobalSession, &xDigestMechanism );
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    /* Subtract one because this hash was performed on the characters without the null terminator. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    /* Call C_DigestFinal on a NULL buffer to get the buffer length required. */
    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, NULL, &xDigestLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( pkcs11SHA256_DIGEST_LENGTH, xDigestLength );

    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, xDigestResult, &xDigestLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    //CU_ASSERT_EQUAL_INT8_ARRAY( xSha256HashOf896BitInput, xDigestResult, pkcs11SHA256_DIGEST_LENGTH );
}

void AFQP_Digest_ErrorConditions(void)
{
    CK_RV xResult = 0;
    CK_MECHANISM xDigestMechanism;
    CK_BYTE xDigestResult[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_ULONG xDigestLength = 0;

    /* Make sure that no NULL pointers in functions to be called in this test. */
    CU_ASSERT_NOT_EQUAL( NULL, pxGlobalFunctionList->C_DigestInit );
    CU_ASSERT_NOT_EQUAL( NULL, pxGlobalFunctionList->C_DigestUpdate );
    CU_ASSERT_NOT_EQUAL( NULL, pxGlobalFunctionList->C_DigestFinal );

    /* Invalid hash mechanism. */
    xDigestMechanism.mechanism = 0x253; /*253 doesn't correspond to anything. */ /*CKM_MD5; */

    xResult = pxGlobalFunctionList->C_DigestInit( xGlobalSession, &xDigestMechanism );
    CU_ASSERT_EQUAL( CKR_MECHANISM_INVALID, xResult );

    /* Null Session. */
    xDigestMechanism.mechanism = CKM_SHA256;
    xResult = pxGlobalFunctionList->C_DigestInit( ( CK_SESSION_HANDLE ) NULL, &xDigestMechanism );
    CU_ASSERT_EQUAL( CKR_SESSION_HANDLE_INVALID, xResult );

    /* Make sure that digest update fails if DigestInit did not succeed. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    CU_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, xResult );

    /* Initialize the session properly. */
    xResult = pxGlobalFunctionList->C_DigestInit( xGlobalSession, &xDigestMechanism );
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    /* Try to update digest with a NULL session handle. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( ( CK_SESSION_HANDLE ) NULL, x896BitInput, sizeof( x896BitInput ) - 1 );
    CU_ASSERT_EQUAL( CKR_SESSION_HANDLE_INVALID, xResult );

    /* DigestUpdate correctly.  Note that digest is not terminated because we didn't tell the session handle last time. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    /* Call C_DigestFinal on a buffer that is too small. */
    xDigestLength = pkcs11SHA256_DIGEST_LENGTH - 1;
    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, xDigestResult, &xDigestLength );
    CU_ASSERT_EQUAL( CKR_BUFFER_TOO_SMALL, xResult );

    /* Call C_DigestFinal on a NULL session handle. */
    xDigestLength = pkcs11SHA256_DIGEST_LENGTH;
    xResult = pxGlobalFunctionList->C_DigestFinal( ( CK_SESSION_HANDLE ) NULL, xDigestResult, &xDigestLength );
    CU_ASSERT_EQUAL( CKR_SESSION_HANDLE_INVALID, xResult );

    /* Call C_DigestFinal on a proper buffer size. Note that Digest is not terminated if error is "buffer too small" or if session handle wasn't present. */
    xDigestLength = pkcs11SHA256_DIGEST_LENGTH;
    xResult = pxGlobalFunctionList->C_DigestFinal( xGlobalSession, xDigestResult, &xDigestLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    //CU_ASSERT_EQUAL_INT8_ARRAY( xSha256HashOf896BitInput, xDigestResult, pkcs11SHA256_DIGEST_LENGTH );

    /* Call C_DigestUpdate after the digest operation has been completed. */
    xResult = pxGlobalFunctionList->C_DigestUpdate( xGlobalSession, x896BitInput, sizeof( x896BitInput ) - 1 );
    CU_ASSERT_EQUAL( CKR_OPERATION_NOT_INITIALIZED, xResult );
}


void AFQP_GenerateRandom(void)
{
    CK_RV xResult = 0;
    BaseType_t xSameSession = 0;
    BaseType_t xDifferentSessions = 0;
    int i;

#define pkcstestRAND_BUFFER_SIZE    10 /* This number is not actually flexible anymore because of the print formatting. */
    CK_BYTE xBuf1[ pkcstestRAND_BUFFER_SIZE ];
    CK_BYTE xBuf2[ pkcstestRAND_BUFFER_SIZE ];
    CK_BYTE xBuf3[ pkcstestRAND_BUFFER_SIZE ];

    /* Generate random bytes twice. */
    if( CKR_OK == xResult )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xGlobalSession, xBuf1, pkcstestRAND_BUFFER_SIZE );
    }

    if( CKR_OK == xResult )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xGlobalSession, xBuf2, pkcstestRAND_BUFFER_SIZE );
    }

    if( CKR_OK == xResult )
    {
        /* Close the session and PKCS #11 module */
        if( NULL != pxGlobalFunctionList )
        {
            ( void ) pxGlobalFunctionList->C_CloseSession( xGlobalSession );
        }
    }

    /* Re-open PKCS #11 session. */
    xResult = xInitializePkcs11Session( &xGlobalSession );

    if( CKR_OK == xResult )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xGlobalSession, xBuf3, pkcstestRAND_BUFFER_SIZE );
    }

    /* Check that the result is good. */
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    /* Check that the random bytes generated within session
     * and between initializations of PKCS module are not the same. */
    for( i = 0; i < pkcstestRAND_BUFFER_SIZE; i++ )
    {
        if( xBuf1[ i ] == xBuf2[ i ] )
        {
            xSameSession++;
        }

        if( xBuf1[ i ] == xBuf3[ i ] )
        {
            xDifferentSessions++;
        }
    }

    if( ( xSameSession > 1 ) || ( xDifferentSessions > 1 ) )
    {
        printf( ( "First Random Bytes: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\r\n",
                        xBuf1[ 0 ], xBuf1[ 1 ], xBuf1[ 2 ], xBuf1[ 3 ], xBuf1[ 4 ],
                        xBuf1[ 5 ], xBuf1[ 6 ], xBuf1[ 7 ], xBuf1[ 8 ], xBuf1[ 9 ] ) );

        printf( ( "Second Set of Random Bytes: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\r\n",
                        xBuf2[ 0 ], xBuf2[ 1 ], xBuf2[ 2 ], xBuf2[ 3 ], xBuf2[ 4 ],
                        xBuf2[ 5 ], xBuf2[ 6 ], xBuf2[ 7 ], xBuf2[ 8 ], xBuf2[ 9 ] ) );

        printf( ( "Third Set of Random Bytes:  %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\r\n",
                        xBuf3[ 0 ], xBuf3[ 1 ], xBuf3[ 2 ], xBuf3[ 3 ], xBuf3[ 4 ],
                        xBuf3[ 5 ], xBuf3[ 6 ], xBuf3[ 7 ], xBuf3[ 8 ], xBuf3[ 9 ] ) );
    }

    //TEST_ASSERT_LESS_THAN( 2, xSameSession );
   // TEST_ASSERT_LESS_THAN( 2, xDifferentSessions );
}
#if 0
#define pkcs11testRANDOM_DATA_LENGTH    10
static void prvGenerateRandomMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    BaseType_t xCount;
    CK_RV xResult;
    CK_BYTE xRandomData[ pkcs11testRANDOM_DATA_LENGTH ];
    CK_SESSION_HANDLE xSession;

    memcpy( &xSession, pxMultiTaskParam->pvTaskData, sizeof( CK_SESSION_HANDLE ) );

    for( xCount = 0; xCount < pkcs11testMULTI_THREAD_LOOP_COUNT; xCount++ )
    {
        xResult = pxGlobalFunctionList->C_GenerateRandom( xSession,
                                                          xRandomData,
                                                          sizeof( xRandomData ) );

        if( xResult != CKR_OK )
        {
            printf( ( "GenerateRandom multi-thread task failed.  Error: %d \r\n", xResult ) );
            break;
        }
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;

    /* Report that task is finished, then delete task. */
    ( void ) xEventGroupSetBits( xSyncEventGroup,
                                 ( 1 << pxMultiTaskParam->xTaskNumber ) );
    vTaskDelete( NULL );
}

#endif

/* Valid RSA private key. */
static const char cValidRSAPrivateKey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAsIqRecRxLz3PZXzZOHF7jMlB25tfv2LDGR7nGTJiey5zxd7o\n"
    "swihe7+26yx8medpNvX1ym9jphty+9IR053k1WGnQQ4aaDeJonqn7V50Vesw6zFx\n"
    "/x8LMdXFoBAkRXIL8WS5YKafC87KPnye8A0piVWUFy7+IEEaK3hQEJTzB6LC/N10\n"
    "0XL5ykLCa4xJBOqlIvbDvJ+bKty1EBA3sStlTNuXi3nBWZbXwCB2A+ddjijFf5+g\n"
    "Ujinr7h6e2uQeipWyiIw9NKWbvq8AG1Mj4XBoFL9wP2YTf2SQAgAzx0ySPNrIYOz\n"
    "BNl1YZ4lIW5sJLATES9+Z8nHi7yRDLw6x/kcVQIDAQABAoIBADd+h3ZIeu/HtT8I\n"
    "vNuSSK0bwpj+wV1O9VcbMLfp760bEAd+J5XHu8NDo4NPi6dxZ9CABpBo7WEUtdNU\n"
    "2Ie11W4B8WpwvXpPIvOxLMJf85/ie5EjDNuObZ1vvlyvVkeCLyDlcaRhHBPBIC/+\n"
    "SpPY/1qNTSzwd6+55zkM69YajD60tFv8WuCsgkAteCoDjcqwDcowyAy4pILhOYaW\n"
    "1x+0ZPMUqwtld+06ct/yqBPB8C9IH7ZIeJr5e58R9SxytbuTwTN4jceOoeD5MBbG\n"
    "A+A0WxGdQ8N+kwWkz77qDbZfP4G8wNxeUXobnfqfDGqb0O5zeEaU7EI+mlEQH58Z\n"
    "B1edj6ECgYEA3rldciCQc4t2qYKiZSffnl7Pg7L+ojzH/Eam4Dlk27+DqOo70MnX\n"
    "LVWUWkLOMQ27dRSBQsUDUaqVRZLkcFKc6C8k2cIpPBMpA9WdZVd9kFawZ8lJ7jko\n"
    "qTbJxnDxvhdHrZRvLRjEenbdNXdAGy2EuqvThUJgPEybLAWg6sE3LB0CgYEAyurT\n"
    "14h4BGEGBpl2KevoPQ4PPS+IoDXMS29mtfcascVkYcxxW1v8wOQVyD4VrsRMErck\n"
    "ZMpu2evd+aQSPSrAod/sQ20C+wCCA7ipBlhAUeuS/FpqFIZWkHzZnVccp8O3nOFO\n"
    "KNeAmw4udq8PyjVVouey/6F386itJdxWt/d8i5kCgYA3Aru045wqHck6RvzLVVTj\n"
    "LfG9Sqmf8rlGc0DmYuapbB0dzHTnteLC3L9ep997uDOT0HO4xSZztllWLNjlcVI1\n"
    "+ub0LgO3Rdg8jTdp/3kQ/IhnqgzrnQyQ9upRbDYZSHC4y8/F6LcmtFMg0Ipx7AU7\n"
    "ghMld+aDHjy5W86KDR0OdQKBgQCAZoPSONqo+rQTbPwmns6AA+uErhVoO2KgwUdf\n"
    "EZPktaFFeVapltWjQTC/WvnhcvkoRpdS5/2pC+WUWEvqRKlMRSN9rvdZ2QJsVGcw\n"
    "Spu4urZx1MyXXEJef4I8W6kYR3JiZPdORL9uXlTsaO425/Tednr/4y7CEhQuhvSg\n"
    "yIwY0QKBgQC2NtKDOwcgFykKRYqtHuo6VpSeLmgm1DjlcAuaGJsblX7C07ZH8Tjm\n"
    "IHQb01oThNEa4tC0vO3518PkQwvyi/TWGHm9SLYdXvpVnBwkk5yRioKPgPmrs4Xi\n"
    "ERIYrvveGGtQ3vSknLWUJ/0BgmuYj5U6aJBZPv8COM2eKIbTQbtQaQ==\n"
    "-----END RSA PRIVATE KEY-----\n";

/* Valid RSA certificate. */
static const char cValidRSACertificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDsTCCApmgAwIBAgIJALg4YJlPspxyMA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNV\n"
    "BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTENMAsGA1UECgwE\n"
    "QW16bjEMMAoGA1UECwwDSW9UMQ0wCwYDVQQDDARUZXN0MRUwEwYJKoZIhvcNAQkB\n"
    "FgZub2JvZHkwHhcNMTgwNjExMTk0NjM2WhcNMjEwMzMxMTk0NjM2WjBvMQswCQYD\n"
    "VQQGEwJVUzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1NlYXR0bGUxDTALBgNVBAoM\n"
    "BEFtem4xDDAKBgNVBAsMA0lvVDENMAsGA1UEAwwEVGVzdDEVMBMGCSqGSIb3DQEJ\n"
    "ARYGbm9ib2R5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsIqRecRx\n"
    "Lz3PZXzZOHF7jMlB25tfv2LDGR7nGTJiey5zxd7oswihe7+26yx8medpNvX1ym9j\n"
    "phty+9IR053k1WGnQQ4aaDeJonqn7V50Vesw6zFx/x8LMdXFoBAkRXIL8WS5YKaf\n"
    "C87KPnye8A0piVWUFy7+IEEaK3hQEJTzB6LC/N100XL5ykLCa4xJBOqlIvbDvJ+b\n"
    "Kty1EBA3sStlTNuXi3nBWZbXwCB2A+ddjijFf5+gUjinr7h6e2uQeipWyiIw9NKW\n"
    "bvq8AG1Mj4XBoFL9wP2YTf2SQAgAzx0ySPNrIYOzBNl1YZ4lIW5sJLATES9+Z8nH\n"
    "i7yRDLw6x/kcVQIDAQABo1AwTjAdBgNVHQ4EFgQUHc4PjEL0CaxZ+1D/4VdeDjxt\n"
    "JO8wHwYDVR0jBBgwFoAUHc4PjEL0CaxZ+1D/4VdeDjxtJO8wDAYDVR0TBAUwAwEB\n"
    "/zANBgkqhkiG9w0BAQsFAAOCAQEAi1/okTpQuPcaQEBgepccZ/Lt/gEQNdGcbsYQ\n"
    "3aEABNVYL8dYOW9r/8l074zD+vi9iSli/yYmwRFD0baN1FRWUqkVEIQ+3yfivOW9\n"
    "R282NuQvEULgERC2KN7vm0vO+DF7ay58qm4PaAGHdQco1LaHKkljMPLHF841facG\n"
    "M9KVtzFveOQKkWvb4VgOyfn7aCnEogGlWt1S0d12pBRwYjJgKrVQaGs6IiGFVtm8\n"
    "JRLZrLL3sfgsN7L1xu//JUoTOkgxdKuYRmPuUdV2hw/VYDzcnKj7/DMXNDvgl3s7\n"
    "5GC4F+8LFLzRrZJWs18FMLaCE+zJChw/oeSt+RS0JZDFn+uX9Q==\n"
    "-----END CERTIFICATE-----\n";

void prvProvisionRsaTestCredentials( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                     CK_OBJECT_HANDLE_PTR pxCertificateHandle )
{
    CK_RV xResult;

    if( xCurrentCredentials != eRsaTest )
    {
        xResult = prvDestroyTestCredentials();
        CU_ASSERT_EQUAL( CKR_OK, xResult );
        xCurrentCredentials = eNone;

        /* Create a private key. */
        xResult = xProvisionPrivateKey( xGlobalSession,
                                        ( uint8_t * ) cValidRSAPrivateKey,
                                        sizeof( cValidRSAPrivateKey ),
                                        ( uint8_t * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                        pxPrivateKeyHandle );

        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxPrivateKeyHandle);

        /* Create a certificate. */
        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidRSACertificate,
                                         sizeof( cValidRSACertificate ),
                                         ( uint8_t * ) pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                         pxCertificateHandle );

        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxCertificateHandle);
        xCurrentCredentials = eRsaTest;
    }
    else
    {
        xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, pxPrivateKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult );
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxPrivateKeyHandle);

        xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, pxCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxCertificateHandle);
    }
}

/* Note: This tests that objects can be created and found successfully.
 * It does not check the correctness or usability of objects stored. */
void AFQP_CreateObjectFindObject(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    CK_OBJECT_HANDLE xFoundPrivateKeyHandle;
    CK_OBJECT_HANDLE xFoundCertificateHandle;

    if( xCurrentCredentials != eNone )
    {
        xResult = prvDestroyTestCredentials();
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        xCurrentCredentials = eNone;
    }

    prvProvisionRsaTestCredentials( &xPrivateKeyHandle, &xCertificateHandle );

    /* Find the newly created private key. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            CKO_PRIVATE_KEY,
                                            &xFoundPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CK_INVALID_HANDLE, xFoundPrivateKeyHandle);
    CU_ASSERT_EQUAL( xPrivateKeyHandle, xFoundPrivateKeyHandle);

    /* Find the newly created certificate. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            CKO_CERTIFICATE,
                                            &xFoundCertificateHandle );

    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xCertificateHandle);
    CU_ASSERT_EQUAL( xCertificateHandle, xFoundCertificateHandle);

    /* Close and reopen a new session.  Make sure that the private key and certificate can still be found. */
    xResult = pxGlobalFunctionList->C_CloseSession( xGlobalSession );
    xResult = xInitializePkcs11Session( &xGlobalSession );

    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            CKO_PRIVATE_KEY,
                                            &xFoundPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xFoundPrivateKeyHandle);

    xResult = xFindObjectWithLabelAndClass( xGlobalSession,
                                            pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                            CKO_CERTIFICATE,
                                            &xFoundCertificateHandle );

    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xCertificateHandle);
}



void AFQP_FindObject(void)
{
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;

    prvProvisionRsaTestCredentials( &xPrivateKey, &xCertificate );
    prvFindObjectTest();
}


void AFQP_CreateObjectGetAttributeValue(void)
{
#define MODULUS_LENGTH              256
#define PUB_EXP_LENGTH              3
#define CERTIFICATE_VALUE_LENGTH    949
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    CK_ATTRIBUTE xTemplate;
    CK_BYTE xCertificateValue[ CERTIFICATE_VALUE_LENGTH ];
    CK_BYTE xKeyComponent[ ( pkcs11RSA_2048_MODULUS_BITS / 8 ) + 1 ] = { 0 };

    prvProvisionRsaTestCredentials( &xPrivateKeyHandle, &xCertificateHandle );

    /* TODO: Add RSA key component GetAttributeValue checks. */

    /* Get the certificate value. */
    xTemplate.type = CKA_VALUE;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificateHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CERTIFICATE_VALUE_LENGTH, xTemplate.ulValueLen);

    xTemplate.pValue = xCertificateValue;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificateHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CERTIFICATE_VALUE_LENGTH, xTemplate.ulValueLen);
    /* TODO: Check byte array */

    /* Check that the private key cannot be retrieved. */
    xTemplate.type = CKA_PRIVATE_EXPONENT;
    xTemplate.pValue = xKeyComponent;
    xTemplate.ulValueLen = sizeof( xKeyComponent );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_ATTRIBUTE_SENSITIVE, xResult);
    //TEST_ASSERT_EACH_EQUAL_INT8_MESSAGE( 0, xKeyComponent, sizeof( xKeyComponent ), "Private key bytes returned when they should not be." );
}


void AFQP_Sign(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    CK_MECHANISM xMechanism;
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    CK_ULONG xSignatureLength;
    CK_BYTE xHashPlusOid[ pkcs11RSA_SIGNATURE_INPUT_LENGTH ];

    prvProvisionRsaTestCredentials( &xPrivateKeyHandle, &xCertificateHandle );

    xResult = vAppendSHA256AlgorithmIdentifierSequence( xHashedMessage, xHashPlusOid );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* The RSA X.509 mechanism assumes a pre-hashed input. */
    xMechanism.mechanism = CKM_RSA_PKCS;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xSignatureLength = sizeof( xSignature );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashPlusOid, sizeof( xHashPlusOid ), xSignature, &xSignatureLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* Verify the signature with mbedTLS */
    mbedtls_pk_context xMbedPkContext;
    int lMbedTLSResult;

    mbedtls_pk_init( &xMbedPkContext );

    if( TEST_PROTECT() )
    {
        lMbedTLSResult = mbedtls_pk_parse_key( ( mbedtls_pk_context * ) &xMbedPkContext,
                                               ( const unsigned char * ) cValidRSAPrivateKey,
                                               sizeof( cValidRSAPrivateKey ),
                                               NULL,
                                               0 );

        lMbedTLSResult = mbedtls_rsa_pkcs1_verify( xMbedPkContext.pk_ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, xHashedMessage, xSignature );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);
    }

    mbedtls_pk_free( &xMbedPkContext );
}


extern int PKI_RSA_RSASSA_PKCS1_v15_Encode( const unsigned char * hash,
                                            size_t dst_len,
                                            unsigned char * dst );

void AFQP_GenerateKeyPair(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_MECHANISM xMechanism;
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0 };
    CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    CK_ULONG xSignatureLength;
    CK_BYTE xModulus[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    unsigned int ulModulusLength = 0;
    CK_BYTE xExponent[ 4 ] = { 0 };
    unsigned int ulExponentLength = 0;
    CK_BYTE xPaddedHash[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    mbedtls_rsa_context xRsaContext;

    xResult = prvDestroyTestCredentials();
    xCurrentCredentials = eNone;
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xResult = xProvisionGenerateKeyPairRSA( xGlobalSession,
                                            ( uint8_t * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            ( uint8_t * ) pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                            &xPrivateKeyHandle,
                                            &xPublicKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( 0, xPrivateKeyHandle);

    CK_ATTRIBUTE xTemplate;
    xTemplate.type = CKA_MODULUS;
    xTemplate.pValue = xModulus;
    xTemplate.ulValueLen = sizeof( xModulus );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    ulModulusLength = xTemplate.ulValueLen;

    xTemplate.type = CKA_PUBLIC_EXPONENT;
    xTemplate.pValue = xExponent;
    xTemplate.ulValueLen = sizeof( xExponent );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    ulExponentLength = xTemplate.ulValueLen;

    //xResult = PKI_RSA_RSASSA_PKCS1_v15_Encode( xHashedMessage, pkcs11RSA_2048_SIGNATURE_LENGTH, xPaddedHash );
    //CU_ASSERT_EQUAL( CKR_OK, xResult );

    /* The RSA X.509 mechanism assumes a pre-hashed input. */
    xMechanism.mechanism = CKM_RSA_X_509;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xSignatureLength = sizeof( xSignature );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xPaddedHash, pkcs11RSA_2048_SIGNATURE_LENGTH, xSignature, &xSignatureLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* Verify the signature with mbedTLS */

    /* Set up the RSA public key. */
    mbedtls_rsa_init( &xRsaContext, MBEDTLS_RSA_PKCS_V15, 0 );

    if( TEST_PROTECT() )
    {
        xResult = mbedtls_mpi_read_binary( &xRsaContext.N, xModulus, ulModulusLength );
        CU_ASSERT_EQUAL( 0, xResult );
        xResult = mbedtls_mpi_read_binary( &xRsaContext.E, xExponent, ulExponentLength );
        CU_ASSERT_EQUAL( 0, xResult );
        xRsaContext.len = pkcs11RSA_2048_SIGNATURE_LENGTH;
        xResult = mbedtls_rsa_check_pubkey( &xRsaContext );
        CU_ASSERT_EQUAL( 0, xResult );
        xResult = mbedtls_rsa_pkcs1_verify( &xRsaContext, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, xHashedMessage, xSignature );
        CU_ASSERT_EQUAL( 0, xResult);
        /* Verify the signature with the generated public key. */
        xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xPaddedHash, pkcs11RSA_2048_SIGNATURE_LENGTH, xSignature, xSignatureLength );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    }

    mbedtls_rsa_free( &xRsaContext );
}


/* Valid ECDSA private key. */
static const char cValidECDSAPrivateKey[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIACZbHljxOFuBeEKRcMijfbVcDzBxa8M4T5jElsElFQ5oAoGCCqGSM49\n"
    "AwEHoUQDQgAEzghp+QstUhOmzKBGEL7uBjsaBbyaNTMLXKLSW78+bdoP9bKTOrqi\n"
    "Kk9GzFk9ChthHFsx+T7UFithbYWtRf0Zww==\n"
    "-----END EC PRIVATE KEY-----";

/* Valid ECDSA certificate. */
static const char cValidECDSACertificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICbjCCAhQCCQDqQDa2NeYOhTAKBggqhkjOPQQDAjCBvjELMAkGA1UEBhMCVVMx\n"
    "EzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxGDAWBgNVBAoM\n"
    "D0FtYXpvbiBGcmVlUlRPUzEhMB8GA1UECwwYUEtDUyAjMTEgVGVzdCBDcmVkZW50\n"
    "aWFsMSgwJgYDVQQDDB9ET05UX1VTRV9USElTX0tFWV9JTl9BX1JFQUxfQVBQMSEw\n"
    "HwYJKoZIhvcNAQkBFhJub2JvZHlAbm93aGVyZS5jb20wHhcNMTkwNTI5MjE1NjAw\n"
    "WhcNMjkwNTI2MjE1NjAwWjCBvjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hp\n"
    "bmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxGDAWBgNVBAoMD0FtYXpvbiBGcmVlUlRP\n"
    "UzEhMB8GA1UECwwYUEtDUyAjMTEgVGVzdCBDcmVkZW50aWFsMSgwJgYDVQQDDB9E\n"
    "T05UX1VTRV9USElTX0tFWV9JTl9BX1JFQUxfQVBQMSEwHwYJKoZIhvcNAQkBFhJu\n"
    "b2JvZHlAbm93aGVyZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATOCGn5\n"
    "Cy1SE6bMoEYQvu4GOxoFvJo1MwtcotJbvz5t2g/1spM6uqIqT0bMWT0KG2EcWzH5\n"
    "PtQWK2Ftha1F/RnDMAoGCCqGSM49BAMCA0gAMEUCIQCs1n3p+fOZxjZT+fnm3MQf\n"
    "IhxppLKnUggV42SAMpSneQIgdufH9clHZgrd9HVpRlIumy3sIMNEu9fzC9XZsSu8\n"
    "yQ8=\n"
    "-----END CERTIFICATE-----";



void prvProvisionCredentialsWithKeyImport( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                           CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                                           CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;


    if( xCurrentCredentials != eEllipticCurveTest )
    {
        xResult = prvDestroyTestCredentials();
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        xCurrentCredentials = eNone;

        xResult = xProvisionPublicKey( xGlobalSession,
                                       ( uint8_t * ) cValidECDSAPrivateKey,
                                       sizeof( cValidECDSAPrivateKey ),
                                       CKK_EC,
                                       ( uint8_t * ) pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                       pxPublicKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( 0, *pxPublicKeyHandle);

        xResult = xProvisionPrivateKey( xGlobalSession,
                                        ( uint8_t * ) cValidECDSAPrivateKey,
                                        sizeof( cValidECDSAPrivateKey ),
                                        ( uint8_t * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                        pxPrivateKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult );
        CU_ASSERT_EQUAL( 0, *pxPrivateKeyHandle);

        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidECDSACertificate,
                                         sizeof( cValidECDSACertificate ),
                                         ( uint8_t * ) pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                         pxCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( 0, *pxPrivateKeyHandle );

        xCurrentCredentials = eEllipticCurveTest;
    }
    else
    {
        xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, pxPrivateKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxPrivateKeyHandle);

        xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, pxCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxCertificateHandle);

        xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, CKO_PUBLIC_KEY, pxPublicKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxPublicKeyHandle);
    }
}

void prvProvisionCredentialsWithGenerateKeyPair( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                                 CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                                                 CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_ATTRIBUTE xTemplate;
    CK_KEY_TYPE xKeyType = 0;
    CK_BBOOL xProvisionKeyNeeded = CK_FALSE;

    /* Check if there is an EC private key in there already. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, pxPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, CKO_PUBLIC_KEY, pxPublicKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    if( *pxPrivateKeyHandle != CK_INVALID_HANDLE )
    {
        xTemplate.type = CKA_KEY_TYPE;
        xTemplate.pValue = &xKeyType;
        xTemplate.ulValueLen = sizeof( CK_KEY_TYPE );
        xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, *pxPrivateKeyHandle, &xTemplate, 1 );
        CU_ASSERT_EQUAL( CKR_OK, xResult);

        if( xKeyType != CKK_EC )
        {
            xProvisionKeyNeeded = CK_TRUE;
        }
    }

    if( *pxPrivateKeyHandle == CK_INVALID_HANDLE )
    {
        xProvisionKeyNeeded = CK_TRUE;
    }

    if( xProvisionKeyNeeded == CK_TRUE )
    {
        xResult = xProvisionGenerateKeyPairEC( xGlobalSession, ( uint8_t * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, ( uint8_t * ) pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, pxPrivateKeyHandle, pxPublicKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxPrivateKeyHandle);
        CU_ASSERT_EQUAL( CK_INVALID_HANDLE, *pxPublicKeyHandle);
    }

    xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, pxCertificateHandle );

    /* NOTE: This certificate is for object storage and retrieval purposes only, and does not correspond to the key pair generated. */
    if( *pxCertificateHandle == CK_INVALID_HANDLE )
    {
        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) cValidECDSACertificate,
                                         sizeof( cValidECDSACertificate ),
                                         ( uint8_t * ) pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                         pxCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( 0, *pxPrivateKeyHandle);
    }
}


void prvProvisionEcTestCredentials( CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                    CK_OBJECT_HANDLE_PTR pxCertificateHandle,
                                    CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    #if ( pkcs11testIMPORT_PRIVATE_KEY_SUPPORT != 0 )
        prvProvisionCredentialsWithKeyImport( pxPrivateKeyHandle, pxCertificateHandle, pxPublicKeyHandle );
    #else
        prvProvisionCredentialsWithGenerateKeyPair( pxPrivateKeyHandle, pxCertificateHandle, pxPublicKeyHandle );
    #endif
}

void AFQP_CreateObjectDestroyObjectKeys(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;

    #if ( pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
        CK_OBJECT_HANDLE xRootCertificateHandle;
        CK_OBJECT_HANDLE xCodeSignPublicKeyHandle;
        CK_OBJECT_HANDLE xJITPCertificateHandle;
    #endif /* if ( pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 ) */


    xResult = prvDestroyTestCredentials();
    xCurrentCredentials = eNone;
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xResult = xProvisionPrivateKey( xGlobalSession,
                                    ( uint8_t * ) cValidECDSAPrivateKey,
                                    sizeof( cValidECDSAPrivateKey ),
                                    ( uint8_t * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                    &xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xPrivateKeyHandle);

    xResult = xProvisionPublicKey( xGlobalSession,
                                   ( uint8_t * ) cValidECDSAPrivateKey,
                                   sizeof( cValidECDSAPrivateKey ),
                                   CKK_EC,
                                   ( uint8_t * ) pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                   &xPublicKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xPrivateKeyHandle);
}

void AFQP_CreateObjectDestroyObjectCertificates(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xClientCertificateHandle;

    xResult = xProvisionCertificate( xGlobalSession,
                                     ( uint8_t * ) cValidECDSACertificate,
                                     sizeof( cValidECDSACertificate ),
                                     ( uint8_t * ) pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                     &xClientCertificateHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( 0, xClientCertificateHandle);

    #if ( pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 )
        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) tlsATS1_ROOT_CERTIFICATE_PEM,
                                         tlsATS1_ROOT_CERTIFICATE_LENGTH,
                                         pkcs11configLABEL_ROOT_CERTIFICATE,
                                         &xRootCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( 0, xRootCertificateHandle);

        xResult = xProvisionCertificate( xGlobalSession,
                                         ( uint8_t * ) tlsATS1_ROOT_CERTIFICATE_PEM,
                                         tlsATS1_ROOT_CERTIFICATE_LENGTH,
                                         pkcs11configLABEL_JITP_CERTIFICATE,
                                         &xJITPCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( 0, xJITPCertificateHandle);

        xResult = xProvisionPublicKey( xGlobalSession,
                                       ( uint8_t * ) cValidECDSAPrivateKey,
                                       sizeof( cValidECDSAPrivateKey ),
                                       CKK_EC,
                                       pkcs11configLABEL_CODE_VERIFICATION_KEY,
                                       &xCodeSignPublicKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
        CU_ASSERT_EQUAL( 0, xCodeSignPublicKeyHandle);

        xResult = pxGlobalFunctionList->C_DestroyObject( xGlobalSession, xRootCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);

        xResult = pxGlobalFunctionList->C_DestroyObject( xGlobalSession, xJITPCertificateHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);

        xResult = pxGlobalFunctionList->C_DestroyObject( xGlobalSession, xCodeSignPublicKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    #endif /* if ( pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED == 1 ) */
}

void AFQP_Sign_ecdsa(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_OBJECT_HANDLE xCertificateHandle;
    /* Note that ECDSA operations on a signature of all 0's is not permitted. */
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xab };
    CK_MECHANISM xMechanism;
    CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    CK_ULONG xSignatureLength;

    prvProvisionCredentialsWithKeyImport( &xPrivateKeyHandle, &xCertificateHandle, &xPublicKeyHandle );

    xMechanism.mechanism = CKM_ECDSA;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xSignatureLength = sizeof( xSignature );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, &xSignatureLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* Verify the signature with mbedTLS */
    int lMbedTLSResult;

    mbedtls_pk_context xEcdsaContext;
    mbedtls_pk_init( &xEcdsaContext );

    if( TEST_PROTECT() )
    {
        lMbedTLSResult = mbedtls_pk_parse_key( &xEcdsaContext,
                                               ( const unsigned char * ) cValidECDSAPrivateKey,
                                               sizeof( cValidECDSAPrivateKey ),
                                               NULL,
                                               0 );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);

        mbedtls_ecp_keypair * pxEcdsaContext = ( mbedtls_ecp_keypair * ) xEcdsaContext.pk_ctx;
        /* An ECDSA signature is comprised of 2 components - R & S. */
        mbedtls_mpi xR;
        mbedtls_mpi xS;
        mbedtls_mpi_init( &xR );
        mbedtls_mpi_init( &xS );
        lMbedTLSResult = mbedtls_mpi_read_binary( &xR, &xSignature[ 0 ], 32 );
        lMbedTLSResult = mbedtls_mpi_read_binary( &xS, &xSignature[ 32 ], 32 );
        lMbedTLSResult = mbedtls_ecdsa_verify( &pxEcdsaContext->grp, xHashedMessage, sizeof( xHashedMessage ), &pxEcdsaContext->Q, &xR, &xS );
        mbedtls_mpi_free( &xR );
        mbedtls_mpi_free( &xS );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);
    }

    mbedtls_pk_free( &xEcdsaContext );
}

/*
 * 1. Generates an Elliptic Curve P256 key pair
 * 2. Calls GetAttributeValue to check generated key & that private key is not extractable.
 * 3. Constructs the public key using values from GetAttributeValue calls
 * 4. Uses private key to perform a sign operation
 * 5. Verifies the signature using mbedTLS library and reconstructed public key
 * 6. Verifies the signature using the public key just created.
 * 7. Finds the public and private key using FindObject calls
 */
void AFQP_GenerateKeyPairEC(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xFoundPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xFoundPublicKeyHandle = CK_INVALID_HANDLE;
    /* Note that ECDSA operations on a signature of all 0's is not permitted. */
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xab };
    CK_MECHANISM xMechanism;
    CK_BYTE xSignature[ pkcs11ECDSA_P256_SIGNATURE_LENGTH ] = { 0 };
    CK_BYTE xEcPoint[ 256 ] = { 0 };
    CK_BYTE xPrivateKeyBuffer[ 32 ] = { 0 };
    CK_BYTE xEcParams[ 11 ] = { 0 };
    CK_KEY_TYPE xKeyType;
    CK_ULONG xSignatureLength;
    CK_ATTRIBUTE xTemplate;
    CK_OBJECT_CLASS xClass;
    /* mbedTLS structures for verification. */
    int lMbedTLSResult;
    mbedtls_ecdsa_context xEcdsaContext;
    uint8_t ucSecp256r1Oid[] = pkcs11DER_ENCODED_OID_P256; /*"\x06\x08" MBEDTLS_OID_EC_GRP_SECP256R1; */

    /* An ECDSA signature is comprised of 2 components - R & S. */
    mbedtls_mpi xR;
    mbedtls_mpi xS;

    //xResult = prvDestroyTestCredentials();
	//printf("\n%d\n",__LINE__);
    //CU_ASSERT_EQUAL( CKR_OK, xResult);
    xCurrentCredentials = eNone;
	 xResult = prvBeforeRunningTests();
    CU_ASSERT_EQUAL( CKR_OK, xResult );
	xResult = xInitializePkcs11Session( &xGlobalSession );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    xResult = xProvisionGenerateKeyPairEC( xGlobalSession,
                                           ( uint8_t * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                           ( uint8_t * ) pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                           &xPrivateKeyHandle,
                                           &xPublicKeyHandle );


    //printf("\n%d xResult = %x\n",__LINE__,xResult);

    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_NOT_EQUAL( CK_INVALID_HANDLE, xPrivateKeyHandle);
    CU_ASSERT_NOT_EQUAL( CK_INVALID_HANDLE, xPublicKeyHandle);
    //printf("\n%d\n",__LINE__);
    /* Call GetAttributeValue to retrieve information about the keypair stored. */
#if 0
    /* Check that correct object class retrieved. */
    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    printf("\n%d\n",__LINE__);
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( sizeof( CK_OBJECT_CLASS ), xTemplate.ulValueLen );

    xTemplate.pValue = &xClass;
    printf("\n%d\n",__LINE__);
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CKO_PRIVATE_KEY, xClass );

    xTemplate.pValue = &xClass;
    printf("\n%d\n",__LINE__);
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CKO_PUBLIC_KEY, xClass);

    /* Check that both keys are stored as EC Keys. */
    xTemplate.type = CKA_KEY_TYPE;
    xTemplate.pValue = &xKeyType;
    xTemplate.ulValueLen = sizeof( CK_KEY_TYPE );
    printf("\n%d\n",__LINE__);
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( sizeof( CK_KEY_TYPE ), xTemplate.ulValueLen);
    CU_ASSERT_EQUAL( CKK_EC, xKeyType);
    printf("\n%d\n",__LINE__);

    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( sizeof( CK_KEY_TYPE ), xTemplate.ulValueLen );
    CU_ASSERT_EQUAL( CKK_EC, xKeyType );
    printf("\n%d\n",__LINE__);

    /* Check that correct curve retrieved for private key. */
    xTemplate.type = CKA_EC_PARAMS;
    xTemplate.pValue = xEcParams;
    xTemplate.ulValueLen = sizeof( xEcParams );
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( ucSecp256r1Oid ), xTemplate.ulValueLen);
    //CU_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( ucSecp256r1Oid, xEcParams, xTemplate.ulValueLen );

    /* Check that the private key cannot be retrieved. */
    xTemplate.type = CKA_VALUE;
    xTemplate.pValue = xPrivateKeyBuffer;
    xTemplate.ulValueLen = sizeof( xPrivateKeyBuffer );
    printf("\n%d\n",__LINE__);
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_ATTRIBUTE_SENSITIVE, xResult);
    //TEST_ASSERT_EACH_EQUAL_INT8_MESSAGE( 0, xPrivateKeyBuffer, sizeof( xPrivateKeyBuffer ));

    /* Check that public key point can be retrieved for public key. */
    xTemplate.type = CKA_EC_POINT;
    xTemplate.pValue = xEcPoint;
    xTemplate.ulValueLen = sizeof( xEcPoint );
    printf("\n%d\n",__LINE__);
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKeyHandle, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
#endif
    /* Perform a sign with the generated private key. */
    xMechanism.mechanism = CKM_ECDSA;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
#if 1
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    //printf("\n%d xResult = %x\n",__LINE__,xResult);

    xSignatureLength = sizeof( xSignature );
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, &xSignatureLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    //printf("\n%d xResult = %x\n",__LINE__,xResult);
#endif
    /* Verify the signature with mbedTLS */
    mbedtls_ecdsa_init( &xEcdsaContext );
    mbedtls_ecp_group_init( &xEcdsaContext.grp );

    if( TEST_PROTECT() )
    {
    #if 0
    printf("\n%d\n",__LINE__);
        lMbedTLSResult = mbedtls_ecp_group_load( &xEcdsaContext.grp, MBEDTLS_ECP_DP_SECP256R1 );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);
        /* The first 2 bytes are for ASN1 type/length encoding. */
        lMbedTLSResult = mbedtls_ecp_point_read_binary( &xEcdsaContext.grp, &xEcdsaContext.Q, &xEcPoint[ 2 ], xTemplate.ulValueLen - 2 );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);
    printf("\n%d\n",__LINE__);

        /* C_Sign returns the R & S components one after another- import these into a format that mbedTLS can work with. */
        mbedtls_mpi_init( &xR );
        mbedtls_mpi_init( &xS );
        lMbedTLSResult = mbedtls_mpi_read_binary( &xR, &xSignature[ 0 ], 32 );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);
        lMbedTLSResult = mbedtls_mpi_read_binary( &xS, &xSignature[ 32 ], 32 );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);
    printf("\n%d\n",__LINE__);

        /* Verify using mbedTLS & exported public key. */
        lMbedTLSResult = mbedtls_ecdsa_verify( &xEcdsaContext.grp, xHashedMessage, sizeof( xHashedMessage ), &xEcdsaContext.Q, &xR, &xS );
        CU_ASSERT_EQUAL( 0, lMbedTLSResult);
    printf("\n%d\n",__LINE__);
	#endif
        /* Verify the signature with the generated public key. */
        xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKeyHandle );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    //printf("\n%d xResult = %x\n",__LINE__,xResult);
        xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, xSignatureLength );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    //printf("\n%d xResult = %x\n",__LINE__,xResult);
    }
#if 0
    mbedtls_mpi_free( &xR );
    mbedtls_mpi_free( &xS );
    mbedtls_ecp_group_free( &xEcdsaContext.grp );
    mbedtls_ecdsa_free( &xEcdsaContext );


    /* Check that FindObject works on Generated Key Pairs. */
    xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, &xFoundPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CK_INVALID_HANDLE, xFoundPrivateKeyHandle);

    xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, CKO_PUBLIC_KEY, &xFoundPublicKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CK_INVALID_HANDLE, xFoundPrivateKeyHandle);

    /* Close & reopen the session.  Make sure you can still find the keys. */
    xResult = pxGlobalFunctionList->C_CloseSession( xGlobalSession );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    xResult = xInitializePkcs11Session( &xGlobalSession );
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, &xFoundPrivateKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( CK_INVALID_HANDLE, xFoundPrivateKeyHandle );

    xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, CKO_PUBLIC_KEY, &xFoundPublicKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( CK_INVALID_HANDLE, xFoundPrivateKeyHandle );
#endif
}

#include "mbedtls/entropy_poll.h"
void AFQP_Verify(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_MECHANISM xMechanism;
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xbe };
    CK_BYTE xSignature[ pkcs11ECDSA_P256_SIGNATURE_LENGTH + 10 ] = { 0 };
    CK_BYTE xSignaturePKCS[ 64 ] = { 0 };
    size_t xSignatureLength = pkcs11ECDSA_P256_SIGNATURE_LENGTH;
    mbedtls_pk_context xPkContext;
    /* TODO: Consider switching this out for a C_GenerateRandom dependent function for ports not implementing mbedTLS. */
    mbedtls_entropy_context xEntropyContext;
    mbedtls_ctr_drbg_context xDrbgContext;
    int lMbedResult;

    prvProvisionCredentialsWithKeyImport( &xPrivateKey, &xCertificate, &xPublicKey );

    /* Sign data w/ PKCS. */
    xMechanism.mechanism = CKM_ECDSA;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKey );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, sizeof( xHashedMessage ), xSignature, ( CK_ULONG * ) &xSignatureLength );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKey );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, sizeof( xSignaturePKCS ) );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    /* Sign data with mbedTLS. */

    /* Initialize the private key. */
    mbedtls_pk_init( &xPkContext );
    lMbedResult = mbedtls_pk_parse_key( &xPkContext,
                                        ( const unsigned char * ) cValidECDSAPrivateKey,
                                        sizeof( cValidECDSAPrivateKey ),
                                        NULL,
                                        0 );
    CU_ASSERT_EQUAL( 0, lMbedResult);
    /* Initialize the RNG. */
    mbedtls_entropy_init( &xEntropyContext );
    mbedtls_ctr_drbg_init( &xDrbgContext );
    lMbedResult = mbedtls_ctr_drbg_seed( &xDrbgContext, mbedtls_entropy_func, &xEntropyContext, NULL, 0 );
    CU_ASSERT_EQUAL( 0, lMbedResult);

    lMbedResult = mbedtls_pk_sign( &xPkContext, MBEDTLS_MD_SHA256, xHashedMessage, sizeof( xHashedMessage ), xSignature, &xSignatureLength, mbedtls_ctr_drbg_random, &xDrbgContext );
    CU_ASSERT_EQUAL( 0, lMbedResult);

    mbedtls_pk_free( &xPkContext );
    mbedtls_ctr_drbg_free( &xDrbgContext );
    mbedtls_entropy_free( &xEntropyContext );

    /* Reconstruct the signature in PKCS #11 format. */
    ////lMbedResult = PKI_mbedTLSSignatureToPkcs11Signature( xSignaturePKCS,
                                                         //xSignature );
    //CU_ASSERT_EQUAL( 0, lMbedResult);

    /* Verify with PKCS #11. */
    xMechanism.mechanism = CKM_ECDSA;
    xMechanism.pParameter = NULL;
    xMechanism.ulParameterLen = 0;
    xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKey );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignaturePKCS, sizeof( xSignaturePKCS ) );
    CU_ASSERT_EQUAL( CKR_OK, xResult);

    /* Modify signature value and make sure verification fails. */
}

void AFQP_FindObject_test(void)
{
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey;
    CK_OBJECT_HANDLE xCertificate;

    prvProvisionCredentialsWithKeyImport( &xPrivateKey, &xCertificate, &xPublicKey );

    /* Provision a device public key as well. */
    prvFindObjectTest();
}

extern int convert_pem_to_der( const unsigned char * pucInput,
                               size_t xLen,
                               unsigned char * pucOutput,
                               size_t * pxOlen );

void AFQP_GetAttributeValue(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_ATTRIBUTE xTemplate;
    CK_KEY_TYPE xKeyType = 0;
    uint8_t ucP256Oid[] = pkcs11DER_ENCODED_OID_P256;
    CK_BYTE xEcParams[ 10 ] = { 0 };
    CK_OBJECT_CLASS xClass;
    CK_BYTE xEcPointExpected[] =
    {
        0x04, 0x41, 0x04, 0xce, 0x08, 0x69, 0xf9, 0x0b, 0x2d, 0x52, 0x13, 0xa6, 0xcc, 0xa0, 0x46, 0x10,
        0xbe, 0xee, 0x06, 0x3b, 0x1a, 0x05, 0xbc, 0x9a, 0x35, 0x33, 0x0b, 0x5c, 0xa2, 0xd2, 0x5b, 0xbf,
        0x3e, 0x6d, 0xda, 0x0f, 0xf5, 0xb2, 0x93, 0x3a, 0xba, 0xa2, 0x2a, 0x4f, 0x46, 0xcc, 0x59, 0x3d,
        0x0a, 0x1b, 0x61, 0x1c, 0x5b, 0x31, 0xf9, 0x3e, 0xd4, 0x16, 0x2b, 0x61, 0x6d, 0x85, 0xad, 0x45,
        0xfd, 0x19, 0xc3
    };
    CK_BYTE xCertificateValueExpected[ 626 ];
    CK_BYTE xCertificateValue[ 626 ];
    CK_BYTE xEcPoint[ sizeof( xEcPointExpected ) ] = { 0 };
    size_t xLength = sizeof( xCertificateValueExpected );
    int lConversionReturn;

    lConversionReturn = convert_pem_to_der( ( const unsigned char * ) cValidECDSACertificate,
                                            sizeof( cValidECDSACertificate ),
                                            xCertificateValueExpected,
                                            &xLength );

    if( lConversionReturn != 0 )
    {
        printf( ( "Failed to convert the EC certificate from PEM to DER. Error code %d \r\n", lConversionReturn ) );
    }

    prvProvisionCredentialsWithKeyImport( &xPrivateKey, &xCertificate, &xPublicKey );

    /* The PKCS #11 standard expects that calling GetAttributeValue with a null pointer to the value
     * will yield a success with the value length updated to the size of the buffer needed to contain
     * the attribute.
     *
     * All tests start by querying the attribute length, and followed by a query of the attribute value. */

    /***** Private Key Checks. *****/

    /* Check object class. */
    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;

    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( CK_OBJECT_CLASS ), xTemplate.ulValueLen);

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CKO_PRIVATE_KEY, xClass );

    /* Key type. */
    xTemplate.type = CKA_KEY_TYPE;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( CK_KEY_TYPE ), xTemplate.ulValueLen);

    xTemplate.pValue = &xKeyType;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CKK_EC, xKeyType);

    /* Check EC Params. */
    xTemplate.type = CKA_EC_PARAMS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_EQUAL( sizeof( ucP256Oid ), xTemplate.ulValueLen);

    xTemplate.pValue = xEcParams;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPrivateKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    //CU_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( ucP256Oid, xEcParams, sizeof( ucP256Oid ));

    /******* Public Key ********/
    /* Object class. */
    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( CK_OBJECT_CLASS ), xTemplate.ulValueLen);

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CKO_PUBLIC_KEY, xClass);

    /* Elliptic Curve Parameters (the OID of the curve). At this time only P256 curves are supported. */
    xTemplate.type = CKA_EC_PARAMS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( ucP256Oid ), xTemplate.ulValueLen);

    memset( xEcParams, 0x0, sizeof( ucP256Oid ) );
    xTemplate.pValue = xEcParams;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    //CU_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( ucP256Oid, xEcParams, sizeof( ucP256Oid ));

    /* Elliptic curve point. */
    xTemplate.type = CKA_EC_POINT;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( xEcPointExpected ), xTemplate.ulValueLen);

    xTemplate.pValue = xEcPoint;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xPublicKey, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    //CU_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( xEcPointExpected, xEcPoint, sizeof( xEcPointExpected ), "Incorrect EC Point returned from GetAttributeValue" );

    /****** Certificate check. *******/
    /* Object class. */

    xTemplate.type = CKA_CLASS;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( CK_OBJECT_CLASS ), xTemplate.ulValueLen);

    xTemplate.pValue = &xClass;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( CKO_CERTIFICATE, xClass);

    /* Certificate value (the DER encoded certificate). */
    xTemplate.type = CKA_VALUE;
    xTemplate.pValue = NULL;
    xTemplate.ulValueLen = 0;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult);
    CU_ASSERT_EQUAL( sizeof( xCertificateValueExpected ), xTemplate.ulValueLen );

    xTemplate.pValue = xCertificateValue;
    xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    //CU_ASSERT_EQUAL_INT8_ARRAY_MESSAGE( xCertificateValueExpected, xCertificateValue, sizeof( xCertificateValueExpected ), "Incorrect certificate value returned." );
}


void ut_generate_keypair_sign_verify_rsa(void)
{
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKeyHandle;
    CK_OBJECT_HANDLE xPublicKeyHandle;
    CK_MECHANISM xMechanism;
    CK_BYTE xHashedMessage[ 64 ] = { 0 };
	CK_ULONG hash_data_length[] = {32, 32, 48, 64};
    CK_BYTE xSignature[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    CK_ULONG xSignatureLength;
    CK_BYTE xModulus[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    unsigned int ulModulusLength = 0;
    CK_BYTE xExponent[ 4 ] = { 0 };
    unsigned int ulExponentLength = 0;
    CK_BYTE xPaddedHash[ pkcs11RSA_2048_SIGNATURE_LENGTH ] = { 0 };
    mbedtls_rsa_context xRsaContext;
	CK_MECHANISM_TYPE test_mechanism[] = {CKM_RSA_PKCS,
										  CKM_SHA256_RSA_PKCS,
										  CKM_SHA384_RSA_PKCS,
										  CKM_SHA512_RSA_PKCS};
	unsigned int loop_count = 0; 

    //xResult = prvDestroyTestCredentials();
    xCurrentCredentials = eNone;
    //CU_ASSERT_EQUAL( CKR_OK, xResult);
	xResult = prvBeforeRunningTests();
    CU_ASSERT_EQUAL( CKR_OK, xResult );
	xResult = xInitializePkcs11Session( &xGlobalSession );
    CU_ASSERT_EQUAL( CKR_OK, xResult );

    xResult = xProvisionGenerateKeyPairRSA( xGlobalSession,
                                            ( uint8_t * ) pkcs11testLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS,
                                            ( uint8_t * ) pkcs11testLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS,
                                            &xPrivateKeyHandle,
                                            &xPublicKeyHandle );
    CU_ASSERT_EQUAL( CKR_OK, xResult );
    CU_ASSERT_NOT_EQUAL( 0, xPrivateKeyHandle );
    /* The RSA X.509 mechanism assumes a pre-hashed input. */
	for(loop_count = 0; loop_count < 4; loop_count++)
	{
	    xMechanism.mechanism = test_mechanism[loop_count];
	    xMechanism.pParameter = NULL;
	    xMechanism.ulParameterLen = 0;
	    xResult = pxGlobalFunctionList->C_SignInit( xGlobalSession, &xMechanism, xPrivateKeyHandle );
	    CU_ASSERT_EQUAL( CKR_OK, xResult );

	    xSignatureLength = sizeof( xSignature );
	    xResult = pxGlobalFunctionList->C_Sign( xGlobalSession, xHashedMessage, hash_data_length[loop_count], xSignature, &xSignatureLength );
	    CU_ASSERT_EQUAL( CKR_OK, xResult);
		
		/* Verify the signature with the generated public key. */
		xResult = pxGlobalFunctionList->C_VerifyInit( xGlobalSession, &xMechanism, xPublicKeyHandle );
		CU_ASSERT_EQUAL( CKR_OK, xResult );
		
		xResult = pxGlobalFunctionList->C_Verify( xGlobalSession, xHashedMessage, hash_data_length[loop_count], xSignature, xSignatureLength );
		CU_ASSERT_EQUAL( CKR_OK, xResult);
	}

}

#if 0
/* Repeatedly tries to find previously provisioned private key and certificate. */
static void prvFindObjectMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    BaseType_t xCount;
    CK_RV xResult;
    CK_OBJECT_HANDLE xHandle;
    CK_SESSION_HANDLE xSession;

    memcpy( &xSession, pxMultiTaskParam->pvTaskData, sizeof( CK_SESSION_HANDLE ) );

    for( xCount = 0; xCount < pkcs11testMULTI_THREAD_LOOP_COUNT; xCount++ )
    {
        xResult = xFindObjectWithLabelAndClass( xSession, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, &xHandle );

        if( xResult != CKR_OK )
        {
            printf( ( "FindObject multithreaded task failed to find private key.  Error: %d  Count: %d \r\n", xResult, xCount ) );
            break;
        }

        if( ( xHandle == CK_INVALID_HANDLE ) )
        {
            printf( ( "FindObject multi-thread task failed to find private key.  Invalid object handle returned.  Count: %d \r\n", xCount ) );
            xResult = CKR_OBJECT_HANDLE_INVALID; /* Mark xResult so that test fails. */
            break;
        }

        xResult = xFindObjectWithLabelAndClass( xSession, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, &xHandle );

        if( xResult != CKR_OK )
        {
            printf( ( "FindObject multithreaded task failed to find certificate.  Error: %d  Count: %d \r\n", xResult, xCount ) );
            break;
        }

        if( ( xHandle == CK_INVALID_HANDLE ) )
        {
            printf( ( "FindObject multi-thread task failed to find certificate.  Invalid object handle returned. Count: %d \r\n", xCount ) );
            xResult = CKR_OBJECT_HANDLE_INVALID; /* Mark xResult so that test fails. */
            break;
        }
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;

    /* Report that task is finished, then delete task. */
    ( void ) xEventGroupSetBits( xSyncEventGroup,
                                 ( 1 << pxMultiTaskParam->xTaskNumber ) );
    vTaskDelete( NULL );
}



/* Different session trying to find token objects. */
void AFQP_FindObjectMultiThread(void)
{
    CK_RV xResult;
    BaseType_t xTaskNumber;
    CK_SESSION_HANDLE xSessionHandle[ pkcs11testMULTI_THREAD_TASK_COUNT ];
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_OBJECT_HANDLE xPublicKey;

    for( xTaskNumber = 0; xTaskNumber < pkcs11testMULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xSessionHandle[ xTaskNumber ] );

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            CU_ASSERT_EQUAL( CKR_OK, xResult);
        }

        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xSessionHandle[ xTaskNumber ];
    }

    prvProvisionEcTestCredentials( &xPrivateKey, &xCertificate, &xPublicKey );

    prvMultiThreadHelper( ( void * ) prvFindObjectMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < pkcs11testMULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xSessionHandle[ xTaskNumber ] );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    }
}

static void prvECGetAttributeValueMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    BaseType_t xCount;
    CK_RV xResult;
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_SESSION_HANDLE xSession;
    CK_ATTRIBUTE xTemplate;
    CK_BYTE xEcParamsExpected[] = pkcs11DER_ENCODED_OID_P256;
    CK_BYTE xEcParams[ sizeof( xEcParamsExpected ) ];
    CK_BYTE xCertificateValue[ 1000 ]; /* TODO: Probably need a max cert length supported per-port. */
    int lMbedReturn;
    mbedtls_x509_crt xMbedCert;

    memcpy( &xSession, pxMultiTaskParam->pvTaskData, sizeof( CK_SESSION_HANDLE ) );

    xResult = xFindObjectWithLabelAndClass( xSession, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, &xPrivateKey );

    if( ( xResult != CKR_OK ) || ( xPrivateKey == CK_INVALID_HANDLE ) )
    {
        xResult = 1;
        printf( ( "Failed to find private key.  Return Value: %d  Handle: %d \r\n", xResult, xPrivateKey ) );
    }

    xResult = xFindObjectWithLabelAndClass( xSession, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, &xCertificate );

    if( ( xResult != CKR_OK ) || ( xCertificate == CK_INVALID_HANDLE ) )
    {
        xResult = 1;
        printf( ( "Failed to find certificate key.  Return Value: %d  Handle: %d \r\n", xResult, xCertificate ) );
    }

    if( xResult == CKR_OK )
    {
        for( xCount = 0; xCount < pkcs11testMULTI_THREAD_LOOP_COUNT; xCount++ )
        {
            xTemplate.type = CKA_EC_PARAMS;
            xTemplate.pValue = xEcParams;
            xTemplate.ulValueLen = sizeof( xEcParams );

            xResult = pxGlobalFunctionList->C_GetAttributeValue( xSession, xPrivateKey, &xTemplate, 1 );

            if( xResult != CKR_OK )
            {
                printf( ( "GetAttributeValue multithread test failed to get private key's EC Params.  Error: %d  Count: %d \r\n", xResult, xCount ) );
                break;
            }

            if( memcmp( xEcParams, xEcParamsExpected, sizeof( xEcParams ) ) )
            {
                printf( ( "GetAttributeValue multithread test returned an incorrect value for EC Params.  Error: %d  Count: %d \r\n", xResult, xCount ) );
                xResult = 1;
                break;
            }

            xTemplate.type = CKA_VALUE;
            xTemplate.pValue = xCertificateValue;
            xTemplate.ulValueLen = sizeof( xCertificateValue );
            xResult = pxGlobalFunctionList->C_GetAttributeValue( xGlobalSession, xCertificate, &xTemplate, 1 );

            if( xResult != CKR_OK )
            {
                printf( ( "GetAttributeValue multi-thread task failed to get certificate.  Error: %d  Count: %d \r\n", xResult, xCount ) );
                xResult = 1;
                break;
            }

            /* Check that the certificate parses. */
            mbedtls_x509_crt_init( &xMbedCert );

            lMbedReturn = mbedtls_x509_crt_parse( &xMbedCert, xTemplate.pValue, xTemplate.ulValueLen );

            if( lMbedReturn != 0 )
            {
                printf( ( "GetAttributeValue multi-thread task found an invalid certificate value. Parse error: %d,  Count: %d \r\n", lMbedReturn, xCount ) );
                printf( ( "First 3 bytes of invalid certificate found are %d, %d, %d \r\n", ( int ) xCertificateValue[ 0 ], ( int ) xCertificateValue[ 1 ], ( int ) xCertificateValue[ 2 ] ) );
                xResult = 1;
                break;
            }

            mbedtls_x509_crt_free( &xMbedCert );
        }
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;

    /* Report that task is finished, then delete task. */
    ( void ) xEventGroupSetBits( xSyncEventGroup,
                                 ( 1 << pxMultiTaskParam->xTaskNumber ) );
    vTaskDelete( NULL );
}

/* Same & different PKCS #11 sessions asking for attribute values of the same 2 objects. */
void AFQP_GetAttributeValueMultiThread(void)
{
    CK_RV xResult;
    BaseType_t xTaskNumber;
    CK_SESSION_HANDLE xSessionHandle[ pkcs11testMULTI_THREAD_TASK_COUNT ];
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_OBJECT_HANDLE xPublicKey;

    for( xTaskNumber = 0; xTaskNumber < pkcs11testMULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xSessionHandle[ xTaskNumber ] );

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            CU_ASSERT_EQUAL( CKR_OK, xResult);
        }

        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xSessionHandle[ xTaskNumber ];
    }

    prvProvisionEcTestCredentials( &xPrivateKey, &xCertificate, &xPublicKey );

    prvMultiThreadHelper( ( void * ) prvECGetAttributeValueMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < pkcs11testMULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xSessionHandle[ xTaskNumber ] );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    }
}


typedef struct SignVerifyMultiThread_t
{
    CK_SESSION_HANDLE xSession;
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey;
    mbedtls_ecp_keypair * pxEcdsaContext; /* Pointer to the pre-parsed ECDSA key. */
} SignVerifyMultiThread_t;

static void prvECSignVerifyMultiThreadTask( void * pvParameters )
{
    MultithreadTaskParams_t * pxMultiTaskParam = pvParameters;
    SignVerifyMultiThread_t * pxSignStruct = pxMultiTaskParam->pvTaskData;
    CK_SESSION_HANDLE xSession = pxSignStruct->xSession;
    CK_OBJECT_HANDLE xPrivateKey = pxSignStruct->xPrivateKey;
    CK_OBJECT_HANDLE xPublicKey = pxSignStruct->xPublicKey;
    BaseType_t xCount;
    CK_RV xResult;
    /* Note that ECDSA operations on a signature of all 0's is not permitted. */
    CK_BYTE xHashedMessage[ pkcs11SHA256_DIGEST_LENGTH ] = { 0xab };
    CK_MECHANISM xMechanism;
    CK_BYTE xSignature[ 64 ] = { 0 };
    CK_ULONG xSignatureLength;

    for( xCount = 0; xCount < pkcs11testMULTI_THREAD_LOOP_COUNT; xCount++ )
    {
        xMechanism.mechanism = CKM_ECDSA;
        xMechanism.pParameter = NULL;
        xMechanism.ulParameterLen = 0;
        xResult = pxGlobalFunctionList->C_SignInit( xSession, &xMechanism, xPrivateKey );

        if( xResult != CKR_OK )
        {
            printf( ( "Sign multi-threaded test failed to SignInit. Error: %d  Count: %d \r\n", xResult, xCount ) );
            break;
        }

        xSignatureLength = sizeof( xSignature );
        xResult = pxGlobalFunctionList->C_Sign( xSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, &xSignatureLength );

        if( xResult != CKR_OK )
        {
            printf( ( "Sign multi-threaded test failed to Sign. Error: %d  Count: %d \r\n", xResult, xCount ) );
            break;
        }

        xResult = pxGlobalFunctionList->C_VerifyInit( xSession, &xMechanism, xPublicKey );

        if( xResult != CKR_OK )
        {
            printf( ( "Multithread VerifyInit failed.  Error: %d, Count: %d \r\n", xResult, xCount ) );
            break;
        }

        xResult = pxGlobalFunctionList->C_Verify( xSession, xHashedMessage, pkcs11SHA256_DIGEST_LENGTH, xSignature, sizeof( xSignature ) );

        if( xResult != CKR_OK )
        {
            printf( ( "Multithread Verify failed.  Error: %d, Count: %d \r\n", xResult, xCount ) );
            break;
        }
    }

    /* Report the result of the loop. */
    pxMultiTaskParam->xTestResult = xResult;

    /* Report that task is finished, then delete task. */
    ( void ) xEventGroupSetBits( xSyncEventGroup,
                                 ( 1 << pxMultiTaskParam->xTaskNumber ) );
    vTaskDelete( NULL );
}


void AFQP_SignVerifyMultiThread(void)
{
    CK_RV xResult;
    BaseType_t xTaskNumber;
    SignVerifyMultiThread_t xSignStructs[ pkcs11testMULTI_THREAD_TASK_COUNT ];
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_OBJECT_HANDLE xPublicKey;

    prvProvisionEcTestCredentials( &xPrivateKey, &xCertificate, &xPublicKey );

    for( xTaskNumber = 0; xTaskNumber < pkcs11testMULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = xInitializePkcs11Session( &xSignStructs[ xTaskNumber ].xSession );

        if( xResult != CKR_USER_ALREADY_LOGGED_IN )
        {
            CU_ASSERT_EQUAL( CKR_OK, xResult );
        }

        xSignStructs[ xTaskNumber ].xPrivateKey = xPrivateKey;
        xSignStructs[ xTaskNumber ].xPublicKey = xPublicKey;
        xGlobalTaskParams[ xTaskNumber ].pvTaskData = &xSignStructs[ xTaskNumber ];
    }

    prvMultiThreadHelper( ( void * ) prvECSignVerifyMultiThreadTask );

    for( xTaskNumber = 0; xTaskNumber < pkcs11testMULTI_THREAD_TASK_COUNT; xTaskNumber++ )
    {
        xResult = pxGlobalFunctionList->C_CloseSession( xSignStructs[ xTaskNumber ].xSession );
        CU_ASSERT_EQUAL( CKR_OK, xResult);
    }
}
#endif
