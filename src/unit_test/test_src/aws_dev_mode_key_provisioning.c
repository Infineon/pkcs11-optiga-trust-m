/*
 * FreeRTOS V202002.00
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


/**
 * @file aws_dev_mode_key_provisioning.c
 * @brief Simple key provisioning example using PKCS #11
 *
 * A simple example to demonstrate key and certificate provisioning in
 * flash using PKCS #11 interface. This should be replaced
 * by production ready key provisioning mechanism.
 */

/* Standard includes. */
#include <stdio.h>
#include <string.h>

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/common/optiga_lib_logger.h"
#include "optiga/pal/pal.h"
#include "pkcs11.h"
#include "aws_dev_mode_key_provisioning.h"
/* mbedTLS includes. */
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"
#include "mbedtls/rsa.h"

/* Default FreeRTOS API for console logging. */
#define DEV_MODE_KEY_PROVISIONING_PRINT( X )    printf(X);

/**
 * @brief RSA signature padding for interoperability between providing hashed messages
 * and providing hashed messages encoded with the digest information.
 *
 * The TLS connection for mbedTLS expects a hashed, but unpadded input,
 * and it appended message digest algorithm encoding.  However, the PKCS #11 sign
 * function either wants unhashed data which it will both hash and pad OR
 * as done in this workaround, we provide hashed data with padding appended.
 *
 * DigestInfo :: = SEQUENCE{
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      digest Digest }
 *
 * DigestAlgorithmIdentifier :: = AlgorithmIdentifier
 * Digest :: = OCTET STRING
 *
 * This is the DigestInfo sequence, digest algorithm, and the octet string/length
 * for the digest, without the actual digest itself.
 */
#define pkcs11STUFF_APPENDED_TO_RSA_SIG    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 }
/* Certificate Template */
/* The object class must be the first attribute in the array. */
typedef struct PKCS11_CertificateTemplate
{
    CK_ATTRIBUTE xObjectClass;     /* CKA_CLASS, set to CKO_CERTIFICATE. */
    CK_ATTRIBUTE xSubject;         /* CKA_SUBJECT, this parameter is required by the PKCS #11 standard. */
    CK_ATTRIBUTE xCertificateType; /* CKA_CERTIFICATE_TYPE, set to CKC_X_509. */
    CK_ATTRIBUTE xValue;           /* CKA_VALUE, the DER byte array of the certificate contents. */
    CK_ATTRIBUTE xLabel;           /* CKA_LABEL. */
    CK_ATTRIBUTE xTokenObject;     /* CKA_TOKEN. */
} PKCS11_CertificateTemplate_t, * PKCS11_CertificateTemplatePtr_t;

/* For writing log lines without a prefix. */
void vLoggingPrint( const char * pcMessage )
{
    printf("%s",pcMessage);
}
#define configPRINTF( X ) //printf(X);


/* Adding one to all of the lengths because ASN1 may pad a leading 0 byte
 * to numbers that could be interpreted as negative */
typedef struct RsaParams_t
{
    CK_BYTE modulus[ MODULUS_LENGTH + 1 ];
    CK_BYTE e[ E_LENGTH + 1 ];
    CK_BYTE d[ D_LENGTH + 1 ];
    CK_BYTE prime1[ PRIME_1_LENGTH + 1 ];
    CK_BYTE prime2[ PRIME_2_LENGTH + 1 ];
    CK_BYTE exponent1[ EXPONENT_1_LENGTH + 1 ];
    CK_BYTE exponent2[ EXPONENT_2_LENGTH + 1 ];
    CK_BYTE coefficient[ COEFFICIENT_LENGTH + 1 ];
} RsaParams_t;

/* Internal structure for capturing the provisioned state of the host device. */
typedef struct ProvisionedState_t
{
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xClientCertificate;
    CK_OBJECT_HANDLE xPublicKey;
    uint8_t * pucDerPublicKey;
    uint32_t ulDerPublicKeyLength;
    char * pcIdentifier; /* The token label. On some devices, a unique device
                          * ID might be stored here which can be used as a field
                          * in the subject of the device certificate. */
} ProvisionedState_t;

/* This function can be found in libraries/3rdparty/mbedtls/utils/mbedtls_utils.c. */
/*-----------------------------------------------------------*/

/* @brief Converts PEM documents into DER formatted byte arrays.
 * This is a helper function from mbedTLS util pem2der.c
 * (https://github.com/ARMmbed/mbedtls/blob/development/programs/util/pem2der.c#L75)
 *
 * \param pucInput[in]       Pointer to PEM object
 * \param xLen[in]           Length of PEM object
 * \param pucOutput[out]     Pointer to buffer where DER oboject will be placed
 * \param pxOlen[in/out]     Pointer to length of DER buffer.  This value is updated
 *                          to contain the actual length of the converted DER object.
 *
 * \return 0 if successful.  Negative if conversion failed.  If buffer is not
 * large enough to hold converted object, pxOlen is still updated but -1 is returned.
 *
 */
int convert_pem_to_der( const unsigned char * pucInput,
                        size_t xLen,
                        unsigned char * pucOutput,
                        size_t * pxOlen )
{
    int lRet;
    const unsigned char * pucS1;
    const unsigned char * pucS2;
    const unsigned char * pucEnd = pucInput + xLen;
    size_t xOtherLen = 0;

    pucS1 = ( unsigned char * ) strstr( ( const char * ) pucInput, "-----BEGIN" );

    if( pucS1 == NULL )
    {
        return( -1 );
    }

    pucS2 = ( unsigned char * ) strstr( ( const char * ) pucInput, "-----END" );

    if( pucS2 == NULL )
    {
        return( -1 );
    }

    pucS1 += 10;

    while( pucS1 < pucEnd && *pucS1 != '-' )
    {
        pucS1++;
    }

    while( pucS1 < pucEnd && *pucS1 == '-' )
    {
        pucS1++;
    }

    if( *pucS1 == '\r' )
    {
        pucS1++;
    }

    if( *pucS1 == '\n' )
    {
        pucS1++;
    }

    if( ( pucS2 <= pucS1 ) || ( pucS2 > pucEnd ) )
    {
        return( -1 );
    }

    lRet = mbedtls_base64_decode( NULL, 0, &xOtherLen, ( const unsigned char * ) pucS1, pucS2 - pucS1 );

    if( lRet == MBEDTLS_ERR_BASE64_INVALID_CHARACTER )
    {
        return( lRet );
    }

    if( xOtherLen > *pxOlen )
    {
        return( -1 );
    }

    if( ( lRet = mbedtls_base64_decode( pucOutput, xOtherLen, &xOtherLen, ( const unsigned char * ) pucS1,
                                        pucS2 - pucS1 ) ) != 0 )
    {
        return( lRet );
    }

    *pxOlen = xOtherLen;

    return( 0 );
}
/*-----------------------------------------------------------*/


/*-----------------------------------------------------------*/
#if 0
/* Parameter validation macros */
#define RSA_VALIDATE_RET( cond )                                       \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_RSA_BAD_INPUT_DATA )
#define RSA_VALIDATE( cond )                                           \
    MBEDTLS_INTERNAL_VALIDATE( cond )
int mbedtls_rsa_export_raw( const mbedtls_rsa_context *ctx,
                            unsigned char *N, size_t N_len,
                            unsigned char *P, size_t P_len,
                            unsigned char *Q, size_t Q_len,
                            unsigned char *D, size_t D_len,
                            unsigned char *E, size_t E_len )
{
    int ret = 0;
    int is_priv;
    RSA_VALIDATE_RET( ctx != NULL );

    /* Check if key is private or public */
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
    {
        /* If we're trying to export private parameters for a public key,
         * something must be wrong. */
        if( P != NULL || Q != NULL || D != NULL )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    }

    if( N != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->N, N, N_len ) );

    if( P != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->P, P, P_len ) );

    if( Q != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->Q, Q, Q_len ) );

    if( D != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->D, D, D_len ) );

    if( E != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->E, E, E_len ) );

cleanup:

    return( ret );
}
#endif
CK_RV xGetSlotList( CK_SLOT_ID ** ppxSlotId,
                    CK_ULONG * pxSlotCount )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_SLOT_ID * pxSlotId = NULL;

    xResult = C_GetFunctionList( &pxFunctionList );

    if( xResult == CKR_OK )
    {
        xResult = pxFunctionList->C_GetSlotList( CK_TRUE, /* Token Present. */
                                                 NULL,    /* We just want to know how many slots there are. */
                                                 pxSlotCount );
    }

    if( xResult == CKR_OK )
    {
        /* Allocate memory for the slot list. */
        pxSlotId = malloc( sizeof( CK_SLOT_ID ) * ( *pxSlotCount ) );

        if( pxSlotId == NULL )
        {
            xResult = CKR_HOST_MEMORY;
        }
        else
        {
            *ppxSlotId = pxSlotId;
        }
    }

    if( xResult == CKR_OK )
    {
        xResult = pxFunctionList->C_GetSlotList( CK_TRUE, pxSlotId, pxSlotCount );
    }

    if( ( xResult != CKR_OK ) && ( pxSlotId != NULL ) )
    {
        free( pxSlotId );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* @brief Open a PKCS #11 Session.
 *
 *  \param[out] pxSession   Pointer to the session handle to be created.
 *  \param[out] xSlotId     Slot ID to be used for the session.
 *
 *  \return CKR_OK or PKCS #11 error code. (PKCS #11 error codes are positive).
 */
CK_RV prvOpenSession( CK_SESSION_HANDLE * pxSession,
                      CK_SLOT_ID xSlotId )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;

    xResult = C_GetFunctionList( &pxFunctionList );

    if( xResult == CKR_OK )
    {
        xResult = pxFunctionList->C_OpenSession( xSlotId,
                                                 CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                                 NULL, /* Application defined pointer. */
                                                 NULL, /* Callback function. */
                                                 pxSession );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

#ifdef CreateMutex
    #undef CreateMutex /* This is a workaround because CreateMutex is redefined to CreateMutexW in synchapi.h in windows. :/ */
#endif

/*-----------------------------------------------------------*/

CK_RV xInitializePKCS11( void )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_C_INITIALIZE_ARGS xInitArgs;

    xInitArgs.CreateMutex = NULL;
    xInitArgs.DestroyMutex = NULL;
    xInitArgs.LockMutex = NULL;
    xInitArgs.UnlockMutex = NULL;
    xInitArgs.flags = CKF_OS_LOCKING_OK;
    xInitArgs.pReserved = NULL;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Initialize the PKCS #11 module. */
    if( xResult == CKR_OK )
    {
        xResult = pxFunctionList->C_Initialize( &xInitArgs );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Perform common token initialization as per the PKCS #11 standard. For
 * compatibility reasons, this may include authentication with a static PIN. */
CK_RV xInitializePkcs11Token( void )
{
    CK_RV xResult;

    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_SLOT_ID * pxSlotId = NULL;
    CK_ULONG xSlotCount;
    CK_FLAGS xTokenFlags = 0;
    CK_TOKEN_INFO_PTR pxTokenInfo = NULL;

    xResult = C_GetFunctionList( &pxFunctionList );

    if( xResult == CKR_OK )
    {
        xResult = xInitializePKCS11();
    }

    if( ( xResult == CKR_OK ) || ( xResult == CKR_CRYPTOKI_ALREADY_INITIALIZED ) )
    {
        xResult = xGetSlotList( &pxSlotId, &xSlotCount );
    }

    if( ( xResult == CKR_OK ) &&
        ( NULL != pxFunctionList->C_GetTokenInfo ) &&
        ( NULL != pxFunctionList->C_InitToken ) )
    {
        /* Check if the token requires further initialization. */
        pxTokenInfo = malloc( sizeof( CK_TOKEN_INFO ) );

        if( pxTokenInfo != NULL )
        {
            /* We will take the first slot available. If your application
             * has multiple slots, insert logic for selecting an appropriate
             * slot here.
             */
            xResult = pxFunctionList->C_GetTokenInfo( pxSlotId[ 0 ], pxTokenInfo );
        }
        else
        {
            xResult = CKR_HOST_MEMORY;
        }

        if( CKR_OK == xResult )
        {
            xTokenFlags = pxTokenInfo->flags;
        }

        if( ( CKR_OK == xResult ) && !( CKF_TOKEN_INITIALIZED & xTokenFlags ) )
        {
            /* Initialize the token if it is not already. */
            xResult = pxFunctionList->C_InitToken( pxSlotId[ 0 ],
                                                   ( CK_UTF8CHAR_PTR ) configPKCS11_DEFAULT_USER_PIN,
                                                   sizeof( configPKCS11_DEFAULT_USER_PIN ) - 1,
                                                   ( CK_UTF8CHAR_PTR ) "FreeRTOS" );
        }
    }

    if( pxTokenInfo != NULL )
    {
        free( pxTokenInfo );
    }

    if( pxSlotId != NULL )
    {
        free( pxSlotId );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

CK_RV xInitializePkcs11Session( CK_SESSION_HANDLE * pxSession )
{
    CK_RV xResult;
    CK_SLOT_ID * pxSlotId = NULL;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_ULONG xSlotCount;

    xResult = C_GetFunctionList( &pxFunctionList );

    if( pxSession == NULL )
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Initialize the module. */
    if( xResult == CKR_OK )
    {
        xResult = xInitializePKCS11();

        if( xResult == CKR_CRYPTOKI_ALREADY_INITIALIZED )
        {
            xResult = CKR_OK;
        }
    }

    /* Get a list of slots available. */
    if( xResult == CKR_OK )
    {
        xResult = xGetSlotList( &pxSlotId, &xSlotCount );
    }

    /* Open a PKCS #11 session. */
    if( xResult == CKR_OK )
    {
        /* We will take the first slot available.
         * If your application has multiple slots, insert logic
         * for selecting an appropriate slot here.
         */
        xResult = prvOpenSession( pxSession, pxSlotId[ 0 ] );

        /* Free the memory allocated by xGetSlotList. */
        free( pxSlotId );
    }

    if( ( xResult == CKR_OK ) && ( pxFunctionList->C_Login != NULL ) )
    {
        xResult = pxFunctionList->C_Login( *pxSession,
                                           CKU_USER,
                                           ( CK_UTF8CHAR_PTR ) configPKCS11_DEFAULT_USER_PIN,
                                           sizeof( configPKCS11_DEFAULT_USER_PIN ) - 1 );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* @brief Finds an object with a given label if it exists.
 *
 *   This function wraps C_FindObjectsInit, C_FindObjects, and C_FindObjectsFinal.
 *
 *   \param[in] xSession         A valid PKCS #11 session.
 *   \param[in] pcLabelName      The label of the object to be found.
 *   \param[out] pxHandle        Pointer to the handle of the found object,
 *                               or 0 if no object is found.
 *   \return CKR_OK if PKCS #11 calls were successful.  PKCS #11
 *   error code if not.
 *
 *   \note This function returns CKR_OK even if an object with the given
 *   CKA_LABEL is not found.  It is critical that functions verify that
 *   the object handle value is not equal to 0 (the invalid handle)
 *   before attempting to use the handle.
 */
CK_RV xFindObjectWithLabelAndClass( CK_SESSION_HANDLE xSession,
                                    const char * pcLabelName,
                                    CK_OBJECT_CLASS xClass,
                                    CK_OBJECT_HANDLE_PTR pxHandle )
{
    CK_RV xResult = CKR_OK;
    CK_ULONG ulCount = 0;
    CK_BBOOL xFindInit = CK_FALSE;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_ATTRIBUTE xTemplate[ 2 ] =
    {
        { CKA_LABEL, ( char * ) pcLabelName, strlen( pcLabelName )     },
        { CKA_CLASS, &xClass,                sizeof( CK_OBJECT_CLASS ) }
    };

    xResult = C_GetFunctionList( &pxFunctionList );

    if( ( pcLabelName == NULL ) || ( pxHandle == NULL ) )
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Initialize the FindObject state in the underlying PKCS #11 module based
     * on the search template provided by the caller. */
    if( CKR_OK == xResult )
    {
        xResult = pxFunctionList->C_FindObjectsInit( xSession, xTemplate, sizeof( xTemplate ) / sizeof( CK_ATTRIBUTE ) );
    }

    if( CKR_OK == xResult )
    {
        xFindInit = CK_TRUE;
        /* Find the first matching object, if any. */
        xResult = pxFunctionList->C_FindObjects( xSession,
                                                 pxHandle,
                                                 1,
                                                 &ulCount );
    }

    if( ( CKR_OK == xResult ) && ( CK_TRUE == xFindInit ) )
    {
        /* Indicate to the module that the we're done looking for the indicated
         * type of object. */
        xResult = pxFunctionList->C_FindObjectsFinal( xSession );
    }

    if( ( CKR_ARGUMENTS_BAD != xResult ) && ( ulCount == 0 ) )
    {
        *pxHandle = CK_INVALID_HANDLE;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

CK_RV vAppendSHA256AlgorithmIdentifierSequence( uint8_t * x32ByteHashedMessage,
                                                uint8_t * x51ByteHashOidBuffer )
{
    CK_RV xResult = CKR_OK;
    uint8_t xOidSequence[] = pkcs11STUFF_APPENDED_TO_RSA_SIG;

    if( ( x32ByteHashedMessage == NULL ) || ( x51ByteHashOidBuffer == NULL ) )
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( xResult == CKR_OK )
    {
        memcpy( x51ByteHashOidBuffer, xOidSequence, sizeof( xOidSequence ) );
        memcpy( &x51ByteHashOidBuffer[ sizeof( xOidSequence ) ], x32ByteHashedMessage, 32 );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified ECDSA private key into storage. */
static CK_RV prvProvisionPrivateECKey( CK_SESSION_HANDLE xSession,
                                       uint8_t * pucLabel,
                                       CK_OBJECT_HANDLE_PTR pxObjectHandle,
                                       mbedtls_pk_context * pxMbedPkContext )
{
    CK_RV xResult = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_BYTE * pxD;               /* Private value D. */
    CK_BYTE * pxEcParams = NULL; /* DER-encoding of an ANSI X9.62 Parameters value */
    int lMbedResult = 0;
    CK_BBOOL xTrue = CK_TRUE;
    CK_KEY_TYPE xPrivateKeyType = CKK_EC;
    CK_OBJECT_CLASS xPrivateKeyClass = CKO_PRIVATE_KEY;
    mbedtls_ecp_keypair * pxKeyPair = ( mbedtls_ecp_keypair * ) pxMbedPkContext->pk_ctx;

    xResult = C_GetFunctionList( &pxFunctionList );

#define EC_PARAMS_LENGTH    10
#define EC_D_LENGTH         32

    pxD = malloc( EC_D_LENGTH );

    if( ( pxD == NULL ) )
    {
        xResult = CKR_HOST_MEMORY;
    }

    if( xResult == CKR_OK )
    {
        lMbedResult = mbedtls_mpi_write_binary( &( pxKeyPair->d ), pxD, EC_D_LENGTH );

        if( lMbedResult != 0 )
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse EC private key components. \r\n" ) );
            xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }

    if( xResult == CKR_OK )
    {
        if( pxKeyPair->grp.id == MBEDTLS_ECP_DP_SECP256R1 )
        {
            pxEcParams = ( CK_BYTE * ) ( "\x06\x08" MBEDTLS_OID_EC_GRP_SECP256R1 );
        }
        else
        {
            xResult = CKR_CURVE_NOT_SUPPORTED;
        }
    }

    if( xResult == CKR_OK )
    {
        CK_ATTRIBUTE xPrivateKeyTemplate[] =
        {
            { CKA_CLASS,     &xPrivateKeyClass, sizeof( CK_OBJECT_CLASS )                        },
            { CKA_KEY_TYPE,  &xPrivateKeyType,  sizeof( CK_KEY_TYPE )                            },
            { CKA_LABEL,     pucLabel,          ( CK_ULONG ) strlen( ( const char * ) pucLabel ) },
            { CKA_TOKEN,     &xTrue,            sizeof( CK_BBOOL )                               },
            { CKA_SIGN,      &xTrue,            sizeof( CK_BBOOL )                               },
            { CKA_EC_PARAMS, pxEcParams,        EC_PARAMS_LENGTH                                 },
            { CKA_VALUE,     pxD,               EC_D_LENGTH                                      }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) &xPrivateKeyTemplate,
                                                  sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxObjectHandle );
    }

    if( pxD != NULL )
    {
        free( pxD );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified RSA private key into storage. */
static CK_RV prvProvisionPrivateRSAKey( CK_SESSION_HANDLE xSession,
                                        uint8_t * pucLabel,
                                        CK_OBJECT_HANDLE_PTR pxObjectHandle,
                                        mbedtls_pk_context * pxMbedPkContext )
{
    CK_RV xResult = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    int lMbedResult = 0;
    CK_KEY_TYPE xPrivateKeyType = CKK_RSA;
    mbedtls_rsa_context * xRsaContext = pxMbedPkContext->pk_ctx;
    CK_OBJECT_CLASS xPrivateKeyClass = CKO_PRIVATE_KEY;
    RsaParams_t * pxRsaParams = NULL;
    CK_BBOOL xTrue = CK_TRUE;

    xResult = C_GetFunctionList( &pxFunctionList );

    pxRsaParams = malloc( sizeof( RsaParams_t ) );

    if( pxRsaParams == NULL )
    {
        xResult = CKR_HOST_MEMORY;
    }
#if 0
    if( xResult == CKR_OK )
    {
        memset( pxRsaParams, 0, sizeof( RsaParams_t ) );

        lMbedResult = mbedtls_rsa_export_raw( xRsaContext,
                                              pxRsaParams->modulus, MODULUS_LENGTH + 1,
                                              pxRsaParams->prime1, PRIME_1_LENGTH + 1,
                                              pxRsaParams->prime2, PRIME_2_LENGTH + 1,
                                              pxRsaParams->d, D_LENGTH + 1,
                                              pxRsaParams->e, E_LENGTH + 1 );

        if( lMbedResult != 0 )
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse RSA private key components. \r\n" ) );
            xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        }

        /* Export Exponent 1, Exponent 2, Coefficient. */
        lMbedResult |= mbedtls_mpi_write_binary( ( mbedtls_mpi const * ) &xRsaContext->DP, pxRsaParams->exponent1, EXPONENT_1_LENGTH + 1 );
        lMbedResult |= mbedtls_mpi_write_binary( ( mbedtls_mpi const * ) &xRsaContext->DQ, pxRsaParams->exponent2, EXPONENT_2_LENGTH + 1 );
        lMbedResult |= mbedtls_mpi_write_binary( ( mbedtls_mpi const * ) &xRsaContext->QP, pxRsaParams->coefficient, COEFFICIENT_LENGTH + 1 );

        if( lMbedResult != 0 )
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse RSA private key Chinese Remainder Theorem variables. \r\n" ) );
            xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
#endif
    if( xResult == CKR_OK )
    {
        /* When importing the fields, the pointer is incremented by 1
         * to remove the leading 0 padding (if it existed) and the original field length is used */


        CK_ATTRIBUTE xPrivateKeyTemplate[] =
        {
            { CKA_CLASS,            &xPrivateKeyClass,            sizeof( CK_OBJECT_CLASS )                        },
            { CKA_KEY_TYPE,         &xPrivateKeyType,             sizeof( CK_KEY_TYPE )                            },
            { CKA_LABEL,            pucLabel,                     ( CK_ULONG ) strlen( ( const char * ) pucLabel ) },
            { CKA_TOKEN,            &xTrue,                       sizeof( CK_BBOOL )                               },
            { CKA_SIGN,             &xTrue,                       sizeof( CK_BBOOL )                               },
            { CKA_MODULUS,          pxRsaParams->modulus + 1,     MODULUS_LENGTH                                   },
            { CKA_PRIVATE_EXPONENT, pxRsaParams->d + 1,           D_LENGTH                                         },
            { CKA_PUBLIC_EXPONENT,  pxRsaParams->e + 1,           E_LENGTH                                         },
            { CKA_PRIME_1,          pxRsaParams->prime1 + 1,      PRIME_1_LENGTH                                   },
            { CKA_PRIME_2,          pxRsaParams->prime2 + 1,      PRIME_2_LENGTH                                   },
            { CKA_EXPONENT_1,       pxRsaParams->exponent1 + 1,   EXPONENT_1_LENGTH                                },
            { CKA_EXPONENT_2,       pxRsaParams->exponent2 + 1,   EXPONENT_2_LENGTH                                },
            { CKA_COEFFICIENT,      pxRsaParams->coefficient + 1, COEFFICIENT_LENGTH                               }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) &xPrivateKeyTemplate,
                                                  sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxObjectHandle );
    }

    if( NULL != pxRsaParams )
    {
        free( pxRsaParams );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified private key into storage. */
CK_RV xProvisionPrivateKey( CK_SESSION_HANDLE xSession,
                            uint8_t * pucPrivateKey,
                            size_t xPrivateKeyLength,
                            uint8_t * pucLabel,
                            CK_OBJECT_HANDLE_PTR pxObjectHandle )
{
    CK_RV xResult = CKR_OK;
    mbedtls_pk_type_t xMbedKeyType = MBEDTLS_PK_NONE;
    int lMbedResult = 0;
    mbedtls_pk_context xMbedPkContext = { 0 };

    mbedtls_pk_init( &xMbedPkContext );
    lMbedResult = mbedtls_pk_parse_key( &xMbedPkContext, pucPrivateKey, xPrivateKeyLength, NULL, 0 );

    if( lMbedResult != 0 )
    {
        DEV_MODE_KEY_PROVISIONING_PRINT( ( "Unable to parse private key.\r\n" ) );
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Determine whether the key to be imported is RSA or EC. */
    if( xResult == CKR_OK )
    {
        xMbedKeyType = mbedtls_pk_get_type( &xMbedPkContext );

        if( xMbedKeyType == MBEDTLS_PK_RSA )
        {
            xResult = prvProvisionPrivateRSAKey( xSession,
                                                 pucLabel,
                                                 pxObjectHandle,
                                                 &xMbedPkContext );
        }
        else if( ( xMbedKeyType == MBEDTLS_PK_ECDSA ) || ( xMbedKeyType == MBEDTLS_PK_ECKEY ) || ( xMbedKeyType == MBEDTLS_PK_ECKEY_DH ) )
        {
            xResult = prvProvisionPrivateECKey( xSession,
                                                pucLabel,
                                                pxObjectHandle,
                                                &xMbedPkContext );
        }
        else
        {
            DEV_MODE_KEY_PROVISIONING_PRINT( ( "Invalid private key type provided.  RSA-2048 and EC P-256 keys are supported.\r\n" ) );
            xResult = CKR_ARGUMENTS_BAD;
        }
    }

    mbedtls_pk_free( &xMbedPkContext );

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified public key into storage. */
CK_RV xProvisionPublicKey( CK_SESSION_HANDLE xSession,
                           uint8_t * pucKey,
                           size_t xKeyLength,
                           CK_KEY_TYPE xPublicKeyType,
                           uint8_t * pucPublicKeyLabel,
                           CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_BBOOL xTrue = CK_TRUE;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_OBJECT_CLASS xClass = CKO_PUBLIC_KEY;
    int lMbedResult = 0;
    mbedtls_pk_context xMbedPkContext = { 0 };

    xResult = C_GetFunctionList( &pxFunctionList );

    mbedtls_pk_init( &xMbedPkContext );

    /* Try parsing the private key using mbedtls_pk_parse_key. */
    lMbedResult = mbedtls_pk_parse_key( &xMbedPkContext, pucKey, xKeyLength, NULL, 0 );

    /* If mbedtls_pk_parse_key didn't work, maybe the private key is not included in the input passed in.
     * Try to parse just the public key. */
    if( lMbedResult != 0 )
    {
        lMbedResult = mbedtls_pk_parse_public_key( &xMbedPkContext, pucKey, xKeyLength );
    }

    if( lMbedResult != 0 )
    {
        DEV_MODE_KEY_PROVISIONING_PRINT( ( "Failed to parse the public key. \r\n" ) );
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( ( xResult == CKR_OK ) && ( xPublicKeyType == CKK_RSA ) )
    {
        CK_BYTE xPublicExponent[] = { 0x01, 0x00, 0x01 };
        CK_BYTE xModulus[ MODULUS_LENGTH + 1 ] = { 0 };
		/*
        lMbedResult = mbedtls_rsa_export_raw( ( mbedtls_rsa_context * ) xMbedPkContext.pk_ctx,
                                              ( unsigned char * ) &xModulus, MODULUS_LENGTH + 1,
                                              NULL, 0,
                                              NULL, 0,
                                              NULL, 0,
                                              NULL, 0 ); */
        CK_ATTRIBUTE xPublicKeyTemplate[] =
        {
            { CKA_CLASS,           &xClass,           sizeof( CK_OBJECT_CLASS )                    },
            { CKA_KEY_TYPE,        &xPublicKeyType,   sizeof( CK_KEY_TYPE )                        },
            { CKA_TOKEN,           &xTrue,            sizeof( xTrue )                              },
            { CKA_MODULUS,         &xModulus + 1,     MODULUS_LENGTH                               },     /* Extra byte allocated at beginning for 0 padding. */
            { CKA_VERIFY,          &xTrue,            sizeof( xTrue )                              },
            { CKA_PUBLIC_EXPONENT, xPublicExponent,   sizeof( xPublicExponent )                    },
            { CKA_LABEL,           pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) xPublicKeyTemplate,
                                                  sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxPublicKeyHandle );
    }
    else if( ( xResult == CKR_OK ) && ( xPublicKeyType == CKK_EC ) )
    {
        CK_BYTE xEcParams[] = pkcs11DER_ENCODED_OID_P256;
        size_t xLength;
        CK_BYTE xEcPoint[ 256 ] = { 0 };

        mbedtls_ecdsa_context * pxEcdsaContext = ( mbedtls_ecdsa_context * ) xMbedPkContext.pk_ctx;

        /* DER encoded EC point. Leave 2 bytes for the tag and length. */
        lMbedResult = mbedtls_ecp_point_write_binary( &pxEcdsaContext->grp,
                                                      &pxEcdsaContext->Q,
                                                      MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                      &xLength,
                                                      xEcPoint + 2,
                                                      sizeof( xEcPoint ) - 2 );
        xEcPoint[ 0 ] = 0x04; /* Octet string. */
        xEcPoint[ 1 ] = ( CK_BYTE ) xLength;

        CK_ATTRIBUTE xPublicKeyTemplate[] =
        {
            { CKA_CLASS,     &xClass,           sizeof( xClass )                             },
            { CKA_KEY_TYPE,  &xPublicKeyType,   sizeof( xPublicKeyType )                     },
            { CKA_TOKEN,     &xTrue,            sizeof( xTrue )                              },
            { CKA_VERIFY,    &xTrue,            sizeof( xTrue )                              },
            { CKA_EC_PARAMS, xEcParams,         sizeof( xEcParams )                          },
            { CKA_EC_POINT,  xEcPoint,          xLength + 2                                  },
            { CKA_LABEL,     pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
        };

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) xPublicKeyTemplate,
                                                  sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxPublicKeyHandle );
    }
    else
    {
        xResult = CKR_ATTRIBUTE_VALUE_INVALID;
        configPRINTF( ( "Invalid key type. Supported options are CKK_RSA and CKK_EC" ) );
    }

    mbedtls_pk_free( &xMbedPkContext );

    return xResult;
}

/*-----------------------------------------------------------*/

/* Generate a new 2048-bit RSA key pair. Please note that C_GenerateKeyPair for
 * RSA keys is not supported by the FreeRTOS mbedTLS PKCS #11 port. */
CK_RV xProvisionGenerateKeyPairRSA( CK_SESSION_HANDLE xSession,
                                    uint8_t * pucPrivateKeyLabel,
                                    uint8_t * pucPublicKeyLabel,
                                    CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                    CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_MECHANISM xMechanism =
    {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_ULONG xModulusBits = pkcs11RSA_1024_MODULUS_BITS;//pkcs11RSA_2048_MODULUS_BITS;
    CK_BYTE xPublicExponent[] = pkcs11RSA_PUBLIC_EXPONENT;

    CK_BBOOL xTrue = CK_TRUE;
    CK_ATTRIBUTE xPublicKeyTemplate[] =
    {
        { CKA_ENCRYPT,         &xTrue,            sizeof( xTrue )                              },
        { CKA_VERIFY,          &xTrue,            sizeof( xTrue )                              },
        { CKA_MODULUS_BITS,    &xModulusBits,     sizeof( xModulusBits )                       },
        //{ CKA_PUBLIC_EXPONENT, xPublicExponent,   sizeof( xPublicExponent )                    },
        { CKA_LABEL,           pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
    };

    CK_ATTRIBUTE xPrivateKeyTemplate[] =
    {
        { CKA_TOKEN,   &xTrue,             sizeof( xTrue )                               },
        { CKA_PRIVATE, &xTrue,             sizeof( xTrue )                               },
        { CKA_DECRYPT, &xTrue,             sizeof( xTrue )                               },
        { CKA_SIGN,    &xTrue,             sizeof( xTrue )                               },
        { CKA_LABEL,   pucPrivateKeyLabel, strlen( ( const char * ) pucPrivateKeyLabel ) }
    };

    xResult = C_GetFunctionList( &pxFunctionList );

    xResult = pxFunctionList->C_GenerateKeyPair( xSession,
                                                 &xMechanism,
                                                 xPublicKeyTemplate,
                                                 sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 xPrivateKeyTemplate, sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 pxPublicKeyHandle,
                                                 pxPrivateKeyHandle );

    return xResult;
}

/*-----------------------------------------------------------*/

/* Generate a new ECDSA key pair using curve P256. */
CK_RV xProvisionGenerateKeyPairEC( CK_SESSION_HANDLE xSession,
                                   uint8_t * pucPrivateKeyLabel,
                                   uint8_t * pucPublicKeyLabel,
                                   CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                   CK_OBJECT_HANDLE_PTR pxPublicKeyHandle )
{
    CK_RV xResult;
    CK_MECHANISM xMechanism =
    {
        CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_BYTE xEcParams[] = pkcs11DER_ENCODED_OID_P256; /* prime256v1 */
    CK_KEY_TYPE xKeyType = CKK_EC;

    CK_BBOOL xTrue = CK_TRUE;
    CK_ATTRIBUTE xPublicKeyTemplate[] =
    {
        { CKA_KEY_TYPE,  &xKeyType,         sizeof( xKeyType )                           },
        { CKA_VERIFY,    &xTrue,            sizeof( xTrue )                              },
        { CKA_EC_PARAMS, xEcParams,         sizeof( xEcParams )                          },
        { CKA_LABEL,     pucPublicKeyLabel, strlen( ( const char * ) pucPublicKeyLabel ) }
    };

    CK_ATTRIBUTE xPrivateKeyTemplate[] =
    {
        { CKA_KEY_TYPE, &xKeyType,          sizeof( xKeyType )                            },
        { CKA_TOKEN,    &xTrue,             sizeof( xTrue )                               },
        { CKA_PRIVATE,  &xTrue,             sizeof( xTrue )                               },
        { CKA_SIGN,     &xTrue,             sizeof( xTrue )                               },
        { CKA_LABEL,    pucPrivateKeyLabel, strlen( ( const char * ) pucPrivateKeyLabel ) }
    };

    xResult = C_GetFunctionList( &pxFunctionList );

    xResult = pxFunctionList->C_GenerateKeyPair( xSession,
                                                 &xMechanism,
                                                 xPublicKeyTemplate,
                                                 sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 xPrivateKeyTemplate, sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 pxPublicKeyHandle,
                                                 pxPrivateKeyHandle );
	//printf("\n%s pxPrivateKeyHandle = %x *pxPrivateKeyHandle = %x \n",__FUNCTION__,pxPrivateKeyHandle,*pxPrivateKeyHandle);

    return xResult;
}

/*-----------------------------------------------------------*/

/* Import the specified X.509 client certificate into storage. */
CK_RV xProvisionCertificate( CK_SESSION_HANDLE xSession,
                             uint8_t * pucCertificate,
                             size_t xCertificateLength,
                             uint8_t * pucLabel,
                             CK_OBJECT_HANDLE_PTR pxObjectHandle )
{
    PKCS11_CertificateTemplate_t xCertificateTemplate;
    CK_OBJECT_CLASS xCertificateClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE xCertificateType = CKC_X_509;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_RV xResult;
    uint8_t * pucDerObject = NULL;
    int32_t lConversionReturn = 0;
    size_t xDerLen = 0;
    CK_BBOOL xTokenStorage = CK_TRUE;

    /* TODO: Subject is a required attribute.
     * Currently, this field is not used by FreeRTOS ports,
     * this should be updated so that subject matches proper
     * format for future ports. */
    CK_BYTE xSubject[] = "TestSubject";

    /* Initialize the client certificate template. */
    xCertificateTemplate.xObjectClass.type = CKA_CLASS;
    xCertificateTemplate.xObjectClass.pValue = &xCertificateClass;
    xCertificateTemplate.xObjectClass.ulValueLen = sizeof( xCertificateClass );
    xCertificateTemplate.xSubject.type = CKA_SUBJECT;
    xCertificateTemplate.xSubject.pValue = xSubject;
    xCertificateTemplate.xSubject.ulValueLen = strlen( ( const char * ) xSubject );
    xCertificateTemplate.xValue.type = CKA_VALUE;
    xCertificateTemplate.xValue.pValue = ( CK_VOID_PTR ) pucCertificate;
    xCertificateTemplate.xValue.ulValueLen = ( CK_ULONG ) xCertificateLength;
    xCertificateTemplate.xLabel.type = CKA_LABEL;
    xCertificateTemplate.xLabel.pValue = ( CK_VOID_PTR ) pucLabel;
    xCertificateTemplate.xLabel.ulValueLen = strlen( ( const char * ) pucLabel );
    xCertificateTemplate.xCertificateType.type = CKA_CERTIFICATE_TYPE;
    xCertificateTemplate.xCertificateType.pValue = &xCertificateType;
    xCertificateTemplate.xCertificateType.ulValueLen = sizeof( CK_CERTIFICATE_TYPE );
    xCertificateTemplate.xTokenObject.type = CKA_TOKEN;
    xCertificateTemplate.xTokenObject.pValue = &xTokenStorage;
    xCertificateTemplate.xTokenObject.ulValueLen = sizeof( xTokenStorage );

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Test for a valid certificate: 0x2d is '-', as in ----- BEGIN CERTIFICATE. */
    if( ( pucCertificate == NULL ) || ( pucCertificate[ 0 ] != 0x2d ) )
    {
        xResult = CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if( xResult == CKR_OK )
    {
        /* Convert the certificate to DER format if it was in PEM. The DER key
         * should be about 3/4 the size of the PEM key, so mallocing the PEM key
         * size is sufficient. */
        pucDerObject = malloc( xCertificateTemplate.xValue.ulValueLen );
        xDerLen = xCertificateTemplate.xValue.ulValueLen;

        if( pucDerObject != NULL )
        {
            lConversionReturn = convert_pem_to_der( xCertificateTemplate.xValue.pValue,
                                                    xCertificateTemplate.xValue.ulValueLen,
                                                    pucDerObject,
                                                    &xDerLen );

            if( 0 != lConversionReturn )
            {
                xResult = CKR_ARGUMENTS_BAD;
            }
        }
        else
        {
            xResult = CKR_HOST_MEMORY;
        }
    }

    if( xResult == CKR_OK )
    {
        /* Set the template pointers to refer to the DER converted objects. */
        xCertificateTemplate.xValue.pValue = pucDerObject;
        xCertificateTemplate.xValue.ulValueLen = xDerLen;
    }

    /* Best effort clean-up of the existing object, if it exists. */
    if( xResult == CKR_OK )
    {
        xDestroyProvidedObjects( xSession,
                                 &pucLabel,
                                 &xCertificateClass,
                                 1 );
    }

    /* Create an object using the encoded client certificate. */
    if( xResult == CKR_OK )
    {
        configPRINTF( ( "Write certificate...\r\n" ) );

        xResult = pxFunctionList->C_CreateObject( xSession,
                                                  ( CK_ATTRIBUTE_PTR ) &xCertificateTemplate,
                                                  sizeof( xCertificateTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                  pxObjectHandle );
    }

    if( pucDerObject != NULL )
    {
        free( pucDerObject );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Delete the specified crypto object from storage. */
CK_RV xDestroyProvidedObjects( CK_SESSION_HANDLE xSession,
                               CK_BYTE_PTR * ppxPkcsLabels,
                               CK_OBJECT_CLASS * xClass,
                               CK_ULONG ulCount )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_OBJECT_HANDLE xObjectHandle;
    CK_BYTE * pxLabel;
    CK_ULONG uiIndex = 0;

    xResult = C_GetFunctionList( &pxFunctionList );

    for( uiIndex = 0; uiIndex < ulCount; uiIndex++ )
    {
        pxLabel = ppxPkcsLabels[ uiIndex ];

        xResult = xFindObjectWithLabelAndClass( xSession,
                                                ( const char * ) pxLabel,
                                                xClass[ uiIndex ],
                                                &xObjectHandle );

        while( ( xResult == CKR_OK ) && ( xObjectHandle != CK_INVALID_HANDLE ) )
        {
            xResult = pxFunctionList->C_DestroyObject( xSession, xObjectHandle );

            /* PKCS #11 allows a module to maintain multiple objects with the same
             * label and type. The intent of this loop is to try to delete all of them.
             * However, to avoid getting stuck, we won't try to find another object
             * of the same label/type if the previous delete failed. */
            if( xResult == CKR_OK )
            {
                xResult = xFindObjectWithLabelAndClass( xSession,
                                                        ( const char * ) pxLabel,
                                                        xClass[ uiIndex ],
                                                        &xObjectHandle );
            }
            else
            {
                break;
            }
        }

        if( xResult == CKR_FUNCTION_NOT_SUPPORTED )
        {
            break;
        }
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Delete well-known crypto objects from storage. */
CK_RV xDestroyDefaultCryptoObjects( CK_SESSION_HANDLE xSession )
{
    CK_RV xResult;
    CK_BYTE * pxPkcsLabels[] =
    {
        ( CK_BYTE * ) pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
        ( CK_BYTE * ) pkcs11configLABEL_CODE_VERIFICATION_KEY,
        ( CK_BYTE * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
        ( CK_BYTE * ) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS
    };
    CK_OBJECT_CLASS xClass[] =
    {
        CKO_CERTIFICATE,
        CKO_PUBLIC_KEY,
        CKO_PRIVATE_KEY,
        CKO_PUBLIC_KEY
    };

    xResult = xDestroyProvidedObjects( xSession,
                                       pxPkcsLabels,
                                       xClass,
                                       sizeof( xClass ) / sizeof( CK_OBJECT_CLASS ) );

    return xResult;
}

/*-----------------------------------------------------------*/

static CK_RV prvExportPublicKey( CK_SESSION_HANDLE xSession,
                                 CK_OBJECT_HANDLE xPublicKeyHandle,
                                 uint8_t ** ppucDerPublicKey,
                                 uint32_t * pulDerPublicKeyLength )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_KEY_TYPE xKeyType = 0;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t pucEcP256AsnAndOid[] =
    {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    };
    uint8_t pucUnusedKeyTag[] = { 0x04, 0x41 };

    /* This variable is used only for its size. This gets rid of compiler warnings. */
    ( void ) pucUnusedKeyTag;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Query the key type. */
    if( CKR_OK == xResult )
    {
        xTemplate.type = CKA_KEY_TYPE;
        xTemplate.pValue = &xKeyType;
        xTemplate.ulValueLen = sizeof( xKeyType );
        xResult = pxFunctionList->C_GetAttributeValue( xSession,
                                                       xPublicKeyHandle,
                                                       &xTemplate,
                                                       1 );
    }

    /* Scope to ECDSA keys only, since there's currently no use case for
     * onboard keygen and certificate enrollment for RSA. */
    if( ( CKR_OK == xResult ) && ( CKK_ECDSA == xKeyType ) )
    {
        /* Query the size of the public key. */
        xTemplate.type = CKA_EC_POINT;
        xTemplate.pValue = NULL;
        xTemplate.ulValueLen = 0;
        xResult = pxFunctionList->C_GetAttributeValue( xSession,
                                                       xPublicKeyHandle,
                                                       &xTemplate,
                                                       1 );

        /* Allocate a buffer large enough for the full, encoded public key. */
        if( CKR_OK == xResult )
        {
            /* Add space for the full DER header. */
            xTemplate.ulValueLen += sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag );
            *pulDerPublicKeyLength = xTemplate.ulValueLen;

            /* Get a heap buffer. */
            *ppucDerPublicKey = malloc( xTemplate.ulValueLen );

            /* Check for resource exhaustion. */
            if( NULL == *ppucDerPublicKey )
            {
                xResult = CKR_HOST_MEMORY;
            }
        }

        /* Export the public key. */
        if( CKR_OK == xResult )
        {
            xTemplate.pValue = *ppucDerPublicKey + sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag );
            xTemplate.ulValueLen -= ( sizeof( pucEcP256AsnAndOid ) - sizeof( pucUnusedKeyTag ) );
            xResult = pxFunctionList->C_GetAttributeValue( xSession,
                                                           xPublicKeyHandle,
                                                           &xTemplate,
                                                           1 );
        }

        /* Prepend the full DER header. */
        if( CKR_OK == xResult )
        {
            memcpy( *ppucDerPublicKey, pucEcP256AsnAndOid, sizeof( pucEcP256AsnAndOid ) );
        }
    }

    /* Free memory if there was an error after allocation. */
    if( ( NULL != *ppucDerPublicKey ) && ( CKR_OK != xResult ) )
    {
        free( *ppucDerPublicKey );
        *ppucDerPublicKey = NULL;
    }

    return xResult;
}

/* Determine which required client crypto objects are already present in
 * storage. */
static CK_RV prvGetProvisionedState( CK_SESSION_HANDLE xSession,
                                     ProvisionedState_t * pxProvisionedState )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_SLOT_ID_PTR pxSlotId = NULL;
    CK_ULONG ulSlotCount = 0;
    CK_TOKEN_INFO xTokenInfo = { 0 };
    int i = 0;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Check for a private key. */
    if( CKR_OK == xResult )
    {
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                CKO_PRIVATE_KEY,
                                                &pxProvisionedState->xPrivateKey );
    }

    if( ( CKR_OK == xResult ) && ( CK_INVALID_HANDLE != pxProvisionedState->xPrivateKey ) )
    {
        /* Check also for the corresponding public. */
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                                CKO_PUBLIC_KEY,
                                                &pxProvisionedState->xPublicKey );
    }

    if( ( CKR_OK == xResult ) && ( CK_INVALID_HANDLE != pxProvisionedState->xPublicKey ) )
    {
        /* Export the public key. */
        xResult = prvExportPublicKey( xSession,
                                      pxProvisionedState->xPublicKey,
                                      &pxProvisionedState->pucDerPublicKey,
                                      &pxProvisionedState->ulDerPublicKeyLength );
    }

    /* Check for the client certificate. */
    if( CKR_OK == xResult )
    {
        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                                CKO_CERTIFICATE,
                                                &pxProvisionedState->xClientCertificate );
    }

    /* Check for a crypto element identifier. */
    if( CKR_OK == xResult )
    {
        xResult = xGetSlotList( &pxSlotId, &ulSlotCount );
    }

    if( CKR_OK == xResult )
    {
        xResult = pxFunctionList->C_GetTokenInfo( pxSlotId[ 0 ], &xTokenInfo );
    }

    if( ( CKR_OK == xResult ) && ( '\0' != xTokenInfo.label[ 0 ] ) && ( ' ' != xTokenInfo.label[ 0 ] ) )
    {
        /* PKCS #11 requires that token info fields are padded out with space
         * characters. However, a NULL terminated copy will be more useful to the
         * caller. */
        for( i = 0; i < sizeof( xTokenInfo.label ); i++ )
        {
            if( xTokenInfo.label[ i ] == ' ' )
            {
                break;
            }
        }

        if( 0 != i )
        {
            pxProvisionedState->pcIdentifier = ( char * ) malloc( 1 + i * sizeof( xTokenInfo.label[ 0 ] ) );

            if( NULL != pxProvisionedState->pcIdentifier )
            {
                memcpy( pxProvisionedState->pcIdentifier,
                        xTokenInfo.label,
                        i );
                pxProvisionedState->pcIdentifier[ i ] = '\0';
            }
            else
            {
                xResult = CKR_HOST_MEMORY;
            }
        }
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Write the ASN.1 encoded bytes of the device public key to the console.
 * This is for debugging purposes as well as to faciliate developer-driven
 * certificate enrollment for onboard crypto hardware (i.e. if available). */
static void prvWriteHexBytesToConsole( char * pcDescription,
                                       uint8_t * pucData,
                                       uint32_t ulDataLength )
{
#define BYTES_TO_DISPLAY_PER_ROW    16
    char pcByteRow[ 1 + ( BYTES_TO_DISPLAY_PER_ROW * 2 ) + ( BYTES_TO_DISPLAY_PER_ROW / 2 ) ];
    char * pcNextChar = pcByteRow;
    uint32_t ulIndex = 0;
    uint8_t ucByteValue = 0;

    /* Write help text to the console. */
    configPRINTF( ( "%s, %d bytes:\r\n", pcDescription, ulDataLength ) );

    /* Iterate over the bytes of the encoded public key. */
    for( ; ulIndex < ulDataLength; ulIndex++ )
    {
        /* Convert one byte to ASCII hex. */
        ucByteValue = *( pucData + ulIndex );
        snprintf( pcNextChar,
                  sizeof( pcByteRow ) - ( pcNextChar - pcByteRow ),
                  "%02x",
                  ucByteValue );
        pcNextChar += 2;

        /* Check for the end of a two-byte display word. */
        if( 0 == ( ( ulIndex + 1 ) % sizeof( uint16_t ) ) )
        {
            *pcNextChar = ' ';
            pcNextChar++;
        }

        /* Check for the end of a row. */
        if( 0 == ( ( ulIndex + 1 ) % BYTES_TO_DISPLAY_PER_ROW ) )
        {
            *pcNextChar = '\0';
            vLoggingPrint( pcByteRow );
            vLoggingPrint( "\r\n" );
            pcNextChar = pcByteRow;
        }
    }

    /* Check for a partial line to print. */
    if( pcNextChar > pcByteRow )
    {
        *pcNextChar = '\0';
        vLoggingPrint( pcByteRow );
        vLoggingPrint( "\r\n" );
    }
}

/*-----------------------------------------------------------*/

/* Attempt to provision the device with a client certificate, associated
 * private and public key pair, and optional Just-in-Time Registration certificate.
 * If either component of the key pair is unavailable in storage, generate a new
 * pair. */
CK_RV xProvisionDevice( CK_SESSION_HANDLE xSession,
                        ProvisioningParams_t * pxParams )
{
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    ProvisionedState_t xProvisionedState = { 0 };
    CK_OBJECT_HANDLE xObject = 0;
    CK_BBOOL xImportedPrivateKey = CK_FALSE;
    CK_BBOOL xKeyPairGenerationMode = CK_FALSE;

    xResult = C_GetFunctionList( &pxFunctionList );

    #if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 )

        /* Attempt to clean-up old crypto objects, but only if private key import is
         * supported by this application, and only if the caller has provided new
         * objects to use instead. */
        if( ( CKR_OK == xResult ) &&
            ( NULL != pxParams->pucClientCertificate ) &&
            ( NULL != pxParams->pucClientPrivateKey ) )
        {
            xResult = xDestroyDefaultCryptoObjects( xSession );

            if( xResult != CKR_OK )
            {
                configPRINTF( ( "Warning: could not clean-up old crypto objects. %d \r\n", xResult ) );
            }
        }
    #endif /* if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 ) */

    /* If a client certificate has been provided by the caller, attempt to
     * import it. */
    if( ( xResult == CKR_OK ) && ( NULL != pxParams->pucClientCertificate ) )
    {
        xResult = xProvisionCertificate( xSession,
                                         pxParams->pucClientCertificate,
                                         pxParams->ulClientCertificateLength,
                                         ( uint8_t * ) pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                         &xObject );

        if( ( xResult != CKR_OK ) || ( xObject == CK_INVALID_HANDLE ) )
        {
            configPRINTF( ( "ERROR: Failed to provision device certificate. %d \r\n", xResult ) );
        }
    }

    #if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 )

        /* If this application supports importing private keys, and if a private
         * key has been provided by the caller, attempt to import it. */
        if( ( xResult == CKR_OK ) && ( NULL != pxParams->pucClientPrivateKey ) )
        {
            xResult = xProvisionPrivateKey( xSession,
                                            pxParams->pucClientPrivateKey,
                                            pxParams->ulClientPrivateKeyLength,
                                            ( uint8_t * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            &xObject );

            if( ( xResult != CKR_OK ) || ( xObject == CK_INVALID_HANDLE ) )
            {
                configPRINTF( ( "ERROR: Failed to provision device private key with status %d.\r\n", xResult ) );
            }
            else
            {
                xImportedPrivateKey = CK_TRUE;
            }
        }
    #endif /* if ( pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED == 1 ) */

    /* If a Just-in-Time Provisioning certificate has been provided by the
     * caller, attempt to import it. Not all crypto tokens
     * and PKCS #11 module implementations provide storage for this particular
     * object. In that case, the statically defined object, if any, will be used
     * during TLS session negotiation with AWS IoT. */
    if( ( xResult == CKR_OK ) && ( NULL != pxParams->pucJITPCertificate ) )
    {
        xResult = xProvisionCertificate( xSession,
                                         pxParams->pucJITPCertificate,
                                         pxParams->ulJITPCertificateLength,
                                         ( uint8_t * ) pkcs11configLABEL_JITP_CERTIFICATE,
                                         &xObject );

        if( xResult == CKR_DEVICE_MEMORY )
        {
            xResult = CKR_OK;
            configPRINTF( ( "Warning: no persistent storage is available for the JITP certificate. The certificate in aws_clientcredential_keys.h will be used instead.\r\n" ) );
        }
    }

    /* Check whether a key pair is now present. In order to support X.509
     * certificate enrollment, the public and private key objects must both be
     * available. */
    if( ( xResult == CKR_OK ) && ( CK_FALSE == xImportedPrivateKey ) )
    {
        xResult = prvGetProvisionedState( xSession,
                                          &xProvisionedState );

        if( ( CK_INVALID_HANDLE == xProvisionedState.xPrivateKey ) ||
            ( CK_INVALID_HANDLE == xProvisionedState.xPublicKey ) ||
            ( NULL == xProvisionedState.pucDerPublicKey ) )
        {
            xKeyPairGenerationMode = CK_TRUE;
        }

        /* Ignore errors, since the board may have been previously used with a
         * different crypto middleware or app. If any of the above objects
         * couldn't be read, try to generate new ones below. */
        xResult = CKR_OK;
    }

    #if ( 1 == keyprovisioningFORCE_GENERATE_NEW_KEY_PAIR )
        xKeyPairGenerationMode = CK_TRUE;
    #endif

    if( ( xResult == CKR_OK ) && ( CK_TRUE == xKeyPairGenerationMode ) )
    {
        /* Generate a new default key pair. */
        xResult = xProvisionGenerateKeyPairEC( xSession,
                                               ( uint8_t * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                               ( uint8_t * ) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                               &xProvisionedState.xPrivateKey,
                                               &xProvisionedState.xPublicKey );

        if( CKR_OK == xResult )
        {
            /* Clean-up the previous buffer, if any. */
            if( NULL != xProvisionedState.pucDerPublicKey )
            {
                free( xProvisionedState.pucDerPublicKey );
                xProvisionedState.pucDerPublicKey = NULL;
            }

            /* Get the bytes of the new public key. */
            prvExportPublicKey( xSession,
                                xProvisionedState.xPublicKey,
                                &xProvisionedState.pucDerPublicKey,
                                &xProvisionedState.ulDerPublicKeyLength );
        }

        /* Ensure that an error condition is set if either object is still
         * missing. */
        if( ( CKR_OK == xResult ) &&
            ( ( CK_INVALID_HANDLE == xProvisionedState.xPrivateKey ) ||
              ( CK_INVALID_HANDLE == xProvisionedState.xPublicKey ) ) )
        {
            xResult = CKR_KEY_HANDLE_INVALID;
        }
    }

    /* Log the device public key for developer enrollment purposes, but only if
    * there's not already a certificate, or if a new key was just generated. */
    if( ( CKR_OK == xResult ) &&
        ( ( CK_INVALID_HANDLE == xProvisionedState.xClientCertificate ) ||
          ( CK_TRUE == xKeyPairGenerationMode ) ) &&
        ( CK_FALSE == xImportedPrivateKey ) )
    {
        configPRINTF( ( "Warning: the client certificate should be updated. Please see https://aws.amazon.com/freertos/getting-started/.\r\n" ) );

        if( NULL != xProvisionedState.pcIdentifier )
        {
            configPRINTF( ( "Recommended certificate subject name: CN=%s\r\n", xProvisionedState.pcIdentifier ) );
        }

        prvWriteHexBytesToConsole( "Device public key",
                                   xProvisionedState.pucDerPublicKey,
                                   xProvisionedState.ulDerPublicKeyLength );

        /* Delay since the downstream demo code is likely to fail quickly if
         * provisioning isn't complete, and device certificate creation in the
         * lab may depend on the developer obtaining the public key. */
        /*vTaskDelay( pdMS_TO_TICKS( 100 ) ); */
    }

    /* Free memory. */
    if( NULL != xProvisionedState.pucDerPublicKey )
    {
        free( xProvisionedState.pucDerPublicKey );
    }

    if( NULL != xProvisionedState.pcIdentifier )
    {
        free( xProvisionedState.pcIdentifier );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Perform device provisioning using the specified TLS client credentials. */
CK_RV vAlternateKeyProvisioning( ProvisioningParams_t * xParams )
{
    CK_RV xResult = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_SESSION_HANDLE xSession = 0;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Initialize the PKCS Module */
    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Token();
    }

    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Session( &xSession );
    }

    if( xResult == CKR_OK )
    {
        xResult = xProvisionDevice( xSession, xParams );

        pxFunctionList->C_CloseSession( xSession );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/* Perform device provisioning using the default TLS client credentials. */
CK_RV vDevModeKeyProvisioning( void )
{
    ProvisioningParams_t xParams;

    xParams.pucJITPCertificate = ( uint8_t * ) keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM;
    xParams.pucClientPrivateKey = ( uint8_t * ) keyCLIENT_PRIVATE_KEY_PEM;
    xParams.pucClientCertificate = ( uint8_t * ) keyCLIENT_CERTIFICATE_PEM;

    /* If using a JITR flow, a JITR certificate must be supplied. If using credentials generated by
     * AWS, this certificate is not needed. */
    if( ( NULL != xParams.pucJITPCertificate ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucJITPCertificate ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulJITPCertificateLength = sizeof( char ) + strlen( ( const char * ) xParams.pucJITPCertificate );
    }
    else
    {
        xParams.pucJITPCertificate = NULL;
    }

    /* The hard-coded client certificate and private key can be useful for
     * first-time lab testing. They are optional after the first run, though, and
     * not recommended at all for going into production. */
    if( ( NULL != xParams.pucClientPrivateKey ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucClientPrivateKey ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientPrivateKeyLength = sizeof( char ) + strlen( ( const char * ) xParams.pucClientPrivateKey );
    }
    else
    {
        xParams.pucClientPrivateKey = NULL;
    }

    if( ( NULL != xParams.pucClientCertificate ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucClientCertificate ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientCertificateLength = sizeof( char ) + strlen( ( const char * ) xParams.pucClientCertificate );
    }
    else
    {
        xParams.pucClientCertificate = NULL;
    }

    return vAlternateKeyProvisioning( &xParams );
}

/*-----------------------------------------------------------*/
