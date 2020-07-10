/**
* \copyright
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
* \endcopyright
*
* \author Infineon Technologies AG
*
* \file main_raspberry_pi3_sample.c
*
* \brief   This sample demonstrates OPTIGA use cases.
*
* \ingroup grOptigaExamples
* @{
*/

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/common/optiga_lib_logger.h"
#include "optiga/pal/pal.h"
#include "pkcs11.h"
/* mbedTLS includes. */
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"


#define pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS        pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS
#define pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS       pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS
#define pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS       pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS


/**
 * Callback when optiga_util_xxxx operation is completed asynchronously
 */
extern void example_optiga_crypt_tls_prf_sha256(void);
extern void example_pair_host_and_optiga_using_pre_shared_secret(void);
#if 1
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

CK_FUNCTION_LIST_PTR pxGlobalFunctionList;
CredentialsProvisioned_t xCurrentCredentials = eStateUnknown;

#endif
static volatile optiga_lib_status_t optiga_lib_status;
CK_FUNCTION_LIST_PTR pFunctionList;

static void optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
}
#if 1
static void test_c_getfunctionlist_good(void **state) {

    //UNUSED(state);

    //Case 1: Successfully obtain function list

    CK_RV rv = C_GetFunctionList(&pFunctionList);
    if (rv)
    {
	printf("Bad function pointer\n");
    }
}
typedef struct test_info {
    CK_SESSION_HANDLE session;
}test_info_t;

#define pkcs11RSA_2048_MODULUS_BITS          2048

#define MODULUS_LENGTH        pkcs11RSA_2048_MODULUS_BITS / 8

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
        printf( "Failed to parse the public key. \r\n"  );
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( ( xResult == CKR_OK ) && ( xPublicKeyType == CKK_RSA ) )
    {
    #if 0
        CK_BYTE xPublicExponent[] = { 0x01, 0x00, 0x01 };
        CK_BYTE xModulus[ MODULUS_LENGTH + 1 ] = { 0 };

        lMbedResult = mbedtls_rsa_export_raw( ( mbedtls_rsa_context * ) xMbedPkContext.pk_ctx,
                                              ( unsigned char * ) &xModulus, MODULUS_LENGTH + 1,
                                              NULL, 0,
                                              NULL, 0,
                                              NULL, 0,
                                              NULL, 0 );
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
		#endif
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
		if (0 != lMbedResult)
		{
			printf("fail in mbedtls_ecp_point_write_binary\n");
		}
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
        printf( "Invalid key type. Supported options are CKK_RSA and CKK_EC"  );
    }

    mbedtls_pk_free( &xMbedPkContext );

    return xResult;
}


CK_RV find_object_with_class( CK_SESSION_HANDLE xSession,
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
            printf ( "Failed to parse EC private key components. \r\n" );
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
        printf ( "Unable to parse private key.\r\n"  );
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Determine whether the key to be imported is RSA or EC. */
    if( xResult == CKR_OK )
    {
        xMbedKeyType = mbedtls_pk_get_type( &xMbedPkContext );

        if( ( xMbedKeyType == MBEDTLS_PK_ECDSA ) || ( xMbedKeyType == MBEDTLS_PK_ECKEY ) || ( xMbedKeyType == MBEDTLS_PK_ECKEY_DH ) )
        {
            xResult = prvProvisionPrivateECKey( xSession,
                                                pucLabel,
                                                pxObjectHandle,
                                                &xMbedPkContext );
        }
        else
        {
            printf ( "Invalid private key type provided.  RSA-2048 and EC P-256 keys are supported.\r\n"  );
            xResult = CKR_ARGUMENTS_BAD;
        }
    }

    mbedtls_pk_free( &xMbedPkContext );

    return xResult;
}
typedef struct PKCS11_CertificateTemplate
{
    CK_ATTRIBUTE xObjectClass;     /* CKA_CLASS, set to CKO_CERTIFICATE. */
    CK_ATTRIBUTE xSubject;         /* CKA_SUBJECT, this parameter is required by the PKCS #11 standard. */
    CK_ATTRIBUTE xCertificateType; /* CKA_CERTIFICATE_TYPE, set to CKC_X_509. */
    CK_ATTRIBUTE xValue;           /* CKA_VALUE, the DER byte array of the certificate contents. */
    CK_ATTRIBUTE xLabel;           /* CKA_LABEL. */
    CK_ATTRIBUTE xTokenObject;     /* CKA_TOKEN. */
} PKCS11_CertificateTemplate_t, * PKCS11_CertificateTemplatePtr_t;
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

        xResult = find_object_with_class( xSession,
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
                xResult = find_object_with_class( xSession,
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
        printf( ( "Write certificate...\r\n" ) );

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
                                           CK_OBJECT_HANDLE_PTR pxPublicKeyHandle,
                                           CK_SESSION_HANDLE_PTR session)
{
    CK_RV xResult;


    if( xCurrentCredentials != eEllipticCurveTest )
    {
        
        xCurrentCredentials = eNone;

        xResult = xProvisionPublicKey( *session,
                                       ( uint8_t * ) cValidECDSAPrivateKey,
                                       sizeof( cValidECDSAPrivateKey ),
                                       CKK_EC,
                                       ( uint8_t * ) pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                       pxPublicKeyHandle );
        if(CKR_OK != xResult)
		{
			printf("failed in xProvisionPublicKey\n ");
		}

        //TEST_ASSERT_NOT_EQUAL_MESSAGE( 0, *pxPublicKeyHandle, "Invalid object handle returned for EC public key." );
#if 0
        xResult = xProvisionPrivateKey( *session,
                                        ( uint8_t * ) cValidECDSAPrivateKey,
                                        sizeof( cValidECDSAPrivateKey ),
                                        ( uint8_t * ) pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                        pxPrivateKeyHandle );
		if(CKR_OK != xResult)
		{
			printf("failed in xProvisionPrivateKey\n ");
		}
		#endif
		#if 0

        TEST_ASSERT_EQUAL_MESSAGE( CKR_OK, xResult, "Failed to create EC private key." );
        TEST_ASSERT_NOT_EQUAL_MESSAGE( 0, *pxPrivateKeyHandle, "Invalid object handle returned for EC private key." );
#endif
        xResult = xProvisionCertificate( *session,
                                         ( uint8_t * ) cValidECDSACertificate,
                                         sizeof( cValidECDSACertificate ),
                                         ( uint8_t * ) pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                         pxCertificateHandle );
		if(CKR_OK != xResult)
		{
			printf("failed in xProvisionCertificate\n ");
		}

        //TEST_ASSERT_EQUAL_MESSAGE( CKR_OK, xResult, "Failed to create EC certificate." );
        //TEST_ASSERT_NOT_EQUAL_MESSAGE( 0, *pxPrivateKeyHandle, "Invalid object handle returned for EC certificate." );

        xCurrentCredentials = eEllipticCurveTest;
    }
    else
    {
        xResult = find_object_with_class( *session, pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, CKO_PRIVATE_KEY, pxPrivateKeyHandle );
        if(CKR_OK != xResult)
		{
			printf("failed in find_object_with_class\n ");
		}
		xResult = find_object_with_class( *session, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, pxCertificateHandle );
        if(CKR_OK != xResult)
		{
			printf("failed in find_object_with_class for certificate\n ");
		}

		#if 0
		TEST_ASSERT_EQUAL_MESSAGE( CKR_OK, xResult, "Failed to find EC private key." );
        TEST_ASSERT_NOT_EQUAL_MESSAGE( CK_INVALID_HANDLE, *pxPrivateKeyHandle, "Invalid object handle found for EC private key." );

        xResult = find_object_with_class( xGlobalSession, pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, pxCertificateHandle );
        TEST_ASSERT_EQUAL_MESSAGE( CKR_OK, xResult, "Failed to find EC certificate." );
        TEST_ASSERT_NOT_EQUAL_MESSAGE( CK_INVALID_HANDLE, *pxCertificateHandle, "Invalid object handle found for EC certificate." );

        xResult = xFindObjectWithLabelAndClass( xGlobalSession, pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, CKO_PUBLIC_KEY, pxPublicKeyHandle );
        TEST_ASSERT_EQUAL_MESSAGE( CKR_OK, xResult, "Failed to find EC public key." );
        TEST_ASSERT_NOT_EQUAL_MESSAGE( CK_INVALID_HANDLE, *pxPublicKeyHandle, "Invalid object handle found for EC public key." );
		#endif
    }
}

void prvProvisionEcTestCredentials(CK_SESSION_HANDLE_PTR session )
{
    CK_OBJECT_HANDLE xPrivateKey;
    CK_OBJECT_HANDLE xCertificate;
    CK_OBJECT_HANDLE xPublicKey;

    prvProvisionCredentialsWithKeyImport( &xPrivateKey, &xCertificate, &xPublicKey,session );

}

CK_RV get_slot_list( CK_SLOT_ID ** ppxSlotId,
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
#endif
/**
 * This function is the entry point of sample.
 *
 * \retval
 *  0 on success
 *  1 on failure
 */

int main(void)
{
    uint8_t return_value = 0;
    CK_RV status;
#if 1
    test_info_t test_handle;
#endif
    CK_SESSION_HANDLE_PTR handle = NULL;//= &test_handle.session;
    optiga_lib_status_t return_status;
    uint8_t rndbuff[32];
    uint16_t offset, bytes_to_read;
    uint16_t optiga_oid;
    uint8_t read_data_buffer[1024];
    uint32_t buff_len = sizeof(rndbuff);
    optiga_util_t * me_util = NULL;
	uint8_t loop_count;
	CK_ULONG pxSlotCount = 1;
	CK_SLOT_ID * pxSlotId = NULL;
	CK_MECHANISM_INFO MechanismInfo = { 0 };
	CK_TOKEN_INFO_PTR pxTokenInfo = NULL;
	CK_FLAGS xTokenFlags = 0;
	//pal_gpio_init(NULL);
	do
	{
#if 0
        //Create an instance of optiga_util to open the application on OPTIGA.
        me_util = optiga_util_create(0, optiga_util_callback, NULL);
        //OPTIGA_EXAMPLE_LOG_MESSAGE("Initializing OPTIGA for example demonstration...\n");
        /**
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_open_application(me_util, 0);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_open_application is completed
        }
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util open application failed
            break;
        }
	
	example_pair_host_and_optiga_using_pre_shared_secret();
	example_optiga_crypt_tls_prf_sha256();
        //Read device end entity certificate from OPTIGA
        optiga_oid = 0xE0E0;
        offset = 0x00;
        bytes_to_read = sizeof(read_data_buffer);

        // OPTIGA Comms Shielded connection settings to enable the protection
        OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
        OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_RESPONSE_PROTECTION);

        /**
         * 2. Read data from a data object (e.g. certificate data object)
         *    using optiga_util_read_data.
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_read_data(me_util,
                                              optiga_oid,
                                              offset,
                                              read_data_buffer,
                                              &bytes_to_read);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (OPTIGA_LIB_BUSY == optiga_lib_status)
        {
            //Wait until the optiga_util_read_data operation is completed
        }

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //Reading the data object failed.
            return_status = optiga_lib_status;
            break;
        }
        // OPTIGA Comms Shielded connection settings to enable the protection
        OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
        OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);

        /**
         * 2. Read data from a data object (e.g. certificate data object)
         *    using optiga_util_read_data.
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_read_data(me_util,
                                              optiga_oid,
                                              offset,
                                              read_data_buffer,
                                              &bytes_to_read);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (OPTIGA_LIB_BUSY == optiga_lib_status)
        {
            //Wait until the optiga_util_read_data operation is completed
        }

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //Reading the data object failed.
            return_status = optiga_lib_status;
            break;
        }	

#endif
#if 1
	test_c_getfunctionlist_good(NULL);


	status = pFunctionList->C_Initialize(NULL);
	if(status)
	{
		printf("init failed\n");
		break;
	}
	else
	{
		printf("init success\n");
	}
	pxSlotId = malloc( sizeof( CK_SLOT_ID ) * 1 );
	if (NULL == pxSlotId)
	{
		printf("\nNULL\n");
	}

	handle = malloc( sizeof( CK_SESSION_HANDLE_PTR ));
	status = pFunctionList->C_OpenSession(0, CKF_SERIAL_SESSION, 0 , 0, handle);
	if(status)
	{
		printf("open session failed\n");
		break;
	}
	else
	{
		printf("open sessiont success\n");
	}
	prvProvisionEcTestCredentials(handle);
#if 1
	status = get_slot_list( &pxSlotId, &pxSlotCount );
	if(status)
	{
		printf("get_slot_list failed\n");
		break;
	}
	else
	{
		printf("get_slot_list success\n");
	}
	pxTokenInfo = malloc( sizeof( CK_TOKEN_INFO ) );
	
	if( pxTokenInfo != NULL )
	{

		status = pFunctionList->C_GetTokenInfo( pxSlotId[ 0 ], pxTokenInfo );
	}
	else
	{
		status = CKR_HOST_MEMORY;
	}
	
	if( CKR_OK == status )
	{
		xTokenFlags = pxTokenInfo->flags;
	}
	
	if( ( CKR_OK == status ) && !( CKF_TOKEN_INITIALIZED & xTokenFlags ) )
	{

		status = pFunctionList->C_InitToken( pxSlotId[ 0 ],
											   ( CK_UTF8CHAR_PTR ) configPKCS11_DEFAULT_USER_PIN,
											   sizeof( configPKCS11_DEFAULT_USER_PIN ) - 1,
											   ( CK_UTF8CHAR_PTR ) "Optiga TrustM pkcs11" );
		if(status)
		{
			printf("InitToken failed\n");
			break;
		}
		else
		{
			printf("InitToken success\n");
		}
	}
#endif
	status = pFunctionList->C_GenerateRandom(*handle,rndbuff,buff_len);
	if(status)
	{
		printf("Generate random failed\n");
		break;
	}
	else
	{
		printf("Generate random success\n");
		for(loop_count = 0; loop_count < buff_len; loop_count++)
		{
			printf("buf[%d] = 0x%x, ",loop_count,rndbuff[loop_count]);
		}

	}
#endif
	printf("\n");
	} while (0);
#if 1
	status = pFunctionList->C_CloseSession(*handle);
	if(status)
	{
		printf("close session failed\n");
		//break;
	}
	else
	{
		printf("close sessiont success\n");
	}

	status = pFunctionList->C_Finalize(NULL);
	if(status)
	{
		printf("Finalize failed\n");
		//break;
	}
	else
	{
		printf("Finalize success\n");
	}
	if (NULL != pxSlotId)
	{
		free(pxSlotId);
	}
#endif
printf("\nreturn_status=%x\n",return_status);
	//pal_gpio_deinit(NULL);
    return return_value;
}


