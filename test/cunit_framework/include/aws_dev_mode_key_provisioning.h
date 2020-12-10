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
 * @file  aws_dev_mode_key_provsioning.h
 * @brief Provisioning example code for developers.
 *
 * Helpers for importing device private key and device
 * certificate for use with AWS connectivity libraries.
 *
 * \warn This code is provided for example purposes only, and
 * should not be used in production code.
 */

#ifndef _AWS_DEV_MODE_KEY_PROVISIONING_H_
#define _AWS_DEV_MODE_KEY_PROVISIONING_H_


#include "pkcs11_optiga_trustm.h"

#include "optiga/common/optiga_lib_types.h"

#define pkcs11testLABEL_DEVICE_PUBLIC_KEY_FOR_TLS        LABEL_DEVICE_PUBLIC_KEY_FOR_TLS
#define pkcs11testLABEL_DEVICE_PRIVATE_KEY_FOR_TLS       LABEL_DEVICE_PRIVATE_KEY_FOR_TLS
#define pkcs11testLABEL_DEVICE_CERTIFICATE_FOR_TLS       LABEL_DEVICE_CERTIFICATE_FOR_TLS
#define pkcs11testLABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS   LABEL_DEVICE_RSA_PRIVATE_KEY_FOR_TLS
#define pkcs11testLABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS    LABEL_DEVICE_RSA_PUBLIC_KEY_FOR_TLS

#define pkcs11testSLOT_NUMBER 0

/* Developer convenience override, for lab testing purposes, for generating
 * a new default key pair, regardless of whether an existing key pair is present. */
#define keyprovisioningFORCE_GENERATE_NEW_KEY_PAIR    0

/**
 *   @brief Length of a SHA256 digest, in bytes.
 */
#define pkcs11SHA256_DIGEST_LENGTH           32

/**
 * @brief Length of a curve P-256 ECDSA signature, in bytes.
 * PKCS #11 EC signatures are represented as a 32-bit R followed
 * by a 32-bit S value, and not ASN.1 encoded.
 */
#define pkcs11ECDSA_P256_SIGNATURE_LENGTH    64

/**
 * @brief Key strength for elliptic-curve P-256.
 */
#define pkcs11ECDSA_P256_KEY_BITS            256

/**
 * @brief Public exponent for RSA.
 */
#define pkcs11RSA_PUBLIC_EXPONENT            { 0x01, 0x00, 0x01 }

/**
 * @brief The number of bits in the RSA-2048 modulus.
 *
 */
#define pkcs11RSA_2048_MODULUS_BITS          2048

/**
 * @brief Length of PKCS #11 signature for RSA 2048 key, in bytes.
 */
#define pkcs11RSA_2048_SIGNATURE_LENGTH      ( pkcs11RSA_2048_MODULUS_BITS / 8 )

/**
 * @brief Length of RSA signature data before padding.
 *
 * This is calculated by adding the SHA-256 hash len (32) to the 19 bytes in
 * pkcs11STUFF_APPENDED_TO_RSA_SIG = 51 bytes total.
 */
#define pkcs11RSA_SIGNATURE_INPUT_LENGTH     51

/**
 * @brief Elliptic-curve object identifiers.
 * From https://tools.ietf.org/html/rfc6637#section-11.
 */
#define pkcs11ELLIPTIC_CURVE_NISTP256        "1.2.840.10045.3.1.7"

/**
 * @brief Maximum length of storage for PKCS #11 label, in bytes.
 */
#define pkcs11MAX_LABEL_LENGTH               32 /* 31 characters + 1 null terminator. */

/**
 * @brief OID for curve P-256.
 */
#define pkcs11DER_ENCODED_OID_P256           { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }


/**
 * @brief Set to 1 if importing private keys is supported.
 *
 * If private key import is not supported, this value should be defined 0 in aws_pkcs11_config.h
 */
#ifndef IMPORT_PRIVATE_KEYS_SUPPORTED
    #define IMPORT_PRIVATE_KEYS_SUPPORTED    1
#endif

/* Length parameters for importing RSA-2048 private keys. */
#define MODULUS_LENGTH        pkcs11RSA_2048_MODULUS_BITS / 8
#define E_LENGTH              3
#define D_LENGTH              pkcs11RSA_2048_MODULUS_BITS / 8
#define PRIME_1_LENGTH        128
#define PRIME_2_LENGTH        128
#define EXPONENT_1_LENGTH     128
#define EXPONENT_2_LENGTH     128
#define COEFFICIENT_LENGTH    128

/*
 * @brief PEM-encoded client certificate.
 *
 * @todo If you are running one of the FreeRTOS demo projects, set this
 * to the certificate that will be used for TLS client authentication.
 *
 * @note Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 */
#define keyCLIENT_CERTIFICATE_PEM                   ""

/*
 * @brief PEM-encoded issuer certificate for AWS IoT Just In Time Registration (JITR).
 *
 * @todo If you are using AWS IoT Just in Time Registration (JITR), set this to
 * the issuer (Certificate Authority) certificate of the client certificate above.
 *
 * @note This setting is required by JITR because the issuer is used by the AWS
 * IoT gateway for routing the device's initial request. (The device client
 * certificate must always be sent as well.) For more information about JITR, see:
 *  https://docs.aws.amazon.com/iot/latest/developerguide/jit-provisioning.html,
 *  https://aws.amazon.com/blogs/iot/just-in-time-registration-of-device-certificates-on-aws-iot/.
 *
 * If you're not using JITR, set below to NULL.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 */
#define keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM    ""

/*
 * @brief PEM-encoded client private key.
 *
 * @todo If you are running one of the FreeRTOS demo projects, set this
 * to the private key that will be used for TLS client authentication.
 *
 * @note Must include the PEM header and footer:
 * "-----BEGIN RSA PRIVATE KEY-----\n"\
 * "...base64 data...\n"\
 * "-----END RSA PRIVATE KEY-----\n"
 */
#define keyCLIENT_PRIVATE_KEY_PEM                   ""


typedef struct ProvisioningParams_t
{
    uint8_t * pucClientPrivateKey;      /**< Pointer to the device private key in PEM format.
                                         *   See tools/certificate_configuration/PEMfileToCString.html
                                         *   for help with formatting.*/
    uint32_t ulClientPrivateKeyLength;  /**< Length of the private key data, in bytes. */
    uint8_t * pucClientCertificate;     /**< Pointer to the device certificate in PEM format.
                                         *   See tools/certificate_configuration/PEMfileToCString.html
                                         *   for help with formatting.*/
    uint32_t ulClientCertificateLength; /**< Length of the device certificate in bytes. */
    uint8_t * pucJITPCertificate;       /**< Pointer to the Just-In-Time Provisioning (JITP) certificate in
                                         *   PEM format.
                                         *   - This is REQUIRED if JITP is being used.
                                         *   - If you are not using JITP, this certificate
                                         *   is not needed and should be set to NULL.
                                         *   - See tools/certificate_configuration/PEMfileToCString.html
                                         *   for help with formatting.
                                         *   - See https://aws.amazon.com/blogs/iot/setting-up-just-in-time-provisioning-with-aws-iot-core/
                                         *   for more information about getting started with JITP */
    uint32_t ulJITPCertificateLength;   /**< Length of the Just-In-Time Provisioning (JITP) certificate in bytes.
                                         *   If JITP is not being used, this value should be set to 0. */
} ProvisioningParams_t;

/** \brief Provisions device with default credentials.
 *
 * Imports the certificate and private key located in
 * aws_clientcredential_keys.h to device NVM.
 *
 * \return CKR_OK upon successful credential setup.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV vDevModeKeyProvisioning( void );

/** \brief Provisiong a device given a valid PKCS #11 session.
 *
 * \param[in] xSession       A valid PKCS #11 session.
 * \param[in] pxParams       Pointer to an initialized provisioning
 *                           structure.
 *
 * \return CKR_OK upon successful credential setup.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV xProvisionDevice( CK_SESSION_HANDLE xSession,
                        ProvisioningParams_t * pxParams );

/** \brief Provisions device with provided credentials.
 *
 * \param[in] xParams       Provisioning parameters for credentials
 *                          to be provisioned.
 *
 * \return CKR_OK upon successful credential setup.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV vAlternateKeyProvisioning( ProvisioningParams_t * xParams );

/** \brief Provisions a private key using PKCS #11 library.
 *
 * \param[in] xSession             An initialized session handle.
 * \param[in] pucPrivateKey        Pointer to private key.  Key may either be PEM formatted
 *                                 or ASN.1 DER encoded.
 * \param[in] xPrivateKeyLength    Length of the data at pucPrivateKey, in bytes.
 * \param[in] pucLabel             PKCS #11 CKA_LABEL attribute value to be used for key.
 *                                 This should be a string values. See iot_pkcs11_config.h
 * \param[out] pxObjectHandle      Points to the location that receives the PKCS #11
 *                                 private key handle created.
 *
 * \return CKR_OK upon successful key creation.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV xProvisionPrivateKey( CK_SESSION_HANDLE xSession,
                            uint8_t * pucPrivateKey,
                            size_t xPrivateKeyLength,
                            uint8_t * pucLabel,
                            CK_OBJECT_HANDLE_PTR pxObjectHandle );

/** \brief Imports a public key into the PKCS #11 module.
 *
 * \param[in] xSession               A valid PKCS #11 session handle.
 * \param[in] pucKey                 Pointer to public key.  Key may either be PEM formatted
 *                                   or ASN.1 DER encoded.
 * \param[in] xKeyLength             Length of the data at pucPrivateKey, in bytes.
 * \param[in] xPublicKeyType         The type of key- either CKK_RSA or CKK_EC.
 * \param[in] pucPublicKeyLabel      PKCS #11 CKA_LABEL attribute value to be used for key.
 *                                   This should be a string values.  See iot_pkcs11_config.h.
 * \param[out] pxPublicKeyHandle     Points to the location that receives the PKCS #11 public
 *                                   key handle created.
 *
 * \return CKR_OK upon successful key creation.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV xProvisionPublicKey( CK_SESSION_HANDLE xSession,
                           uint8_t * pucKey,
                           size_t xKeyLength,
                           CK_KEY_TYPE xPublicKeyType,
                           uint8_t * pucPublicKeyLabel,
                           CK_OBJECT_HANDLE_PTR pxPublicKeyHandle );


/** \brief Imports a certificate into the PKCS #11 module.
 *
 * \param[in] xSession              A valid PKCS #11 session handle.
 * \param[in] pucCertificate        Pointer to a PEM certificate.
 *                                  See tools/certificate_configuration/PEMfileToCString.html
 *                                  for help with formatting.
 * \param[in] xCertificateLength    Length of pucCertificate, in bytes.
 * \param[in] pucLabel              PKCS #11 label attribute value for certificate to be imported.
 *                                  This should be a string value. See iot_pkcs11.h.
 *                                  This should be a string value. See iot_pkcs11_config.h.
 * \param[out] pxObjectHandle       Points to the location that receives the PKCS #11
 *                                  certificate handle created.
 *
 * \return CKR_OK if certificate import succeeded.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV xProvisionCertificate( CK_SESSION_HANDLE xSession,
                             uint8_t * pucCertificate,
                             size_t xCertificateLength,
                             uint8_t * pucLabel,
                             CK_OBJECT_HANDLE_PTR pxObjectHandle );

/** \brief Generates an RSA key pair.
 *
 * \param[in] xSession              A valid PKCS #11 session handle.
 * \param[in] pucPrivateKeyLabel    PKCS #11 label attribute value for private key to be created.
 *                                  This should be a string value. See iot_pkcs11_config.h.
 * \param[in] pucPublicKeyLabel     PKCS #11 label attribute value for public key to be created.
 *                                  This should be a string value. See iot_pkcs11_config.h.
 * \param[out] pxPrivateKeyHandle   Points to the location that receives the PKCS #11 private
 *                                  key handle created.
 * \param[out] pxPublicKeyHandle    Points to the location that receives the PKCS #11 public
 *                                  key handle created.
 *
 * \return CKR_OK if RSA key pair generation succeeded.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV xProvisionGenerateKeyPairRSA( CK_SESSION_HANDLE xSession,
                                    uint8_t * pucPrivateKeyLabel,
                                    uint8_t * pucPublicKeyLabel,
                                    CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                    CK_OBJECT_HANDLE_PTR pxPublicKeyHandle );

/** \brief Generates an elliptic curve key pair.
 *
 * \param[in] xSession              A valid PKCS #11 session handle.
 * \param[in] pucPrivateKeyLabel    PKCS #11 label attribute value for private key to be created.
 *                                  This should be a string value. See iot_pkcs11_config.h.
 * \param[in] pucPublicKeyLabel     PKCS #11 label attribute value for public key to be created.
 *                                  This should be a string value. See iot_pkcs11_config.h.
 * \param[out] pxPrivateKeyHandle   Points to the location that receives the PKCS #11 private
 *                                  key handle created.
 * \param[out] pxPublicKeyHandle    Points to the location that receives the PKCS #11 public
 *                                  key handle created.
 *
 * \return CKR_OK if EC key pair generation succeeded.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV xProvisionGenerateKeyPairEC( CK_SESSION_HANDLE xSession,
                                   uint8_t * pucPrivateKeyLabel,
                                   uint8_t * pucPublicKeyLabel,
                                   CK_OBJECT_HANDLE_PTR pxPrivateKeyHandle,
                                   CK_OBJECT_HANDLE_PTR pxPublicKeyHandle );

/**
 *\brief Destroys FreeRTOS credentials stored in device PKCS #11 module.
 *
 * \note Not all ports support the deletion of all objects.  Successful
 * function return only indicates that all objects for which destroy is
 * supported on the port were erased from non-volatile memory.
 *
 * Destroys objects with the following labels, if applicable:
 *     LABEL_DEVICE_CERTIFICATE_FOR_TLS,
 *     LABEL_CODE_VERIFICATION_KEY,
 *     LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
 *     LABEL_DEVICE_PUBLIC_KEY_FOR_TLS
 *
 *   \param[in] xSession         A valid PKCS #11 session handle.
 *
 *   \return CKR_OK if all credentials were destroyed.
 *   Otherwise, a positive PKCS #11 error code.
 */
CK_RV xDestroyDefaultCryptoObjects( CK_SESSION_HANDLE xSession );

/**
 * \brief Destroys specified credentials in PKCS #11 module.
 *
 * \note Some ports only support lookup of objects by label (and
 * not label + class).  For these ports, only the label field is used
 * for determining what objects to destroy.
 *
 * \note Not all ports support the deletion of all objects.  Successful
 * function return only indicates that all objects for which destroy is
 * supported on the port were erased from non-volatile memory.
 *
 *   \param[in] xSession         A valid PKCS #11 session handle.
 *   \param[in] ppxPkcsLabels    An array of pointers to object labels.
 *                               Labels are assumed to be NULL terminated
 *                               strings.
 *   \param[in] pxClass          An array of object classes, corresponding
 *                               to the array of ppxPkcsLabels.  For example
 *                               the first label pointer and first class in
 *                               ppxPkcsLabels are used in combination for
 *                               lookup of the object to be deleted.
 *   \param[in] ulCount          The number of label-class pairs passed in
 *                               to be destroyed.
 *
 *   \return CKR_OK if all credentials were destroyed.
 *   Otherwise, a positive PKCS #11 error code.
 */
CK_RV xDestroyProvidedObjects( CK_SESSION_HANDLE xSession,
                               CK_BYTE_PTR * ppxPkcsLabels,
                               CK_OBJECT_CLASS * pxClass,
                               CK_ULONG ulCount );

#endif /* _AWS_DEV_MODE_KEY_PROVISIONING_H_ */
