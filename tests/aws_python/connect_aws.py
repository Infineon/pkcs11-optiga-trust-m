# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: MIT

from awscrt import io
from awsiot import mqtt_connection_builder
from uuid import uuid4
import argparse
import sys

# Callback when connection is accidentally lost.
def on_connection_interrupted(connection, error, **kwargs):
    print("Connection interrupted. error: {}".format(error))

# Callback when an interrupted connection is re-established.
def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print("Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))

if __name__ == '__main__':
    # Create a connection using websockets.
    # Note: The data for the connection is gotten from cmdUtils.
    # (see build_pkcs11_mqtt_connection for implementation)

    parser = argparse.ArgumentParser(description='Input arguments for PKCS#11 MQTT Client.')
    parser.add_argument("--pcks11lib", type=str , help="path to pkcs11 library")
    parser.add_argument("--slot", type=int , help="HSM slot")
    parser.add_argument("--pin", type=str , help="HSM slot pin")
    parser.add_argument("--tokenlabel", type=str , help="HSM token label")
    parser.add_argument("--keylabel", type=str , help="HSM ptivate key label")
    parser.add_argument("--certpath", type=str , help="device certificate file path")
    parser.add_argument("--endpoint", type=str , help="AWS IoT Core endpoint")
    parser.add_argument("--cafile", type=str , help="CA certificate file path")
    parser.add_argument("--clientid", type=str , help="clientId to use for MQTT connection")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()
    
    # We load the HSM library
    pkcs11_lib_path = args.pcks11lib
    print(f"Loading PKCS#11 library '{pkcs11_lib_path}' ...")
    pkcs11_lib = io.Pkcs11Lib(
        file=pkcs11_lib_path,
        behavior=io.Pkcs11Lib.InitializeFinalizeBehavior.STRICT)
    print("Loaded!")

    pkcs11_slot_id = args.slot
    pkcs11_pin = args.pin
    pkcs11_tokenlabel = args.tokenlabel
    pkcs11_keylabel = args.keylabel
    certpath = args.certpath
    endpoint = args.endpoint     
    cafile = args.cafile 
    clientid = args.clientid

    # This is the core section of the example client. 
    # This single instruction instantiates an MQTT connection 
    # and performs encyrption operations using your HSM
    # through the mqtt_connection_builder.mtls_with_pkcs11 method
    mqtt_connection = mqtt_connection_builder.mtls_with_pkcs11(
        pkcs11_lib          =   pkcs11_lib,
        user_pin            =   pkcs11_pin,
        slot_id             =   pkcs11_slot_id,
        token_label         =   pkcs11_tokenlabel,
        private_key_label   =   pkcs11_keylabel,
        cert_filepath       =   certpath,
        endpoint            =   endpoint,
        port                =   8883,
        ca_filepath         =   cafile,
        on_connection_interrupted   =   on_connection_interrupted,
        on_connection_resumed       =   on_connection_resumed,
        client_id           =   clientid,
        clean_session       =   False,
        keep_alive_secs     =   30)

    connect_future = mqtt_connection.connect()

    # Future.result() waits until a result is available
    connect_future.result()
    print("Connected!")

    # Disconnect
    print("Disconnecting...")
    disconnect_future = mqtt_connection.disconnect()
    disconnect_future.result()
    print("Disconnected!")