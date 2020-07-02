/**
INFINEON_OPTIGA_SOURCE_CODE_BOILER_PLATE
*
* \file pal_socket.h
*
* \brief   This file provides the socket platform abstraction layer(PAL) APIs for UDP
*
* \ingroup  grPAL
*
* @{
*/

#ifndef _PAL_SOCKET_H_
#define _PAL_SOCKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "optiga/pal/pal.h"

/// Default IP address to indicate the the socket layer to assign any IP address
#define PAL_SOCKET_ANY_IP_ADDR (0x00000000)

/**********************************************************************************************************************
 * ENUMS
 *********************************************************************************************************************/
typedef enum blocking_mode
{
    /// Reception in Blocking Mode
    BLOCKING = 0x10,
    /// Reception in Non-Blocking Mode
    NONBLOCKING = 0x20
} blocking_mode_t;

typedef enum protocol_type
{
    /// TCP protocol
    TCP = 1,
    /// UDP protocol
    UDP = 2
} protocol_type_t;

/**********************************************************************************************************************
 * DATA STRUCTURES
 *********************************************************************************************************************/

/// typedef for application event handler
typedef void ( * socket_event_handler_t)(void * upper_layer_ctx, optiga_lib_status_t event);


/** @brief PAL socket context structure */
typedef struct pal_socket
{
    /// Pointer to platform specific context for socket
    void * p_socket_hw_config;

    /// Timeout value in milli-seconds
    uint16_t timeout;

    /// Blocking or Non blocking mode
    uint8_t mode;

    /// Protocol type
    uint8_t protocol;

    /// Upper layer context
    void * p_upper_layer_ctx;

    /// Upper layer event handler
    socket_event_handler_t upper_layer_event_handler;
} pal_socket_t;

/**********************************************************************************************************************
 * API Prototypes
 *********************************************************************************************************************/

/**
 * \brief Initializes the socket
 *
 * \details
 * Initializes socket communication structure
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \param[in,out]  p_socket_context        Valid pointer to the socket communication structure
 *
 * \retval         #PAL_STATUS_SUCCESS     On successful execution
 * \retval         #PAL_STATUS_FAILURE     On failure
 */
pal_status_t pal_socket_init(pal_socket_t * p_socket_context);

/**
 * \brief Returns the network PMTU
 *
 * \details
 * Returns the network PMTU
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \retval  #PAL_STATUS_SUCCESS    On successful execution
 * \retval  #PAL_STATUS_FAILURE    On failure
 */
pal_status_t pal_socket_get_pmtu(pal_socket_t * p_socket_context);

/**
 * \brief Creates server port and binds
 *
 * \details
 * Creates an socket server port and binds the port to the server's IP address.
 * - It creates a server socket and initializes it.
 * - It binds the socket to the given IP address and port
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \param[out]  p_socket_context           Valid pointer to the socket communication structure
 * \param[in]   p_server_ip_address        Server IP address
 * \param[in]   server_port                Port number for server
 *
 * \retval      #PAL_STATUS_SUCCESS        On successful execution
 * \retval      #PAL_STATUS_FAILURE        On failure
 */
pal_status_t pal_socket_accept(pal_socket_t * p_socket_context, const void * p_server_ip_address, uint16_t server_port);

/**
 * \brief Creates the client port
 *
 * \details
 * Creates the client port
 * - It creates a client socket and initializes it.
 * - It connects the socket to the server at the given IP address and port.
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \param[in,out]  p_socket_context          Valid pointer to the socket communication structure
 * \param[out]     p_server_ip_address       Server IP address
 * \param[in]      port                      Port number for server
 *
 * \retval         #PAL_STATUS_SUCCESS       On successful execution
 * \retval         #PAL_STATUS_FAILURE       On failure
 */
pal_status_t pal_socket_connect(pal_socket_t * p_socket_context, const void * p_server_ip_address, uint16_t port);

/**
 * \brief Receive data from either the client or the server
 *
 * \details
 * Receives the data from the client/server.
 * - It receives the client data through the socket.
 * - The maximum data length that can be received for datagram socket is limited by the PMTU
 * - If upper_layer_event_handler is initialized, the upper layer handler is invoked with the respective event
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \param[in,out]  p_socket_context        Valid pointer to the socket communication structure
 * \param[out]     p_data                  Valid pointer to the data buffer to be received
 * \param[in,out]  p_data_length           Valid pointer to the length of the buffer
 *
 * \retval         #PAL_STATUS_SUCCESS     On successful execution
 * \retval         #PAL_STATUS_FAILURE     On failure
 */
pal_status_t pal_socket_receive(pal_socket_t * p_socket_context, uint8_t * p_data, uint32_t * p_data_length);

/**
 * \brief Sends the data to the client or the server
 *
 * \details
 * Transmits the data to the client/server.
 * - It send the user provided data through the socket.
 * - The maximum data length to be transmitted for datagram socket is limited by the PMTU
 * - If upper_layer_event_handler is initialized, the upper layer handler is invoked with the respective event
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \param[in]  p_socket_context        Valid pointer to the socket communication structure
 * \param[in]  p_data                  Valid pointer to the data buffer to be transmitted
 * \param[in]  data_length             The length of the data to be transmitted
 *
 * \retval     #PAL_STATUS_SUCCESS     On successful execution
 * \retval     #PAL_STATUS_FAILURE     On failure
 */
pal_status_t pal_socket_send(pal_socket_t * p_socket_context, uint8_t * p_data, uint32_t data_length);

/**
 * \brief Closes the socket communication and release the port.
 *
 * \details
 * Closes the socket communication and releases all the associated resources
 * - In case of server, it stops listening on the IP address
 * - In case of client, it will disconnect from the server port
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \param[in]   p_socket_context       Valid pointer to the socket communication structure
 *
 * \retval      #PAL_STATUS_SUCCESS    On successful execution
 * \retval      #PAL_STATUS_FAILURE    On failure
 */
pal_status_t pal_socket_close(pal_socket_t * p_socket_context);

/**
 * \brief De-Initializes socket hardware associated with the given context.
 *
 * \details
 * De-Initializes socket communication structure.
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 * \param[in,out]  p_socket_context       Valid pointer to the socket communication structure
 *
 * \retval         #PAL_STATUS_SUCCESS    On successful execution
 * \retval         #PAL_STATUS_FAILURE    On failure
 */
pal_status_t pal_socket_deinit(pal_socket_t * p_socket_context);

#ifdef __cplusplus
}
#endif

#endif /*_PAL_SOCKET_H_ */
/**
* @}
*/

