/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Functions for the core network crypto.
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
 */
#include "net_crypto.h"

#include <string.h>

#include "DHT.h"
#include "LAN_discovery.h"
#include "TCP_client.h"
#include "TCP_connection.h"
#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "list.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"
#include "util.h"
typedef struct Packet_Data {
    uint64_t sent_time;
    uint16_t length;
    uint8_t data[MAX_CRYPTO_DATA_SIZE];
} Packet_Data;

typedef struct Packets_Array {
    Packet_Data *buffer[CRYPTO_PACKET_BUFFER_SIZE];
    uint32_t  buffer_start;
    uint32_t  buffer_end; /* packet numbers in array: `{buffer_start, buffer_end)` */
} Packets_Array;

typedef enum Crypto_Conn_State {
    /* the connection slot is free. This value is 0 so it is valid after
     * `crypto_memzero(...)` of the parent struct
     */
    CRYPTO_CONN_FREE = 0,
    CRYPTO_CONN_NO_CONNECTION,       /* the connection is allocated, but not yet used */
    CRYPTO_CONN_COOKIE_REQUESTING,   /* we are sending cookie request packets */
    CRYPTO_CONN_HANDSHAKE_SENT,      /* we are sending handshake packets */
    /* we are sending handshake packets.
     * we have received one from the other, but no data */
    CRYPTO_CONN_NOT_CONFIRMED,
    CRYPTO_CONN_ESTABLISHED,         /* the connection is established */
} Crypto_Conn_State;

typedef struct Crypto_Connection {
    // Necessary for non-Noise handshake
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The real public key of the peer. */
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of sent packets. */
    uint8_t sessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* Our public key for this session. */
    uint8_t sessionsecret_key[CRYPTO_SECRET_KEY_SIZE]; /* Our private key for this session. */
    uint8_t peersessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The public key of the peer. */
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE]; /* The precomputed shared key from encrypt_precompute. */
    Crypto_Conn_State status; /* See Crypto_Conn_State documentation */
    uint64_t cookie_request_number; /* number used in the cookie request packets for this connection */
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The dht public key of the peer */

    // For Noise
    bool noise_handshake_enabled;
    Noise_Handshake *noise_handshake;
    uint8_t send_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t recv_key[CRYPTO_SHARED_KEY_SIZE];
    //TODO: remove
    // uint8_t noise_hash[CRYPTO_SHA512_SIZE];
    // uint8_t noise_chaining_key[CRYPTO_SHA512_SIZE];
    // uint8_t niose_send_key[CRYPTO_PUBLIC_KEY_SIZE];
    // uint8_t noise_recv_key[CRYPTO_PUBLIC_KEY_SIZE];
    //TODO: necessary?
    // uint16_t handshake_send_interval;
    // bool initiator;
    // uint8_t precomputed_static_static[CRYPTO_PUBLIC_KEY_SIZE];

    uint8_t *temp_packet; /* Where the cookie request/handshake packet is stored while it is being sent. */
    uint16_t temp_packet_length;
    uint64_t temp_packet_sent_time; /* The time at which the last temp_packet was sent in ms. */
    uint32_t temp_packet_num_sent;

    IP_Port ip_portv4; /* The ip and port to contact this guy directly.*/
    IP_Port ip_portv6;
    uint64_t direct_lastrecv_timev4; /* The Time at which we last received a direct packet in ms. */
    uint64_t direct_lastrecv_timev6;

    uint64_t last_tcp_sent; /* Time the last TCP packet was sent. */

    Packets_Array send_array;
    Packets_Array recv_array;

    connection_status_cb *connection_status_callback;
    void *connection_status_callback_object;
    int connection_status_callback_id;

    connection_data_cb *connection_data_callback;
    void *connection_data_callback_object;
    int connection_data_callback_id;

    connection_lossy_data_cb *connection_lossy_data_callback;
    void *connection_lossy_data_callback_object;
    int connection_lossy_data_callback_id;

    uint64_t last_request_packet_sent;
    uint64_t direct_send_attempt_time;

    uint32_t packet_counter;
    double packet_recv_rate;
    uint64_t packet_counter_set;

    double packet_send_rate;
    uint32_t packets_left;
    uint64_t last_packets_left_set;
    double last_packets_left_rem;

    double packet_send_rate_requested;
    uint32_t packets_left_requested;
    uint64_t last_packets_left_requested_set;
    double last_packets_left_requested_rem;

    uint32_t last_sendqueue_size[CONGESTION_QUEUE_ARRAY_SIZE];
    uint32_t last_sendqueue_counter;
    long signed int last_num_packets_sent[CONGESTION_LAST_SENT_ARRAY_SIZE];
    long signed int last_num_packets_resent[CONGESTION_LAST_SENT_ARRAY_SIZE];
    uint32_t packets_sent;
    uint32_t packets_resent;
    uint64_t last_congestion_event;
    uint64_t rtt_time;

    /* TCP_connection connection_number */
    unsigned int connection_number_tcp;

    bool maximum_speed_reached;

    /* Must be a pointer, because the struct is moved in memory */
    pthread_mutex_t *mutex;

    dht_pk_cb *dht_pk_callback;
    void *dht_pk_callback_object;
    uint32_t dht_pk_callback_number;
} Crypto_Connection;

static const Crypto_Connection empty_crypto_connection = {{0}};

struct Net_Crypto {
    const Logger *log;
    const Memory *mem;
    const Random *rng;
    Mono_Time *mono_time;
    const Network *ns;

    DHT *dht;
    TCP_Connections *tcp_c;

    Crypto_Connection *crypto_connections;
    pthread_mutex_t tcp_mutex;

    pthread_mutex_t connections_mutex;
    unsigned int connection_use_counter;

    uint32_t crypto_connections_length; /* Length of connections array. */

    /* Our public and secret keys. */
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];

    /* The secret key used for cookies */
    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];

    new_connection_cb *new_connection_callback;
    void *new_connection_callback_object;

    /* The current optimal sleep time */
    uint32_t current_sleep_time;

    BS_List ip_port_list;
};

const uint8_t *nc_get_self_public_key(const Net_Crypto *c)
{
    return c->self_public_key;
}

const uint8_t *nc_get_self_secret_key(const Net_Crypto *c)
{
    return c->self_secret_key;
}

TCP_Connections *nc_get_tcp_c(const Net_Crypto *c)
{
    return c->tcp_c;
}

DHT *nc_get_dht(const Net_Crypto *c)
{
    return c->dht;
}

non_null()
static bool crypt_connection_id_is_valid(const Net_Crypto *c, int crypt_connection_id)
{
    if ((uint32_t)crypt_connection_id >= c->crypto_connections_length) {
        return false;
    }

    if (c->crypto_connections == nullptr) {
        return false;
    }

    const Crypto_Conn_State status = c->crypto_connections[crypt_connection_id].status;

    return status != CRYPTO_CONN_NO_CONNECTION && status != CRYPTO_CONN_FREE;
}

/** cookie timeout in seconds */
#define COOKIE_TIMEOUT 15
#define COOKIE_DATA_LENGTH (uint16_t)(CRYPTO_PUBLIC_KEY_SIZE * 2)
#define COOKIE_CONTENTS_LENGTH (uint16_t)(sizeof(uint64_t) + COOKIE_DATA_LENGTH)
#define COOKIE_LENGTH (uint16_t)(CRYPTO_NONCE_SIZE + COOKIE_CONTENTS_LENGTH + CRYPTO_MAC_SIZE)

#define COOKIE_REQUEST_PLAIN_LENGTH (uint16_t)(COOKIE_DATA_LENGTH + sizeof(uint64_t))
#define COOKIE_REQUEST_LENGTH (uint16_t)(1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE)
#define COOKIE_RESPONSE_LENGTH (uint16_t)(1 + CRYPTO_NONCE_SIZE + COOKIE_LENGTH + sizeof(uint64_t) + CRYPTO_MAC_SIZE)

/** @brief Create a cookie request packet and put it in packet.
 *
 * dht_public_key is the dht public key of the other
 *
 * packet must be of size COOKIE_REQUEST_LENGTH or bigger.
 *
 * @retval -1 on failure.
 * @retval COOKIE_REQUEST_LENGTH on success.
 */
non_null()
static int create_cookie_request(const Net_Crypto *c, uint8_t *packet, const uint8_t *dht_public_key,
                                 uint64_t number, uint8_t *shared_key)
{
    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");
    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH];

    memcpy(plain, c->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    //TODO: "Padding is used to maintain backwards-compatibility with previous versions of the protocol." => can this be removed by now?
    memzero(plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + (CRYPTO_PUBLIC_KEY_SIZE * 2), &number, sizeof(uint64_t));
    const uint8_t *tmp_shared_key = dht_get_shared_key_sent(c->dht, dht_public_key);
    memcpy(shared_key, tmp_shared_key, CRYPTO_SHARED_KEY_SIZE);
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(c->rng, nonce);
    packet[0] = NET_PACKET_COOKIE_REQUEST;
    memcpy(packet + 1, dht_get_self_public_key(c->dht), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    const int len = encrypt_data_symmetric(shared_key, nonce, plain, sizeof(plain),
                                           packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE) {
        return -1;
    }

    return 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + len;
}

/** @brief Create cookie of length COOKIE_LENGTH from bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int create_cookie(const Random *rng, const Mono_Time *mono_time, uint8_t *cookie, const uint8_t *bytes,
                         const uint8_t *encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH];
    const uint64_t temp_time = mono_time_get(mono_time);
    memcpy(contents, &temp_time, sizeof(temp_time));
    memcpy(contents + sizeof(temp_time), bytes, COOKIE_DATA_LENGTH);
    random_nonce(rng, cookie);
    const int len = encrypt_data_symmetric(encryption_key, cookie, contents, sizeof(contents), cookie + CRYPTO_NONCE_SIZE);

    if (len != COOKIE_LENGTH - CRYPTO_NONCE_SIZE) {
        return -1;
    }

    return 0;
}

/** @brief Open cookie of length COOKIE_LENGTH to bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int open_cookie(const Mono_Time *mono_time, uint8_t *bytes, const uint8_t *cookie,
                       const uint8_t *encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH];
    const int len = decrypt_data_symmetric(encryption_key, cookie, cookie + CRYPTO_NONCE_SIZE,
                                           COOKIE_LENGTH - CRYPTO_NONCE_SIZE, contents);

    if (len != sizeof(contents)) {
        return -1;
    }

    uint64_t cookie_time;
    memcpy(&cookie_time, contents, sizeof(cookie_time));
    const uint64_t temp_time = mono_time_get(mono_time);

    if (cookie_time + COOKIE_TIMEOUT < temp_time || temp_time < cookie_time) {
        return -1;
    }

    memcpy(bytes, contents + sizeof(cookie_time), COOKIE_DATA_LENGTH);
    return 0;
}

/** @brief Create a cookie response packet and put it in packet.
 * @param request_plain must be COOKIE_REQUEST_PLAIN_LENGTH bytes.
 * @param packet must be of size COOKIE_RESPONSE_LENGTH or bigger.
 *
 * @retval -1 on failure.
 * @retval COOKIE_RESPONSE_LENGTH on success.
 */
non_null()
static int create_cookie_response(const Net_Crypto *c, uint8_t *packet, const uint8_t *request_plain,
                                  const uint8_t *shared_key, const uint8_t *dht_public_key)
{
    LOGGER_DEBUG(c->log, "ENTERING");
    uint8_t cookie_plain[COOKIE_DATA_LENGTH];
    memcpy(cookie_plain, request_plain, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];

    if (create_cookie(c->rng, c->mono_time, plain, cookie_plain, c->secret_symmetric_key) != 0) {
        return -1;
    }

    memcpy(plain + COOKIE_LENGTH, request_plain + COOKIE_DATA_LENGTH, sizeof(uint64_t));
    packet[0] = NET_PACKET_COOKIE_RESPONSE;
    random_nonce(c->rng, packet + 1);
    const int len = encrypt_data_symmetric(shared_key, packet + 1, plain, sizeof(plain), packet + 1 + CRYPTO_NONCE_SIZE);

    if (len != COOKIE_RESPONSE_LENGTH - (1 + CRYPTO_NONCE_SIZE)) {
        return -1;
    }

    return COOKIE_RESPONSE_LENGTH;
}

/** @brief Handle the cookie request packet of length length.
 * Put what was in the request in request_plain (must be of size COOKIE_REQUEST_PLAIN_LENGTH)
 * Put the key used to decrypt the request into shared_key (of size CRYPTO_SHARED_KEY_SIZE) for use in the response.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int handle_cookie_request(const Net_Crypto *c, uint8_t *request_plain, uint8_t *shared_key,
                                 uint8_t *dht_public_key, const uint8_t *packet, uint16_t length)
{
    LOGGER_DEBUG(c->log, "ENTERING");
    if (length != COOKIE_REQUEST_LENGTH) {
        return -1;
    }

    memcpy(dht_public_key, packet + 1, CRYPTO_PUBLIC_KEY_SIZE);
    const uint8_t *tmp_shared_key = dht_get_shared_key_sent(c->dht, dht_public_key);
    memcpy(shared_key, tmp_shared_key, CRYPTO_SHARED_KEY_SIZE);
    const int len = decrypt_data_symmetric(shared_key, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                           packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE,
                                           request_plain);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH) {
        return -1;
    }

    return 0;
}

/** Handle the cookie request packet (for raw UDP) */
non_null(1, 2, 3) nullable(5)
static int udp_handle_cookie_request(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                     void *userdata)
{
    const Net_Crypto *c = (const Net_Crypto *)object;

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0) {
        return 1;
    }

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data)) {
        return 1;
    }

    if ((uint32_t)sendpacket(dht_get_net(c->dht), source, data, sizeof(data)) != sizeof(data)) {
        return 1;
    }

    return 0;
}

/** Handle the cookie request packet (for TCP) */
non_null()
static int tcp_handle_cookie_request(const Net_Crypto *c, int connections_number, const uint8_t *packet,
                                     uint16_t length)
{
    LOGGER_DEBUG(c->log, "ENTERING");
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0) {
        return -1;
    }

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data)) {
        return -1;
    }

    const int ret = send_packet_tcp_connection(c->tcp_c, connections_number, data, sizeof(data));
    return ret;
}

/** Handle the cookie request packet (for TCP oob packets) */
non_null()
static int tcp_oob_handle_cookie_request(const Net_Crypto *c, unsigned int tcp_connections_number,
        const uint8_t *dht_public_key, const uint8_t *packet, uint16_t length)
{
    LOGGER_DEBUG(c->log, "ENTERING");
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t dht_public_key_temp[CRYPTO_PUBLIC_KEY_SIZE];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key_temp, packet, length) != 0) {
        return -1;
    }

    if (!pk_equal(dht_public_key, dht_public_key_temp)) {
        return -1;
    }

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data)) {
        return -1;
    }

    const int ret = tcp_send_oob_packet(c->tcp_c, tcp_connections_number, dht_public_key, data, sizeof(data));
    return ret;
}

/** @brief Handle a cookie response packet of length encrypted with shared_key.
 * put the cookie in the response in cookie
 *
 * @param cookie must be of length COOKIE_LENGTH.
 *
 * @retval -1 on failure.
 * @retval COOKIE_LENGTH on success.
 */
non_null()
static int handle_cookie_response(uint8_t *cookie, uint64_t *number,
                                  const uint8_t *packet, uint16_t length,
                                  const uint8_t *shared_key)
{
    if (length != COOKIE_RESPONSE_LENGTH) {
        return -1;
    }

    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];
    const int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE,
                                           length - (1 + CRYPTO_NONCE_SIZE), plain);

    if (len != sizeof(plain)) {
        return -1;
    }

    memcpy(cookie, plain, COOKIE_LENGTH);
    memcpy(number, plain + COOKIE_LENGTH, sizeof(uint64_t));
    return COOKIE_LENGTH;
}

/* Non-noise: Necessary for backwards compatiblity to non-Noise handshake */
#define HANDSHAKE_PACKET_LENGTH (1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
/* Noise: Necessary for Noise-based handshake */
#define NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_NONCE_SIZE + COOKIE_LENGTH + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
#define NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_NONCE_SIZE + COOKIE_LENGTH + CRYPTO_MAC_SIZE)
#define NOISE_HANDSHAKE_PAYLOAD_PLAIN_LENGTH_INITIATOR (CRYPTO_NONCE_SIZE + COOKIE_LENGTH + COOKIE_LENGTH)
#define NOISE_HANDSHAKE_PAYLOAD_PLAIN_LENGTH_RESPONDER (CRYPTO_NONCE_SIZE + COOKIE_LENGTH)

/*
* TODO: Helper function to print hashes, keys, packets, etc.
* TODO: remove from production code or make dependent on MIN_LOGGER_LEVEL=DEBUG?
* bytes_to_string() from util.h
*/
static void bytes2string(char *string, size_t string_length, const uint8_t *bytes, size_t bytes_length, const Logger *log)
{
    bytes_to_string(bytes, bytes_length, string, string_length);
}

/**
 * @brief Initializes a Noise Handshake State with provided static X25519 ID key pair, X25519 static ID public key from peer
 * and sets if initiator or not.
 *
 * cf. Noise section 5.3
 * Calls InitializeSymmetric(protocol_name).
 * Calls MixHash(prologue).
 * Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
 * Calls MixHash() once for each public key listed in the pre-messages.
 *
 * //TODO: remove Logger Param
 * @param log Tox logger
 * @param noise_handshake handshake struct to save the necessary values to
 * @param self_secret_key static private ID X25519 key of this Tox instance
 * @param peer_public_key X25519 static ID public key from peer to connect to
 * @param initiator specifies if this Tox instance is the initiator of this crypto connection
 *
 * @return -1 on failure
 * @return 0 on success
 */
static int noise_handshake_init
(const Logger *log, Noise_Handshake *noise_handshake, const uint8_t *self_secret_key, const uint8_t *peer_public_key, bool initiator)
{
    //TODO: remove
    if (log != nullptr) {
        LOGGER_DEBUG(log, "ENTERING");
    }

    //TODO: move to handle_packet_crypto_hs()?
    crypto_memzero(noise_handshake, sizeof(Noise_Handshake));

    /* IntializeSymmetric(protocol_name) => set h to NOISE_PROTOCOL_NAME and append zero bytes to make 64 bytes, sets ck = h
     Nothing gets hashed in Tox case because NOISE_PROTOCOL_NAME < CRYPTO_SHA512_SIZE */
    uint8_t temp_hash[CRYPTO_SHA512_SIZE];
    memset(temp_hash, '\0', CRYPTO_SHA512_SIZE);
    memcpy(temp_hash, NOISE_PROTOCOL_NAME, sizeof(NOISE_PROTOCOL_NAME));
    memcpy(noise_handshake->hash, temp_hash, CRYPTO_SHA512_SIZE);
    memcpy(noise_handshake->chaining_key, temp_hash, CRYPTO_SHA512_SIZE);

    //TODO: remove
    // char log_ck[CRYPTO_SHA512_SIZE*2+1];
    // if (log != nullptr) {
    //     bytes2string(log_ck, sizeof(log_ck), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE, log);
    //     LOGGER_DEBUG(log, "ck: %s", log_ck);
    // }

    /* Sets the initiator, s => ephemeral keys are set afterwards */
    noise_handshake->initiator = initiator;
    if (self_secret_key != nullptr) {
        memcpy(noise_handshake->static_private, self_secret_key, CRYPTO_SECRET_KEY_SIZE);
        crypto_derive_public_key(noise_handshake->static_public, self_secret_key);

        //TODO: remove
        if (log != nullptr) {
            char log_spub[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
            bytes2string(log_spub, sizeof(log_spub), noise_handshake->static_public, CRYPTO_PUBLIC_KEY_SIZE, log);
            LOGGER_DEBUG(log, "static pub: %s", log_spub);
        }

    } else {
        // fprintf(stderr, "Local static private key required, but not provided.\n");
        LOGGER_DEBUG(log, "Local static private key required, but not provided.");
        return -1;
    }
    /* <- s: pre-message from responder to initiator => sets rs (only initiator) */
    if (initiator) {
        if (peer_public_key != nullptr) {
            memcpy(noise_handshake->remote_static, peer_public_key, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: Remove
            if (log != nullptr) {
                char log_spub[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
                bytes2string(log_spub, sizeof(log_spub), noise_handshake->remote_static, CRYPTO_PUBLIC_KEY_SIZE, log);
                LOGGER_DEBUG(log, "INITIATOR remote static: %s", log_spub);
            }

            /* Calls MixHash() once for each public key listed in the pre-messages from Noise IK */
            noise_mix_hash(noise_handshake->hash, peer_public_key, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: remove
            // if (log != nullptr) {
            //     bytes2string(log_hash, sizeof(log_hash), noise_handshake->hash, CRYPTO_SHA512_SIZE, log);
            //     LOGGER_DEBUG(log, "INITIATOR hash: %s", log_hash);
            // }
        } else {
            // fprintf(stderr, "Remote peer static public key required, but not provided.\n");
            LOGGER_DEBUG(log, "Remote peer static public key required, but not provided.");
            return -1;
        }
    }
    /* Noise RESPONDER */
    else {
        /* Calls MixHash() once for each public key listed in the pre-messages from Noise IK */
        noise_mix_hash(noise_handshake->hash, noise_handshake->static_public, CRYPTO_PUBLIC_KEY_SIZE);

        //TODO: remove
        // if (log != nullptr) {
        //     bytes2string(log_hash, sizeof(log_hash), noise_handshake->hash, CRYPTO_SHA512_SIZE, log);
        //     LOGGER_DEBUG(log, "RESPONDER hash: %s", log_hash);
        // }
    }

    /* Ready to go */
    return 0;
}

/**  @brief Create a handshake packet and put it in packet. Currently supports noise-Noise and Noise handshake.
 *
 * cf. Noise section 5.3 -> WriteMessage(payload, message_buffer)
 *
 * @param cookie must be COOKIE_LENGTH bytes.
 * @param packet must be of size HANDSHAKE_PACKET_LENGTH or bigger.
 * @param nonce base nonce for this Tox instance, to be used for transport message encryption after handshake
 * @param ephemeral_private Ephemeral private X25519 key of this Tox instance for this handshake
 * @param ephemeral_public Ephemeral public X25519 key of this Tox instance for this handshake
 * @param peer_real_pk X25519 static ID public key from peer to connect to
 * @param peer_dht_pubkey X25519 DHT public key from peer to connect to
 * @param noise_handshake struct containing Noise information/values
 *
 * @retval -1 on failure.
 * @retval HANDSHAKE_PACKET_LENGTH on success (non-Noise handshake).
 * @retval NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR if Noise handshake initiator
 * @retval NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER if Noise handshake responder
 *
 */
non_null(1, 2, 3, 4, 6, 7, 8) nullable(5, 9)
static int create_crypto_handshake(const Net_Crypto *c, uint8_t *packet, const uint8_t *cookie, const uint8_t *nonce, const uint8_t *ephemeral_private,
                                   const uint8_t *ephemeral_public, const uint8_t *peer_real_pk, const uint8_t *peer_dht_pubkey, Noise_Handshake *noise_handshake)
{
    LOGGER_DEBUG(c->log, "ENTERING: create_crypto_handshake()");
    /* Noise-based handshake */
    if (noise_handshake != nullptr) {
        LOGGER_DEBUG(c->log, "NOISE HANDSHAKE");
        /* Noise INITIATOR: -> e, es, s, ss */
        /* Initiator: Handshake packet structure
            [uint8_t 26]
            [session public key of the peer (32 bytes)] => currently in plain
            [24 bytes nonce for static pub key encryption]
            [encrypted static public key of the INITIATOR (32 bytes)]
            [MAC encrypted static pubkey 16 bytes]
            [24 bytes nonce handshake payload encryption]
            [Encrypted message containing:
            [24 bytes base nonce] => WITH base Nonce, to be used for transport message encryption after handshake
            [Cookie 112 bytes] => Cookie encrypted and authenticated via XAEAD
            [112 bytes Other Cookie (used by the other peer to respond to the handshake packet)]
            [MAC encrypted payload 16 bytes]
            => 393 bytes in total
            */
        if (noise_handshake->initiator) {
            /* set ephemeral private+public */
            memcpy(noise_handshake->ephemeral_private, ephemeral_private, CRYPTO_SECRET_KEY_SIZE);
            memcpy(noise_handshake->ephemeral_public, ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

            /* e */
            memcpy(packet + 1, ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
            noise_mix_hash(noise_handshake->hash, ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: remove from production code
            // char log_hash1[CRYPTO_SHA512_SIZE*2+1];
            // bytes2string(log_hash1, sizeof(log_hash1), noise_handshake->hash, CRYPTO_SHA512_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "hash1 INITIATOR: %s", log_hash1);

            /* es */
            uint8_t noise_handshake_temp_key[CRYPTO_SHARED_KEY_SIZE];
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, ephemeral_private, noise_handshake->remote_static);

            /* s */
            /*Nonce provided as parameter is the base nonce! -> Add nonce for static pub key encryption to packet
            || TODO: or use 0? or leads to nonce reuse? */
            random_nonce(c->rng, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE);
            noise_encrypt_and_hash(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, noise_handshake->static_public, CRYPTO_PUBLIC_KEY_SIZE, noise_handshake_temp_key,
                                   noise_handshake->hash, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: remove from production code
            // char log_hash2[CRYPTO_SHA512_SIZE*2+1];
            // bytes2string(log_hash2, sizeof(log_hash2), noise_handshake->hash, CRYPTO_SHA512_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "hash2 INITIATOR: %s", log_hash2);
            char log_ephemeral[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
            bytes2string(log_ephemeral, sizeof(log_ephemeral), noise_handshake->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE, c->log);
            LOGGER_DEBUG(c->log, "ephemeral public: %s", log_ephemeral);

            /* ss */
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, noise_handshake->static_private, noise_handshake->remote_static);

            /* Noise Handshake Payload */
            uint8_t handshake_payload_plain[NOISE_HANDSHAKE_PAYLOAD_PLAIN_LENGTH_INITIATOR];
            memcpy(handshake_payload_plain, nonce, CRYPTO_NONCE_SIZE);
            // Noise: Cookie authenticated via ciphertext MAC
            // crypto_sha512(handshake_payload_plain + CRYPTO_NONCE_SIZE, cookie, COOKIE_LENGTH);

            // Noise: Cookie from RESPONDER
            memcpy(handshake_payload_plain + CRYPTO_NONCE_SIZE, cookie, COOKIE_LENGTH);

            uint8_t cookie_plain[COOKIE_DATA_LENGTH];
            memcpy(cookie_plain, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
            memcpy(cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, peer_dht_pubkey, CRYPTO_PUBLIC_KEY_SIZE);

            /* OtherCookie is added to payload */
            if (create_cookie(c->rng, c->mono_time, handshake_payload_plain + CRYPTO_NONCE_SIZE + COOKIE_LENGTH,
                              cookie_plain, c->secret_symmetric_key) != 0) {
                return -1;
            }

            /* Add Handshake payload nonce */
            random_nonce(c->rng, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE);

            noise_encrypt_and_hash(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE,
                                   handshake_payload_plain, sizeof(handshake_payload_plain), noise_handshake_temp_key,
                                   noise_handshake->hash, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE);

            //TODO: remove from production code
            // LOGGER_DEBUG(c->log, "AFTER noise_encrypt_and_hash()");
            // char log_ciphertext[(sizeof(handshake_payload_plain)+CRYPTO_MAC_SIZE)*2+1];
            // bytes2string(log_ciphertext, sizeof(log_ciphertext), (packet + 1 + COOKIE_LENGTH + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE),
            //             (sizeof(handshake_payload_plain)+CRYPTO_MAC_SIZE), c->log);
            // LOGGER_DEBUG(c->log, "Ciphertext INITIATOR: %s", log_ciphertext);

            packet[0] = NET_PACKET_CRYPTO_HS;
            // Noise: cookie (from other peer/RESPONDER) is encrypted and included in ciphertext
            // memcpy(packet + 1, cookie, COOKIE_LENGTH);

            //TODO: remove from production code
            // char log_packet[NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR*2+1];
            // bytes2string(log_packet, sizeof(log_packet), packet, NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR, c->log);
            // LOGGER_DEBUG(c->log, "HS Packet I: %s", log_packet);

            //TODO: memzero handshake_payload_plain
            crypto_memzero(noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE);

            return NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR;
        }
        /* Noise RESPONDER: <- e, ee, se */
        /* Responder: Handshake packet structure
            [uint8_t 26]
            [session public key of the peer (32 bytes)] => currently in plain
            [24 bytes nonce for handshake payload encryption]
            [Encrypted message containing:
            [24 bytes base nonce] => WITH base Nonce, to be used for transport message encryption after handshake
            [Cookie 112 bytes] => INITIATOR Cookie encrypted and authenticate via XAEAD
            ~~[112 bytes Other Cookie (used by the other to respond to the handshake packet)]~~ NOT necessary for NoiseIK
            [MAC encrypted payload 16 bytes]
            => ~~321~~ 209 bytes in total
            */
        else {
            /* set ephemeral private+public */
            memcpy(noise_handshake->ephemeral_private, ephemeral_private, CRYPTO_SECRET_KEY_SIZE);
            memcpy(noise_handshake->ephemeral_public, ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

            /* e */
            memcpy(packet + 1, ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
            noise_mix_hash(noise_handshake->hash, ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: Remove
            // char log_ck[CRYPTO_SHA512_SIZE*2+1];
            // bytes2string(log_ck, sizeof(log_ck), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "RESPONDER pre ee ck: %s", log_ck);

            /* ee */
            uint8_t noise_handshake_temp_key[CRYPTO_SHARED_KEY_SIZE];
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, ephemeral_private, noise_handshake->remote_ephemeral);

            //TODO: Remove
            // char log_temp_key[CRYPTO_SHARED_KEY_SIZE*2+1];
            // bytes2string(log_temp_key, sizeof(log_temp_key), noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "RESPONDER ee temp_key: %s", log_temp_key);

            /* se */
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, noise_handshake->ephemeral_private, noise_handshake->remote_static);

            //TODO: Remove
            // bytes2string(log_temp_key, sizeof(log_temp_key), noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "RESPONDER es temp_key: %s", log_temp_key);

            /* Create Noise Handshake Payload */
            uint8_t handshake_payload_plain[NOISE_HANDSHAKE_PAYLOAD_PLAIN_LENGTH_RESPONDER];
            memcpy(handshake_payload_plain, nonce, CRYPTO_NONCE_SIZE);
            // Noise: Cookie authenticated via ciphertext MAC
            // crypto_sha512(handshake_payload_plain + CRYPTO_NONCE_SIZE, cookie, COOKIE_LENGTH);

            // Noise: Cookie from INITIATOR
            memcpy(handshake_payload_plain + CRYPTO_NONCE_SIZE, cookie, COOKIE_LENGTH);

            /* OtherCookie is added to payload => NOT necessary for RESPONDER HS Packet */
            // uint8_t cookie_plain[COOKIE_DATA_LENGTH];
            // memcpy(cookie_plain, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
            // memcpy(cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, peer_dht_pubkey, CRYPTO_PUBLIC_KEY_SIZE);
            // if (create_cookie(c->rng, c->mono_time, handshake_payload_plain + CRYPTO_NONCE_SIZE + COOKIE_LENGTH,
            //                   cookie_plain, c->secret_symmetric_key) != 0) {
            //     return -1;
            // }

            /* Add Handshake payload nonce
             Nonce provided as parameter is the base nonce! -> Add nonce for static pub key encryption to packet
            || TODO: or use 0? or leads to nonce reuse? */
            random_nonce(c->rng, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE);
            noise_encrypt_and_hash(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                                   handshake_payload_plain, sizeof(handshake_payload_plain), noise_handshake_temp_key,
                                   noise_handshake->hash, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE);

            packet[0] = NET_PACKET_CRYPTO_HS;
            // Noise: cookie (from other peer/INITIATOR) is encrypted and included in ciphertext
            // memcpy(packet + 1, cookie, COOKIE_LENGTH);

            //TODO: memzero handshake_payload_plain
            crypto_memzero(noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE);

            return NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER;
        }
    }
    /* non-Noise handshake */
    else {
        uint8_t plain[CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH];
        memcpy(plain, nonce, CRYPTO_NONCE_SIZE);
        memcpy(plain + CRYPTO_NONCE_SIZE, ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
        crypto_sha512(plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE, cookie, COOKIE_LENGTH);
        uint8_t cookie_plain[COOKIE_DATA_LENGTH];
        memcpy(cookie_plain, peer_real_pk, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, peer_dht_pubkey, CRYPTO_PUBLIC_KEY_SIZE);

        if (create_cookie(c->rng, c->mono_time, plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE,
                          cookie_plain, c->secret_symmetric_key) != 0) {
            return -1;
        }

        random_nonce(c->rng, packet + 1 + COOKIE_LENGTH);
        const int len = encrypt_data(peer_real_pk, c->self_secret_key, packet + 1 + COOKIE_LENGTH, plain, sizeof(plain),
                                     packet + 1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE);

        if (len != HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE)) {
            return -1;
        }

        packet[0] = NET_PACKET_CRYPTO_HS;
        memcpy(packet + 1, cookie, COOKIE_LENGTH);

        return HANDSHAKE_PACKET_LENGTH;
    }
}

/** @brief Handle a crypto handshake packet of length.
 * put the base nonce contained in the packet in nonce,
 * the session public key in session_pk
 * the real public key of the peer in peer_real_pk
 * the dht public key of the peer in dht_public_key and
 * the cookie inside the encrypted part of the packet in cookie.
 * Currently supports noise-Noise and Noise handshake
 *
 * if expected_real_pk isn't NULL it denotes the real public key
 * the packet should be from.
 *
 * nonce must be at least CRYPTO_NONCE_SIZE
 * session_pk must be at least CRYPTO_PUBLIC_KEY_SIZE
 * peer_real_pk must be at least CRYPTO_PUBLIC_KEY_SIZE
 * cookie must be at least COOKIE_LENGTH
 *
 * cf. Noise section 5.3 -> ReadMessage(payload, message_buffer)
 *
 * @retval false on failure.
 * @retval true on success.
 */
non_null(1, 2, 5, 7) nullable(3, 4, 6, 9, 10)
static bool handle_crypto_handshake(const Net_Crypto *c, uint8_t *nonce, uint8_t *session_pk, uint8_t *peer_real_pk,
                                    uint8_t *dht_public_key, uint8_t *cookie, const uint8_t *packet, uint16_t length, const uint8_t *expected_real_pk,
                                    Noise_Handshake *noise_handshake)
{
    LOGGER_DEBUG(c->log, "ENTERING");
    /* Noise-based handshake */
    if (noise_handshake != nullptr) {
        LOGGER_DEBUG(c->log, "NOISE handshake => INITIATOR or RESPONDER: %d", noise_handshake->initiator);

        uint8_t cookie_plain[COOKIE_DATA_LENGTH];

        /* -> e, es, s, ss */
        /* Initiator: Handshake packet structure handled here
            [uint8_t 26]
            [session public key of the peer (32 bytes)] => currently in plain
            [24 bytes nonce static pub key encryption]
            [encrypted static public key of the INITIATOR (32 bytes)] => handled by Noise
            [MAC encrypted static pubkey 16 bytes]
            [24 bytes nonce handshake payload encryption]
            [Encrypted message containing:
            [24 bytes base nonce] => WITH base Nonce, to be used for transport message decryption after handshake
            [Cookie 112 bytes] => Cookie encrypted and authenticated via XAEAD
            [112 bytes Other Cookie (used by the other to respond to the handshake packet)]
            [MAC 16 bytes]
            => 393 bytes in total
            */
        if (!noise_handshake->initiator) {
            LOGGER_DEBUG(c->log, "RESPONDER: Noise HS handle/ReadMessage");
            if (length != NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR) {
                return false;
            }

            //TODO: remove from production code
            // char log_packet[NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR*2+1];
            // bytes2string(log_packet, sizeof(log_packet), packet, NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR, c->log);
            // LOGGER_DEBUG(c->log, "HS Packet I (R): %s", log_packet);

            //TODO: Check here if remote_ephemeral is already the same ephemeral key?

            /* e */
            memcpy(noise_handshake->remote_ephemeral, packet + 1, CRYPTO_PUBLIC_KEY_SIZE);
            noise_mix_hash(noise_handshake->hash, noise_handshake->remote_ephemeral, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: remove from production code
            // char log_hash1[CRYPTO_SHA512_SIZE*2+1];
            // bytes2string(log_hash1, sizeof(log_hash1), noise_handshake->hash, CRYPTO_SHA512_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "hash1 RESPONDER: %s", log_hash1);
            char log_static[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
            bytes2string(log_static, sizeof(log_static), noise_handshake->static_public, CRYPTO_PUBLIC_KEY_SIZE, c->log);
            LOGGER_DEBUG(c->log, "local static pub: %s", log_static);
            bytes2string(log_static, sizeof(log_static), noise_handshake->remote_ephemeral, CRYPTO_PUBLIC_KEY_SIZE, c->log);
            LOGGER_DEBUG(c->log, "remote ephemeral: %s", log_static);

            /* es */
            uint8_t noise_handshake_temp_key[CRYPTO_SHARED_KEY_SIZE];
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, noise_handshake->static_private, noise_handshake->remote_ephemeral);
            /* s */
            /* Nonces contained in packet! */
            memcpy(nonce, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);

            if (noise_decrypt_and_hash(noise_handshake->remote_static, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE,
                                       noise_handshake_temp_key, noise_handshake->hash, nonce) != CRYPTO_PUBLIC_KEY_SIZE) {
                LOGGER_DEBUG(c->log, "RESPONDER: Noise ReadMessage remote static decryption failed");
                return false;
            }

            //TODO: remove
            bytes2string(log_static, sizeof(log_static), noise_handshake->remote_static, CRYPTO_PUBLIC_KEY_SIZE, c->log);
            LOGGER_DEBUG(c->log, "local remote pub: %s", log_static);

            //TODO: remove from production code
            // char log_hash2[CRYPTO_SHA512_SIZE*2+1];
            // bytes2string(log_hash2, sizeof(log_hash2), noise_handshake->hash, CRYPTO_SHA512_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "hash1 RESPONDER: %s", log_hash2);

            /* ss */
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, noise_handshake->static_private, noise_handshake->remote_static);
            /* Payload decryption */
            uint8_t handshake_payload_plain[NOISE_HANDSHAKE_PAYLOAD_PLAIN_LENGTH_INITIATOR];
            /* get Handshake payload base nonce */
            memcpy(nonce, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE, CRYPTO_NONCE_SIZE);

            if (noise_decrypt_and_hash(handshake_payload_plain, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE,
                                       sizeof(handshake_payload_plain) + CRYPTO_MAC_SIZE, noise_handshake_temp_key,
                                       noise_handshake->hash, nonce) != sizeof(handshake_payload_plain)) {
                LOGGER_DEBUG(c->log, "RESPONDER: Noise HS payload decryption failed");
                return false;
            }

            crypto_memzero(noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE);

            if (open_cookie(c->mono_time, cookie_plain, handshake_payload_plain + CRYPTO_NONCE_SIZE, c->secret_symmetric_key) != 0) {
                return false;
            }

            if (expected_real_pk != nullptr && !pk_equal(cookie_plain, expected_real_pk)) {
                return false;
            }

            // received base nonce
            memcpy(nonce, handshake_payload_plain, CRYPTO_NONCE_SIZE);
            // not necessary for Noise (=remote ephemeral)
            // memcpy(session_pk, packet + 1 + COOKIE_LENGTH, CRYPTO_PUBLIC_KEY_SIZE);
            // cookie necessary for Noise RESPONDER, used afterwards in create_send_handshake()
            memcpy(cookie, handshake_payload_plain + CRYPTO_NONCE_SIZE + COOKIE_LENGTH, COOKIE_LENGTH);
            /* Noise: not necessary for Noise (=remote static), but necessary for friend_connection.c->handle_new_connections() */
            //TODO: check for nullptr when called via handle_packet_crypto_hs() (not necessary there)?
            memcpy(peer_real_pk, noise_handshake->remote_static, CRYPTO_PUBLIC_KEY_SIZE);
            // necessary
            memcpy(dht_public_key, cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
            //TODO: memzero packet, unwatend side effects? TODO: not possible currently because const
            // crypto_memzero(packet, length);

            //TODO: memzero handshake_payload_plain

            LOGGER_DEBUG(c->log, "RESPONDER: END Noise HS handle/ReadMessage");
            return true;
        }
        /* Noise ReadMessage() if initiator:  <- e, ee, se */
        /* Responder: Handshake packet structure
            [uint8_t 26]
            [session public key of the peer (32 bytes)]
            [24 bytes nonce handshake payload encryption]
            [Encrypted message containing:
            [24 bytes base nonce] => WITH base Nonce, to be used for transport message encryption after handshake
            [Cookie 112 bytes] => Cookie encrypted and authenticated via XAEAD
            ~~[112 bytes Other Cookie (used by the other to respond to the handshake packet)]~~ NOT necessary for NoiseIK
            [MAC 16 bytes]
            => ~~321~~ 209 bytes in total
            */
        else {
            LOGGER_DEBUG(c->log, "INITIATOR: Noise HS handle/ReadMessage");

            if (length != NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER) {
                return false;
            }

            memcpy(noise_handshake->remote_ephemeral, packet + 1, CRYPTO_PUBLIC_KEY_SIZE);
            noise_mix_hash(noise_handshake->hash, noise_handshake->remote_ephemeral, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: Remove
            // char log_ck[CRYPTO_SHA512_SIZE*2+1];
            // bytes2string(log_ck, sizeof(log_ck), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "INITIATOR pre ee ck: %s", log_ck);

            /* ee */
            uint8_t noise_handshake_temp_key[CRYPTO_SHARED_KEY_SIZE];
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, noise_handshake->ephemeral_private, noise_handshake->remote_ephemeral);

            //TODO: Remove
            // char log_temp_key[CRYPTO_SHARED_KEY_SIZE*2+1];
            // bytes2string(log_temp_key, sizeof(log_temp_key), noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "INITIATOR ee temp_key: %s", log_temp_key);

            /* se */
            noise_mix_key(noise_handshake->chaining_key, noise_handshake_temp_key, noise_handshake->static_private, noise_handshake->remote_ephemeral);
            /* Payload decryption */
            uint8_t handshake_payload_plain[NOISE_HANDSHAKE_PAYLOAD_PLAIN_LENGTH_RESPONDER];
            memcpy(nonce, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);

            //TODO: Remove
            // bytes2string(log_temp_key, sizeof(log_temp_key), noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE, c->log);
            // LOGGER_DEBUG(c->log, "INITIATOR se temp_key: %s", log_temp_key);

            if (noise_decrypt_and_hash(handshake_payload_plain, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                                       sizeof(handshake_payload_plain) + CRYPTO_MAC_SIZE, noise_handshake_temp_key,
                                       noise_handshake->hash, nonce) != sizeof(handshake_payload_plain)) {
                LOGGER_DEBUG(c->log, "INITIATOR: Noise ReadMessage remote static decryption failed");
                return false;
            }

            crypto_memzero(noise_handshake_temp_key, CRYPTO_SHARED_KEY_SIZE);

            if (open_cookie(c->mono_time, cookie_plain, handshake_payload_plain + CRYPTO_NONCE_SIZE, c->secret_symmetric_key) != 0) {
                return false;
            }

            if (expected_real_pk != nullptr && !pk_equal(cookie_plain, expected_real_pk)) {
                return false;
            }

            // neccessary, base nonce
            memcpy(nonce, handshake_payload_plain, CRYPTO_NONCE_SIZE);
            // not necessary for Noise (=remote ephemeral)
            // memcpy(session_pk, packet + 1 + COOKIE_LENGTH, CRYPTO_PUBLIC_KEY_SIZE);
            // not necessary for Noise INITIATOR
            //memcpy(cookie, handshake_payload_plain + CRYPTO_NONCE_SIZE + CRYPTO_SHA512_SIZE, COOKIE_LENGTH);
            // not necessary for Noise (=remote static)
            // memcpy(peer_real_pk, cookie_plain, CRYPTO_PUBLIC_KEY_SIZE);
            // necessary
            memcpy(dht_public_key, cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: memzero packet, unwatend side effects? TODO: not possible currently because const
            // crypto_memzero(packet, length);

            //TODO: memzero handshake_payload_plain

            LOGGER_DEBUG(c->log, "INITIATOR: END Noise HS handle/ReadMessage");
            return true;
        }
    }
    /* non-Noise handshake */
    else {
        LOGGER_DEBUG(c->log, "ENTERING: handle_crypto_handshake() => OLD HANDSHAKE");

        if (length != HANDSHAKE_PACKET_LENGTH) {
            return false;
        }

        uint8_t cookie_plain[COOKIE_DATA_LENGTH];

        if (open_cookie(c->mono_time, cookie_plain, packet + 1, c->secret_symmetric_key) != 0) {
            return false;
        }

        if (expected_real_pk != nullptr && !pk_equal(cookie_plain, expected_real_pk)) {
            return false;
        }

        uint8_t cookie_hash[CRYPTO_SHA512_SIZE];
        crypto_sha512(cookie_hash, packet + 1, COOKIE_LENGTH);

        uint8_t plain[CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + COOKIE_LENGTH];
        const int len = decrypt_data(cookie_plain, c->self_secret_key, packet + 1 + COOKIE_LENGTH,
                                     packet + 1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE,
                                     HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + CRYPTO_NONCE_SIZE), plain);

        if (len != sizeof(plain)) {
            return false;
        }

        if (!crypto_sha512_eq(cookie_hash, plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE)) {
            return false;
        }

        memcpy(nonce, plain, CRYPTO_NONCE_SIZE);
        memcpy(session_pk, plain + CRYPTO_NONCE_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(cookie, plain + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE, COOKIE_LENGTH);
        memcpy(peer_real_pk, cookie_plain, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(dht_public_key, cookie_plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);

        //TODO: memzero packet, unwatend side effects?
        // crypto_memzero(packet, length);

        return true;
    }
}

non_null()
static Crypto_Connection *get_crypto_connection(const Net_Crypto *c, int crypt_connection_id)
{
    if (!crypt_connection_id_is_valid(c, crypt_connection_id)) {
        return nullptr;
    }

    return &c->crypto_connections[crypt_connection_id];
}

/** @brief Associate an ip_port to a connection.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int add_ip_port_connection(Net_Crypto *c, int crypt_connection_id, const IP_Port *ip_port)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (net_family_is_ipv4(ip_port->ip.family)) {
        if (!ipport_equal(ip_port, &conn->ip_portv4) && !ip_is_lan(&conn->ip_portv4.ip)) {
            if (!bs_list_add(&c->ip_port_list, (const uint8_t *)ip_port, crypt_connection_id)) {
                return -1;
            }

            bs_list_remove(&c->ip_port_list, (uint8_t *)&conn->ip_portv4, crypt_connection_id);
            conn->ip_portv4 = *ip_port;
            return 0;
        }
    } else if (net_family_is_ipv6(ip_port->ip.family)) {
        if (!ipport_equal(ip_port, &conn->ip_portv6)) {
            if (!bs_list_add(&c->ip_port_list, (const uint8_t *)ip_port, crypt_connection_id)) {
                return -1;
            }

            bs_list_remove(&c->ip_port_list, (uint8_t *)&conn->ip_portv6, crypt_connection_id);
            conn->ip_portv6 = *ip_port;
            return 0;
        }
    }

    return -1;
}

/** @brief Return the IP_Port that should be used to send packets to the other peer.
 *
 * @retval IP_Port with family 0 on failure.
 * @return IP_Port on success.
 */
non_null()
static IP_Port return_ip_port_connection(const Net_Crypto *c, int crypt_connection_id)
{
    const IP_Port empty = {{{0}}};

    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return empty;
    }

    const uint64_t current_time = mono_time_get(c->mono_time);
    bool v6 = false;
    bool v4 = false;

    if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev4) > current_time) {
        v4 = true;
    }

    if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev6) > current_time) {
        v6 = true;
    }

    /* Prefer IP_Ports which haven't timed out to those which have.
     * To break ties, prefer ipv4 lan, then ipv6, then non-lan ipv4.
     */
    if (v4 && ip_is_lan(&conn->ip_portv4.ip)) {
        return conn->ip_portv4;
    }

    if (v6 && net_family_is_ipv6(conn->ip_portv6.ip.family)) {
        return conn->ip_portv6;
    }

    if (v4 && net_family_is_ipv4(conn->ip_portv4.ip.family)) {
        return conn->ip_portv4;
    }

    if (ip_is_lan(&conn->ip_portv4.ip)) {
        return conn->ip_portv4;
    }

    if (net_family_is_ipv6(conn->ip_portv6.ip.family)) {
        return conn->ip_portv6;
    }

    if (net_family_is_ipv4(conn->ip_portv4.ip.family)) {
        return conn->ip_portv4;
    }

    return empty;
}

/** @brief Sends a packet to the peer using the fastest route.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int send_packet_to(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
// TODO(irungentoo): TCP, etc...
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    //TODO: remove
    // LOGGER_DEBUG(c->log, "ENTERING: send_packet_to()");

    bool direct_send_attempt = false;

    pthread_mutex_lock(conn->mutex);
    const IP_Port ip_port = return_ip_port_connection(c, crypt_connection_id);

    // TODO(irungentoo): on bad networks, direct connections might not last indefinitely.
    if (!net_family_is_unspec(ip_port.ip.family)) {
        bool direct_connected = false;

        // FIXME(sudden6): handle return value
        crypto_connection_status(c, crypt_connection_id, &direct_connected, nullptr);

        if (direct_connected) {
            if ((uint32_t)sendpacket(dht_get_net(c->dht), &ip_port, data, length) == length) {
                pthread_mutex_unlock(conn->mutex);
                return 0;
            }

            pthread_mutex_unlock(conn->mutex);
            LOGGER_WARNING(c->log, "sending packet of length %d failed", length);
            return -1;
        }

        // TODO(irungentoo): a better way of sending packets directly to confirm the others ip.
        const uint64_t current_time = mono_time_get(c->mono_time);

        if ((((UDP_DIRECT_TIMEOUT / 2) + conn->direct_send_attempt_time) < current_time && length < 96)
                || data[0] == NET_PACKET_COOKIE_REQUEST || data[0] == NET_PACKET_CRYPTO_HS) {
            if ((uint32_t)sendpacket(dht_get_net(c->dht), &ip_port, data, length) == length) {
                direct_send_attempt = true;
                conn->direct_send_attempt_time = mono_time_get(c->mono_time);
            }
        }
    }

    //TODO: remove
    // LOGGER_DEBUG(c->log, "send_packet_to() => TCP");

    pthread_mutex_unlock(conn->mutex);
    pthread_mutex_lock(&c->tcp_mutex);
    const int ret = send_packet_tcp_connection(c->tcp_c, conn->connection_number_tcp, data, length);
    pthread_mutex_unlock(&c->tcp_mutex);

    pthread_mutex_lock(conn->mutex);

    if (ret == 0) {
        conn->last_tcp_sent = current_time_monotonic(c->mono_time);
    }

    pthread_mutex_unlock(conn->mutex);

    if (direct_send_attempt) {
        return 0;
    }

    return ret;
}

/*** START: Array Related functions */

/** @brief Return number of packets in array
 * Note that holes are counted too.
 */
non_null()
static uint32_t num_packets_array(const Packets_Array *array)
{
    return array->buffer_end - array->buffer_start;
}

/** @brief Add data with packet number to array.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int add_data_to_buffer(const Memory *mem, Packets_Array *array, uint32_t number, const Packet_Data *data)
{
    if (number - array->buffer_start >= CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    const uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (array->buffer[num] != nullptr) {
        return -1;
    }

    Packet_Data *new_d = (Packet_Data *)mem_alloc(mem, sizeof(Packet_Data));

    if (new_d == nullptr) {
        return -1;
    }

    *new_d = *data;
    array->buffer[num] = new_d;

    if (number - array->buffer_start >= num_packets_array(array)) {
        array->buffer_end = number + 1;
    }

    return 0;
}

/** @brief Get pointer of data with packet number.
 *
 * @retval -1 on failure.
 * @retval 0 if data at number is empty.
 * @retval 1 if data pointer was put in data.
 */
non_null()
static int get_data_pointer(const Packets_Array *array, Packet_Data **data, uint32_t number)
{
    const uint32_t num_spots = num_packets_array(array);

    if (array->buffer_end - number > num_spots || number - array->buffer_start >= num_spots) {
        return -1;
    }

    const uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (array->buffer[num] == nullptr) {
        return 0;
    }

    *data = array->buffer[num];
    return 1;
}

/** @brief Add data to end of array.
 *
 * @retval -1 on failure.
 * @return packet number on success.
 */
non_null()
static int64_t add_data_end_of_buffer(const Logger *logger, const Memory *mem, Packets_Array *array, const Packet_Data *data)
{
    const uint32_t num_spots = num_packets_array(array);

    if (num_spots >= CRYPTO_PACKET_BUFFER_SIZE) {
        LOGGER_WARNING(logger, "crypto packet buffer size exceeded; rejecting packet of length %d", data->length);
        return -1;
    }

    Packet_Data *new_d = (Packet_Data *)mem_alloc(mem, sizeof(Packet_Data));

    if (new_d == nullptr) {
        LOGGER_ERROR(logger, "packet data allocation failed");
        return -1;
    }

    *new_d = *data;
    const uint32_t id = array->buffer_end;
    array->buffer[id % CRYPTO_PACKET_BUFFER_SIZE] = new_d;
    ++array->buffer_end;
    return id;
}

/** @brief Read data from beginning of array.
 *
 * @retval -1 on failure.
 * @return packet number on success.
 */
non_null()
static int64_t read_data_beg_buffer(const Memory *mem, Packets_Array *array, Packet_Data *data)
{
    if (array->buffer_end == array->buffer_start) {
        return -1;
    }

    const uint32_t num = array->buffer_start % CRYPTO_PACKET_BUFFER_SIZE;

    if (array->buffer[num] == nullptr) {
        return -1;
    }

    *data = *array->buffer[num];
    const uint32_t id = array->buffer_start;
    ++array->buffer_start;
    mem_delete(mem, array->buffer[num]);
    array->buffer[num] = nullptr;
    return id;
}

/** @brief Delete all packets in array before number (but not number)
 *
 * @retval -1 on failure.
 * @retval 0 on success
 */
non_null()
static int clear_buffer_until(const Memory *mem, Packets_Array *array, uint32_t number)
{
    const uint32_t num_spots = num_packets_array(array);

    if (array->buffer_end - number >= num_spots || number - array->buffer_start > num_spots) {
        return -1;
    }

    uint32_t i;

    for (i = array->buffer_start; i != number; ++i) {
        const uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num] != nullptr) {
            mem_delete(mem, array->buffer[num]);
            array->buffer[num] = nullptr;
        }
    }

    array->buffer_start = i;
    return 0;
}

non_null()
static int clear_buffer(const Memory *mem, Packets_Array *array)
{
    uint32_t i;

    for (i = array->buffer_start; i != array->buffer_end; ++i) {
        const uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num] != nullptr) {
            mem_delete(mem, array->buffer[num]);
            array->buffer[num] = nullptr;
        }
    }

    array->buffer_start = i;
    return 0;
}

/** @brief Set array buffer end to number.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int set_buffer_end(Packets_Array *array, uint32_t number)
{
    if (number - array->buffer_start > CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    if (number - array->buffer_end > CRYPTO_PACKET_BUFFER_SIZE) {
        return -1;
    }

    array->buffer_end = number;
    return 0;
}

/**
 * @brief Create a packet request packet from recv_array and send_buffer_end into
 *   data of length.
 *
 * @retval -1 on failure.
 * @return length of packet on success.
 */
non_null()
static int generate_request_packet(uint8_t *data, uint16_t length, const Packets_Array *recv_array)
{
    if (length == 0) {
        return -1;
    }

    data[0] = PACKET_ID_REQUEST;

    uint16_t cur_len = 1;

    if (recv_array->buffer_start == recv_array->buffer_end) {
        return cur_len;
    }

    if (length <= cur_len) {
        return cur_len;
    }

    uint32_t n = 1;

    for (uint32_t i = recv_array->buffer_start; i != recv_array->buffer_end; ++i) {
        const uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (recv_array->buffer[num] == nullptr) {
            data[cur_len] = n;
            n = 0;
            ++cur_len;

            if (length <= cur_len) {
                return cur_len;
            }
        } else if (n == 255) {
            data[cur_len] = 0;
            n = 0;
            ++cur_len;

            if (length <= cur_len) {
                return cur_len;
            }
        }

        ++n;
    }

    return cur_len;
}

/** @brief Handle a request data packet.
 * Remove all the packets the other received from the array.
 *
 * @retval -1 on failure.
 * @return number of requested packets on success.
 */
non_null()
static int handle_request_packet(const Memory *mem, Mono_Time *mono_time, Packets_Array *send_array,
                                 const uint8_t *data, uint16_t length,
                                 uint64_t *latest_send_time, uint64_t rtt_time)
{
    if (length == 0) {
        return -1;
    }

    if (data[0] != PACKET_ID_REQUEST) {
        return -1;
    }

    if (length == 1) {
        return 0;
    }

    ++data;
    --length;

    uint32_t n = 1;
    uint32_t requested = 0;

    const uint64_t temp_time = current_time_monotonic(mono_time);
    uint64_t l_sent_time = 0;

    for (uint32_t i = send_array->buffer_start; i != send_array->buffer_end; ++i) {
        if (length == 0) {
            break;
        }

        const uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (n == data[0]) {
            if (send_array->buffer[num] != nullptr) {
                const uint64_t sent_time = send_array->buffer[num]->sent_time;

                if ((sent_time + rtt_time) < temp_time) {
                    send_array->buffer[num]->sent_time = 0;
                }
            }

            ++data;
            --length;
            n = 0;
            ++requested;
        } else {
            if (send_array->buffer[num] != nullptr) {
                l_sent_time = max_u64(l_sent_time, send_array->buffer[num]->sent_time);

                mem_delete(mem, send_array->buffer[num]);
                send_array->buffer[num] = nullptr;
            }
        }

        if (n == 255) {
            n = 1;

            if (data[0] != 0) {
                return -1;
            }

            ++data;
            --length;
        } else {
            ++n;
        }
    }

    *latest_send_time = max_u64(*latest_send_time, l_sent_time);

    return requested;
}

/** END: Array Related functions */

#define MAX_DATA_DATA_PACKET_SIZE (MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE))

/** @brief Creates and sends a data packet to the peer using the fastest route. Currently only supports Noise (XChaCha20-Poly1305)
 * transport encryption.
 *
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int send_data_packet(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
    //TODO: remove
    // LOGGER_DEBUG(c->log, "ENTERING");

    const uint16_t max_length = MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE);

    if (length == 0 || length > max_length) {
        LOGGER_ERROR(c->log, "zero-length or too large data packet: %d (max: %d)", length, max_length);
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        LOGGER_ERROR(c->log, "connection id %d not found", crypt_connection_id);
        return -1;
    }

    pthread_mutex_lock(conn->mutex);
    const uint16_t packet_size = 1 + sizeof(uint16_t) + length + CRYPTO_MAC_SIZE;
    VLA(uint8_t, packet, packet_size);
    packet[0] = NET_PACKET_CRYPTO_DATA;
    memcpy(packet + 1, conn->sent_nonce + (CRYPTO_NONCE_SIZE - sizeof(uint16_t)), sizeof(uint16_t));

    //TODO: remove
    // char key[CRYPTO_SECRET_KEY_SIZE*2+1];
    // bytes2string(key, sizeof(key), conn->send_key, CRYPTO_SECRET_KEY_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "send_key: %s", key);
    // char nonce_print[CRYPTO_NONCE_SIZE*2+1];
    // bytes2string(nonce_print, sizeof(nonce_print), conn->sent_nonce, CRYPTO_NONCE_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "nonce: %s", nonce_print);

    //TODO: len was const
    int len = 0;
    if (conn->noise_handshake_enabled) { /* Case NoiseIK handshake */
        //TODO: add ad? only packet ID and last two bytes of nonce sent in plain
        int len = encrypt_data_symmetric_xaead(conn->send_key, conn->sent_nonce, data, length, packet + 1 + sizeof(uint16_t), nullptr, 0);
    } else { /* Case non-Noise handshake */
        int len = encrypt_data_symmetric(conn->shared_key, conn->sent_nonce, data, length, packet + 1 + sizeof(uint16_t));
    }
    

    if (len + 1 + sizeof(uint16_t) != packet_size) {
        LOGGER_ERROR(c->log, "encryption failed: %d", len);
        pthread_mutex_unlock(conn->mutex);
        return -1;
    }

    increment_nonce(conn->sent_nonce);
    pthread_mutex_unlock(conn->mutex);

    return send_packet_to(c, crypt_connection_id, packet, packet_size);
}

/** @brief Creates and sends a data packet with buffer_start and num to the peer using the fastest route.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int send_data_packet_helper(Net_Crypto *c, int crypt_connection_id, uint32_t buffer_start, uint32_t num,
                                   const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        LOGGER_ERROR(c->log, "zero-length or too large data packet: %d (max: %d)", length, MAX_CRYPTO_PACKET_SIZE);
        return -1;
    }

    num = net_htonl(num);
    buffer_start = net_htonl(buffer_start);
    const uint16_t padding_length = (MAX_CRYPTO_DATA_SIZE - length) % CRYPTO_MAX_PADDING;
    const uint16_t packet_size = sizeof(uint32_t) + sizeof(uint32_t) + padding_length + length;
    VLA(uint8_t, packet, packet_size);
    memcpy(packet, &buffer_start, sizeof(uint32_t));
    memcpy(packet + sizeof(uint32_t), &num, sizeof(uint32_t));
    memzero(packet + (sizeof(uint32_t) * 2), padding_length);
    memcpy(packet + (sizeof(uint32_t) * 2) + padding_length, data, length);

    return send_data_packet(c, crypt_connection_id, packet, packet_size);
}

non_null()
static int reset_max_speed_reached(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    /* If last packet send failed, try to send packet again.
     * If sending it fails we won't be able to send the new packet. */
    if (conn->maximum_speed_reached) {
        Packet_Data *dt = nullptr;
        const uint32_t packet_num = conn->send_array.buffer_end - 1;
        const int ret = get_data_pointer(&conn->send_array, &dt, packet_num);

        if (ret == 1 && dt->sent_time == 0) {
            if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num,
                                        dt->data, dt->length) != 0) {
                return -1;
            }

            dt->sent_time = current_time_monotonic(c->mono_time);
        }

        conn->maximum_speed_reached = false;
    }

    return 0;
}

/**
 * @retval -1 if data could not be put in packet queue.
 * @return positive packet number if data was put into the queue.
 */
non_null()
static int64_t send_lossless_packet(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length,
                                    bool congestion_control)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        LOGGER_ERROR(c->log, "rejecting too large (or empty) packet of size %d on crypt connection %d", length,
                     crypt_connection_id);
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    /* If last packet send failed, try to send packet again.
     * If sending it fails we won't be able to send the new packet. */
    reset_max_speed_reached(c, crypt_connection_id);

    if (conn->maximum_speed_reached && congestion_control) {
        LOGGER_INFO(c->log, "congestion control: maximum speed reached on crypt connection %d", crypt_connection_id);
        return -1;
    }

    Packet_Data dt;
    dt.sent_time = 0;
    dt.length = length;
    memcpy(dt.data, data, length);
    pthread_mutex_lock(conn->mutex);
    const int64_t packet_num = add_data_end_of_buffer(c->log, c->mem, &conn->send_array, &dt);
    pthread_mutex_unlock(conn->mutex);

    if (packet_num == -1) {
        return -1;
    }

    if (!congestion_control && conn->maximum_speed_reached) {
        return packet_num;
    }

    if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, data, length) == 0) {
        Packet_Data *dt1 = nullptr;

        if (get_data_pointer(&conn->send_array, &dt1, packet_num) == 1) {
            dt1->sent_time = current_time_monotonic(c->mono_time);
        }
    } else {
        conn->maximum_speed_reached = true;
        LOGGER_DEBUG(c->log, "send_data_packet failed (packet_num = %ld)", (long)packet_num);
    }

    return packet_num;
}

/**
 * @brief Get the lowest 2 bytes from the nonce and convert
 *   them to host byte format before returning them.
 */
non_null()
static uint16_t get_nonce_uint16(const uint8_t *nonce)
{
    uint16_t num;
    memcpy(&num, nonce + (CRYPTO_NONCE_SIZE - sizeof(uint16_t)), sizeof(uint16_t));
    return net_ntohs(num);
}

#define DATA_NUM_THRESHOLD 21845

/** @brief Handle a data packet.
 * Decrypt packet of length and put it into data.
 * data must be at least MAX_DATA_DATA_PACKET_SIZE big.
 * Currently only supports Noise (XChaCha20-Poly1305)
 * transport decryption.
 *
 *
 * @retval -1 on failure.
 * @return length of data on success.
 */
non_null()
static int handle_data_packet(const Net_Crypto *c, int crypt_connection_id, uint8_t *data, const uint8_t *packet,
                              uint16_t length)
{
    const uint16_t crypto_packet_overhead = 1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE;

    if (length <= crypto_packet_overhead || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(nonce, conn->recv_nonce, CRYPTO_NONCE_SIZE);
    const uint16_t num_cur_nonce = get_nonce_uint16(nonce);
    uint16_t num;
    net_unpack_u16(packet + 1, &num);
    const uint16_t diff = num - num_cur_nonce;
    increment_nonce_number(nonce, diff);

    //TODO: remove
    // char key[CRYPTO_SECRET_KEY_SIZE*2+1];
    // bytes2string(key, sizeof(key), conn->recv_key, CRYPTO_SECRET_KEY_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "recv_key: %s", key);
    // char nonce_print[CRYPTO_NONCE_SIZE*2+1];
    // bytes2string(nonce_print, sizeof(nonce_print), nonce, CRYPTO_NONCE_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "nonce: %s", nonce_print);

    //TODO: len was const
    int len = 0;
    if (conn->noise_handshake_enabled) { /* case NoiseIK handshake */
        //TODO: add ad? only packet ID and last two bytes of nonce sent in plain
        len = decrypt_data_symmetric_xaead(conn->recv_key, nonce, packet + 1 + sizeof(uint16_t), length - (1 + sizeof(uint16_t)), data,
                    nullptr, 0);
    } else { /* case non-Noise handshake */
        len = decrypt_data_symmetric(conn->shared_key, nonce, packet + 1 + sizeof(uint16_t),
                                           length - (1 + sizeof(uint16_t)), data);
    }

    

    //TODO: remove
    // LOGGER_DEBUG(c->log, "data packet decrypt len: %d", len);

    if ((unsigned int)len != length - crypto_packet_overhead) {
        return -1;
    }

    if (diff > DATA_NUM_THRESHOLD * 2) {
        increment_nonce_number(conn->recv_nonce, DATA_NUM_THRESHOLD);
    }

    return len;
}

/** @brief Send a request packet.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int send_request_packet(Net_Crypto *c, int crypt_connection_id)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t data[MAX_CRYPTO_DATA_SIZE];
    const int len = generate_request_packet(data, sizeof(data), &conn->recv_array);

    if (len == -1) {
        return -1;
    }

    return send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, conn->send_array.buffer_end, data,
                                   len);
}

/** @brief Send up to max num previously requested data packets.
 *
 * @retval -1 on failure.
 * @return number of packets sent on success.
 */
non_null()
static int send_requested_packets(Net_Crypto *c, int crypt_connection_id, uint32_t max_num)
{
    if (max_num == 0) {
        return -1;
    }

    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    const uint64_t temp_time = current_time_monotonic(c->mono_time);
    const uint32_t array_size = num_packets_array(&conn->send_array);
    uint32_t num_sent = 0;

    for (uint32_t i = 0; i < array_size; ++i) {
        Packet_Data *dt;
        const uint32_t packet_num = i + conn->send_array.buffer_start;
        const int ret = get_data_pointer(&conn->send_array, &dt, packet_num);

        if (ret == -1) {
            return -1;
        }

        if (ret == 0) {
            continue;
        }

        if (dt->sent_time != 0) {
            continue;
        }

        if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, dt->data,
                                    dt->length) == 0) {
            dt->sent_time = temp_time;
            ++num_sent;
        }

        if (num_sent >= max_num) {
            break;
        }
    }

    return num_sent;
}

/** @brief Add a new temp packet to send repeatedly.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int new_temp_packet(const Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t *temp_packet = (uint8_t *)mem_balloc(c->mem, length);

    if (temp_packet == nullptr) {
        return -1;
    }

    if (conn->temp_packet != nullptr) {
        mem_delete(c->mem, conn->temp_packet);
    }

    memcpy(temp_packet, packet, length);
    conn->temp_packet = temp_packet;
    conn->temp_packet_length = length;
    conn->temp_packet_sent_time = 0;
    //TODO: remove
    // LOGGER_DEBUG(c->log, "conn->temp_packet_sent_time = 0");
    conn->temp_packet_num_sent = 0;
    return 0;
}

/** @brief Clear the temp packet.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int clear_temp_packet(const Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (conn->temp_packet != nullptr) {
        mem_delete(c->mem, conn->temp_packet);
    }

    conn->temp_packet = nullptr;
    conn->temp_packet_length = 0;
    conn->temp_packet_sent_time = 0;
    conn->temp_packet_num_sent = 0;
    return 0;
}

/** @brief Send the temp packet.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int send_temp_packet(Net_Crypto *c, int crypt_connection_id)
{
    //TODO: remove
    // LOGGER_DEBUG(c->log, "ENTERING");

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (conn->temp_packet == nullptr) {
        return -1;
    }

    if (send_packet_to(c, crypt_connection_id, conn->temp_packet, conn->temp_packet_length) != 0) {
        return -1;
    }

    conn->temp_packet_sent_time = current_time_monotonic(c->mono_time);
    // LOGGER_DEBUG(c->log, "conn->temp_packet_sent_time: %lu", conn->temp_packet_sent_time);
    ++conn->temp_packet_num_sent;
    return 0;
}

/** @brief Create a handshake packet and set it as a temp packet. Currently supports non-Noise and
 * Noise-based handshake.
 * @param cookie must be COOKIE_LENGTH.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int create_send_handshake(Net_Crypto *c, int crypt_connection_id, const uint8_t *cookie,
                                 const uint8_t *dht_public_key)
{
    LOGGER_DEBUG(c->log, "ENTERING");

    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        //TODO: remove
        // LOGGER_DEBUG(c->log, "nullptr");
        return -1;
    }

    LOGGER_DEBUG(c->log, "conn->noise_handshake->initiator: %d", conn->noise_handshake->initiator);

    /* Noise-based handshake */
    if (conn->noise_handshake_enabled && conn->noise_handshake != nullptr) {
        if (conn->noise_handshake->initiator) {
            uint8_t handshake_packet[NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR];

            if (create_crypto_handshake(c, handshake_packet, cookie, conn->sent_nonce, conn->sessionsecret_key, conn->sessionpublic_key,
                                        conn->public_key, dht_public_key, conn->noise_handshake) != sizeof(handshake_packet)) {
                return -1;
            }

            if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0) {
                return -1;
            }
        }
        /* Noise RESPONDER */
        else {
            uint8_t handshake_packet[NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER];

            if (create_crypto_handshake(c, handshake_packet, cookie, conn->sent_nonce, conn->sessionsecret_key, conn->sessionpublic_key,
                                        conn->public_key, dht_public_key, conn->noise_handshake) != sizeof(handshake_packet)) {
                return -1;
            }

            if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0) {
                return -1;
            }
        }
    }
    /* non-Noise handshake*/
    else {
        uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH];

        /* ephemeral_private and noise_handshake not necessary for old handshake */
        if (create_crypto_handshake(c, handshake_packet, cookie, conn->sent_nonce, nullptr, conn->sessionpublic_key,
                                    conn->public_key, dht_public_key, nullptr) != sizeof(handshake_packet)) {
            return -1;
        }

        if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0) {
            return -1;
        }
    }

    send_temp_packet(c, crypt_connection_id);
    return 0;
}

/** @brief Send a kill packet.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int send_kill_packet(Net_Crypto *c, int crypt_connection_id)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    const uint8_t kill_packet[1] = {PACKET_ID_KILL};

    //TODO: remove
    LOGGER_DEBUG(c->log, "KILL PACKET");

    return send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, conn->send_array.buffer_end,
                                   kill_packet, sizeof(kill_packet));
}

non_null(1) nullable(3)
static void connection_kill(Net_Crypto *c, int crypt_connection_id, void *userdata)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    //TODO: remove
    LOGGER_DEBUG(c->log, "CONNECTION KILL");

    if (conn == nullptr) {
        return;
    }

    if (conn->connection_status_callback != nullptr) {
        conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id,
                                         false, userdata);
    }

    while (true) { /* TODO(irungentoo): is this really the best way to do this? */
        pthread_mutex_lock(&c->connections_mutex);

        if (c->connection_use_counter == 0) {
            break;
        }

        pthread_mutex_unlock(&c->connections_mutex);
    }

    crypto_kill(c, crypt_connection_id);
    pthread_mutex_unlock(&c->connections_mutex);
}

/** @brief Handle a received data packet.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null(1, 3) nullable(6)
static int handle_data_packet_core(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                   bool udp, void *userdata)
{
    LOGGER_DEBUG(c->log, "ENTERING: PACKET: %d", packet[0]);

    if (length > MAX_CRYPTO_PACKET_SIZE || length <= CRYPTO_DATA_PACKET_MIN_SIZE) {
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    uint8_t data[MAX_DATA_DATA_PACKET_SIZE];
    const int len = handle_data_packet(c, crypt_connection_id, data, packet, length);

    if (len <= (int)(sizeof(uint32_t) * 2)) {
        LOGGER_DEBUG(c->log, "connection_kill() because data packet decryption failure, crypt_connection_id: %d", crypt_connection_id);
        //TODO: unwanted side effects? leave here?
        connection_kill(c, crypt_connection_id, userdata);
        return -1;
    }

    uint32_t buffer_start;
    uint32_t num;
    memcpy(&buffer_start, data, sizeof(uint32_t));
    memcpy(&num, data + sizeof(uint32_t), sizeof(uint32_t));
    buffer_start = net_ntohl(buffer_start);
    num = net_ntohl(num);

    uint64_t rtt_calc_time = 0;

    if (buffer_start != conn->send_array.buffer_start) {
        Packet_Data *packet_time;

        if (get_data_pointer(&conn->send_array, &packet_time, conn->send_array.buffer_start) == 1) {
            rtt_calc_time = packet_time->sent_time;
        }

        if (clear_buffer_until(c->mem, &conn->send_array, buffer_start) != 0) {
            return -1;
        }
    }

    const uint8_t *real_data = data + (sizeof(uint32_t) * 2);
    uint16_t real_length = len - (sizeof(uint32_t) * 2);

    //TODO: remove
    // LOGGER_DEBUG(c->log, "DATA ID: %d", real_data[0]);

    while (real_data[0] == 0) { /* Remove Padding */
        ++real_data;
        --real_length;

        if (real_length == 0) {
            return -1;
        }
    }

    //TODO: remove
    // LOGGER_DEBUG(c->log, "DATA ID after PADDING: %d", real_data[0]);

    if (real_data[0] == PACKET_ID_KILL) {
        LOGGER_DEBUG(c->log, "KILL PACKET RECEIVED");
        connection_kill(c, crypt_connection_id, userdata);
        return 0;
    }

    if (conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
        clear_temp_packet(c, crypt_connection_id);
        conn->status = CRYPTO_CONN_ESTABLISHED;

        LOGGER_DEBUG(c->log, "CRYPTO_CONN_ESTABLISHED");

        //Noise: noise_handshake not necessary anymore => memzero and free
        crypto_memzero(conn->noise_handshake, sizeof(Noise_Handshake));
        mem_delete(c->mem, conn->noise_handshake);
        conn->noise_handshake = nullptr;
        //TODO: non-Noise: also crypto_memzero() values from conn?

        if (conn->connection_status_callback != nullptr) {
            conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id,
                                             true, userdata);
        }
    }

    if (real_data[0] == PACKET_ID_REQUEST) {
        uint64_t rtt_time;

        if (udp) {
            rtt_time = conn->rtt_time;
        } else {
            rtt_time = DEFAULT_TCP_PING_CONNECTION;
        }

        const int requested = handle_request_packet(c->mem, c->mono_time, &conn->send_array, real_data, real_length, &rtt_calc_time, rtt_time);

        if (requested == -1) {
            return -1;
        }

        set_buffer_end(&conn->recv_array, num);
    } else if (real_data[0] >= PACKET_ID_RANGE_LOSSLESS_START && real_data[0] <= PACKET_ID_RANGE_LOSSLESS_END) {
        Packet_Data dt = {0};
        dt.length = real_length;
        memcpy(dt.data, real_data, real_length);

        if (add_data_to_buffer(c->mem, &conn->recv_array, num, &dt) != 0) {
            return -1;
        }

        while (true) {
            pthread_mutex_lock(conn->mutex);
            const int ret = read_data_beg_buffer(c->mem, &conn->recv_array, &dt);
            pthread_mutex_unlock(conn->mutex);

            if (ret == -1) {
                break;
            }

            if (conn->connection_data_callback != nullptr) {
                conn->connection_data_callback(conn->connection_data_callback_object, conn->connection_data_callback_id, dt.data,
                                               dt.length, userdata);
            }

            /* conn might get killed in callback. */
            conn = get_crypto_connection(c, crypt_connection_id);

            if (conn == nullptr) {
                return -1;
            }
        }

        /* Packet counter. */
        ++conn->packet_counter;
    } else if (real_data[0] >= PACKET_ID_RANGE_LOSSY_START && real_data[0] <= PACKET_ID_RANGE_LOSSY_END) {

        set_buffer_end(&conn->recv_array, num);

        if (conn->connection_lossy_data_callback != nullptr) {
            conn->connection_lossy_data_callback(conn->connection_lossy_data_callback_object,
                                                 conn->connection_lossy_data_callback_id, real_data, real_length, userdata);
        }
    } else {
        return -1;
    }

    if (rtt_calc_time != 0) {
        const uint64_t rtt_time = current_time_monotonic(c->mono_time) - rtt_calc_time;

        if (rtt_time < conn->rtt_time) {
            conn->rtt_time = rtt_time;
        }
    }

    return 0;
}

non_null()
/**
 * @brief Handles a cookie response packet. Currently supports non-Noise and Noise-bashed handshake.
 *
 * @return -1 in case of failure
 * @return 0 if cookie response handled successfully
 */
static int handle_packet_cookie_response(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    LOGGER_DEBUG(c->log, "ENTERING: crypto_connection_id: %d => PACKET: %d => CRYPTO CONN STATE: %d",
                 crypt_connection_id,
                 packet[0],
                 conn->status);

    if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING) {
        return -1;
    }

    uint8_t cookie[COOKIE_LENGTH];
    uint64_t number;

    if (handle_cookie_response(cookie, &number, packet, length, conn->shared_key) != sizeof(cookie)) {
        return -1;
    }

    if (number != conn->cookie_request_number) {
        return -1;
    }

    // Noise: only necessary if Cookie response was successful
    if (conn->noise_handshake_enabled && noise_handshake_init(c->log, conn->noise_handshake, c->self_secret_key, conn->public_key, true) != 0) {
        return -1;
    }

    if (conn->noise_handshake != nullptr) {
        if (conn->noise_handshake->initiator) {
            LOGGER_DEBUG(c->log, "INITIATOR -> NOISE Handshake");
            if (create_send_handshake(c, crypt_connection_id, cookie, conn->dht_public_key) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
    } else {
        /* non-Noise handshake */
        LOGGER_DEBUG(c->log, "non-Noise Handshake");
        if (create_send_handshake(c, crypt_connection_id, cookie, conn->dht_public_key) != 0) {
            return -1;
        }
    }

    conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
    return 0;
}

non_null(1, 3) nullable(5)
/**
 * @brief Handles receive handshake packets. Currently supports non-Noise and Noise-based handshake.
 *
 * @return -1 in case of failure
 * @return 0 if successful
 */
static int handle_packet_crypto_hs(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                   void *userdata)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    LOGGER_DEBUG(c->log, "ENTERING: crypt_connection_id: %d | PACKET: %d | CRYPTO CONN STATE: %d",
                 crypt_connection_id,
                 packet[0],
                 conn->status);

    //TODO: what if I remove CRYPTO_CONN_NOT_CONFIRMED from here? => doesn't work together with connection_kill() after decrypting failure (after new handshake)
    if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING
            && conn->status != CRYPTO_CONN_HANDSHAKE_SENT
            && conn->status != CRYPTO_CONN_NOT_CONFIRMED) {
        return -1;
    }
    //TODO: unwanted side effects? => yes, see above
    // if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING
    //         && conn->status != CRYPTO_CONN_HANDSHAKE_SENT) {
    //     return -1;
    // }

    // necessary for Noise and non-Noise
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    // necessary for Noise RESPONDER and non-Noise
    uint8_t cookie[COOKIE_LENGTH];

    //TODO: via noise_handshake struct? TODO: remove
    // bool initiator_change = false;

    if (length == HANDSHAKE_PACKET_LENGTH) {
        conn->noise_handshake_enabled = false;
        //TODO: Wipe noise_handshake etc. in this case?
    }

    if (conn->noise_handshake_enabled && conn->noise_handshake != nullptr) {
        LOGGER_DEBUG(c->log, "NOISE HANDHSHAKE");
        if (conn->noise_handshake->initiator) {
            if (length == NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER) {
                LOGGER_DEBUG(c->log, "INITIATOR: NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER");
                //TODO: fails if peer receives two handshake packets.. check for send_key/recv_key?
                if (!handle_crypto_handshake(c, conn->recv_nonce, nullptr, nullptr, dht_public_key, nullptr,
                                             packet, length, conn->public_key, conn->noise_handshake)) {
                    return -1;
                }
            } else if (length == NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR) {
                LOGGER_DEBUG(c->log, "INITIATOR: CHANGED TO RESPONDER");
                if (noise_handshake_init(c->log, conn->noise_handshake, c->self_secret_key, nullptr, false) != 0) {
                    return -1;
                }

                /* Noise: peer_real_pk (=conn->public_key) not necessary here, but for call in handle_new_connection_handshake()
                    -> otherwise not working (call via friend_connection.c) */
                if (!handle_crypto_handshake(c, conn->recv_nonce, nullptr, conn->public_key, dht_public_key, cookie,
                                             packet, length, nullptr, conn->noise_handshake)) {
                    return -1;
                }

                //TODO: remove
                // char ck_print[CRYPTO_SHA512_SIZE*2+1];
                // bytes2string(ck_print, sizeof(ck_print), conn->noise_handshake->chaining_key, CRYPTO_SHA512_SIZE, c->log);
                // LOGGER_DEBUG(c->log, "ck: %s", ck_print);

                // initiator_change = true;

                /* RESPONDER needs to send handshake packet, afterwards finished */
                if (create_send_handshake(c, crypt_connection_id, cookie, dht_public_key) != 0) {
                    return -1;
                }
                //TODO: here?
                conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
            } else {
                return -1;
            }
        }
        //TODO: Differentiate between change and not change? if not changed, no call to noise_handshake_init() necessary => TODO: need info in conn or noise_handshake
        /* Case where RESPONDER with and without change from INITIATOR */
        else {
            if (length == NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR) {
                LOGGER_DEBUG(c->log, "RESPONDER: NOISE_HANDSHAKE_PACKET_LENGTH_INITIATOR");
                /* necessary, otherwise broken after INITIATOR to RESPONDER change */
                if (noise_handshake_init(c->log, conn->noise_handshake, c->self_secret_key, nullptr, false) != 0) {
                    return false;
                }
                /* Noise: peer_real_pk (=conn->public_key) not necessary here, but for call in handle_new_connection_handshake()
                    -> otherwise not working (call via friend_connection.c) */
                if (!handle_crypto_handshake(c, conn->recv_nonce, nullptr, conn->public_key, dht_public_key, cookie,
                                             packet, length, nullptr, conn->noise_handshake)) {
                    return -1;
                }
                /* RESPONDER needs to send handshake packet, afterwards finished */
                if (create_send_handshake(c, crypt_connection_id, cookie, dht_public_key) != 0) {
                    return -1;
                }
                //TODO: here?
                conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
            } else if (length == NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER) {
                LOGGER_DEBUG(c->log, "RESPONDER: NOISE_HANDSHAKE_PACKET_LENGTH_RESPONDER");
                /* cannot chagne to INITIATOR here, connection broken */
                //TODO: leave here?
                connection_kill(c, crypt_connection_id, userdata);
                return -1;
            }
        }
    }
    /* non-Noise handshake */
    else {
        LOGGER_DEBUG(c->log, "handle_packet_crypto_hs() => non-Noise HANDHSHAKE");
        // necessary only for non-Noise
        uint8_t peer_real_pk[CRYPTO_PUBLIC_KEY_SIZE];
        if (!handle_crypto_handshake(c, conn->recv_nonce, conn->peersessionpublic_key, peer_real_pk, dht_public_key, cookie,
                                     packet, length, conn->public_key, nullptr)) {
            return -1;
        }
    }

    if (pk_equal(dht_public_key, conn->dht_public_key)) {

        LOGGER_DEBUG(c->log, "Crypto Conn Status: %d", conn->status);

        if (conn->noise_handshake_enabled && conn->noise_handshake != nullptr) {
            LOGGER_DEBUG(c->log, "NOISE HANDHSHAKE");
            conn->status = CRYPTO_CONN_NOT_CONFIRMED;
            if (conn->noise_handshake->initiator) {
                //TODO: remove
                // char ck_print[CRYPTO_SHA512_SIZE*2+1];
                // bytes2string(ck_print, sizeof(ck_print), conn->noise_handshake->chaining_key, CRYPTO_SHA512_SIZE, c->log);
                // LOGGER_DEBUG(c->log, "ck: %s", ck_print);

                /* INITIATOR Noise Split(), nonces already set in crypto connection */
                crypto_hkdf(conn->send_key, conn->recv_key, nullptr, CRYPTO_SYMMETRIC_KEY_SIZE, CRYPTO_SYMMETRIC_KEY_SIZE, 0, conn->noise_handshake->chaining_key);
                LOGGER_DEBUG(c->log, "INITIATOR: After Noise Split()");

                //TODO: remove
                // char key[CRYPTO_SECRET_KEY_SIZE*2+1];
                // bytes2string(key, sizeof(key), conn->send_key, CRYPTO_SECRET_KEY_SIZE, c->log);
                // LOGGER_DEBUG(c->log, "send_key: %s", key);
                // bytes2string(key, sizeof(key), conn->recv_key, CRYPTO_SECRET_KEY_SIZE, c->log);
                // LOGGER_DEBUG(c->log, "recv_key: %s", key);
            }
            /* Noise RESPONDER */
            else {
                /* RESPONDER Noise Split(): vice-verse keys in comparison to initiator */
                crypto_hkdf(conn->recv_key, conn->send_key, nullptr, CRYPTO_SYMMETRIC_KEY_SIZE, CRYPTO_SYMMETRIC_KEY_SIZE, 0, conn->noise_handshake->chaining_key);
                //TODO: remove
                LOGGER_DEBUG(c->log, "RESPONDER: After Noise Split()");
            }
        }
        /* Backwards compatibility: non-Noise handshake case */
        else {
            if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
                if (create_send_handshake(c, crypt_connection_id, cookie, dht_public_key) != 0) {
                    return -1;
                }
            }
            /* Backwards compatibility: necessary for non-Noise handshake */ 
            encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);
            //TODO: why here and not before? => set before, in case of dht_pk_callback there is a new crypto connection created anyway
            /* Backwards compatibility: necessary for non-Noise handshake */ 
            conn->status = CRYPTO_CONN_NOT_CONFIRMED;
        }
    } else {
        if (conn->dht_pk_callback != nullptr) {
            conn->dht_pk_callback(conn->dht_pk_callback_object, conn->dht_pk_callback_number, dht_public_key, userdata);
        }
    }

    return 0;
}

non_null(1, 3) nullable(6)
static int handle_packet_crypto_data(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                     bool udp, void *userdata)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    //TODO: remove from prod code
    LOGGER_DEBUG(c->log, "ENTERING: PACKET: %d | CRYPTO CONN STATE: %d",
                 packet[0],
                 conn->status);


    if (conn->status != CRYPTO_CONN_NOT_CONFIRMED && conn->status != CRYPTO_CONN_ESTABLISHED) {
        return -1;
    }

    return handle_data_packet_core(c, crypt_connection_id, packet, length, udp, userdata);
}

/** @brief Handle a packet that was received for the connection.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null(1, 3) nullable(6)
static int handle_packet_connection(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                    bool udp, void *userdata)
{
    //TODO: remove from prod code
    LOGGER_DEBUG(c->log, "ENTERING: PACKET: %d", packet[0]);

    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    switch (packet[0]) {
        case NET_PACKET_COOKIE_RESPONSE:
            return handle_packet_cookie_response(c, crypt_connection_id, packet, length);

        case NET_PACKET_CRYPTO_HS:
            return handle_packet_crypto_hs(c, crypt_connection_id, packet, length, userdata);

        case NET_PACKET_CRYPTO_DATA:
            return handle_packet_crypto_data(c, crypt_connection_id, packet, length, udp, userdata);

        default:
            return -1;
    }
}

/** @brief Set the size of the friend list to numfriends.
 *
 * @retval -1 if mem_vrealloc fails.
 * @retval 0 if it succeeds.
 */
non_null()
static int realloc_cryptoconnection(Net_Crypto *c, uint32_t num)
{
    //TODO: remove
    // LOGGER_DEBUG(c->log, "ENTERING: NUM: %d", num);

    if (num == 0) {
        mem_delete(c->mem, c->crypto_connections);
        c->crypto_connections = nullptr;
        //TODO: remove
        // LOGGER_DEBUG(c->log, "FREE crypto_connections");
        return 0;
    }

    Crypto_Connection *newcrypto_connections = (Crypto_Connection *)mem_vrealloc(
                c->mem, c->crypto_connections, num, sizeof(Crypto_Connection));

    if (newcrypto_connections == nullptr) {
        return -1;
    }

    c->crypto_connections = newcrypto_connections;

    //TODO: remove
    // LOGGER_DEBUG(c->log, "END: realloc done");
    return 0;
}

/** @brief Create a new empty crypto connection.
 *
 * @retval -1 on failure.
 * @return connection id on success.
 */
non_null()
static int create_crypto_connection(Net_Crypto *c)
{
    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    while (true) { /* TODO(irungentoo): is this really the best way to do this? */
        pthread_mutex_lock(&c->connections_mutex);

        if (c->connection_use_counter == 0) {
            break;
        }

        pthread_mutex_unlock(&c->connections_mutex);
    }

    int id = -1;

    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_FREE) {
            id = i;
            //TODO: remove
            LOGGER_DEBUG(c->log, "NO realloc");
            break;
        }
    }

    if (id == -1) {
        if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == 0) {
            id = c->crypto_connections_length;
            ++c->crypto_connections_length;
            c->crypto_connections[id] = empty_crypto_connection;
            //TODO: remove
            LOGGER_DEBUG(c->log, "DONE realloc");
        }
    }

    if (id != -1) {
        pthread_mutex_t *mutex = (pthread_mutex_t *)mem_alloc(c->mem, sizeof(pthread_mutex_t));

        if (mutex == nullptr) {
            pthread_mutex_unlock(&c->connections_mutex);
            return -1;
        }

        if (pthread_mutex_init(mutex, nullptr) != 0) {
            mem_delete(c->mem, mutex);
            pthread_mutex_unlock(&c->connections_mutex);
            return -1;
        }

        // Memsetting float/double to 0 is non-portable, so we explicitly set them to 0
        c->crypto_connections[id].packet_recv_rate = 0.0;
        c->crypto_connections[id].packet_send_rate = 0.0;
        c->crypto_connections[id].last_packets_left_rem = 0.0;
        c->crypto_connections[id].packet_send_rate_requested = 0.0;
        c->crypto_connections[id].last_packets_left_requested_rem = 0.0;
        c->crypto_connections[id].mutex = mutex;
        c->crypto_connections[id].status = CRYPTO_CONN_NO_CONNECTION;
    }

    if (c->crypto_connections[id].mutex == nullptr) {
        LOGGER_ERROR(c->log, "failed to alloc mutex");
        pthread_mutex_unlock(&c->connections_mutex);
        return -1;
    }

    if (pthread_mutex_init(c->crypto_connections[id].mutex, nullptr) != 0) {
        mem_delete(c->mem, c->crypto_connections[id].mutex);
        pthread_mutex_unlock(&c->connections_mutex);
        return -1;
    }

    c->crypto_connections[id].noise_handshake = (Noise_Handshake *) mem_alloc(c->mem, sizeof(Noise_Handshake));

    if (c->crypto_connections[id].noise_handshake == nullptr) {
        LOGGER_ERROR(c->log, "failed to alloc noise_handshake");
        mem_delete(c->mem, c->crypto_connections[id].mutex);
        pthread_mutex_unlock(&c->connections_mutex);
        return  -1;
    }

    //TODO: Remove
    // c->crypto_connections[id].handshake_send_interval = CRYPTO_SEND_PACKET_INTERVAL + (rand() % 800);
    // LOGGER_DEBUG(c->log, "handshake_send_interval: %d", c->crypto_connections[id].handshake_send_interval);

    c->crypto_connections[id].status = CRYPTO_CONN_NO_CONNECTION;

    pthread_mutex_unlock(&c->connections_mutex);
    return id;
}

/** @brief Wipe a crypto connection.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int wipe_crypto_connection(Net_Crypto *c, int crypt_connection_id)
{
    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    if ((uint32_t)crypt_connection_id >= c->crypto_connections_length) {
        return -1;
    }

    if (c->crypto_connections == nullptr) {
        return -1;
    }

    const Crypto_Conn_State status = c->crypto_connections[crypt_connection_id].status;

    if (status == CRYPTO_CONN_FREE) {
        return -1;
    }

    LOGGER_DEBUG(c->log, "valid id provided, free()'ing");

    uint32_t i;

    pthread_mutex_destroy(c->crypto_connections[crypt_connection_id].mutex);
    mem_delete(c->mem, c->crypto_connections[crypt_connection_id].mutex);

    /* Noise: necessary for backwards compatibility and because after CRYPTO_CONN_ESTABLISHED noise_handshake is already memzeroed/freed */
    if (c->crypto_connections[crypt_connection_id].noise_handshake != nullptr) {
        crypto_memzero(c->crypto_connections[crypt_connection_id].noise_handshake, sizeof(Noise_Handshake));
        mem_delete(c->mem, c->crypto_connections[crypt_connection_id].noise_handshake);
        c->crypto_connections[crypt_connection_id].noise_handshake = nullptr;
    }

    crypto_memzero(&c->crypto_connections[crypt_connection_id], sizeof(Crypto_Connection));

    /* check if we can resize the connections array */
    for (i = c->crypto_connections_length; i != 0; --i) {
        if (c->crypto_connections[i - 1].status != CRYPTO_CONN_FREE) {
            break;
        }
    }

    if (c->crypto_connections_length != i) {
        c->crypto_connections_length = i;
        realloc_cryptoconnection(c, c->crypto_connections_length);
    }

    return 0;
}

/** @brief Get crypto connection id from public key of peer.
 *
 * @retval -1 if there are no connections like we are looking for.
 * @return id if it found it.
 */
non_null()
static int getcryptconnection_id(const Net_Crypto *c, const uint8_t *public_key)
{
    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        if (!crypt_connection_id_is_valid(c, i)) {
            continue;
        }

        if (pk_equal(public_key, c->crypto_connections[i].public_key)) {
            return i;
        }
    }

    return -1;
}

/** @brief Add a source to the crypto connection.
 * This is to be used only when we have received a packet from that source.
 *
 * @retval -1 on failure.
 * @retval 0 if source was a direct UDP connection.
 * @return positive number on success.
 */
non_null()
static int crypto_connection_add_source(Net_Crypto *c, int crypt_connection_id, const IP_Port *source)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (net_family_is_ipv4(source->ip.family) || net_family_is_ipv6(source->ip.family)) {
        if (add_ip_port_connection(c, crypt_connection_id, source) != 0) {
            return -1;
        }

        if (net_family_is_ipv4(source->ip.family)) {
            conn->direct_lastrecv_timev4 = mono_time_get(c->mono_time);
        } else {
            conn->direct_lastrecv_timev6 = mono_time_get(c->mono_time);
        }

        return 0;
    }

    unsigned int tcp_connections_number;

    if (ip_port_to_tcp_connections_number(source, &tcp_connections_number)) {
        if (add_tcp_number_relay_connection(c->tcp_c, conn->connection_number_tcp, tcp_connections_number) == 0) {
            return 1;
        }
    }

    return -1;
}

/** @brief Set function to be called when someone requests a new connection to us.
 *
 * The set function should return -1 on failure and 0 on success.
 *
 * n_c is only valid for the duration of the function call.
 */
void new_connection_handler(Net_Crypto *c, new_connection_cb *new_connection_callback, void *object)
{
    c->new_connection_callback = new_connection_callback;
    c->new_connection_callback_object = object;
}

/** @brief Handle a handshake packet by someone who wants to initiate a new connection with us.
 * This calls the callback set by `new_connection_handler()` if the handshake is ok.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null(1, 2, 3) nullable(5)
static int handle_new_connection_handshake(Net_Crypto *c, const IP_Port *source, const uint8_t *data, uint16_t length,
        void *userdata)
{
    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    uint8_t *cookie = (uint8_t *)mem_balloc(c->mem, COOKIE_LENGTH);

    if (cookie == nullptr) {
        return -1;
    }

    New_Connection n_c = {{{{0}}}};
    n_c.cookie = cookie;
    n_c.source = *source;
    n_c.cookie_length = COOKIE_LENGTH;


    /* Backwards comptability: Differention between non-Noise and Noise-based handshake based on received HS packet length */ 
    if (length != HANDSHAKE_PACKET_LENGTH) {
        //TODO: adapt static allocation?
        n_c.noise_handshake = &n_c.noise_handshake_data;    
        if (noise_handshake_init(nullptr, n_c.noise_handshake, c->self_secret_key, nullptr, false) != 0) {
            crypto_memzero(n_c.noise_handshake, sizeof(Noise_Handshake));
            n_c.noise_handshake = nullptr;
            mem_delete(c->mem, n_c.cookie);
            return -1;
        }

        //TODO: remove
        LOGGER_DEBUG(c->log, "RESPONDER: After Handshake init");

        /* Noise: peer_real_pk (=n_c.public_key) not necessary for Noise, but need to include -> otherwise not working (call via friend_connection.c) */
        if (!handle_crypto_handshake(c, n_c.recv_nonce, nullptr, n_c.public_key, n_c.dht_public_key,
                                     n_c.cookie, data, length, nullptr, n_c.noise_handshake)) {
            crypto_memzero(n_c.noise_handshake, sizeof(Noise_Handshake));
            n_c.noise_handshake = nullptr;
            mem_delete(c->mem, n_c.cookie);
            return -1;
        }
    } else { /* case non-Noise handshake */
        // Necessary for backwards compatibility
        n_c.noise_handshake = nullptr;
        if (!handle_crypto_handshake(c, n_c.recv_nonce, n_c.peersessionpublic_key, n_c.public_key, n_c.dht_public_key,
                                     n_c.cookie, data, length, nullptr, nullptr)) {
            mem_delete(c->mem, n_c.cookie);
            return -1;
        }
    }

    //TODO: remove
    // char log_spub[CRYPTO_PUBLIC_KEY_SIZE*2+1];
    // bytes2string(log_spub, sizeof(log_spub), n_c.peersessionpublic_key, CRYPTO_PUBLIC_KEY_SIZE, c->log);
    // LOGGER_DEBUG(c->log, "RESPONDER: session pub: %s", log_spub);
    // char log_cookie[COOKIE_LENGTH*2+1];
    // bytes2string(log_cookie, sizeof(log_cookie), n_c.cookie, COOKIE_LENGTH, c->log);
    // LOGGER_DEBUG(c->log, "RESPONDER: cookie: %s", log_cookie);

    const int crypt_connection_id = getcryptconnection_id(c, n_c.public_key);

    //TODO: This is only called if new_crypto_connection() was already called in the meantime! Now RESPONDER!
    //TODO: Does it make sense to handle this case for NoiseIK handshake?
    if (crypt_connection_id != -1) {
        LOGGER_DEBUG(c->log, "RESPONDER: CRYPTO CONN EXISTING");
        Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

        if (conn == nullptr) {
            return -1;
        }

        if (!pk_equal(n_c.dht_public_key, conn->dht_public_key)) {
            connection_kill(c, crypt_connection_id, userdata);
        } else  if(length != HANDSHAKE_PACKET_LENGTH) { /* case NoiseIK handshake */
            conn->noise_handshake_enabled = true;
            if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING && conn->status != CRYPTO_CONN_HANDSHAKE_SENT) {
                mem_delete(c->mem, n_c.cookie);
                return -1;
            }
            /* there is already something in conn->noise_handshake -> necessary to memzero in this case! */
            crypto_memzero(conn->noise_handshake, sizeof(Noise_Handshake));
            memcpy(conn->noise_handshake, n_c.noise_handshake, sizeof(Noise_Handshake));

            memcpy(conn->recv_nonce, n_c.recv_nonce, CRYPTO_NONCE_SIZE);
            /* unnecessary for Noise */
            // memcpy(conn->peersessionpublic_key, n_c.peersessionpublic_key, CRYPTO_PUBLIC_KEY_SIZE);

            crypto_connection_add_source(c, crypt_connection_id, source);


            if (create_send_handshake(c, crypt_connection_id, n_c.cookie, n_c.dht_public_key) != 0) {
                mem_delete(c->mem, n_c.cookie);
                return -1;
            }

            conn->status = CRYPTO_CONN_NOT_CONFIRMED;

            /* RESPONDER Noise Split(): vice-verse keys in comparison to initiator */
            //TODO: remove here?
            crypto_hkdf(conn->recv_key, conn->send_key, nullptr, CRYPTO_SYMMETRIC_KEY_SIZE, CRYPTO_SYMMETRIC_KEY_SIZE, 0, conn->noise_handshake->chaining_key);
            //TODO: remove
            LOGGER_DEBUG(c->log, "RESPONDER: After Noise Split()");

            crypto_memzero(n_c.noise_handshake, sizeof(Noise_Handshake));
            n_c.noise_handshake = nullptr;

            mem_delete(c->mem, n_c.cookie);
            return 0;
        } else { /* case non-Noise handshake */
            conn->noise_handshake_enabled = false;
            if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING && conn->status != CRYPTO_CONN_HANDSHAKE_SENT) {
                mem_delete(c->mem, n_c.cookie);
                return -1;
            }

            memcpy(conn->recv_nonce, n_c.recv_nonce, CRYPTO_NONCE_SIZE);
            memcpy(conn->peersessionpublic_key, n_c.peersessionpublic_key, CRYPTO_PUBLIC_KEY_SIZE);
            encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

            crypto_connection_add_source(c, crypt_connection_id, source);

            if (create_send_handshake(c, crypt_connection_id, n_c.cookie, n_c.dht_public_key) != 0) {
                mem_delete(c->mem, n_c.cookie);
                return -1;
            }

            conn->status = CRYPTO_CONN_NOT_CONFIRMED;
            mem_delete(c->mem, n_c.cookie);
            return 0;
        }
    }

    const int ret = c->new_connection_callback(c->new_connection_callback_object, &n_c);
    mem_delete(c->mem, n_c.cookie);
    LOGGER_DEBUG(c->log, "ret (!= 0?): %d", ret);
    return ret;
}

/** @brief Accept a crypto connection. Currently supports non-Noise and Noise-based handshake.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int accept_crypto_connection(Net_Crypto *c, const New_Connection *n_c)
{

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    if (getcryptconnection_id(c, n_c->public_key) != -1) {
        //TODO: remove
        LOGGER_DEBUG(c->log, "RESPONDER: Crypto Connection already exists");
        return -1;
    }

    const int crypt_connection_id = create_crypto_connection(c);

    //TODO: remove
    //TODO: Print pub key of peer?
    LOGGER_DEBUG(c->log, "RESPONDER: AFTER: create_crypto_connection() => crypt_connection_id: %d", crypt_connection_id);

    if (crypt_connection_id == -1) {
        LOGGER_ERROR(c->log, "Could not create new crypto connection");
        return -1;
    }

    Crypto_Connection *conn = &c->crypto_connections[crypt_connection_id];

    if (n_c->cookie_length != COOKIE_LENGTH) {
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    pthread_mutex_lock(&c->tcp_mutex);
    const int connection_number_tcp = new_tcp_connection_to(c->tcp_c, n_c->dht_public_key, crypt_connection_id);
    pthread_mutex_unlock(&c->tcp_mutex);

    if (connection_number_tcp == -1) {
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    conn->connection_number_tcp = connection_number_tcp;

    // NoiseIK: only happening for RESPONDER
    if (n_c->noise_handshake != nullptr) {
        if (!n_c->noise_handshake->initiator) {
            //TODO: remove
            LOGGER_DEBUG(c->log, "Responder: Noise WriteMessage");
            memcpy(conn->noise_handshake, n_c->noise_handshake, sizeof(Noise_Handshake));

            //NOT possible here, need content afterwards!
            // crypto_memzero(n_c->noise_handshake, sizeof(struct noise_handshake));

            // necessary -> TODO: duplicated code necessary?
            memcpy(conn->public_key, n_c->public_key, CRYPTO_PUBLIC_KEY_SIZE);
            memcpy(conn->recv_nonce, n_c->recv_nonce, CRYPTO_NONCE_SIZE);
            // not necessary for Noise
            // memcpy(conn->peersessionpublic_key, n_c->peersessionpublic_key, CRYPTO_PUBLIC_KEY_SIZE);
            random_nonce(c->rng, conn->sent_nonce);
            crypto_new_keypair(c->rng, conn->sessionpublic_key, conn->sessionsecret_key);

            /* IMPORTANT: in this case here/before create_send_handshake(), otherwise get_crypto_connection() in
            create_send_handshake() returns a nullptr */
            conn->status = CRYPTO_CONN_NOT_CONFIRMED;

            if (create_send_handshake(c, crypt_connection_id, n_c->cookie, n_c->dht_public_key) != 0) {
                pthread_mutex_lock(&c->tcp_mutex);
                kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
                pthread_mutex_unlock(&c->tcp_mutex);
                wipe_crypto_connection(c, crypt_connection_id);
                return -1;
            }

            /* Noise Split(), base nonces already set */
            crypto_hkdf(conn->recv_key, conn->send_key, nullptr, CRYPTO_SYMMETRIC_KEY_SIZE, CRYPTO_SYMMETRIC_KEY_SIZE, 0, conn->noise_handshake->chaining_key);

            //TODO: remove
            LOGGER_DEBUG(c->log, "RESPONDER: After Noise Split()");
        } else {
            pthread_mutex_lock(&c->tcp_mutex);
            kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
            pthread_mutex_unlock(&c->tcp_mutex);
            wipe_crypto_connection(c, crypt_connection_id);
            return -1;
        }

    }
    /* non-Noise handshake */
    else {
        //TODO: remove
        LOGGER_DEBUG(c->log, "non-Noise handshake");
        memcpy(conn->public_key, n_c->public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(conn->recv_nonce, n_c->recv_nonce, CRYPTO_NONCE_SIZE);
        memcpy(conn->peersessionpublic_key, n_c->peersessionpublic_key, CRYPTO_PUBLIC_KEY_SIZE);
        random_nonce(c->rng, conn->sent_nonce);
        crypto_new_keypair(c->rng, conn->sessionpublic_key, conn->sessionsecret_key);
        encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);
        conn->status = CRYPTO_CONN_NOT_CONFIRMED;

        if (create_send_handshake(c, crypt_connection_id, n_c->cookie, n_c->dht_public_key) != 0) {
            pthread_mutex_lock(&c->tcp_mutex);
            kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
            pthread_mutex_unlock(&c->tcp_mutex);
            wipe_crypto_connection(c, crypt_connection_id);
            return -1;
        }
    }

    memcpy(conn->dht_public_key, n_c->dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    conn->packet_send_rate_requested = CRYPTO_PACKET_MIN_RATE;
    conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    conn->rtt_time = DEFAULT_PING_CONNECTION;
    crypto_connection_add_source(c, crypt_connection_id, &n_c->source);

    //TODO: here correct?
    crypto_memzero(n_c->noise_handshake, sizeof(Noise_Handshake));

    return crypt_connection_id;
}

/** @brief Create a crypto connection. Currently independent of non-Noise/Noise handshake.
 * If one to that real public key already exists, return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_crypto_connection(Net_Crypto *c, const uint8_t *real_public_key, const uint8_t *dht_public_key)
{
    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    int crypt_connection_id = getcryptconnection_id(c, real_public_key);

    if (crypt_connection_id != -1) {
        //TODO: remove
        //TODO: Print pub key?
        LOGGER_DEBUG(c->log, "INITIATOR: Crypto connection already exists => crypt_connection_id: %d", crypt_connection_id);
        return crypt_connection_id;
    }

    crypt_connection_id = create_crypto_connection(c);

    //TODO: remove
    LOGGER_DEBUG(c->log, "INITIATOR: AFTER create_crypto_connection() => crypt_connection_id: %d", crypt_connection_id);

    if (crypt_connection_id == -1) {
        return -1;
    }

    Crypto_Connection *conn = &c->crypto_connections[crypt_connection_id];

    pthread_mutex_lock(&c->tcp_mutex);
    const int connection_number_tcp = new_tcp_connection_to(c->tcp_c, dht_public_key, crypt_connection_id);
    pthread_mutex_unlock(&c->tcp_mutex);

    if (connection_number_tcp == -1) {
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    conn->connection_number_tcp = connection_number_tcp;
    memcpy(conn->public_key, real_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    random_nonce(c->rng, conn->sent_nonce);
    crypto_new_keypair(c->rng, conn->sessionpublic_key, conn->sessionsecret_key);
    conn->status = CRYPTO_CONN_COOKIE_REQUESTING;
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    conn->packet_send_rate_requested = CRYPTO_PACKET_MIN_RATE;
    conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    conn->rtt_time = DEFAULT_PING_CONNECTION;
    memcpy(conn->dht_public_key, dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    // Necessary for backwards compatibility to non-Noise handshake
    conn->noise_handshake = nullptr;
    conn->noise_handshake_enabled = true;

    conn->cookie_request_number = random_u64(c->rng);
    uint8_t cookie_request[COOKIE_REQUEST_LENGTH];

    //TODO: remove
    // LOGGER_DEBUG(c->log, "INITIATOR: BEFORE: create_cookie_request()");

    if (create_cookie_request(c, cookie_request, conn->dht_public_key, conn->cookie_request_number,
                              conn->shared_key) != sizeof(cookie_request)
            || new_temp_packet(c, crypt_connection_id, cookie_request, sizeof(cookie_request)) != 0) {
        pthread_mutex_lock(&c->tcp_mutex);
        kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
        pthread_mutex_unlock(&c->tcp_mutex);
        wipe_crypto_connection(c, crypt_connection_id);
        return -1;
    }

    //TODO: remove
    // LOGGER_DEBUG(c->log, "AFTER: create_cookie_request()");

    //TODO: here?
    // only necessary if Cookie request was successful
    // if (noise_handshake_init(c->log, conn->noise_handshake, c->self_secret_key, real_public_key, true) != 0) {
    //     // crypto_memzero(conn->noise_handshake, sizeof(struct noise_handshake));
    //    mem_delete(c->mem, conn->noise_handshake);
    //     pthread_mutex_lock(&c->tcp_mutex);
    //     kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
    //     pthread_mutex_unlock(&c->tcp_mutex);
    //     wipe_crypto_connection(c, crypt_connection_id);
    //     return -1;
    // }

    //TODO: remove
    LOGGER_DEBUG(c->log, "INITIATOR: END");

    return crypt_connection_id;
}

/** @brief Set the direct ip of the crypto connection.
 *
 * Connected is 0 if we are not sure we are connected to that person, 1 if we are sure.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_direct_ip_port(Net_Crypto *c, int crypt_connection_id, const IP_Port *ip_port, bool connected)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (add_ip_port_connection(c, crypt_connection_id, ip_port) != 0) {
        return -1;
    }

    const uint64_t direct_lastrecv_time = connected ? mono_time_get(c->mono_time) : 0;

    if (net_family_is_ipv4(ip_port->ip.family)) {
        conn->direct_lastrecv_timev4 = direct_lastrecv_time;
    } else {
        conn->direct_lastrecv_timev6 = direct_lastrecv_time;
    }

    return 0;
}

non_null(1, 3) nullable(5)
static int tcp_data_callback(void *object, int crypt_connection_id, const uint8_t *packet, uint16_t length,
                             void *userdata)
{
    Net_Crypto *c = (Net_Crypto *)object;

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING => PACKET: %d", packet[0]);

    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    if (packet[0] == NET_PACKET_COOKIE_REQUEST) {
        return tcp_handle_cookie_request(c, conn->connection_number_tcp, packet, length);
    }

    // This unlocks the mutex that at this point is locked by do_tcp before
    // calling do_tcp_connections.
    pthread_mutex_unlock(&c->tcp_mutex);
    const int ret = handle_packet_connection(c, crypt_connection_id, packet, length, false, userdata);
    pthread_mutex_lock(&c->tcp_mutex);

    if (ret != 0) {
        return -1;
    }

    // TODO(irungentoo): detect and kill bad TCP connections.
    return 0;
}

non_null(1, 2, 4) nullable(6)
static int tcp_oob_callback(void *object, const uint8_t *public_key, unsigned int tcp_connections_number,
                            const uint8_t *packet, uint16_t length, void *userdata)
{
    Net_Crypto *c = (Net_Crypto *)object;

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING => PACKET: %d", packet[0]);

    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE) {
        return -1;
    }

    if (packet[0] == NET_PACKET_COOKIE_REQUEST) {
        return tcp_oob_handle_cookie_request(c, tcp_connections_number, public_key, packet, length);
    }

    if (packet[0] == NET_PACKET_CRYPTO_HS) {
        const IP_Port source = tcp_connections_number_to_ip_port(tcp_connections_number);

        if (handle_new_connection_handshake(c, &source, packet, length, userdata) != 0) {
            return -1;
        }

        return 0;
    }

    return -1;
}

/** @brief Add a tcp relay, associating it to a crypt_connection_id.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay_peer(Net_Crypto *c, int crypt_connection_id, const IP_Port *ip_port, const uint8_t *public_key)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    pthread_mutex_lock(&c->tcp_mutex);
    const int ret = add_tcp_relay_connection(c->tcp_c, conn->connection_number_tcp, ip_port, public_key);
    pthread_mutex_unlock(&c->tcp_mutex);
    return ret;
}

/** @brief Add a tcp relay to the array.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay(Net_Crypto *c, const IP_Port *ip_port, const uint8_t *public_key)
{
    pthread_mutex_lock(&c->tcp_mutex);
    const int ret = add_tcp_relay_global(c->tcp_c, ip_port, public_key);
    pthread_mutex_unlock(&c->tcp_mutex);
    return ret;
}

/** @brief Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO(irungentoo): This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_con_number(Net_Crypto *c)
{
    pthread_mutex_lock(&c->tcp_mutex);
    const int ret = get_random_tcp_onion_conn_number(c->tcp_c);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

/** @brief Put IP_Port of a random onion TCP connection in ip_port.
 *
 * return true on success.
 * return false on failure.
 */
bool get_random_tcp_conn_ip_port(Net_Crypto *c, IP_Port *ip_port)
{
    pthread_mutex_lock(&c->tcp_mutex);
    const bool ret = tcp_get_random_conn_ip_port(c->tcp_c, ip_port);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

/** @brief Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_onion_request(Net_Crypto *c, unsigned int tcp_connections_number, const uint8_t *data, uint16_t length)
{
    pthread_mutex_lock(&c->tcp_mutex);
    const int ret = tcp_send_onion_request(c->tcp_c, tcp_connections_number, data, length);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

/**
 * Send a forward request to the TCP relay with IP_Port tcp_forwarder,
 * requesting to forward data via a chain of dht nodes starting with dht_node.
 * A chain_length of 0 means that dht_node is the final destination of data.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_forward_request(const Logger *logger, Net_Crypto *c, const IP_Port *tcp_forwarder, const IP_Port *dht_node,
                             const uint8_t *chain_keys, uint16_t chain_length,
                             const uint8_t *data, uint16_t data_length)
{
    pthread_mutex_lock(&c->tcp_mutex);
    const int ret = tcp_send_forward_request(logger, c->tcp_c, tcp_forwarder, dht_node,
                    chain_keys, chain_length, data, data_length);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

/** @brief Copy a maximum of num random TCP relays we are connected to to tcp_relays.
 *
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int copy_connected_tcp_relays(Net_Crypto *c, Node_format *tcp_relays, uint16_t num)
{
    if (num == 0) {
        return 0;
    }

    pthread_mutex_lock(&c->tcp_mutex);
    const unsigned int ret = tcp_copy_connected_relays(c->tcp_c, tcp_relays, num);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

uint32_t copy_connected_tcp_relays_index(Net_Crypto *c, Node_format *tcp_relays, uint16_t num, uint32_t idx)
{
    if (num == 0) {
        return 0;
    }

    pthread_mutex_lock(&c->tcp_mutex);
    const uint32_t ret = tcp_copy_connected_relays_index(c->tcp_c, tcp_relays, num, idx);
    pthread_mutex_unlock(&c->tcp_mutex);

    return ret;
}

non_null()
static void do_tcp(Net_Crypto *c, void *userdata)
{
    pthread_mutex_lock(&c->tcp_mutex);
    do_tcp_connections(c->log, c->tcp_c, userdata);
    pthread_mutex_unlock(&c->tcp_mutex);

    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        const Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == nullptr) {
            continue;
        }

        if (conn->status != CRYPTO_CONN_ESTABLISHED) {
            continue;
        }

        bool direct_connected = false;

        if (!crypto_connection_status(c, i, &direct_connected, nullptr)) {
            continue;
        }

        pthread_mutex_lock(&c->tcp_mutex);
        set_tcp_connection_to_status(c->tcp_c, conn->connection_number_tcp, !direct_connected);
        pthread_mutex_unlock(&c->tcp_mutex);
    }
}

/** @brief Set function to be called when connection with crypt_connection_id goes connects/disconnects.
 *
 * The set function should return -1 on failure and 0 on success.
 * Note that if this function is set, the connection will clear itself on disconnect.
 * Object and id will be passed to this function untouched.
 * status is 1 if the connection is going online, 0 if it is going offline.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_status_handler(const Net_Crypto *c, int crypt_connection_id,
                              connection_status_cb *connection_status_callback, void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    conn->connection_status_callback = connection_status_callback;
    conn->connection_status_callback_object = object;
    conn->connection_status_callback_id = id;
    return 0;
}

/** @brief Set function to be called when connection with crypt_connection_id receives a lossless data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_data_handler(const Net_Crypto *c, int crypt_connection_id,
                            connection_data_cb *connection_data_callback, void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    if (conn == nullptr) {
        return -1;
    }

    conn->connection_data_callback = connection_data_callback;
    conn->connection_data_callback_object = object;
    conn->connection_data_callback_id = id;
    return 0;
}

/** @brief Set function to be called when connection with crypt_connection_id receives a lossy data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_lossy_data_handler(const Net_Crypto *c, int crypt_connection_id,
                                  connection_lossy_data_cb *connection_lossy_data_callback,
                                  void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    if (conn == nullptr) {
        return -1;
    }

    conn->connection_lossy_data_callback = connection_lossy_data_callback;
    conn->connection_lossy_data_callback_object = object;
    conn->connection_lossy_data_callback_id = id;
    return 0;
}

/** @brief Set the function for this friend that will be callbacked with object and number if
 * the friend sends us a different dht public key than we have associated to him.
 *
 * If this function is called, the connection should be recreated with the new public key.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int nc_dht_pk_callback(const Net_Crypto *c, int crypt_connection_id, dht_pk_cb *function, void *object, uint32_t number)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    if (conn == nullptr) {
        return -1;
    }

    conn->dht_pk_callback = function;
    conn->dht_pk_callback_object = object;
    conn->dht_pk_callback_number = number;
    return 0;
}

/** @brief Get the crypto connection id from the ip_port.
 *
 * return -1 on failure.
 * return connection id on success.
 */
non_null()
static int crypto_id_ip_port(const Net_Crypto *c, const IP_Port *ip_port)
{
    return bs_list_find(&c->ip_port_list, (const uint8_t *)ip_port);
}

#define CRYPTO_MIN_PACKET_SIZE (1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE)

/** @brief Handle raw UDP packets coming directly from the socket.
 *
 * Handles:
 * Cookie response packets.
 * Crypto handshake packets.
 * Crypto data packets.
 *
 */
non_null(1, 2, 3) nullable(5)
static int udp_handle_packet(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                             void *userdata)
{
    Net_Crypto *c = (Net_Crypto *)object;

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING => PACKET: %d", packet[0]);

    if (length <= CRYPTO_MIN_PACKET_SIZE || length > MAX_CRYPTO_PACKET_SIZE) {
        return 1;
    }

    const int crypt_connection_id = crypto_id_ip_port(c, source);

    /* No crypto connection yet = RESPONDER case */
    if (crypt_connection_id == -1) {
        if (packet[0] != NET_PACKET_CRYPTO_HS) {
            return 1;
        }

        if (handle_new_connection_handshake(c, source, packet, length, userdata) != 0) {
            return 1;
        }

        return 0;
    }

    //TODO: return -1 if RESPONDER?

    if (handle_packet_connection(c, crypt_connection_id, packet, length, true, userdata) != 0) {
        return 1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return -1;
    }

    pthread_mutex_lock(conn->mutex);

    if (net_family_is_ipv4(source->ip.family)) {
        conn->direct_lastrecv_timev4 = mono_time_get(c->mono_time);
    } else {
        conn->direct_lastrecv_timev6 = mono_time_get(c->mono_time);
    }

    pthread_mutex_unlock(conn->mutex);

    return 0;
}

/** @brief The dT for the average packet receiving rate calculations.
 * Also used as the
 */
#define PACKET_COUNTER_AVERAGE_INTERVAL 50

/** @brief Ratio of recv queue size / recv packet rate (in seconds) times
 * the number of ms between request packets to send at that ratio
 */
#define REQUEST_PACKETS_COMPARE_CONSTANT (0.125 * 100.0)

/** @brief Timeout for increasing speed after congestion event (in ms). */
#define CONGESTION_EVENT_TIMEOUT 1000

/**
 * If the send queue is SEND_QUEUE_RATIO times larger than the
 * calculated link speed the packet send speed will be reduced
 * by a value depending on this number.
 */
#define SEND_QUEUE_RATIO 2.0

non_null()
static void send_crypto_packets(Net_Crypto *c)
{
    const uint64_t temp_time = current_time_monotonic(c->mono_time);
    double total_send_rate = 0;
    uint32_t peak_request_packet_interval = -1;

    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == nullptr) {
            continue;
        }

        //TODO: remove TODO: interesting if want to adapt interval
        // LOGGER_DEBUG(c->log, "conn->handshake_send_interval: %d", conn->handshake_send_interval);
        // LOGGER_DEBUG(c->log, "conn->temp_packet_sent_time: %lu", conn->temp_packet_sent_time);
        // LOGGER_DEBUG(c->log, "(conn->handshake_send_interval + conn->temp_packet_sent_time): %lu", (conn->handshake_send_interval + conn->temp_packet_sent_time));
        // LOGGER_DEBUG(c->log, "temp_time: %lu", temp_time);

        //TODO: Use again? / TODO: adapt interval?
        if ((CRYPTO_SEND_PACKET_INTERVAL + conn->temp_packet_sent_time) < temp_time) {
            //TODO: remove
            //LOGGER_DEBUG(c->log, "=> call send_temp_packet() => random_backoff: %d", random_backoff);
            // c_sleep(random_backoff);
            send_temp_packet(c, i);
        }

        //TODO: remove? where to add?
        // if ((conn->handshake_send_interval + conn->temp_packet_sent_time) < temp_time) {
        //     send_temp_packet(c, i);
        // }

        if ((conn->status == CRYPTO_CONN_NOT_CONFIRMED || conn->status == CRYPTO_CONN_ESTABLISHED)
                && (CRYPTO_SEND_PACKET_INTERVAL + conn->last_request_packet_sent) < temp_time) {
            if (send_request_packet(c, i) == 0) {
                conn->last_request_packet_sent = temp_time;
            }
        }

        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            if (conn->packet_recv_rate > CRYPTO_PACKET_MIN_RATE) {
                double request_packet_interval = REQUEST_PACKETS_COMPARE_CONSTANT / ((num_packets_array(
                                                     &conn->recv_array) + 1.0) / (conn->packet_recv_rate + 1.0));

                const double request_packet_interval2 = ((CRYPTO_PACKET_MIN_RATE / conn->packet_recv_rate) *
                                                        (double)CRYPTO_SEND_PACKET_INTERVAL) + (double)PACKET_COUNTER_AVERAGE_INTERVAL;

                if (request_packet_interval2 < request_packet_interval) {
                    request_packet_interval = request_packet_interval2;
                }

                if (request_packet_interval < PACKET_COUNTER_AVERAGE_INTERVAL) {
                    request_packet_interval = PACKET_COUNTER_AVERAGE_INTERVAL;
                }

                if (request_packet_interval > CRYPTO_SEND_PACKET_INTERVAL) {
                    request_packet_interval = CRYPTO_SEND_PACKET_INTERVAL;
                }

                if (temp_time - conn->last_request_packet_sent > (uint64_t)request_packet_interval) {
                    if (send_request_packet(c, i) == 0) {
                        conn->last_request_packet_sent = temp_time;
                    }
                }

                if (request_packet_interval < peak_request_packet_interval) {
                    peak_request_packet_interval = request_packet_interval;
                }
            }

            if ((PACKET_COUNTER_AVERAGE_INTERVAL + conn->packet_counter_set) < temp_time) {
                const double dt = (double)(temp_time - conn->packet_counter_set);

                conn->packet_recv_rate = (double)conn->packet_counter / (dt / 1000.0);
                conn->packet_counter = 0;
                conn->packet_counter_set = temp_time;

                const uint32_t packets_sent = conn->packets_sent;
                conn->packets_sent = 0;

                const uint32_t packets_resent = conn->packets_resent;
                conn->packets_resent = 0;

                /* conjestion control
                 *  calculate a new value of conn->packet_send_rate based on some data
                 */

                const unsigned int pos = conn->last_sendqueue_counter % CONGESTION_QUEUE_ARRAY_SIZE;
                conn->last_sendqueue_size[pos] = num_packets_array(&conn->send_array);

                long signed int sum = 0;
                sum = (long signed int)conn->last_sendqueue_size[pos] -
                      (long signed int)conn->last_sendqueue_size[(pos + 1) % CONGESTION_QUEUE_ARRAY_SIZE];

                const unsigned int n_p_pos = conn->last_sendqueue_counter % CONGESTION_LAST_SENT_ARRAY_SIZE;
                conn->last_num_packets_sent[n_p_pos] = packets_sent;
                conn->last_num_packets_resent[n_p_pos] = packets_resent;

                conn->last_sendqueue_counter = (conn->last_sendqueue_counter + 1) %
                                               (CONGESTION_QUEUE_ARRAY_SIZE * CONGESTION_LAST_SENT_ARRAY_SIZE);

                bool direct_connected = false;
                /* return value can be ignored since the `if` above ensures the connection is established */
                crypto_connection_status(c, i, &direct_connected, nullptr);

                /* When switching from TCP to UDP, don't change the packet send rate for CONGESTION_EVENT_TIMEOUT ms. */
                if (!(direct_connected && conn->last_tcp_sent + CONGESTION_EVENT_TIMEOUT > temp_time)) {
                    long signed int total_sent = 0;
                    long signed int total_resent = 0;

                    // TODO(irungentoo): use real delay
                    unsigned int delay = (unsigned int)(((double)conn->rtt_time / PACKET_COUNTER_AVERAGE_INTERVAL) + 0.5);
                    const unsigned int packets_set_rem_array = CONGESTION_LAST_SENT_ARRAY_SIZE - CONGESTION_QUEUE_ARRAY_SIZE;

                    if (delay > packets_set_rem_array) {
                        delay = packets_set_rem_array;
                    }

                    for (unsigned j = 0; j < CONGESTION_QUEUE_ARRAY_SIZE; ++j) {
                        const unsigned int ind = (j + (packets_set_rem_array  - delay) + n_p_pos) % CONGESTION_LAST_SENT_ARRAY_SIZE;
                        total_sent += conn->last_num_packets_sent[ind];
                        total_resent += conn->last_num_packets_resent[ind];
                    }

                    if (sum > 0) {
                        total_sent -= sum;
                    } else {
                        if (total_resent > -sum) {
                            total_resent = -sum;
                        }
                    }

                    /* if queue is too big only allow resending packets. */
                    const uint32_t npackets = num_packets_array(&conn->send_array);
                    double min_speed = 1000.0 * (((double)total_sent) / ((double)CONGESTION_QUEUE_ARRAY_SIZE *
                                                 PACKET_COUNTER_AVERAGE_INTERVAL));

                    const double min_speed_request = 1000.0 * (((double)(total_sent + total_resent)) / (
                                                         (double)CONGESTION_QUEUE_ARRAY_SIZE * PACKET_COUNTER_AVERAGE_INTERVAL));

                    if (min_speed < CRYPTO_PACKET_MIN_RATE) {
                        min_speed = CRYPTO_PACKET_MIN_RATE;
                    }

                    const double send_array_ratio = (double)npackets / min_speed;

                    // TODO(irungentoo): Improve formula?
                    if (send_array_ratio > SEND_QUEUE_RATIO && CRYPTO_MIN_QUEUE_LENGTH < npackets) {
                        conn->packet_send_rate = min_speed * (1.0 / (send_array_ratio / SEND_QUEUE_RATIO));
                    } else if (conn->last_congestion_event + CONGESTION_EVENT_TIMEOUT < temp_time) {
                        conn->packet_send_rate = min_speed * 1.2;
                    } else {
                        conn->packet_send_rate = min_speed * 0.9;
                    }

                    conn->packet_send_rate_requested = min_speed_request * 1.2;

                    if (conn->packet_send_rate < CRYPTO_PACKET_MIN_RATE) {
                        conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
                    }

                    if (conn->packet_send_rate_requested < conn->packet_send_rate) {
                        conn->packet_send_rate_requested = conn->packet_send_rate;
                    }
                }
            }

            if (conn->last_packets_left_set == 0 || conn->last_packets_left_requested_set == 0) {
                conn->last_packets_left_requested_set = temp_time;
                conn->last_packets_left_set = temp_time;
                conn->packets_left_requested = CRYPTO_MIN_QUEUE_LENGTH;
                conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
            } else {
                if (((uint64_t)((1000.0 / conn->packet_send_rate) + 0.5) + conn->last_packets_left_set) <= temp_time) {
                    double n_packets = conn->packet_send_rate * (((double)(temp_time - conn->last_packets_left_set)) / 1000.0);
                    n_packets += conn->last_packets_left_rem;

                    const uint32_t num_packets = n_packets;
                    const double rem = n_packets - (double)num_packets;

                    if (conn->packets_left > num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH) {
                        conn->packets_left = num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH;
                    } else {
                        conn->packets_left += num_packets;
                    }

                    conn->last_packets_left_set = temp_time;
                    conn->last_packets_left_rem = rem;
                }

                if (((uint64_t)((1000.0 / conn->packet_send_rate_requested) + 0.5) + conn->last_packets_left_requested_set) <=
                        temp_time) {
                    double n_packets = conn->packet_send_rate_requested * (((double)(temp_time - conn->last_packets_left_requested_set)) /
                                       1000.0);
                    n_packets += conn->last_packets_left_requested_rem;

                    const uint32_t num_packets = n_packets;
                    const double rem = n_packets - (double)num_packets;
                    conn->packets_left_requested = num_packets;

                    conn->last_packets_left_requested_set = temp_time;
                    conn->last_packets_left_requested_rem = rem;
                }

                if (conn->packets_left > conn->packets_left_requested) {
                    conn->packets_left_requested = conn->packets_left;
                }
            }

            const int ret = send_requested_packets(c, i, conn->packets_left_requested);

            if (ret != -1) {
                conn->packets_left_requested -= ret;
                conn->packets_resent += ret;

                if ((unsigned int)ret < conn->packets_left) {
                    conn->packets_left -= ret;
                } else {
                    conn->last_congestion_event = temp_time;
                    conn->packets_left = 0;
                }
            }

            if (conn->packet_send_rate > CRYPTO_PACKET_MIN_RATE * 1.5) {
                total_send_rate += conn->packet_send_rate;
            }
        }
    }

    c->current_sleep_time = -1;
    uint32_t sleep_time = peak_request_packet_interval;

    if (c->current_sleep_time > sleep_time) {
        c->current_sleep_time = sleep_time;
    }

    if (total_send_rate > CRYPTO_PACKET_MIN_RATE) {
        sleep_time = 1000.0 / total_send_rate;

        if (c->current_sleep_time > sleep_time) {
            c->current_sleep_time = sleep_time + 1;
        }
    }

    sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

    if (c->current_sleep_time > sleep_time) {
        c->current_sleep_time = sleep_time;
    }
}

/**
 * @retval 1 if max speed was reached for this connection (no more data can be physically through the pipe).
 * @retval 0 if it wasn't reached.
 */
bool max_speed_reached(Net_Crypto *c, int crypt_connection_id)
{
    return reset_max_speed_reached(c, crypt_connection_id) != 0;
}

/**
 * @return the number of packet slots left in the sendbuffer.
 * @retval 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(const Net_Crypto *c, int crypt_connection_id)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return 0;
    }

    const uint32_t max_packets = CRYPTO_PACKET_BUFFER_SIZE - num_packets_array(&conn->send_array);

    if (conn->packets_left < max_packets) {
        return conn->packets_left;
    }

    return max_packets;
}

/** @brief Sends a lossless cryptopacket.
 *
 * return -1 if data could not be put in packet queue.
 * return positive packet number if data was put into the queue.
 *
 * The first byte of data must be in the PACKET_ID_RANGE_LOSSLESS.
 *
 * congestion_control: should congestion control apply to this packet?
 */
int64_t write_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length,
                          bool congestion_control)
{
    if (length == 0) {
        // We need at least a packet id.
        LOGGER_ERROR(c->log, "rejecting empty packet for crypto connection %d", crypt_connection_id);
        return -1;
    }

    if (data[0] < PACKET_ID_RANGE_LOSSLESS_START || data[0] > PACKET_ID_RANGE_LOSSLESS_END) {
        LOGGER_ERROR(c->log, "rejecting lossless packet with out-of-range id %d", data[0]);
        return -1;
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        LOGGER_WARNING(c->log, "invalid crypt connection id %d", crypt_connection_id);
        return -1;
    }

    if (conn->status != CRYPTO_CONN_ESTABLISHED) {
        LOGGER_WARNING(c->log, "attempted to send packet to non-established connection %d", crypt_connection_id);
        return -1;
    }

    if (congestion_control && conn->packets_left == 0) {
        LOGGER_ERROR(c->log, "congestion control: rejecting packet of length %d on crypt connection %d", length,
                     crypt_connection_id);
        return -1;
    }

    const int64_t ret = send_lossless_packet(c, crypt_connection_id, data, length, congestion_control);

    if (ret == -1) {
        return -1;
    }

    if (congestion_control) {
        --conn->packets_left;
        --conn->packets_left_requested;
        ++conn->packets_sent;
    }

    return ret;
}

/** @brief Check if packet_number was received by the other side.
 *
 * packet_number must be a valid packet number of a packet sent on this connection.
 *
 * return -1 on failure.
 * return 0 on success.
 *
 * Note: The condition `buffer_end - buffer_start < packet_number - buffer_start` is
 * a trick which handles situations `buffer_end >= buffer_start` and
 * `buffer_end < buffer_start` (when buffer_end overflowed) both correctly.
 *
 * It CANNOT be simplified to `packet_number < buffer_start`, as it will fail
 * when `buffer_end < buffer_start`.
 */
int cryptpacket_received(const Net_Crypto *c, int crypt_connection_id, uint32_t packet_number)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    //TODO: remove
    // LOGGER_DEBUG(c->log, "ENTERING");

    if (conn == nullptr) {
        return -1;
    }

    const uint32_t num = num_packets_array(&conn->send_array);
    const uint32_t num1 = packet_number - conn->send_array.buffer_start;

    if (num >= num1) {
        return -1;
    }

    return 0;
}

/** @brief Sends a lossy cryptopacket.
 *
 * return -1 on failure.
 * return 0 on success.
 *
 * The first byte of data must be in the PACKET_ID_RANGE_LOSSY.
 */
int send_lossy_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        return -1;
    }

    if (data[0] < PACKET_ID_RANGE_LOSSY_START || data[0] > PACKET_ID_RANGE_LOSSY_END) {
        return -1;
    }

    pthread_mutex_lock(&c->connections_mutex);
    ++c->connection_use_counter;
    pthread_mutex_unlock(&c->connections_mutex);

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    int ret = -1;

    if (conn != nullptr) {
        pthread_mutex_lock(conn->mutex);
        const uint32_t buffer_start = conn->recv_array.buffer_start;
        const uint32_t buffer_end = conn->send_array.buffer_end;
        pthread_mutex_unlock(conn->mutex);
        ret = send_data_packet_helper(c, crypt_connection_id, buffer_start, buffer_end, data, length);
    }

    pthread_mutex_lock(&c->connections_mutex);
    --c->connection_use_counter;
    pthread_mutex_unlock(&c->connections_mutex);

    return ret;
}

/** @brief Kill a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    LOGGER_DEBUG(c->log, "ENTERING: crypto conn: %d", crypt_connection_id);

    int ret = -1;

    if (conn != nullptr) {
        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            send_kill_packet(c, crypt_connection_id);
        }

        pthread_mutex_lock(&c->tcp_mutex);
        kill_tcp_connection_to(c->tcp_c, conn->connection_number_tcp);
        pthread_mutex_unlock(&c->tcp_mutex);

        bs_list_remove(&c->ip_port_list, (uint8_t *)&conn->ip_portv4, crypt_connection_id);
        bs_list_remove(&c->ip_port_list, (uint8_t *)&conn->ip_portv6, crypt_connection_id);
        clear_temp_packet(c, crypt_connection_id);
        clear_buffer(c->mem, &conn->send_array);
        clear_buffer(c->mem, &conn->recv_array);
        ret = wipe_crypto_connection(c, crypt_connection_id);
    }

    return ret;
}

bool crypto_connection_status(const Net_Crypto *c, int crypt_connection_id, bool *direct_connected,
                              uint32_t *online_tcp_relays)
{
    const Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == nullptr) {
        return false;
    }

    if (direct_connected != nullptr) {
        *direct_connected = false;

        const uint64_t current_time = mono_time_get(c->mono_time);

        if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev4) > current_time ||
                (UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_timev6) > current_time) {
            *direct_connected = true;
        }
    }

    if (online_tcp_relays != nullptr) {
        *online_tcp_relays = tcp_connection_to_online_tcp_relays(c->tcp_c, conn->connection_number_tcp);
    }

    return true;
}

void new_keys(Net_Crypto *c)
{
    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");
    crypto_new_keypair(c->rng, c->self_public_key, c->self_secret_key);
}

/** @brief Save the public and private keys to the keys array.
 * Length must be CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE.
 *
 * TODO(irungentoo): Save only secret key.
 */
void save_keys(const Net_Crypto *c, uint8_t *keys)
{
    memcpy(keys, c->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(keys + CRYPTO_PUBLIC_KEY_SIZE, c->self_secret_key, CRYPTO_SECRET_KEY_SIZE);
}

/** @brief Load the secret key.
 * Length must be CRYPTO_SECRET_KEY_SIZE.
 */
void load_secret_key(Net_Crypto *c, const uint8_t *sk)
{
    memcpy(c->self_secret_key, sk, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(c->self_public_key, c->self_secret_key);
}

/** @brief Create new instance of Net_Crypto.
 * Sets all the global connection variables to their default values.
 */
Net_Crypto *new_net_crypto(const Logger *log, const Memory *mem, const Random *rng, const Network *ns,
                           Mono_Time *mono_time, DHT *dht, const TCP_Proxy_Info *proxy_info)
{
    if (dht == nullptr) {
        return nullptr;
    }

    Net_Crypto *temp = (Net_Crypto *)mem_alloc(mem, sizeof(Net_Crypto));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->log = log;
    temp->mem = mem;
    temp->rng = rng;
    temp->mono_time = mono_time;
    temp->ns = ns;

    temp->tcp_c = new_tcp_connections(log, mem, rng, ns, mono_time, dht_get_self_secret_key(dht), proxy_info);

    if (temp->tcp_c == nullptr) {
        mem_delete(mem, temp);
        return nullptr;
    }

    set_packet_tcp_connection_callback(temp->tcp_c, &tcp_data_callback, temp);
    set_oob_packet_tcp_connection_callback(temp->tcp_c, &tcp_oob_callback, temp);

    if (create_recursive_mutex(&temp->tcp_mutex) != 0 ||
            pthread_mutex_init(&temp->connections_mutex, nullptr) != 0) {
        kill_tcp_connections(temp->tcp_c);
        mem_delete(mem, temp);
        return nullptr;
    }

    temp->dht = dht;

    new_keys(temp);
    new_symmetric_key(rng, temp->secret_symmetric_key);

    temp->current_sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

    networking_registerhandler(dht_get_net(dht), NET_PACKET_COOKIE_REQUEST, &udp_handle_cookie_request, temp);
    networking_registerhandler(dht_get_net(dht), NET_PACKET_COOKIE_RESPONSE, &udp_handle_packet, temp);
    networking_registerhandler(dht_get_net(dht), NET_PACKET_CRYPTO_HS, &udp_handle_packet, temp);
    networking_registerhandler(dht_get_net(dht), NET_PACKET_CRYPTO_DATA, &udp_handle_packet, temp);

    bs_list_init(&temp->ip_port_list, sizeof(IP_Port), 8, ipport_cmp_handler);

    LOGGER_DEBUG(temp->log, "DONE");

    return temp;
}

non_null(1) nullable(2)
static void kill_timedout(Net_Crypto *c, void *userdata)
{
    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        const Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == nullptr) {
            continue;
        }

        if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT
                || conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
            if (conn->temp_packet_num_sent < MAX_NUM_SENDPACKET_TRIES) {
                continue;
            }

            //TODO: remove
            LOGGER_DEBUG(c->log, "connection_kill");
            connection_kill(c, i, userdata);
        }

#if 0

        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            // TODO(irungentoo): add a timeout here?
            /* do_timeout_here(); */
        }

#endif /* 0 */
    }
}

/** return the optimal interval in ms for running do_net_crypto. */
uint32_t crypto_run_interval(const Net_Crypto *c)
{
    return c->current_sleep_time;
}

/** Main loop. */
void do_net_crypto(Net_Crypto *c, void *userdata)
{
    kill_timedout(c, userdata);
    do_tcp(c, userdata);
    send_crypto_packets(c);
}

void kill_net_crypto(Net_Crypto *c)
{
    if (c == nullptr) {
        return;
    }

    //TODO: remove
    LOGGER_DEBUG(c->log, "ENTERING");

    const Memory *mem = c->mem;

    for (uint32_t i = 0; i < c->crypto_connections_length; ++i) {
        crypto_kill(c, i);
    }

    pthread_mutex_destroy(&c->tcp_mutex);
    pthread_mutex_destroy(&c->connections_mutex);

    kill_tcp_connections(c->tcp_c);
    bs_list_free(&c->ip_port_list);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_COOKIE_REQUEST, nullptr, nullptr);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_COOKIE_RESPONSE, nullptr, nullptr);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_CRYPTO_HS, nullptr, nullptr);
    networking_registerhandler(dht_get_net(c->dht), NET_PACKET_CRYPTO_DATA, nullptr, nullptr);
    crypto_memzero(c, sizeof(Net_Crypto));
    mem_delete(mem, c);
}
