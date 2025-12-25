/*
 * lsquic_congestion_data.h -- Congestion Control Data Exchange
 *
 * Based on draft-yuan-quic-congestion-data-00
 *
 */


#ifndef LSQUIC_CC_DATA_H
#define LSQUIC_CC_DATA_H 1

#include <stdint.h>
#include <sys/types.h>
#include "lsquic_types.h"

/* Network Type */
enum cc_network_type
{
    CC_NET_TYPE_RESERVED              = 0x00,
    CC_NET_TYPE_WIRED                 = 0x01,
    CC_NET_TYPE_MOBILE                = 0x02,
    CC_NET_TYPE_WIFI                  = 0x03,
    CC_NET_TYPE_2G                    = 0x04,
    CC_NET_TYPE_3G                    = 0x05,
    CC_NET_TYPE_4G                    = 0x06,
    CC_NET_TYPE_5G                    = 0x07,
    CC_NET_TYPE_UNKNOWN               = 0xFF,
};


/* Network Statistics Field Types */
enum cc_stats_type
{
    CC_STAT_TIMESTAMP                 = 0xC8,
    CC_STAT_PATH_TUPLE                = 0xCA,
    CC_STAT_SLOW_START_STATUS         = 0xCB,
    CC_STAT_NETWORK_TYPE              = 0xCC,
    CC_STAT_MAX_CONGESTION_WINDOW     = 0xCD,
    CC_STAT_MAX_IN_FLIGHT_DATA        = 0xCE,
    CC_STAT_SMOOTHED_RTT              = 0xCF,
    CC_STAT_MIN_RTT                   = 0xD0,
    CC_STAT_RTT_VARIANCE              = 0xD1,
    CC_STAT_LATEST_BANDWIDTH          = 0xD2,
    CC_STAT_MAX_BANDWIDTH             = 0xD3,
    CC_STAT_THROUGHPUT                = 0xD4,
    CC_STAT_SEND_RATE                 = 0xD5,
    CC_STAT_RECEIVE_RATE              = 0xD6,
    CC_STAT_INPUT_RATE                = 0xD7,
    CC_STAT_LOSS_RATE                 = 0xD8,
    CC_STAT_BUFFER_LENGTH             = 0xD9,
};


/* Slow Start Status */
enum cc_slow_start_status
{
    CC_SS_NOT_IN_SLOW_START           = 0x00,
    CC_SS_IN_SLOW_START               = 0x01,
};


/* Path Tuple */
struct cc_path_tuple
{
    uint8_t     local_addr[16];      /* IPv4 (4 bytes) or IPv6 (16 bytes) */
    uint16_t    local_port;
    uint8_t     remote_addr[16];     /* IPv4 (4 bytes) or IPv6 (16 bytes) */
    uint16_t    remote_port;
    uint8_t     addr_family;         /* 4 for IPv4, 6 for IPv6 */
};

struct cc_network_stats
{
    uint64_t                        timestamp; /* microseconds since epoch */
    struct cc_path_tuple            path_tuple; /* local and remote addresses and ports */
    enum cc_slow_start_status       slow_start_status; /* whether the connection is in slow start */
    enum cc_network_type            network_type; /* type of network */
    uint64_t                        max_congestion_window; /* maximum congestion window (bytes)*/
    uint64_t                        max_in_flight_data; /* maximum in-flight data (bytes) */
    uint64_t                        smoothed_rtt; /* smoothed RTT (ms) */
    uint64_t                        min_rtt; /* minimum RTT (ms) */
    uint64_t                        rtt_variance; /* RTT variance (ms) */
    uint64_t                        latest_bandwidth; /* latest bandwidth (kbps) */
    uint64_t                        max_bandwidth; /* maximum bandwidth (kbps) */
    uint64_t                        throughput; /* throughput (kbps) */
    uint64_t                        send_rate; /* send rate (kbps) */
    uint64_t                        receive_rate; /* receive rate (kbps) */
    uint64_t                        input_rate; /* input rate (kbps) */
    uint64_t                        loss_rate; /* loss rate (0-1) */
    uint64_t                        buffer_length; /* buffer length (bytes) */
    uint32_t                        fields_set; /* flags indicating which fields are set */
};


/* Field flags for fields_set */
#define CC_FIELD_TIMESTAMP              (1U << 0)
#define CC_FIELD_PATH_TUPLE             (1U << 1)
#define CC_FIELD_SLOW_START_STATUS      (1U << 2)
#define CC_FIELD_NETWORK_TYPE           (1U << 3)
#define CC_FIELD_MAX_CONGESTION_WINDOW  (1U << 4)
#define CC_FIELD_MAX_IN_FLIGHT_DATA     (1U << 5)
#define CC_FIELD_SMOOTHED_RTT           (1U << 6)
#define CC_FIELD_MIN_RTT                (1U << 7)
#define CC_FIELD_RTT_VARIANCE           (1U << 8)
#define CC_FIELD_LATEST_BANDWIDTH       (1U << 9)
#define CC_FIELD_MAX_BANDWIDTH          (1U << 10)
#define CC_FIELD_THROUGHPUT             (1U << 11)
#define CC_FIELD_SEND_RATE              (1U << 12)
#define CC_FIELD_RECEIVE_RATE           (1U << 13)
#define CC_FIELD_INPUT_RATE             (1U << 14)
#define CC_FIELD_LOSS_RATE              (1U << 15)
#define CC_FIELD_BUFFER_LENGTH          (1U << 16)

/* Integrity Tag */
#define CC_INTEGRITY_TAG_SIZE           35  /* 1 byte alg + 2 bytes nonce + 32 bytes digest */
struct cc_integrity_tag
{
    uint8_t     algorithm_id;         /* Algorithm identifier (1 = HMAC-SHA256) */
    uint16_t    nonce;                /* Private nonce */
    uint8_t     digest[32];           /* SHA256 digest */
};

struct cc_data_recall
{
    struct cc_path_tuple    path_tuple;
    uint64_t                timestamp_start;  /* Start of time range */
    uint64_t                timestamp_end;    /* End of time range */
};

/* Serialization/Deserialization functions */

/**
 * Calculate the size needed to encode network statistics.
 * Returns the number of bytes needed, or -1 on error.
 */

int
lsquic_cc_data_encode_size (const struct cc_network_stats *stats);

/**
 * Encode network statistics to wire format (TLV format).
 * Returns the number of bytes written, or -1 on error.
 */
int
lsquic_cc_data_encode (const struct cc_network_stats *stats,
                       unsigned char *buf, size_t bufsz);

/**
 * Decode network statistics from wire format.
 * Returns the number of bytes read, or -1 on error.
 */
int
lsquic_cc_data_decode (const unsigned char *buf, size_t bufsz,
                       struct cc_network_stats *stats);


/**
 * Encode path tuple to wire format.
 * Returns the number of bytes written, or -1 on error.
 */
int    
lsquic_cc_path_tuple_encode (const struct cc_path_tuple *tuple,
                             unsigned char *buf, size_t bufsz);

/**
 * Decode path tuple from wire format.
 * Returns the number of bytes read, or -1 on error.
 */
int
lsquic_cc_path_tuple_decode (const unsigned char *buf, size_t bufsz,
                             struct cc_path_tuple *tuple);

/**
* Encode integrity tag to wire format.
* Returns the number of bytes written (always CD_INTEGRITY_TAG_SIZE), or -1 on error.
*/
int
lsquic_cc_data_integrity_tag_encode (const struct cc_integrity_tag *tag,
                                        unsigned char *buf, size_t bufsz);

/**
* Decode integrity tag from wire format.
* Returns the number of bytes read (always CD_INTEGRITY_TAG_SIZE), or -1 on error.
*/
int
lsquic_cc_data_integrity_tag_decode (const unsigned char *buf, size_t bufsz,
                                        struct cc_integrity_tag *tag);

/**
* Encode CONGESTION_DATA_RECALL frame payload.
* Returns the number of bytes written, or -1 on error.
*/
int
lsquic_cc_data_recall_encode (const struct cc_data_recall *recall,
                                    unsigned char *buf, size_t bufsz);

/**
* Decode CONGESTION_DATA_RECALL frame payload.
* Returns the number of bytes read, or -1 on error.
*/
int
lsquic_cc_data_recall_decode (const unsigned char *buf, size_t bufsz,
                                    struct cc_data_recall *recall);

/**
* Initialize network statistics structure.
*/
void
lsquic_cc_data_stats_init (struct cc_network_stats *stats);

/**
* Initialize path tuple structure.
*/
void
lsquic_cc_data_path_tuple_init (struct cc_path_tuple *tuple);


/* Forward declarations */
struct lsquic_conn_public;
struct lsquic_send_ctl;
struct network_path;

/**
* Collect network statistics from connection.
* This is the main function to gather all congestion control data.
* Returns 0 on success, -1 on error.
*/

int 
lsquic_cc_data_collect_stats (const struct lsquic_conn_public *conn_pub,
                              const struct lsquic_send_ctl *send_ctl,
                              const struct network_path *path,
                              struct cc_network_stats *stats);

/**
* Fill path tuple from network path structure.
* Returns 0 on success, -1 on error.
*/
int
lsquic_cc_data_fill_path_tuple (const struct network_path *path,
                                struct cc_path_tuple *tuple);

#endif /* LSQUIC_CC_DATA_H */

