/*
* lsquic_congestion_data.c -- Congestion Control Data Exchange
*
* Based on draft-yuan-quic-congestion-data-00
*/


#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_congestion_data.h"
#include "lsquic_varint.h"
#include "lsquic_int_types.h"
#include "lsquic.h"
#include <sys/queue.h>
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_minmax.h"
#include "lsquic_bw_sampler.h"
#include "lsquic_rtt.h"
#include "lsquic_cong_ctl.h"
#include "lsquic_senhist.h"
#include "lsquic_pacer.h"
#include "lsquic_cubic.h"
#include "lsquic_bbr.h"
#include "lsquic_adaptive_cc.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_conn_public.h"
#include "lsquic_util.h"
#include "lsquic_malo.h"
#include "lsquic_crand.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_send_ctl.h"
#include <sys/time.h>
#include <arpa/inet.h>

#ifndef WIN32
#include <netinet/in.h>
#else
#include "vc_compat.h"
#include "Ws2tcpip.h"
#endif

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
#include "lsquic_logger.h"


void
lsquic_cc_data_stats_init (struct cc_network_stats *stats)
{
    memset(stats, 0, sizeof(*stats));
}


static int
encode_cc_stat_field (unsigned char **pbuf, size_t *prem, enum cc_stats_type type,
                      uint64_t value)
{
    unsigned char *p = *pbuf;
    int n;

    if (*prem < 1)
        return -1;

    /* Encode type (1 byte) */
    *p++ = (unsigned char)type;
    (*prem)--;

    /* Encode value as varint */
    n = vint_size(value);
    if (*prem < (size_t)n)
        return -1;

    vint_write(p, value, vint_val2bits(value), n);
    p += n;
    (*prem) -= n;

    *pbuf = p;
    return 0;
}

static int
encode_stat_field_u32 (unsigned char **pbuf, size_t *prem, enum cc_stats_type type,
                        uint32_t value)
{
    return encode_stat_field(pbuf, prem, type, (uint64_t)value);
}

static int
decode_stat_field (const unsigned char **pbuf, const unsigned char *end,
                   enum cc_stats_type *type, uint64_t *value)
{
    const unsigned char *p = *pbuf;
    int n;

    if (p >= end)
        return -1;

    *type = (enum cc_stats_type)*p++;
    n = lsquic_varint_read(p, end, value);
    if (n < 0)
        return -1;

    p += n;
    *pbuf = p;
    return 0;
}


int 
lsquic_cc_data_encode_size (const struct cc_network_stats *stats)
{
    size_t size = 0;
    size_t addr_len;

    if (!stats)
        return -1;

    /* Each field: 1 byte (type) + varint (value) */
    if (stats->fields_set & CC_FIELD_TIMESTAMP)
        size += 1 + vint_size(stats->timestamp);

    if (stats->fields_set & CC_FIELD_PATH_TUPLE)
    {
        if (stats->path_tuple.addr_family == 4)
            addr_len = 4;
        else if (stats->path_tuple.addr_family == 6)
            addr_len = 16;
        else
            return -1;
        size += 1 + 1 + addr_len * 2 + 4; /* type + addr_family + addresses + ports */

    }

    if (stats->fields_set & CC_FIELD_SLOW_START_STATUS)
        size += 1 + vint_size(stats->slow_start_status);

    if (stats->fields_set & CC_FIELD_NETWORK_TYPE)
        size += 1 + vint_size(stats->network_type);

    if (stats->fields_set & CC_FIELD_MAX_CONGESTION_WINDOW)
        size += 1 + vint_size(stats->max_congestion_window);

    if (stats->fields_set & CC_FIELD_MAX_IN_FLIGHT_DATA)
        size += 1 + vint_size(stats->max_in_flight_data);

    if (stats->fields_set & CC_FIELD_SMOOTHED_RTT)
        size += 1 + vint_size(stats->smoothed_rtt);

    if (stats->fields_set & CC_FIELD_MIN_RTT)
        size += 1 + vint_size(stats->min_rtt);
        
    if (stats->fields_set & CC_FIELD_RTT_VARIANCE)
        size += 1 + vint_size(stats->rtt_variance);

    if (stats->fields_set & CC_FIELD_LATEST_BANDWIDTH)
        size += 1 + vint_size(stats->latest_bandwidth);

    if (stats->fields_set & CC_FIELD_MAX_BANDWIDTH)
        size += 1 + vint_size(stats->max_bandwidth);
        
    if (stats->fields_set & CC_FIELD_THROUGHPUT)
        size += 1 + vint_size(stats->throughput);

    if (stats->fields_set & CC_FIELD_SEND_RATE)
        size += 1 + vint_size(stats->send_rate);

    if (stats->fields_set & CC_FIELD_RECEIVE_RATE)
        size += 1 + vint_size(stats->receive_rate);

    if (stats->fields_set & CC_FIELD_INPUT_RATE)
        size += 1 + vint_size(stats->input_rate);

    if (stats->fields_set & CC_FIELD_LOSS_RATE)
        size += 1 + vint_size(stats->loss_rate);

    if (stats->fields_set & CC_FIELD_BUFFER_LENGTH)
        size += 1 + vint_size(stats->buffer_length);

    return (int)size;

}

int 
lsquic_cc_data_encode (const struct cc_network_stats *stats, unsigned char *buf, size_t bufsz)
{
    unsigned char *p = buf;
    size_t rem = bufsz;
    int n;

    if (!stats || !buf)
        return -1;

    /* Encode each set field in TLV format */
    if (stats->fields_set & CC_FIELD_TIMESTAMP)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_TIMESTAMP, stats->timestamp) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_PATH_TUPLE)
    {
        if (rem < 1)
            return -1;
        *p++ = (unsigned char)CC_STAT_PATH_TUPLE;
        rem--;
        n = lsquic_cc_path_tuple_encode(&stats->path_tuple, p, rem);
        if (n < 0)
            return -1;
        p += n;
        rem -= n;
    }

    if (stats->fields_set & CC_FIELD_SLOW_START_STATUS)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_SLOW_START_STATUS, stats->slow_start_status) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_NETWORK_TYPE)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_NETWORK_TYPE, stats->network_type) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_MAX_CONGESTION_WINDOW)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_MAX_CONGESTION_WINDOW, stats->max_congestion_window) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_MAX_IN_FLIGHT_DATA)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_MAX_IN_FLIGHT_DATA, stats->max_in_flight_data) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_SMOOTHED_RTT)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_SMOOTHED_RTT, stats->smoothed_rtt) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_MIN_RTT)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_MIN_RTT, stats->min_rtt) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_RTT_VARIANCE)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_RTT_VARIANCE, stats->rtt_variance) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_LATEST_BANDWIDTH)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_LATEST_BANDWIDTH, stats->latest_bandwidth) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_MAX_BANDWIDTH)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_MAX_BANDWIDTH, stats->max_bandwidth) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_THROUGHPUT)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_THROUGHPUT, stats->throughput) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_SEND_RATE)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_SEND_RATE, stats->send_rate) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_RECEIVE_RATE)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_RECEIVE_RATE, stats->receive_rate) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_INPUT_RATE)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_INPUT_RATE, stats->input_rate) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_LOSS_RATE)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_LOSS_RATE, stats->loss_rate) < 0)
            return -1;
    }

    if (stats->fields_set & CC_FIELD_BUFFER_LENGTH)
    {
        if (encode_cc_stat_field(&p, &rem, CC_STAT_BUFFER_LENGTH, stats->buffer_length) < 0)
            return -1;
    }

    return (int)(p - buf);
}

int
lsquic_cc_data_decode (const unsigned char *buf, size_t bufsz, struct cc_network_stats *stats)
{
    const unsigned char *p = buf;
    const unsigned char *end = buf + bufsz;
    enum cc_stats_type type;
    uint64_t value;
    int n;

    if (!buf || !stats)
        return -1;

    lsquic_cc_data_stats_init(stats);

    while (p < end)
    {
        if (decode_stat_field(&p, end, &type, &value) < 0)
            return -1;

        switch (type)
        {
        case CC_STAT_TIMESTAMP:
            stats->timestamp = value;
            stats->fields_set |= CC_FIELD_TIMESTAMP;
            break;
        

        case CC_STAT_PATH_TUPLE:
            n = lsquic_cc_path_tuple_decode(&p, end - p, &stats->path_tuple);
            if (n < 0)
                return -1;
            p += n;
            stats->fields_set |= CC_FIELD_PATH_TUPLE;
            break;

        case CC_STAT_SLOW_START_STATUS:
            stats->slow_start_status = (enum cc_slow_start_status)value;
            stats->fields_set |= CC_FIELD_SLOW_START_STATUS;
            break;

        case CC_STAT_NETWORK_TYPE:
            stats->network_type = (enum cc_network_type)value;
            stats->fields_set |= CC_FIELD_NETWORK_TYPE;
            break;

        case CC_STAT_MAX_CONGESTION_WINDOW:
            stats->max_congestion_window = value;
            stats->fields_set |= CC_FIELD_MAX_CONGESTION_WINDOW;
            break;

        case CC_STAT_MAX_IN_FLIGHT_DATA:
            stats->max_in_flight_data = value;
            stats->fields_set |= CC_FIELD_MAX_IN_FLIGHT_DATA;
            break;

        case CC_STAT_SMOOTHED_RTT:
            stats->smoothed_rtt = value;
            stats->fields_set |= CC_FIELD_SMOOTHED_RTT;
            break;

        case CC_STAT_MIN_RTT:
            stats->min_rtt = value;
            stats->fields_set |= CC_FIELD_MIN_RTT;
            break;
            
        case CC_STAT_RTT_VARIANCE:
            stats->rtt_variance = value;
            stats->fields_set |= CC_FIELD_RTT_VARIANCE;
            break;

        case CC_STAT_LATEST_BANDWIDTH:
            stats->latest_bandwidth = value;
            stats->fields_set |= CC_FIELD_LATEST_BANDWIDTH;

        case CC_STAT_MAX_BANDWIDTH:
            stats->max_bandwidth = value;
            stats->fields_set |= CC_FIELD_MAX_BANDWIDTH;
            break;

        case CC_STAT_THROUGHPUT:
            stats->throughput = value;
            stats->fields_set |= CC_FIELD_THROUGHPUT;
            break;

        case CC_STAT_SEND_RATE:
            stats->send_rate = value;
            stats->fields_set |= CC_FIELD_SEND_RATE;
            break;

        case CC_STAT_RECEIVE_RATE:
            stats->receive_rate = value;
            stats->fields_set |= CC_FIELD_RECEIVE_RATE;
            break;

        case CC_STAT_INPUT_RATE:
            stats->input_rate = value;
            stats->fields_set |= CC_FIELD_INPUT_RATE;
            break;
            
        case CC_STAT_LOSS_RATE:
            stats->loss_rate = value;
            stats->fields_set |= CC_FIELD_LOSS_RATE;
            break;

        case CC_STAT_BUFFER_LENGTH:
            stats->buffer_length = value;
            stats->fields_set |= CC_FIELD_BUFFER_LENGTH;
            break;

        default:
            /* Unknown field type - skip it*/
            LSQ_WARN("unknown congestion control data type: %d", type);
            break;
        }
    }
    return (int)(p - buf);
    
}

void
lsquic_cc_data_path_tuple_init (struct cc_path_tuple *tuple)
{
    memset(tuple, 0, sizeof(*tuple));
}

int    
lsquic_cc_path_tuple_encode (const struct cc_path_tuple *tuple,
                             unsigned char *buf, size_t bufsz)
{
    unsigned char *p = buf;
    size_t addr_len;

    if (!tuple || !buf)
        return -1;

    if (tuple->addr_family == 4)
        addr_len = 4;
    else if (tuple->addr_family == 6)
        addr_len = 16;
    else
        return -1;

    /* Need: 1 byte (addr_family) + addr_len * 2 (local + remote) + 2 bytes (ports) * 2 */
    if (bufsz < 1 + addr_len * 2 + 4)
        return -1;

    *p++ = tuple->addr_family;
    memcpy(p, tuple->local_addr, addr_len);
    p += addr_len;
    memcpy(p, tuple->remote_addr, addr_len);
    p += addr_len;
    *p++ = (tuple->local_port >> 8) & 0xFF;
    *p++ = tuple->local_port & 0xFF;
    *p++ = (tuple->remote_port >> 8) & 0xFF;
    *p++ = tuple->remote_port & 0xFF;

    return (int)(p - buf);

}

int 
lsquic_cc_path_tuple_decode (const unsigned char *buf, size_t bufsz, struct cc_path_tuple *tuple)
{
    const unsigned char *p = buf;
    size_t addr_len;

    if (!buf || !tuple)
        return -1;

    if (bufsz < 1)
        return -1;

    tuple->addr_family = *p++;
    if (tuple->addr_family == 4)
        addr_len = 4;
    else if (tuple->addr_family == 6)
        addr_len = 16;
    else
        return -1;

    if (bufsz < 1 + addr_len * 2 + 4)
        return -1;

    memcpy(tuple->local_addr, p, addr_len);
    p += addr_len;
    memcpy(tuple->remote_addr, p, addr_len);
    p += addr_len;
    tuple->local_port = ((uint16_t)p[0] << 8) | p[1];
    p += 2;
    tuple->remote_port = ((uint16_t)p[0] << 8) | p[1];
    p += 2;

    return (int)(p - buf);
   
}

int
lsquic_cc_data_integrity_tag_encode (const struct cc_integrity_tag *tag,
                                        unsigned char *buf, size_t bufsz);
{
    if (!tag || !buf)
        return -1;

    if (bufsz < CC_INTEGRITY_TAG_SIZE)
        return -1;

    buf[0] = tag->algorithm_id;
    buf[1] = (tag->nonce >> 8) & 0xFF;
    buf[2] = tag->nonce & 0xFF;
    memcpy(buf + 3, tag->digest, 32);

    return CC_INTEGRITY_TAG_SIZE;

}

int
lsquic_cc_data_integrity_tag_decode (const unsigned char *buf, size_t bufsz, struct cc_integrity_tag *tag)
{
    if (!buf || !tag)
        return -1;

    if (bufsz < CC_INTEGRITY_TAG_SIZE)
        return -1;

    tag->algorithm_id = buf[0];
    tag->nonce = ((uint16_t)buf[1] << 8) | buf[2];
    memcpy(tag->digest, buf + 3, 32);

    return CC_INTEGRITY_TAG_SIZE;

}

int
lsquic_cc_data_recall_encode (const struct cc_data_recall *recall,
                                unsigned char *buf, size_t bufsz)
{
    
    unsigned char *p = buf;
    int n;

    if (!recall || !buf)
        return -1;

    /* Encode path tuple */
    n = lsquic_cc_path_tuple_encode(&recall->path_tuple, buf, bufsz);
    if (n < 0)
        return -1;
    p += n;

    if (bufsz < (size_t)(n + 16))
        return -1;

    /* Encode timestamp_start as varint */
    n = vint_size(recall->timestamp_start);
    if (bufsz < (size_t)(p - buf + n))
        return -1;

    vint_write(p, recall->timestamp_start, vint_val2bits(recall->timestamp_start), n);
    p += n;

    /* Encode timestamp_end as varint */
    n = vint_size(recall->timestamp_end);
    if (bufsz < (size_t)(p - buf + n))
        return -1;

    vint_write(p, recall->timestamp_end, vint_val2bits(recall->timestamp_end), n);
    p += n;

    return (int)(p - buf);
}

int
lsquic_cc_data_recall_decode (const unsigned char *buf, size_t bufsz, struct cc_data_recall *recall)
{
    const unsigned char *p = buf;
    const unsigned char *end = buf + bufsz;
    int n;

    if (!buf || !recall)
        return -1;

    /* Decode path tuple */
    n = lsquic_congestion_path_tuple_decode(p, end - p, &recall->path_tuple);
    if (n < 0)
        return -1;
    p += n;

    /* Decode timestamp_start */
    n = lsquic_varint_read(p, end, &recall->timestamp_start);
    if (n < 0)
        return -1;
    p += n;

    /* Decode timestamp_end */
    n = lsquic_varint_read(p, end, &recall->timestamp_end);
    if (n < 0)
        return -1;
    p += n;

    return (int)(p - buf);

}

int
lsquic_cc_data_fill_path_tuple (const struct network_path *path,
                                struct cc_path_tuple *tuple)
{
    const struct sockaddr *local_sa, *peer_sa;
    const struct sockaddr_in *sin;
    const struct sockaddr_in6 *sin6;

    if (!path || !tuple)
        return -1;

    lsquic_cc_data_path_tuple_init(tuple);

    local_sa = NP_LOCAL_SA(path);
    peer_sa = NP_PEER_SA(path);

    if (!local_sa || !peer_sa)
        return -1;

    if (local_sa->sa_family == AF_INET)
    {
        tuple->addr_family = 4;
        sin = (const struct sockaddr_in *)local_sa;
        memcpy(tuple->local_addr, &sin->sin_addr, 4);
        tuple->local_port = ntohs(sin->sin_port);

        sin = (const struct sockaddr_in *)peer_sa;
        memcpy(tuple->remote_addr, &sin->sin_addr, 4);
        tuple->remote_port = ntohs(sin->sin_port);
    }
    else if (local_sa->sa_family == AF_INET6)
    {
        tuple->addr_family = 6;
        sin6 = (const struct sockaddr_in6 *)local_sa;
        memcpy(tuple->local_addr, &sin6->sin6_addr, 16);
        tuple->local_port = ntohs(sin6->sin6_port);

        sin6 = (const struct sockaddr_in6 *)peer_sa;
        memcpy(tuple->remote_addr, &sin6->sin6_addr, 16);
        tuple->remote_port = ntohs(sin6->sin6_port);
    }
    else
        return -1;

    return 0;

}

static uint64_t
get_timestamp_usec (void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

static uint64_t
get_in_flight_bytes (const struct lsquic_send_ctl *send_ctl)
{
    if (!send_ctl)
        return 0;
    return send_ctl->sc_bytes_unacked_all + send_ctl->sc_bytes_scheduled;
}

static uint64_t
get_max_bandwidth_from_bbr (const struct lsquic_bbr *bbr)
{
    if (!bbr)
        return 0;
    /* Get maximum bandwidth from BBR's max filter */
    return minmax_get(&bbr->bbr_max_bandwidth);
}

static int
is_in_slow_start (const struct lsquic_send_ctl *send_ctl)
{
    const struct lsquic_bbr *bbr;

    if (!send_ctl || !send_ctl->sc_cong_ctl)
        return 0;

    /* Check BBR mode */
    if (send_ctl->sc_ci == &lsquic_cong_bbr_if)
    {
        bbr = (const struct lsquic_bbr *)send_ctl->sc_cong_ctl;
        return bbr->bbr_mode == BBR_MODE_STARTUP;
    }

    /* For Cubic/Adaptive, LU::TODO */
    return 0;
}

static enum cc_network_type
detect_network_type (const struct network_path *path)
{
    /* Simple heuristic: check if it's a loopback address */
    if (!path)
        return CD_NET_TYPE_UNKNOWN;

    // LU::TODO
    return CC_NET_TYPE_WIRED;
    
}

int
lsquic_cc_data_collect_stats (const struct lsquic_conn_public *conn_pub,
                              const struct lsquic_send_ctl *send_ctl,
                              const struct network_path *path,
                              struct cc_network_stats *stats)
{
    uint64_t cwnd, pacing_rate, in_flight;
    const struct lsquic_rtt_stats *rtt_stats;
    uint32_t loss_rate_ppm;

    if (!conn_pub || !send_ctl || !path || !stats)
        return -1;

    lsquic_cc_data_stats_init(stats);

    /* Timestamp */
    stats->timestamp = get_timestamp_usec();
    stats->fields_set |= CC_FIELD_TIMESTAMP;

    /* Path Tuple */
    if (lsquic_cc_data_fill_path_tuple(path, &stats->path_tuple) == 0)
        stats->fields_set |= CC_FIELD_PATH_TUPLE;

    /* Slow Start Status */
    stats->slow_start_status = is_in_slow_start(send_ctl) ?
        CC_SS_IN_SLOW_START : CC_SS_NOT_IN_SLOW_START;
    stats->fields_set |= CC_FIELD_SLOW_START_STATUS;

    /* Network Type */
    stats->network_type = detect_network_type(path);
    stats->fields_set |= CC_FIELD_NETWORK_TYPE;

    /* Congestion Window */
    if (send_ctl->sc_ci && send_ctl->sc_ci->cci_get_cwnd)
    {
        cwnd = send_ctl->sc_ci->cci_get_cwnd(send_ctl->sc_cong_ctl);
        stats->max_congestion_window = cwnd;
        stats->fields_set |= CC_FIELD_MAX_CONGESTION_WINDOW;
    }

    /* In-Flight Data */
    in_flight = get_in_flight_bytes(send_ctl);
    stats->max_in_flight_data = in_flight;
    stats->fields_set |= CC_FIELD_MAX_IN_FLIGHT_DATA;

    /* RTT Statistics */
    rtt_stats = &conn_pub->rtt_stats;
    if (rtt_stats->srtt > 0)
    {
        stats->smoothed_rtt = rtt_stats->srtt / 1000;  /* Convert to ms */
        stats->fields_set |= CC_FIELD_SMOOTHED_RTT;
    }
    if (rtt_stats->min_rtt > 0)
    {
        stats->min_rtt = rtt_stats->min_rtt / 1000;  /* Convert to ms */
        stats->fields_set |= CC_FIELD_MIN_RTT;
    }
    if (rtt_stats->rttvar > 0)
    {
        stats->rtt_variance = rtt_stats->rttvar / 1000;  /* Convert to ms */
        stats->fields_set |= CC_FIELD_RTT_VARIANCE;
    }

    /* Bandwidth and Rates */
    if (send_ctl->sc_ci && send_ctl->sc_ci->cci_pacing_rate)
    {
        pacing_rate = send_ctl->sc_ci->cci_pacing_rate(send_ctl->sc_cong_ctl, 0);
        /* Convert bytes per second to kbps */
        stats->latest_bandwidth = (pacing_rate * 8) / 1000;
        stats->fields_set |= CC_FIELD_LATEST_BANDWIDTH;

        /* For BBR, get max bandwidth */
        if (send_ctl->sc_ci == &lsquic_cong_bbr_if)
        {
            const struct lsquic_bbr *bbr = (const struct lsquic_bbr *)send_ctl->sc_cong_ctl;
            uint64_t max_bw = get_max_bandwidth_from_bbr(bbr);
            if (max_bw > 0)
            {
                stats->max_bandwidth = (max_bw * 8) / 1000;  /* Convert to kbps */
                stats->fields_set |= CC_FIELD_MAX_BANDWIDTH;
            }
        }
    }

    /* Send Rate - approximate from pacing rate */
    if (stats->fields_set & CC_FIELD_LATEST_BANDWIDTH)
    {
        stats->send_rate = stats->latest_bandwidth;
        stats->fields_set |= CC_FIELD_SEND_RATE;
    }

    /* Throughput - use latest bandwidth as approximation */
    if (stats->fields_set & CC_FIELD_LATEST_BANDWIDTH)
    {
        stats->throughput = stats->latest_bandwidth;
        stats->fields_set |= CC_FIELD_THROUGHPUT;
    }

    /* Loss Rate - would need connection statistics */
    // LU::TODO
    stats->loss_rate = 0;
    stats->fields_set |= CC_FIELD_LOSS_RATE;

    /* Buffer Length - use connection flow control window */
    // LU::TODO
    if (conn_pub->conn_cap.cc_max > 0)
    {
        stats->buffer_length = -1;
        stats->fields_set |= CC_FIELD_BUFFER_LENGTH;
    }

    return 0;
}