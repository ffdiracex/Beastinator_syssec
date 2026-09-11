/*
 * netinspect.h - Live Network Inspector for SYSSEC
 * 
 * Provides:
 * - Live connection tracking (TCP/UDP IPv4/IPv6)
 * - IP-to-port mapping
 * - Connection state analysis
 * - Process-to-connection correlation
 * - Suspicious pattern detection
 * - Historical tracking with diff analysis
 * 
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_NETINSPECT_H
#define SYSSEC_NETINSPECT_H

#include "syssec.h"
#include <netinet/in.h>
#include <arpa/inet.h>

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define NET_MAX_CONNECTIONS     2048
#define NET_MAX_UNIQUE_IPS      512
#define NET_MAX_PORTS           1024
#define NET_MAX_SNAPSHOTS       16
#define NET_MAX_ALERTS          256
#define NET_MAX_PROC_NAME       64
#define NET_STR_SMALL           32
#define NET_STR_MED             64
#define NET_STR_LARGE           256

/* ============================================================
 * ENUMS
 * ============================================================ */

typedef enum {
    NET_PROTO_TCP = 0,
    NET_PROTO_UDP,
    NET_PROTO_TCP6,
    NET_PROTO_UDP6,
    NET_PROTO_UNKNOWN
} net_proto_t;

typedef enum {
    NET_STATE_LISTEN = 0,
    NET_STATE_ESTABLISHED,
    NET_STATE_TIME_WAIT,
    NET_STATE_CLOSE_WAIT,
    NET_STATE_SYN_SENT,
    NET_STATE_SYN_RECV,
    NET_STATE_FIN_WAIT1,
    NET_STATE_FIN_WAIT2,
    NET_STATE_LAST_ACK,
    NET_STATE_CLOSED,
    NET_STATE_UNKNOWN
} net_state_t;

typedef enum {
    NET_SUSPICIOUS_NONE = 0,
    NET_SUSPICIOUS_HIGH_PORT,       /* Listener on high port */
    NET_SUSPICIOUS_UNKNOWN_PROC,    /* Unknown process listening */
    NET_SUSPICIOUS_EXTERNAL_CONN,   /* Connection to public IP */
    NET_SUSPICIOUS_UNUSUAL_PORT,    /* Port outside normal ranges */
    NET_SUSPICIOUS_MANY_CONNS,      /* Many connections from same IP */
    NET_SUSPICIOUS_BIND_ALL,        /* Listening on 0.0.0.0 with unusual port */
    NET_SUSPICIOUS_ROOT_PROC,       /* Root process on unexpected port */
    NET_SUSPICIOUS_DYNAMIC_DNS,     /* Connection to dynamic DNS range */
    NET_SUSPICIOUS_BLACKLISTED      /* Known bad IP */
} net_suspicion_t;

/* ============================================================
 * CONNECTION STRUCTURE
 * ============================================================ */

typedef struct {
    net_proto_t     proto;
    net_state_t     state;
    
    /* Local endpoint */
    char            local_addr[NET_STR_MED];
    int             local_port;
    int             local_is_wildcard;
    
    /* Remote endpoint */
    char            remote_addr[NET_STR_MED];
    int             remote_port;
    int             remote_is_public;
    
    /* Process info */
    int             pid;
    uid_t           uid;
    char            process[NET_MAX_PROC_NAME];
    char            command[NET_STR_LARGE];
    
    /* Metadata */
    time_t          first_seen;
    time_t          last_seen;
    int             seen_count;
    
    /* Analysis */
    net_suspicion_t suspicion;
    char            suspicion_reason[NET_STR_LARGE];
} net_connection_t;

/* ============================================================
 * UNIQUE IP STRUCTURE
 * ============================================================ */

typedef struct {
    char            addr[NET_STR_MED];
    int             is_public;
    int             is_local;
    int             connection_count;
    int             listen_count;
    int             ports[NET_MAX_PORTS];
    int             port_count;
    int             processes[16];
    int             process_count;
    time_t          first_seen;
    time_t          last_seen;
    net_suspicion_t suspicion;
} net_ip_t;

/* ============================================================
 * PORT STRUCTURE
 * ============================================================ */

typedef struct {
    int             port;
    net_proto_t     proto;
    int             listeners;
    int             established;
    char            process[NET_MAX_PROC_NAME];
    int             pid;
    uid_t           uid;
    int             is_well_known;
    int             is_suspicious;
    char            reason[NET_STR_LARGE];
} net_port_t;

/* ============================================================
 * SNAPSHOT (for diff tracking)
 * ============================================================ */

typedef struct {
    time_t              timestamp;
    net_connection_t    connections[NET_MAX_CONNECTIONS];
    int                 connection_count;
    net_ip_t            ips[NET_MAX_UNIQUE_IPS];
    int                 ip_count;
    net_port_t          ports[NET_MAX_PORTS];
    int                 port_count;
} net_snapshot_t;

/* ============================================================
 * ALERT
 * ============================================================ */

typedef struct {
    time_t              timestamp;
    net_suspicion_t     type;
    char                message[NET_STR_LARGE];
    char                local[NET_STR_MED];
    char                remote[NET_STR_MED];
    int                 port;
    int                 pid;
    char                process[NET_MAX_PROC_NAME];
} net_alert_t;

/* ============================================================
 * MAIN INSPECTOR STATE
 * ============================================================ */

typedef struct {
    /* Current snapshot */
    net_snapshot_t      current;
    
    /* Historical snapshots (for diff) */
    net_snapshot_t      snapshots[NET_MAX_SNAPSHOTS];
    int                 snapshot_count;
    int                 snapshot_index;
    
    /* Alerts */
    net_alert_t         alerts[NET_MAX_ALERTS];
    int                 alert_count;
    
    /* Stats */
    int                 total_connections;
    int                 total_listeners;
    int                 total_established;
    int                 total_public_ips;
    int                 total_local_ips;
    int                 suspicious_count;
    
    /* Config */
    int                 verbose;
} netinspect_t;

/* ============================================================
 * PUBLIC API
 * ============================================================ */

/* Initialization */
void netinspect_init(netinspect_t *ni, int verbose);
void netinspect_free(netinspect_t *ni);

/* Live scanning */
int netinspect_scan(netinspect_t *ni);

/* Analysis */
void netinspect_analyze(netinspect_t *ni);
void netinspect_diff_snapshots(netinspect_t *ni);

/* Reporting */
void netinspect_print_connections(netinspect_t *ni);
void netinspect_print_ips(netinspect_t *ni);
void netinspect_print_ports(netinspect_t *ni);
void netinspect_print_alerts(netinspect_t *ni);
void netinspect_print_summary(netinspect_t *ni);
void netinspect_print_full(netinspect_t *ni);

/* Integration with syssec */
void netinspect_report(netinspect_t *ni, syssec_t *s);

/* Helpers */
const char* netinspect_state_string(net_state_t state);
const char* netinspect_proto_string(net_proto_t proto);
const char* netinspect_suspicion_string(net_suspicion_t susp);

#endif /* SYSSEC_NETINSPECT_H */
