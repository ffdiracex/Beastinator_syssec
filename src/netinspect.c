/*
 * netinspect.c - Live Network Inspector for SYSSEC
 * 
 * Compile: cc -Wall -Wextra -O2 -c netinspect.c -o netinspect.o
 */

#define __BSD_VISIBLE 1

#include "netinspect.h"
#include "syssec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//static void aggregate_ips(netinspect_t *ni);
//static void aggregate_ports(netinspect_t *ni);

/* ============================================================
 * HELPERS
 * ============================================================ */

const char* netinspect_state_string(net_state_t state) {
    switch (state) {
        case NET_STATE_LISTEN:       return "LISTEN";
        case NET_STATE_ESTABLISHED:  return "ESTABLISHED";
        case NET_STATE_TIME_WAIT:    return "TIME_WAIT";
        case NET_STATE_CLOSE_WAIT:   return "CLOSE_WAIT";
        case NET_STATE_SYN_SENT:     return "SYN_SENT";
        case NET_STATE_SYN_RECV:     return "SYN_RECV";
        case NET_STATE_FIN_WAIT1:    return "FIN_WAIT1";
        case NET_STATE_FIN_WAIT2:    return "FIN_WAIT2";
        case NET_STATE_LAST_ACK:     return "LAST_ACK";
        case NET_STATE_CLOSED:       return "CLOSED";
        default:                     return "UNKNOWN";
    }
}

const char* netinspect_proto_string(net_proto_t proto) {
    switch (proto) {
        case NET_PROTO_TCP:      return "tcp4";
        case NET_PROTO_UDP:      return "udp4";
        case NET_PROTO_TCP6:     return "tcp6";
        case NET_PROTO_UDP6:     return "udp6";
        default:                 return "?";
    }
}

const char* netinspect_suspicion_string(net_suspicion_t susp) {
    switch (susp) {
        case NET_SUSPICIOUS_NONE:           return "none";
        case NET_SUSPICIOUS_HIGH_PORT:      return "high-port";
        case NET_SUSPICIOUS_UNKNOWN_PROC:   return "unknown-proc";
        case NET_SUSPICIOUS_EXTERNAL_CONN:  return "external-conn";
        case NET_SUSPICIOUS_UNUSUAL_PORT:   return "unusual-port";
        case NET_SUSPICIOUS_MANY_CONNS:     return "many-conns";
        case NET_SUSPICIOUS_BIND_ALL:       return "bind-all";
        case NET_SUSPICIOUS_ROOT_PROC:      return "root-proc";
        case NET_SUSPICIOUS_DYNAMIC_DNS:    return "dyn-dns";
        case NET_SUSPICIOUS_BLACKLISTED:    return "blacklisted";
        default:                            return "?";
    }
}

/*
 * Classify an address as public/local
 */
static int is_public_ip(const char *addr) {
    if (!addr || !addr[0]) return 0;
    
    /* IPv6 */
    if (strchr(addr, ':')) {
        if (strncmp(addr, "::1", 3) == 0) return 0;
        if (strncmp(addr, "fe80:", 5) == 0) return 0;
        if (strncmp(addr, "fc00:", 5) == 0) return 0;
        if (strncmp(addr, "fd", 2) == 0) return 0;
        return 1;
    }
    
    /* IPv4 */
    unsigned int a, b, c, d;
    if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    
    /* 10.0.0.0/8 */
    if (a == 10) return 0;
    /* 172.16.0.0/12 */
    if (a == 172 && b >= 16 && b <= 31) return 0;
    /* 192.168.0.0/16 */
    if (a == 192 && b == 168) return 0;
    /* 127.0.0.0/8 */
    if (a == 127) return 0;
    /* 169.254.0.0/16 */
    if (a == 169 && b == 254) return 0;
    /* 0.0.0.0 */
    if (a == 0) return 0;
    /* 224.0.0.0/4 multicast */
    if (a >= 224 && a <= 239) return 0;
    /* 240.0.0.0/4 reserved */
    if (a >= 240) return 0;
    
    return 1;
}

/*
 * Check if a port is a well-known/system port
 */
static int is_well_known_port(int port) {
    return (port > 0 && port < 1024);
}

/*
 * Check if a port is suspicious based on common patterns
 */
static int is_suspicious_port(int port) {
    /* Known malware/backdoor ports */
    switch (port) {
        case 4444: case 4445: case 5555: case 6666: case 6667:
        case 6668: case 7777: case 8888: case 9999: case 1337:
        case 31337: case 31338: case 12345: case 54321:
        case 11111: case 22222: case 33333:
            return 1;
    }
    return 0;
}

/*
 * Map state string from sockstat output to enum
 */
static net_state_t parse_state(const char *state) {
    if (!state) return NET_STATE_UNKNOWN;
    
    if (strcasecmp(state, "LISTEN") == 0)       return NET_STATE_LISTEN;
    if (strcasecmp(state, "ESTABLISHED") == 0)  return NET_STATE_ESTABLISHED;
    if (strcasecmp(state, "TIME_WAIT") == 0)    return NET_STATE_TIME_WAIT;
    if (strcasecmp(state, "CLOSE_WAIT") == 0)   return NET_STATE_CLOSE_WAIT;
    if (strcasecmp(state, "SYN_SENT") == 0)     return NET_STATE_SYN_SENT;
    if (strcasecmp(state, "SYN_RECV") == 0)     return NET_STATE_SYN_RECV;
    if (strcasecmp(state, "FIN_WAIT1") == 0)    return NET_STATE_FIN_WAIT1;
    if (strcasecmp(state, "FIN_WAIT2") == 0)    return NET_STATE_FIN_WAIT2;
    if (strcasecmp(state, "LAST_ACK") == 0)     return NET_STATE_LAST_ACK;
    if (strcasecmp(state, "CLOSED") == 0)       return NET_STATE_CLOSED;
    
    return NET_STATE_UNKNOWN;
}

/*
 * Split "addr:port" into components
 */
static void split_endpoint(const char *src, char *addr, size_t addr_size, int *port) {
    if (!src || !addr || !port) return;
    
    addr[0] = '\0';
    *port = 0;
    
    const char *last_colon = strrchr(src, ':');
    if (!last_colon) {
        strncpy(addr, src, addr_size - 1);
        return;
    }
    
    size_t alen = last_colon - src;
    if (alen >= addr_size) alen = addr_size - 1;
    strncpy(addr, src, alen);
    addr[alen] = '\0';
    
    *port = atoi(last_colon + 1);
    
    /* Strip surrounding brackets for IPv6 */
    if (addr[0] == '[') {
        memmove(addr, addr + 1, strlen(addr));
        char *rb = strchr(addr, ']');
        if (rb) *rb = '\0';
    }
}

/* ============================================================
 * INIT
 * ============================================================ */

void netinspect_init(netinspect_t *ni, int verbose) {
    if (!ni) return;
    memset(ni, 0, sizeof(*ni));
    ni->verbose = verbose;
}

void netinspect_free(netinspect_t *ni) {
    if (ni) memset(ni, 0, sizeof(*ni));
}

/* ============================================================
 * LIVE SCANNING
 * ============================================================ */

/*
 * Parse sockstat output.
 * 
 * Format: USER COMMAND PID FD PROTO LOCAL_ADDR FOREIGN_ADDR STATE
 * 
 * Example:
 * root     sshd      1234  3  tcp4   192.168.1.1:22     *:*             LISTEN
 */
static int parse_sockstat_line(const char *line, net_connection_t *conn) {
    char user[NET_STR_SMALL];
    char command[NET_MAX_PROC_NAME];
    char proto[NET_STR_SMALL];
    char local[NET_STR_MED];
    char remote[NET_STR_MED];
    char state[NET_STR_SMALL];
    int pid, fd;
    
    if (!line || !conn) return -1;
    
    memset(conn, 0, sizeof(*conn));
    
    int fields = sscanf(line, "%31s %63s %d %d %15s %63s %63s %31s",
                        user, command, &pid, &fd, proto, local, remote, state);
    
    if (fields < 8) {
        /* Maybe there's no state (UDP) */
        fields = sscanf(line, "%31s %63s %d %d %15s %63s %63s",
                        user, command, &pid, &fd, proto, local, remote);
        if (fields < 7) return -1;
        state[0] = '\0';
    }
    
    /* Determine protocol */
    if (strcmp(proto, "tcp4") == 0)      conn->proto = NET_PROTO_TCP;
    else if (strcmp(proto, "udp4") == 0) conn->proto = NET_PROTO_UDP;
    else if (strcmp(proto, "tcp6") == 0) conn->proto = NET_PROTO_TCP6;
    else if (strcmp(proto, "udp6") == 0) conn->proto = NET_PROTO_UDP6;
    else                                 conn->proto = NET_PROTO_UNKNOWN;
    
    conn->state = parse_state(state);
    
    /* Parse endpoints */
    split_endpoint(local, conn->local_addr, sizeof(conn->local_addr),
                   &conn->local_port);
    split_endpoint(remote, conn->remote_addr, sizeof(conn->remote_addr),
                   &conn->remote_port);
    
    conn->local_is_wildcard = (strcmp(conn->local_addr, "*") == 0 ||
                                strcmp(conn->local_addr, "0.0.0.0") == 0 ||
                                strcmp(conn->local_addr, "::") == 0);
    
    conn->remote_is_public = is_public_ip(conn->remote_addr);
    
    /* Process info */
    conn->pid = pid;
    strncpy(conn->process, command, sizeof(conn->process) - 1);
    
    conn->first_seen = time(NULL);
    conn->last_seen = conn->first_seen;
    conn->seen_count = 1;
    conn->suspicion = NET_SUSPICIOUS_NONE;
    
    return 0;
}

/*
 * Scan with sockstat and populate the current snapshot
 */
int netinspect_scan(netinspect_t *ni) {
    if (!ni) return -1;
    
    FILE *fp;
    char line[1024];
    net_snapshot_t *snap = &ni->current;
    
    memset(snap, 0, sizeof(*snap));
    snap->timestamp = time(NULL);
    
    /* Try IPv4 first */
    fp = popen("sockstat -4 2>/dev/null", "r");
    if (!fp) return -1;
    
    /* Skip header */
    fgets(line, sizeof(line), fp);
    
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        if (snap->connection_count >= NET_MAX_CONNECTIONS) break;
        
        net_connection_t *conn = &snap->connections[snap->connection_count];
        if (parse_sockstat_line(line, conn) == 0) {
            snap->connection_count++;
        }
    }
    pclose(fp);
    
    /* Now IPv6 */
    fp = popen("sockstat -6 2>/dev/null", "r");
    if (fp) {
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            
            if (snap->connection_count >= NET_MAX_CONNECTIONS) break;
            
            net_connection_t *conn = &snap->connections[snap->connection_count];
            if (parse_sockstat_line(line, conn) == 0) {
                snap->connection_count++;
            }
        }
        pclose(fp);
    }
    
    /* Count listeners and established */
    for (int i = 0; i < snap->connection_count; i++) {
        if (snap->connections[i].state == NET_STATE_LISTEN) {
            ni->total_listeners++;
        } else if (snap->connections[i].state == NET_STATE_ESTABLISHED) {
            ni->total_established++;
        }
    }
    ni->total_connections = snap->connection_count;
    
    return 0;
}

/* ============================================================
 * AGGREGATE IPS
 * ============================================================ */

static net_ip_t* find_or_add_ip(net_snapshot_t *snap, const char *addr) {
    if (!snap || !addr || !addr[0]) return NULL;
    
    /* Search existing */
    for (int i = 0; i < snap->ip_count; i++) {
        if (strcmp(snap->ips[i].addr, addr) == 0) {
            return &snap->ips[i];
        }
    }
    
    if (snap->ip_count >= NET_MAX_UNIQUE_IPS) return NULL;
    
    net_ip_t *ip = &snap->ips[snap->ip_count++];
    memset(ip, 0, sizeof(*ip));
    strncpy(ip->addr, addr, sizeof(ip->addr) - 1);
    ip->is_public = is_public_ip(addr);
    ip->is_local = !ip->is_public;
    ip->first_seen = time(NULL);
    ip->last_seen = ip->first_seen;
    return ip;
}

//old: static void aggregate_ips(netinspect_t *ni) {}
void netinspect_aggregate_ips(netinspect_t *ni) {
    net_snapshot_t *snap = &ni->current;
    
    snap->ip_count = 0;
    
    for (int i = 0; i < snap->connection_count; i++) {
        net_connection_t *c = &snap->connections[i];
        
        /* Skip wildcard */
        if (c->local_is_wildcard) continue;
        
        /* Local IP */
        if (c->local_addr[0]) {
            net_ip_t *ip = find_or_add_ip(snap, c->local_addr);
            if (ip) {
                ip->connection_count++;
                ip->last_seen = time(NULL);
                
                if (c->state == NET_STATE_LISTEN) ip->listen_count++;
                
                /* Track port */
                int found_port = 0;
                for (int p = 0; p < ip->port_count; p++) {
                    if (ip->ports[p] == c->local_port) { found_port = 1; break; }
                }
                if (!found_port && ip->port_count < NET_MAX_PORTS) {
                    ip->ports[ip->port_count++] = c->local_port;
                }
            }
        }
        
        /* Remote IP */
        if (c->remote_addr[0] && strcmp(c->remote_addr, "*") != 0 &&
            strcmp(c->remote_addr, "0.0.0.0") != 0) {
            net_ip_t *ip = find_or_add_ip(snap, c->remote_addr);
            if (ip) {
                ip->connection_count++;
                ip->last_seen = time(NULL);
            }
        }
    }
    
    /* Count public/local */
    ni->total_public_ips = 0;
    ni->total_local_ips = 0;
    for (int i = 0; i < snap->ip_count; i++) {
        if (snap->ips[i].is_public) ni->total_public_ips++;
        else                        ni->total_local_ips++;
    }
}

/* ============================================================
 * AGGREGATE PORTS
 * ============================================================ */

static net_port_t* find_or_add_port(net_snapshot_t *snap, int port, 
                                    net_proto_t proto) {
    if (!snap) return NULL;
    
    for (int i = 0; i < snap->port_count; i++) {
        if (snap->ports[i].port == port && snap->ports[i].proto == proto) {
            return &snap->ports[i];
        }
    }
    
    if (snap->port_count >= NET_MAX_PORTS) return NULL;
    
    net_port_t *p = &snap->ports[snap->port_count++];
    memset(p, 0, sizeof(*p));
    p->port = port;
    p->proto = proto;
    p->is_well_known = is_well_known_port(port);
    p->is_suspicious = is_suspicious_port(port);
    return p;
}

//old: static void aggregate_ports(netinspect_t *ni) {}
void netinspect_aggregate_ports(netinspect_t *ni) {
    net_snapshot_t *snap = &ni->current;
    snap->port_count = 0;
    
    for (int i = 0; i < snap->connection_count; i++) {
        net_connection_t *c = &snap->connections[i];
        
        if (c->local_port <= 0) continue;
        
        net_port_t *p = find_or_add_port(snap, c->local_port, c->proto);
        if (!p) continue;
        
        if (c->state == NET_STATE_LISTEN) p->listeners++;
        if (c->state == NET_STATE_ESTABLISHED) p->established++;
        
        /* Track process */
        if (p->process[0] == '\0' && c->process[0]) {
            strncpy(p->process, c->process, sizeof(p->process) - 1);
            p->pid = c->pid;
        }
    }
}

/* ============================================================
 * ANALYSIS
 * ============================================================ */

static void analyze_connection(net_connection_t *c) {
    if (!c) return;
    
    /* Rule 1: Listener on suspicious port */
    if (c->state == NET_STATE_LISTEN && is_suspicious_port(c->local_port)) {
        c->suspicion = NET_SUSPICIOUS_UNUSUAL_PORT;
        snprintf(c->suspicion_reason, sizeof(c->suspicion_reason),
                 "Listener on known malware/backdoor port %d", c->local_port);
        return;
    }
    
    /* Rule 2: Listener on wildcard with unusual port */
    if (c->state == NET_STATE_LISTEN && c->local_is_wildcard && 
        !is_well_known_port(c->local_port) && c->local_port > 10000 &&
        c->local_port < 49152) {
        c->suspicion = NET_SUSPICIOUS_HIGH_PORT;
        snprintf(c->suspicion_reason, sizeof(c->suspicion_reason),
                 "Listening on high port %d bound to all interfaces",
                 c->local_port);
        return;
    }
    
    /* Rule 3: External connection from unknown process */
    if (c->state == NET_STATE_ESTABLISHED && c->remote_is_public) {
        /* Check for known-safe processes */
        const char *safe[] = {"sshd", "httpd", "nginx", "apache", 
                              "sendmail", "postfix", "dovecot", 
                              "ntpd", "chrome", "firefox", NULL};
        int is_safe = 0;
        for (int i = 0; safe[i]; i++) {
            if (strcasecmp(c->process, safe[i]) == 0) {
                is_safe = 1;
                break;
            }
        }
        if (!is_safe && c->process[0]) {
            c->suspicion = NET_SUSPICIOUS_EXTERNAL_CONN;
            snprintf(c->suspicion_reason, sizeof(c->suspicion_reason),
                     "Connection to public IP %s:%d from unknown process %s",
                     c->remote_addr, c->remote_port, c->process);
        }
    }
}

static void analyze_ips(netinspect_t *ni) {
    net_snapshot_t *snap = &ni->current;
    
    for (int i = 0; i < snap->ip_count; i++) {
        net_ip_t *ip = &snap->ips[i];
        
        /* Rule: Many connections from same IP */
        if (ip->connection_count > 50) {
            ip->suspicion = NET_SUSPICIOUS_MANY_CONNS;
        }
    }
}

void netinspect_analyze(netinspect_t *ni) {
    if (!ni) return;
    
    net_snapshot_t *snap = &ni->current;
    
    ni->suspicious_count = 0;
    
    /* Analyze connections */
    for (int i = 0; i < snap->connection_count; i++) {
        analyze_connection(&snap->connections[i]);
        if (snap->connections[i].suspicion != NET_SUSPICIOUS_NONE) {
            ni->suspicious_count++;
            
            /* Create alert */
            if (ni->alert_count < NET_MAX_ALERTS) {
                net_alert_t *a = &ni->alerts[ni->alert_count++];
                a->timestamp = time(NULL);
                a->type = snap->connections[i].suspicion;
                snprintf(a->message, sizeof(a->message), "%s",
                         snap->connections[i].suspicion_reason);
                snprintf(a->local, sizeof(a->local), "%s:%d",
                         snap->connections[i].local_addr,
                         snap->connections[i].local_port);
                snprintf(a->remote, sizeof(a->remote), "%s:%d",
                         snap->connections[i].remote_addr,
                         snap->connections[i].remote_port);
                a->port = snap->connections[i].local_port;
                a->pid = snap->connections[i].pid;
                snprintf(a->process, sizeof(a->process), "%s",
                         snap->connections[i].process);
            }
        }
    }
    
    /* Analyze IPs */
    analyze_ips(ni);
}

void netinspect_diff_snapshots(netinspect_t *ni) {
    if (!ni || ni->snapshot_count < 2) return;
    
    int prev_idx = (ni->snapshot_index - 1 + NET_MAX_SNAPSHOTS) % NET_MAX_SNAPSHOTS;
    net_snapshot_t *prev = &ni->snapshots[prev_idx];
    net_snapshot_t *curr = &ni->current;
    
    printf(COL_BOLD "─── Snapshot Diff ───\n" COL_RESET);
    printf("  Previous: %d connections\n", prev->connection_count);
    printf("  Current:  %d connections\n", curr->connection_count);
    
    /* Find new connections */
    int new_conns = 0;
    for (int i = 0; i < curr->connection_count; i++) {
        net_connection_t *c = &curr->connections[i];
        int found = 0;
        for (int j = 0; j < prev->connection_count; j++) {
            net_connection_t *p = &prev->connections[j];
            if (c->local_port == p->local_port &&
                c->remote_port == p->remote_port &&
                strcmp(c->remote_addr, p->remote_addr) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) new_conns++;
    }
    
    if (new_conns > 0) {
        printf("  " COL_YELLOW "⚠ %d new connections since last snapshot" COL_RESET "\n",
               new_conns);
    } else {
        printf("  " COL_GREEN "✓ No new connections" COL_RESET "\n");
    }
}

/* ============================================================
 * REPORTING
 * ============================================================ */

void netinspect_print_connections(netinspect_t *ni) {
    if (!ni) return;
    
    net_snapshot_t *snap = &ni->current;
    
    printf("\n" COL_BOLD "═══ Live Connections (%d) ═══\n" COL_RESET "\n",
           snap->connection_count);
    
    if (snap->connection_count == 0) {
        printf("  No active connections\n");
        return;
    }
    
    printf("  %-10s %-15s %-22s %-22s %-8s %s\n",
           "PROTO", "STATE", "LOCAL", "REMOTE", "PID", "PROCESS");
    printf("  %-10s %-15s %-22s %-22s %-8s %s\n",
           "-----", "-----", "-----", "------", "---", "-------");
    
    for (int i = 0; i < snap->connection_count; i++) {
        net_connection_t *c = &snap->connections[i];
        
        const char *color = COL_RESET;
        if (c->suspicion != NET_SUSPICIOUS_NONE) color = COL_RED;
        
        char local_ep[NET_STR_LARGE];
        char remote_ep[NET_STR_LARGE];
        
        snprintf(local_ep, sizeof(local_ep), "%s:%d",
                 c->local_addr, c->local_port);
        snprintf(remote_ep, sizeof(remote_ep), "%s:%d",
                 c->remote_addr, c->remote_port);
        
        printf("  %s%-10s %-15s %-22s %-22s %-8d %s" COL_RESET "\n",
               color,
               netinspect_proto_string(c->proto),
               netinspect_state_string(c->state),
               local_ep,
               remote_ep,
               c->pid,
               c->process);
        
        /* Show suspicion reason */
        if (c->suspicion != NET_SUSPICIOUS_NONE) {
            printf("     " COL_RED "⚠ %s" COL_RESET "\n",
                   c->suspicion_reason);
        }
    }
}

void netinspect_print_ips(netinspect_t *ni) {
    if (!ni) return;
    
    net_snapshot_t *snap = &ni->current;
    
    printf("\n" COL_BOLD "═══ Unique IPs (%d) ═══\n" COL_RESET "\n",
           snap->ip_count);
    
    printf("  %-40s %-10s %-8s %-8s %s\n",
           "ADDRESS", "TYPE", "CONNS", "LISTENS", "PORTS");
    printf("  %-40s %-10s %-8s %-8s %s\n",
           "-------", "----", "-----", "-------", "-----");
    
    for (int i = 0; i < snap->ip_count; i++) {
        net_ip_t *ip = &snap->ips[i];
        
        const char *type = ip->is_public ? "PUBLIC" : "LOCAL";
        const char *color = ip->is_public ? COL_YELLOW : COL_GREEN;
        
        char ports[256] = {0};
        for (int p = 0; p < ip->port_count && p < 5; p++) {
            char tmp[16];
            snprintf(tmp, sizeof(tmp), "%s%d", p ? "," : "", ip->ports[p]);
            strncat(ports, tmp, sizeof(ports) - strlen(ports) - 1);
        }
        if (ip->port_count > 5) {
            strncat(ports, "...", sizeof(ports) - strlen(ports) - 1);
        }
        
        printf("  %s%-40s %-10s %-8d %-8d %s" COL_RESET "\n",
               color, ip->addr, type, ip->connection_count,
               ip->listen_count, ports);
    }
}

void netinspect_print_ports(netinspect_t *ni) {
    if (!ni) return;
    
    net_snapshot_t *snap = &ni->current;
    
    printf("\n" COL_BOLD "═══ Port Map (%d) ═══\n" COL_RESET "\n",
           snap->port_count);
    
    printf("  %-8s %-8s %-8s %-10s %-8s %s\n",
           "PORT", "PROTO", "LISTEN", "ESTAB", "PID", "PROCESS");
    printf("  %-8s %-8s %-8s %-10s %-8s %s\n",
           "----", "-----", "------", "-----", "---", "-------");
    
    for (int i = 0; i < snap->port_count; i++) {
        net_port_t *p = &snap->ports[i];
        
        const char *color = COL_RESET;
        if (p->is_suspicious) color = COL_RED;
        else if (!p->is_well_known && p->listeners > 0) color = COL_YELLOW;
        
        printf("  %s%-8d %-8s %-8d %-10d %-8d %s" COL_RESET "\n",
               color, p->port, netinspect_proto_string(p->proto),
               p->listeners, p->established, p->pid, p->process);
    }
}

void netinspect_print_alerts(netinspect_t *ni) {
    if (!ni) return;
    
    printf("\n" COL_BOLD "═══ Network Alerts (%d) ═══\n" COL_RESET "\n",
           ni->alert_count);
    
    if (ni->alert_count == 0) {
        printf("  " COL_GREEN "✓ No suspicious network activity" COL_RESET "\n");
        return;
    }
    
    for (int i = 0; i < ni->alert_count; i++) {
        net_alert_t *a = &ni->alerts[i];
        
        char timebuf[64];
        struct tm *tm = localtime(&a->timestamp);
        strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
        
        printf("  %s[" COL_RESET "%s%s" COL_RESET "%s] " COL_RESET,
               COL_DIM, timebuf, COL_DIM, COL_RESET);
        printf("%s%s%s\n", COL_RED,
               netinspect_suspicion_string(a->type), COL_RESET);
        printf("     %s\n", a->message);
        printf("     Local:  %s\n", a->local);
        printf("     Remote: %s\n", a->remote);
        printf("     PID:    %d (%s)\n", a->pid, a->process);
        printf("\n");
    }
}

void netinspect_print_summary(netinspect_t *ni) {
    if (!ni) return;
    
    printf("\n" COL_BOLD "═══ Network Inspector Summary ═══\n" COL_RESET "\n");
    printf("  Total connections:    %d\n", ni->total_connections);
    printf("  Total listeners:      %d\n", ni->total_listeners);
    printf("  Total established:    %d\n", ni->total_established);
    printf("  Unique local IPs:     %d\n", ni->total_local_ips);
    printf("  Unique public IPs:    %d\n", ni->total_public_ips);
    printf("  Unique ports:         %d\n", ni->current.port_count);
    
    if (ni->suspicious_count > 0) {
        printf("  %sSuspicious items:    %d" COL_RESET "\n",
               COL_RED, ni->suspicious_count);
    } else {
        printf("  %s✓ No suspicious items" COL_RESET "\n", COL_GREEN);
    }
}

void netinspect_print_full(netinspect_t *ni) {
    if (!ni) return;
    
    printf("\n");
    printf(COL_BOLD COL_CYAN "═══════════════════════════════════════════════════════════════\n");
    printf("  NETWORK INSPECTOR\n");
    printf("═══════════════════════════════════════════════════════════════\n" COL_RESET);
    
    netinspect_print_summary(ni);
    netinspect_print_connections(ni);
    netinspect_print_ips(ni);
    netinspect_print_ports(ni);
    netinspect_print_alerts(ni);
    
    netinspect_diff_snapshots(ni);
}

/* ============================================================
 * SYSEC INTEGRATION
 * ============================================================ */

void netinspect_report(netinspect_t *ni, syssec_t *s) {
    char buf[512];
    
    if (!ni || !s) return;
    
    /* Summary entry */
    snprintf(buf, sizeof(buf),
             "%d connections, %d listeners, %d established",
             ni->total_connections, ni->total_listeners,
             ni->total_established);
    syssec_report_add(s, "Network-Deep", "Connection Summary", buf,
                      SEV_INFO, STATUS_PASS, NULL);
    
    /* IP entries */
    snprintf(buf, sizeof(buf), "%d local, %d public",
             ni->total_local_ips, ni->total_public_ips);
    syssec_report_add(s, "Network-Deep", "Unique IPs", buf,
                      SEV_INFO, STATUS_PASS, NULL);
    
    /* Alerts */
    if (ni->alert_count > 0) {
        snprintf(buf, sizeof(buf), "%d suspicious items detected",
                 ni->alert_count);
        syssec_report_add(s, "Network-Deep", "Suspicious Activity", buf,
                          SEV_WARNING, STATUS_WARN,
                          "Review network alerts for details");
        
        /* Add individual critical alerts */
        for (int i = 0; i < ni->alert_count && i < 10; i++) {
            net_alert_t *a = &ni->alerts[i];
            
            if (a->type == NET_SUSPICIOUS_UNUSUAL_PORT ||
                a->type == NET_SUSPICIOUS_BLACKLISTED) {
                snprintf(buf, sizeof(buf), "%s", a->message);
                syssec_report_add(s, "Network-Deep",
                                  netinspect_suspicion_string(a->type),
                                  buf, SEV_CRITICAL, STATUS_FAIL,
                                  "Investigate immediately");
            }
        }
    } else {
        syssec_report_add(s, "Network-Deep", "Network Analysis",
                          "No suspicious network activity",
                          SEV_INFO, STATUS_PASS, NULL);
    }
}
