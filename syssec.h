#ifndef SYSSEC_H
#define SYSSEC_H

#define __BSD_VISIBLE 1
#define _WANT_FREEBSD11_STAT 1
#define _WANT_FREEBSD11_KINFO 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/disk.h>
#include <sys/disklabel.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ============================================================
 * VERSION & CONFIG
 * ============================================================ */

#define SYSSEC_VERSION      "1.1.0"
#define MAX_LINE            1024
#define MAX_PATH            512
#define MAX_NAME            256
#define MAX_STRING          1024
#define MAX_RESULTS         1024

/* ============================================================
 * COLORS
 * ============================================================ */

#define COL_RESET       "\033[0m"
#define COL_RED         "\033[31m"
#define COL_GREEN       "\033[32m"
#define COL_YELLOW      "\033[33m"
#define COL_BLUE        "\033[34m"
#define COL_MAGENTA     "\033[35m"
#define COL_CYAN        "\033[36m"
#define COL_WHITE       "\033[37m"
#define COL_BOLD        "\033[1m"
#define COL_DIM         "\033[2m"

/* ============================================================
 * ENUMS
 * ============================================================ */

typedef enum {
    SEV_INFO = 0,
    SEV_WARNING = 1,
    SEV_CRITICAL = 2
} severity_t;

typedef enum {
    STATUS_PASS = 0,
    STATUS_WARN = 1,
    STATUS_FAIL = 2,
    STATUS_UNKNOWN = 3
} status_t;

typedef enum {
    LOG_ERROR = 0,
    LOG_WARNING = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3
} log_level_t;

/* ============================================================
 * RESULT
 * ============================================================ */

typedef struct {
    char            name[128];
    char            description[512];
    char            recommendation[512];
    char            category[64];
    severity_t      severity;
    status_t        status;
} result_t;

/* ============================================================
 * SCANNER STATE
 * ============================================================ */

typedef struct {
    result_t        results[MAX_RESULTS];
    int             count;
    
    char            hostname[MAX_NAME];
    char            kernel[MAX_STRING];
    char            os_release[MAX_NAME];
    char            cpu_model[MAX_NAME];
    int             ncpu;
    long            physmem;
    long            boot_time;
    time_t          timestamp;
    
    int             passed;
    int             warnings;
    int             failures;
    
    int             verbose;
    int             is_root;
} syssec_t;

/* ============================================================
 * PUBLIC API
 * ============================================================ */

void syssec_init(syssec_t *s, int verbose);
void syssec_free(syssec_t *s);
void syssec_scan(syssec_t *s);

/* Individual checks */
void syssec_check_system(syssec_t *s);
void syssec_check_processes(syssec_t *s);
void syssec_check_users(syssec_t *s);
void syssec_check_filesystem(syssec_t *s);
void syssec_check_disks(syssec_t *s);
void syssec_check_dev(syssec_t *s);
void syssec_check_sys(syssec_t *s);
void syssec_check_network(syssec_t *s);
void syssec_check_services(syssec_t *s);
void syssec_check_security(syssec_t *s);
void syssec_check_ssh(syssec_t *s);
void syssec_check_suid(syssec_t *s);
void syssec_check_ttys(syssec_t *s);
void syssec_check_logs(syssec_t *s);
void syssec_check_updates(syssec_t *s);

/* Reporting */
void syssec_print_banner(void);
void syssec_print_summary(syssec_t *s);
void syssec_print_results(syssec_t *s);
void syssec_print_critical(syssec_t *s);
void syssec_print_recommendations(syssec_t *s);

int  syssec_save_report(syssec_t *s, const char *path);

void syssec_log(log_level_t level, const char *fmt, ...);

/*
 * syssec_report_add - Public wrapper for adding a result
 * (used by parser.c to inject findings)
 */
void syssec_report_add(syssec_t *s, const char *category,
                       const char *name, const char *desc,
                       severity_t sev, status_t status,
                       const char *rec);

void syssec_check_deep_parse(syssec_t *s);

#endif /* SYSSEC_H */
