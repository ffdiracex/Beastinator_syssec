/*
 * syssec.c - SYSSEC: System Security Tools for FreeBSD
 * 
 * Enhanced version with verbose progressive output.
 * 
 * Compile: cc -Wall -Wextra -O2 syssec.c -o syssec -lm
 * Run:     sudo ./syssec [-v] [-o output.html]
 */

#include "syssec.h"
#include "parser.h"
#include "netinspect.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

static log_level_t g_log_level = LOG_INFO;
static int g_quiet = 0;
static void check_start(const char *fmt, ...);
static void add_result(syssec_t *s, const char *category, const char *name, const char *desc,
                severity_t sev, status_t status, const char *rec);



void syssec_check_network_deep(syssec_t *s) {
    netinspect_t ni;
    
    if (!s) return;
    
    printf("\n");
    check_start("Deep Network Inspection");
    
    netinspect_init(&ni, s->verbose);
    
    /* Scan */
    if (netinspect_scan(&ni) != 0) {
        add_result(s, "Network-Deep", "Scan",
                   "Failed to scan network",
                   SEV_WARNING, STATUS_WARN, NULL);
        return;
    }
    
    /* Aggregate */
    aggregate_ips(&ni);
    aggregate_ports(&ni);
    
    /* Analyze */
    netinspect_analyze(&ni);
    
    /* Print full report if verbose */
    if (s->verbose) {
        netinspect_print_full(&ni);
    } else {
        netinspect_print_summary(&ni);
    }
    
    /* Report to syssec */
    netinspect_report(&ni, s);
    
    netinspect_free(&ni);
}

/* ============================================================
 * LOGGING
 * ============================================================ */


void syssec_log(log_level_t level, const char *fmt, ...) {
    va_list args;
    time_t now;
    struct tm *tm;
    char timebuf[64];
    const char *level_str;
    const char *color;
    
    if (g_quiet && level > LOG_ERROR) return;
    if (level > g_log_level) return;
    
    switch (level) {
        case LOG_ERROR:   level_str = "ERROR";   color = COL_RED;     break;
        case LOG_WARNING: level_str = "WARNING"; color = COL_YELLOW;  break;
        case LOG_INFO:    level_str = "INFO";    color = COL_GREEN;   break;
        case LOG_DEBUG:   level_str = "DEBUG";   color = COL_CYAN;    break;
        default:          level_str = "?";       color = COL_RESET;   break;
    }
    
    now = time(NULL);
    tm = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
    
    fprintf(stderr, "%s[%s] %-7s%s ", COL_DIM, timebuf, level_str, COL_RESET);
    fprintf(stderr, "%s", color);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "%s\n", COL_RESET);
}

/* ============================================================
 * VERBOSE HELPERS
 * ============================================================ */

/*
 * Start a check group
 */
static void check_start(const char *fmt, ...) {
    va_list args;
    if (g_log_level < LOG_INFO) return;
    printf(COL_BOLD COL_CYAN "▸ " COL_RESET);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

/*
 * Print an item result during check
 */
static void check_item(const char *item, int status, const char *extra) {
    if (g_log_level < LOG_INFO) return;
    
    const char *color;
    const char *symbol;
    
    switch (status) {
        case 0:  color = COL_GREEN;  symbol = "✓"; break;
        case 1:  color = COL_YELLOW; symbol = "⚠"; break;
        case 2:  color = COL_RED;    symbol = "✗"; break;
        default: color = COL_BLUE;   symbol = "?"; break;
    }
    
    printf("    %s%s%s %-40s", color, symbol, COL_RESET, item);
    
    if (extra && extra[0]) {
        printf(" " COL_DIM "%s" COL_RESET, extra);
    }
    printf("\n");
    fflush(stdout);
}

/*
 * Print an item being checked (in progress)
 */
static void check_progress(const char *fmt, ...) {
    va_list args;
    if (g_log_level < LOG_INFO) return;
    
    printf(COL_DIM "    ... ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(COL_RESET "\n");
    fflush(stdout);
}

/* ============================================================
 * RESULT MANAGEMENT
 * ============================================================ */

static void add_result(syssec_t *s, const char *category,
                       const char *name, const char *desc,
                       severity_t sev, status_t status,
                       const char *rec) {
    result_t *r;
    
    if (!s || s->count >= MAX_RESULTS) return;
    
    r = &s->results[s->count++];
    
    strncpy(r->name, name ? name : "", sizeof(r->name) - 1);
    strncpy(r->description, desc ? desc : "", sizeof(r->description) - 1);
    strncpy(r->recommendation, rec ? rec : "", sizeof(r->recommendation) - 1);
    strncpy(r->category, category ? category : "General", sizeof(r->category) - 1);
    
    r->severity = sev;
    r->status = status;
    
    switch (status) {
        case STATUS_PASS: s->passed++;   break;
        case STATUS_WARN: s->warnings++; break;
        case STATUS_FAIL: s->failures++; break;
        default: break;
    }
    
    /* Verbose per-item output */
    check_item(name, status, desc);
}

/* ============================================================
 * HELPERS
 * ============================================================ */

static int proc_running(const char *name) {
    char buf[256];
    snprintf(buf, sizeof(buf), "pgrep -x %s >/dev/null 2>&1", name);
    return system(buf) == 0;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void get_hostname(char *buf, size_t size) {
    size_t len = size;
    if (sysctlbyname("kern.hostname", buf, &len, NULL, 0) < 0) {
        strncpy(buf, "unknown", size - 1);
    }
}

static void get_kernel_version(char *buf, size_t size) {
    size_t len = size;
    if (sysctlbyname("kern.version", buf, &len, NULL, 0) < 0) {
        strncpy(buf, "unknown", size - 1);
    }
}

static void get_os_release(char *buf, size_t size) {
    size_t len = size;
    if (sysctlbyname("kern.osrelease", buf, &len, NULL, 0) < 0) {
        strncpy(buf, "unknown", size - 1);
    }
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void syssec_init(syssec_t *s, int verbose) {
    if (!s) return;
    
    memset(s, 0, sizeof(syssec_t));
    
    s->verbose = verbose;
    s->is_root = (geteuid() == 0);
    s->timestamp = time(NULL);
    
    get_hostname(s->hostname, sizeof(s->hostname));
    get_kernel_version(s->kernel, sizeof(s->kernel));
    get_os_release(s->os_release, sizeof(s->os_release));
    
    size_t len = sizeof(s->ncpu);
    sysctlbyname("hw.ncpu", &s->ncpu, &len, NULL, 0);
    
    len = sizeof(s->cpu_model);
    sysctlbyname("hw.model", s->cpu_model, &len, NULL, 0);
    
    len = sizeof(s->physmem);
    sysctlbyname("hw.physmem", &s->physmem, &len, NULL, 0);
    
    len = sizeof(s->boot_time);
    sysctlbyname("kern.boottime", &s->boot_time, &len, NULL, 0);
}

void syssec_free(syssec_t *s) {
    if (s) memset(s, 0, sizeof(syssec_t));
}

/* ============================================================
 * CHECK: SYSTEM
 * ============================================================ */

void syssec_check_system(syssec_t *s) {
    char buf[512];
    time_t uptime;
    
    if (!s) return;
    
    check_start("System Information");
    
    snprintf(buf, sizeof(buf), "%d cores: %s", s->ncpu, s->cpu_model);
    add_result(s, "System", "CPU", buf, SEV_INFO, STATUS_PASS, NULL);
    
    snprintf(buf, sizeof(buf), "%ld MB total", s->physmem / (1024 * 1024));
    add_result(s, "System", "Memory", buf, SEV_INFO, STATUS_PASS, NULL);
    
    uptime = s->timestamp - s->boot_time;
    snprintf(buf, sizeof(buf), "%ld days, %02ld:%02ld:%02ld",
             uptime / 86400,
             (uptime % 86400) / 3600,
             (uptime % 3600) / 60,
             uptime % 60);
    add_result(s, "System", "Uptime", buf, SEV_INFO, STATUS_PASS, NULL);
    
    struct loadavg load;
    size_t len = sizeof(load);
    int mib[2] = {CTL_VM, VM_LOADAVG};
    if (sysctl(mib, 2, &load, &len, NULL, 0) == 0) {
        double l1 = (double)load.ldavg[0] / load.fscale;
        double l5 = (double)load.ldavg[1] / load.fscale;
        double l15 = (double)load.ldavg[2] / load.fscale;
        
        snprintf(buf, sizeof(buf), "%.2f, %.2f, %.2f", l1, l5, l15);
        
        status_t status = STATUS_PASS;
        severity_t sev = SEV_INFO;
        const char *rec = NULL;
        
        if (s->ncpu > 0 && l1 > s->ncpu * 1.5) {
            status = STATUS_WARN;
            sev = SEV_WARNING;
            rec = "High load - check running processes";
        }
        
        add_result(s, "System", "Load Average", buf, sev, status, rec);
    }
}

/* ============================================================
 * CHECK: PROCESSES
 * ============================================================ */

void syssec_check_processes(syssec_t *s) {
    struct kinfo_proc *procs = NULL;
    size_t len = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int count, zombies = 0, running = 0, sleeping = 0;
    char buf[512];
    
    if (!s) return;
    
    check_start("Processes");
    
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        add_result(s, "Processes", "Process Scan", "Failed to read process list",
                   SEV_WARNING, STATUS_WARN, "Check permissions");
        return;
    }
    
    procs = malloc(len);
    if (!procs) return;
    
    if (sysctl(mib, 4, procs, &len, NULL, 0) < 0) {
        free(procs);
        return;
    }
    
    count = len / sizeof(struct kinfo_proc);
    
    for (int i = 0; i < count; i++) {
        switch (procs[i].ki_stat) {
            case 'Z': zombies++; break;
            case 'R': running++; break;
            case 'S': sleeping++; break;
        }
    }
    
    free(procs);
    
    snprintf(buf, sizeof(buf), "%d total (%d running, %d sleeping, %d zombie)",
             count, running, sleeping, zombies);
    
    status_t status = STATUS_PASS;
    severity_t sev = SEV_INFO;
    const char *rec = NULL;
    
    if (zombies > 10) {
        status = STATUS_WARN;
        sev = SEV_WARNING;
        rec = "Many zombie processes - check parent processes";
    }
    
    if (count > 500) {
        status = STATUS_WARN;
        sev = SEV_WARNING;
        rec = "High process count - check for runaway processes";
    }
    
    add_result(s, "Processes", "Process Count", buf, sev, status, rec);
}

/* ============================================================
 * CHECK: USERS
 * ============================================================ */

void syssec_check_users(syssec_t *s) {
    struct passwd *pw;
    int total = 0, uid0 = 0, valid_shell = 0;
    char buf[512];
    char bad_users[256] = {0};
    uid_t seen_uids[1024];
    int seen_count = 0, duplicates = 0;
    
    if (!s) return;
    
    check_start("User Accounts");
    
    setpwent();
    while ((pw = getpwent()) != NULL) {
        total++;
        
        if (pw->pw_uid == 0 && strcmp(pw->pw_name, "root") != 0) {
            uid0++;
            if (bad_users[0]) strncat(bad_users, ", ", sizeof(bad_users) - strlen(bad_users) - 1);
            strncat(bad_users, pw->pw_name, sizeof(bad_users) - strlen(bad_users) - 1);
        }
        
        if (strcmp(pw->pw_shell, "/sbin/nologin") != 0 &&
            strcmp(pw->pw_shell, "/usr/sbin/nologin") != 0 &&
            strcmp(pw->pw_shell, "/bin/false") != 0) {
            valid_shell++;
        }
        
        for (int i = 0; i < seen_count; i++) {
            if (seen_uids[i] == pw->pw_uid && pw->pw_uid != 0) {
                duplicates++;
                break;
            }
        }
        if (seen_count < 1024) seen_uids[seen_count++] = pw->pw_uid;
    }
    endpwent();
    
    snprintf(buf, sizeof(buf), "%d users (%d with shell)", total, valid_shell);
    add_result(s, "Users", "User Accounts", buf, SEV_INFO, STATUS_PASS, NULL);
    
    if (uid0 > 0) {
        snprintf(buf, sizeof(buf), "Found %d additional UID 0: %s", uid0, bad_users);
        add_result(s, "Users", "UID 0 Users", buf, SEV_CRITICAL, STATUS_FAIL,
                   "Remove additional UID 0 users immediately");
    } else {
        add_result(s, "Users", "UID 0 Users", "Only root has UID 0",
                   SEV_INFO, STATUS_PASS, NULL);
    }
    
    if (duplicates > 0) {
        snprintf(buf, sizeof(buf), "%d duplicate UIDs found", duplicates);
        add_result(s, "Users", "Duplicate UIDs", buf, SEV_WARNING, STATUS_WARN,
                   "Each user should have a unique UID");
    }
}

/* ============================================================
 * CHECK: FILESYSTEM
 * ============================================================ */

void syssec_check_filesystem(syssec_t *s) {
    const struct {
        const char *path;
        mode_t      expected;
        const char *name;
        int         critical;
    } files[] = {
        {"/etc/passwd",        0644, "Passwd file",    0},
        {"/etc/master.passwd", 0600, "Master passwd",  1},
        {"/etc/group",         0644, "Group file",     0},
        {"/etc/sudoers",       0440, "Sudoers file",   1},
        {NULL, 0, NULL, 0}
    };
    
    char buf[512];
    
    if (!s) return;
    
    check_start("Critical Filesystem Files");
    
    for (int i = 0; files[i].path != NULL; i++) {
        struct stat st;
        
        if (stat(files[i].path, &st) < 0) {
            snprintf(buf, sizeof(buf), "%s does not exist", files[i].path);
            add_result(s, "Filesystem", files[i].name, buf,
                       files[i].critical ? SEV_CRITICAL : SEV_WARNING,
                       STATUS_FAIL,
                       "File should exist with proper permissions");
            continue;
        }
        
        mode_t mode = st.st_mode & 0777;
        snprintf(buf, sizeof(buf), "Permissions: %03o", mode);
        
        status_t status = STATUS_PASS;
        severity_t sev = SEV_INFO;
        const char *rec = NULL;
        
        if (mode != files[i].expected) {
            if (st.st_mode & S_IWOTH) {
                status = STATUS_FAIL;
                sev = files[i].critical ? SEV_CRITICAL : SEV_WARNING;
                snprintf(buf, sizeof(buf), "WORLD-WRITABLE (%03o)", mode);
                rec = "Remove world-writable permission immediately";
            } else {
                status = STATUS_WARN;
                sev = SEV_WARNING;
                rec = "Check file permissions";
            }
        }
        
        add_result(s, "Filesystem", files[i].name, buf, sev, status, rec);
    }
    
    /* World-writable directories */
    const char *dirs[] = {"/tmp", "/var/tmp", "/usr/tmp", NULL};
    check_start("Temporary Directories");
    
    for (int i = 0; dirs[i] != NULL; i++) {
        struct stat st;
        if (stat(dirs[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            if (st.st_mode & S_ISVTX) {
                snprintf(buf, sizeof(buf), "%s has sticky bit", dirs[i]);
                add_result(s, "Filesystem", dirs[i], buf, SEV_INFO, STATUS_PASS, NULL);
            } else if (st.st_mode & S_IWOTH) {
                snprintf(buf, sizeof(buf), "%s world-writable, no sticky bit!", dirs[i]);
                add_result(s, "Filesystem", dirs[i], buf, SEV_CRITICAL, STATUS_FAIL,
                           "Add sticky bit: chmod +t");
            } else {
                snprintf(buf, sizeof(buf), "%s ok", dirs[i]);
                add_result(s, "Filesystem", dirs[i], buf, SEV_INFO, STATUS_PASS, NULL);
            }
        }
    }
}

/* ============================================================
 * CHECK: DISKS
 * ============================================================ */

void syssec_check_disks(syssec_t *s) {
    char buf[512];
    FILE *fp;
    char line[1024];
    
    if (!s) return;
    
    check_start("Disk Usage");
    
    /* df for mounted filesystems */
    fp = popen("df -h 2>/dev/null", "r");
    if (fp) {
        int first = 1;
        while (fgets(line, sizeof(line), fp)) {
            if (first) { first = 0; continue; }
            
            char filesystem[128], size[32], used[32], avail[32], capacity[16], mount[256];
            if (sscanf(line, "%127s %31s %31s %31s %15s %255s",
                       filesystem, size, used, avail, capacity, mount) >= 5) {
                int cap = atoi(capacity);
                
                snprintf(buf, sizeof(buf), "%s: %s used of %s (%s)",
                         mount, used, size, capacity);
                
                status_t status = STATUS_PASS;
                severity_t sev = SEV_INFO;
                const char *rec = NULL;
                
                if (cap >= 95) {
                    status = STATUS_FAIL;
                    sev = SEV_CRITICAL;
                    rec = "Disk almost full - free space immediately";
                } else if (cap >= 80) {
                    status = STATUS_WARN;
                    sev = SEV_WARNING;
                    rec = "Disk getting full - monitor usage";
                }
                
                add_result(s, "Disks", mount, buf, sev, status, rec);
            }
        }
        pclose(fp);
    }
    
    /* Physical disks */
    check_start("Physical Disks");
    
    DIR *dev = opendir("/dev");
    if (dev) {
        struct dirent *entry;
        while ((entry = readdir(dev)) != NULL) {
            /* Look for ada*, da*, nvd*, ada*p*, da*p*, etc. */
            if ((strncmp(entry->d_name, "ada", 3) == 0 ||
                 strncmp(entry->d_name, "da", 2) == 0 ||
                 strncmp(entry->d_name, "nvd", 3) == 0 ||
                 strncmp(entry->d_name, "mmcsd", 5) == 0)) {
                
                char path[512];
                snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
                
                struct stat st;
                if (stat(path, &st) == 0 && S_ISCHR(st.st_mode)) {
                    /* Read disk size via ioctl */
                    int fd = open(path, O_RDONLY);
                    if (fd >= 0) {
                        off_t media_size = 0;
                        if (ioctl(fd, DIOCGMEDIASIZE, &media_size) == 0) {
                            snprintf(buf, sizeof(buf), "%lld MB",
                                     (long long)(media_size / (1024 * 1024)));
                            add_result(s, "Disks", entry->d_name, buf,
                                       SEV_INFO, STATUS_PASS, NULL);
                        } else {
                            add_result(s, "Disks", entry->d_name, "unknown size",
                                       SEV_INFO, STATUS_PASS, NULL);
                        }
                        close(fd);
                    }
                }
            }
        }
        closedir(dev);
    }
    
    /* Swap */
    check_start("Swap");
    fp = popen("swapinfo -m 2>/dev/null | tail -n +2", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char device[128];
            int total, used, avail;
            int percent = 0;
            
            if (sscanf(line, "%127s %d %d %d %d%%",
                       device, &total, &used, &avail, &percent) >= 4) {
                snprintf(buf, sizeof(buf), "%s: %d used of %d MB (%d%%)",
                         device, used, total, percent);
                
                status_t status = STATUS_PASS;
                severity_t sev = SEV_INFO;
                const char *rec = NULL;
                
                if (percent >= 90) {
                    status = STATUS_FAIL;
                    sev = SEV_CRITICAL;
                    rec = "Swap nearly full - add more swap";
                } else if (percent >= 50) {
                    status = STATUS_WARN;
                    sev = SEV_WARNING;
                    rec = "Swap usage moderate - monitor";
                }
                
                add_result(s, "Disks", device, buf, sev, status, rec);
            }
        }
        pclose(fp);
    }
}

/* ============================================================
 * CHECK: /dev
 * ============================================================ */

void syssec_check_dev(syssec_t *s) {
    DIR *dir;
    struct dirent *entry;
    char buf[512];
    int total = 0;
    int char_devs = 0;
    int block_devs = 0;
    int world_writable = 0;
    int symlinks = 0;
    char suspicious_list[512] = {0};
    
    if (!s) return;
    
    check_start("Device Files (/dev)");
    
    dir = opendir("/dev");
    if (!dir) {
        add_result(s, "Devices", "/dev", "Cannot open /dev",
                   SEV_WARNING, STATUS_WARN, NULL);
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char path[512];
        snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
        
        struct stat st;
        if (lstat(path, &st) < 0) continue;
        
        total++;
        
        if (S_ISCHR(st.st_mode)) char_devs++;
        else if (S_ISBLK(st.st_mode)) block_devs++;
        else if (S_ISLNK(st.st_mode)) symlinks++;
        
        /* Check for world-writable device nodes (suspicious) */
        if ((S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) &&
            (st.st_mode & S_IWOTH)) {
            world_writable++;
            if (strlen(suspicious_list) < sizeof(suspicious_list) - 64) {
                if (suspicious_list[0]) {
                    strncat(suspicious_list, ", ",
                            sizeof(suspicious_list) - strlen(suspicious_list) - 1);
                }
                strncat(suspicious_list, entry->d_name,
                        sizeof(suspicious_list) - strlen(suspicious_list) - 1);
            }
        }
    }
    closedir(dir);
    
    snprintf(buf, sizeof(buf), "%d devices (%d char, %d block, %d symlinks)",
             total, char_devs, block_devs, symlinks);
    add_result(s, "Devices", "/dev Summary", buf, SEV_INFO, STATUS_PASS, NULL);
    
    if (world_writable > 0) {
        snprintf(buf, sizeof(buf), "%d world-writable devices: %s",
                 world_writable, suspicious_list);
        add_result(s, "Devices", "World-Writable", buf,
                   SEV_WARNING, STATUS_WARN,
                   "Review world-writable device nodes");
    } else {
        add_result(s, "Devices", "World-Writable",
                   "No world-writable device nodes",
                   SEV_INFO, STATUS_PASS, NULL);
    }
    
    /* Check /dev/console, /dev/null, /dev/zero exist */
    const char *required[] = {"/dev/null", "/dev/zero", "/dev/random",
                              "/dev/urandom", "/dev/console", NULL};
    
    check_start("Essential Devices");
    
    for (int i = 0; required[i] != NULL; i++) {
        if (file_exists(required[i])) {
            add_result(s, "Devices", required[i], "present",
                       SEV_INFO, STATUS_PASS, NULL);
        } else {
            snprintf(buf, sizeof(buf), "%s missing!", required[i]);
            add_result(s, "Devices", required[i], buf,
                       SEV_WARNING, STATUS_WARN,
                       "Essential device missing");
        }
    }
}

/* ============================================================
 * CHECK: /sys
 * ============================================================ */

void syssec_check_sys(syssec_t *s) {
    DIR *dir;
    struct dirent *entry;
    char buf[512];
    int found = 0;
    
    if (!s) return;
    
    check_start("Sysfs (/sys)");
    
    if (!file_exists("/sys")) {
        add_result(s, "Sysfs", "/sys", "Not mounted (expected on FreeBSD)",
                   SEV_INFO, STATUS_PASS, NULL);
        return;
    }
    
    /* Check /sys/devices */
    if (file_exists("/sys/devices")) {
        check_progress("scanning /sys/devices...");
        dir = opendir("/sys/devices");
        if (dir) {
            int count = 0;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                count++;
            }
            closedir(dir);
            snprintf(buf, sizeof(buf), "%d devices", count);
            add_result(s, "Sysfs", "/sys/devices", buf,
                       SEV_INFO, STATUS_PASS, NULL);
            found++;
        }
    }
    
    /* Check /sys/class */
    if (file_exists("/sys/class")) {
        check_progress("scanning /sys/class...");
        dir = opendir("/sys/class");
        if (dir) {
            int count = 0;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                count++;
            }
            closedir(dir);
            snprintf(buf, sizeof(buf), "%d classes", count);
            add_result(s, "Sysfs", "/sys/class", buf,
                       SEV_INFO, STATUS_PASS, NULL);
            found++;
        }
    }
    
    /* Check /sys/module */
    if (file_exists("/sys/module")) {
        check_progress("scanning /sys/module...");
        dir = opendir("/sys/module");
        if (dir) {
            int count = 0;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                count++;
                if (g_log_level >= LOG_INFO) {
                    printf(COL_DIM "      module: %s" COL_RESET "\n", entry->d_name);
                }
            }
            closedir(dir);
            snprintf(buf, sizeof(buf), "%d modules", count);
            add_result(s, "Sysfs", "/sys/module", buf,
                       SEV_INFO, STATUS_PASS, NULL);
            found++;
        }
    }
    
    if (found == 0) {
        add_result(s, "Sysfs", "/sys", "No standard /sys entries found",
                   SEV_INFO, STATUS_PASS, NULL);
    }
}

/* ============================================================
 * CHECK: TTY (verbose per-TTY)
 * ============================================================ */

void syssec_check_ttys(syssec_t *s) {
    DIR *dev;
    struct dirent *entry;
    char buf[512];
    int total = 0;
    int active = 0;
    int suspicious = 0;
    char suspicious_list[512] = {0};
    
    if (!s) return;
    
    check_start("TTY Devices (/dev/tty*)");
    
    dev = opendir("/dev");
    if (!dev) return;
    
    while ((entry = readdir(dev)) != NULL) {
        /* Match tty* devices */
        if (strncmp(entry->d_name, "tty", 3) != 0) continue;
        if (strlen(entry->d_name) <= 3) continue;
        
        char path[512];
        snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
        
        struct stat st;
        if (stat(path, &st) < 0) continue;
        if (!S_ISCHR(st.st_mode)) continue;
        
        total++;
        
        /* Check if active via /proc */
        int is_active = 0;
        if (file_exists("/proc")) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "find /proc -maxdepth 3 -name 0 -path '*/fd/0' "
                     "-exec readlink {} \\; 2>/dev/null | grep -q '%s$'",
                     path);
            is_active = (system(cmd) == 0);
        }
        
        if (is_active) {
            active++;
            
            /* Check if there's a login on it */
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "who 2>/dev/null | grep -q '%s'",
                     entry->d_name);
            
            if (system(cmd) != 0) {
                suspicious++;
                if (strlen(suspicious_list) < sizeof(suspicious_list) - 64) {
                    if (suspicious_list[0]) {
                        strncat(suspicious_list, ", ",
                                sizeof(suspicious_list) - strlen(suspicious_list) - 1);
                    }
                    strncat(suspicious_list, entry->d_name,
                            sizeof(suspicious_list) - strlen(suspicious_list) - 1);
                }
                check_item(entry->d_name, 2, "active, no login session");
            } else {
                check_item(entry->d_name, 0, "active, login present");
            }
        } else {
            if (s->verbose) {
                check_item(entry->d_name, 0, "inactive");
            }
        }
    }
    closedir(dev);
    
    snprintf(buf, sizeof(buf), "%d TTYs, %d active", total, active);
    add_result(s, "TTY", "TTY Summary", buf, SEV_INFO, STATUS_PASS, NULL);
    
    if (suspicious > 0) {
        snprintf(buf, sizeof(buf), "%d suspicious: %s",
                 suspicious, suspicious_list);
        add_result(s, "TTY", "Suspicious TTYs", buf,
                   SEV_WARNING, STATUS_WARN,
                   "Investigate TTYs without login sessions");
    }
}

/* ============================================================
 * CHECK: NETWORK
 * ============================================================ */

void syssec_check_network(syssec_t *s) {
    FILE *fp;
    char buf[512];
    int ports;
    
    if (!s) return;
    
    check_start("Network");
    
    fp = popen("sockstat -4 -l 2>/dev/null | grep -v '^USER' | wc -l", "r");
    if (fp) {
        if (fgets(buf, sizeof(buf), fp)) {
            ports = atoi(buf);
            pclose(fp);
            
            snprintf(buf, sizeof(buf), "%d listening TCP ports", ports);
            
            status_t status = STATUS_PASS;
            severity_t sev = SEV_INFO;
            const char *rec = NULL;
            
            if (ports > 20) {
                status = STATUS_WARN;
                sev = SEV_WARNING;
                rec = "Many listening ports - review with 'sockstat -4 -l'";
            }
            
            add_result(s, "Network", "Listening Ports", buf, sev, status, rec);
        } else {
            pclose(fp);
        }
    }
    
    int pf_running = proc_running("pfctl");
    int ipfw_running = proc_running("ipfw");
    
    if (pf_running || ipfw_running) {
        add_result(s, "Network", "Firewall", "Firewall is running",
                   SEV_INFO, STATUS_PASS, NULL);
    } else {
        add_result(s, "Network", "Firewall", "No firewall detected",
                   SEV_CRITICAL, STATUS_FAIL,
                   "Enable PF: add 'pf_enable=\"YES\"' to /etc/rc.conf");
    }
    
    int ip_forward = 0;
    size_t len = sizeof(ip_forward);
    if (sysctlbyname("net.inet.ip.forwarding", &ip_forward, &len, NULL, 0) == 0) {
        if (ip_forward) {
            add_result(s, "Network", "IP Forwarding",
                       "IP forwarding is ENABLED",
                       SEV_WARNING, STATUS_WARN,
                       "Disable if not a router");
        } else {
            add_result(s, "Network", "IP Forwarding",
                       "IP forwarding disabled",
                       SEV_INFO, STATUS_PASS, NULL);
        }
    }
}

/* ============================================================
 * CHECK: SERVICES
 * ============================================================ */

void syssec_check_services(syssec_t *s) {
    const char *critical[] = {"syslogd", "cron", "sshd", NULL};
    const char *dangerous[] = {"telnetd", "ftpd", "rlogind", "rshd", "inetd", NULL};
    char buf[512];
    
    if (!s) return;
    
    check_start("Critical Services");
    
    for (int i = 0; critical[i] != NULL; i++) {
        int running = proc_running(critical[i]);
        
        snprintf(buf, sizeof(buf), "%s", running ? "running" : "STOPPED");
        
        if (running) {
            add_result(s, "Services", critical[i], buf, SEV_INFO, STATUS_PASS, NULL);
        } else {
            snprintf(buf, sizeof(buf), "Service '%s' is not running", critical[i]);
            add_result(s, "Services", critical[i], buf, SEV_WARNING, STATUS_WARN,
                       "Check if service should be running");
        }
    }
    
    check_start("Dangerous Services");
    
    for (int i = 0; dangerous[i] != NULL; i++) {
        if (proc_running(dangerous[i])) {
            snprintf(buf, sizeof(buf), "Insecure service '%s' running!", dangerous[i]);
            add_result(s, "Services", dangerous[i], buf, SEV_CRITICAL, STATUS_FAIL,
                       "Disable immediately - insecure");
        } else {
            add_result(s, "Services", dangerous[i], "not running",
                       SEV_INFO, STATUS_PASS, NULL);
        }
    }
}

/* ============================================================
 * CHECK: SECURITY
 * ============================================================ */

void syssec_check_security(syssec_t *s) {
    char buf[512];
    int value;
    size_t len;
    
    if (!s) return;
    
    check_start("Kernel Security Settings");
    
    len = sizeof(value);
    if (sysctlbyname("kern.securelevel", &value, &len, NULL, 0) == 0) {
        snprintf(buf, sizeof(buf), "Securelevel: %d", value);
        
        if (value == 0) {
            add_result(s, "Security", "Securelevel", buf,
                       SEV_WARNING, STATUS_WARN,
                       "Set kern.securelevel=1 in /etc/sysctl.conf");
        } else {
            add_result(s, "Security", "Securelevel", buf,
                       SEV_INFO, STATUS_PASS, NULL);
        }
    }
    
    len = sizeof(value);
    if (sysctlbyname("kern.elf64.aslr.enable", &value, &len, NULL, 0) == 0) {
        if (value) {
            add_result(s, "Security", "ASLR (64-bit)", "enabled",
                       SEV_INFO, STATUS_PASS, NULL);
        } else {
            add_result(s, "Security", "ASLR (64-bit)", "disabled",
                       SEV_WARNING, STATUS_WARN,
                       "Enable: kern.elf64.aslr.enable=1");
        }
    }
    
    /* Kernel modules */
    check_start("Kernel Modules");
    
    struct kld_file_stat kfs;
    int fileid = kldnext(0);
    int hidden = 0;
    int total = 0;
    
    while (fileid > 0) {
        if (kldstat(fileid, &kfs) == 0) {
            total++;
            
            char path[512];
            snprintf(path, sizeof(path), "/boot/kernel/%s.ko", kfs.name);
            
            int in_fs = file_exists(path);
            if (!in_fs) {
                snprintf(path, sizeof(path), "/boot/modules/%s.ko", kfs.name);
                in_fs = file_exists(path);
            }
            
            if (!in_fs) {
                hidden++;
                check_item(kfs.name, 2, "NOT in filesystem (suspicious!)");
            } else if (s->verbose) {
                check_item(kfs.name, 0, "loaded");
            }
        }
        fileid = kldnext(fileid);
    }
    
    snprintf(buf, sizeof(buf), "%d modules loaded", total);
    add_result(s, "Security", "Module Count", buf,
               SEV_INFO, STATUS_PASS, NULL);
    
    if (hidden > 0) {
        snprintf(buf, sizeof(buf), "%d modules loaded but NOT in filesystem", hidden);
        add_result(s, "Security", "Hidden Modules", buf,
                   SEV_CRITICAL, STATUS_FAIL,
                   "Investigate hidden modules - possible rootkit");
    } else {
        add_result(s, "Security", "Module Files",
                   "All loaded modules found in filesystem",
                   SEV_INFO, STATUS_PASS, NULL);
    }
}

/* ============================================================
 * CHECK: SSH
 * ============================================================ */

void syssec_check_ssh(syssec_t *s) {
    FILE *fp;
    char line[1024];
    int permit_root = 0;
    int password_auth = 0;
    int x11_forward = 0;
    
    if (!s) return;
    
    check_start("SSH Configuration");
    
    fp = fopen("/etc/ssh/sshd_config", "r");
    if (!fp) {
        add_result(s, "SSH", "Config", "Cannot read /etc/ssh/sshd_config",
                   SEV_INFO, STATUS_UNKNOWN,
                   "Ensure SSH is configured");
        return;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0') continue;
        
        if (strncasecmp(p, "PermitRootLogin", 15) == 0) {
            if (strcasestr(p, "yes") && !strcasestr(p, "without-password") &&
                !strcasestr(p, "prohibit-password")) {
                permit_root = 1;
            }
        }
        
        if (strncasecmp(p, "PasswordAuthentication", 22) == 0) {
            if (strcasestr(p, "yes")) {
                password_auth = 1;
            }
        }
        
        if (strncasecmp(p, "X11Forwarding", 13) == 0) {
            if (strcasestr(p, "yes")) {
                x11_forward = 1;
            }
        }
    }
    fclose(fp);
    
    if (permit_root) {
        add_result(s, "SSH", "Root Login", "PermitRootLogin is enabled",
                   SEV_CRITICAL, STATUS_FAIL,
                   "Set 'PermitRootLogin no'");
    } else {
        add_result(s, "SSH", "Root Login", "Root login disabled",
                   SEV_INFO, STATUS_PASS, NULL);
    }
    
    if (password_auth) {
        add_result(s, "SSH", "Password Auth", "Password auth enabled",
                   SEV_WARNING, STATUS_WARN,
                   "Use key-based auth only");
    } else {
        add_result(s, "SSH", "Password Auth", "Password auth disabled",
                   SEV_INFO, STATUS_PASS, NULL);
    }
    
    if (x11_forward) {
        add_result(s, "SSH", "X11 Forwarding", "X11 forwarding enabled",
                   SEV_WARNING, STATUS_WARN,
                   "Disable X11 forwarding unless needed");
    }
}

/* ============================================================
 * CHECK: SUID/SGID
 * ============================================================ */

void syssec_check_suid(syssec_t *s) {
    FILE *fp;
    char line[1024];
    char buf[512];
    int count = 0;
    int suspicious = 0;
    char suspicious_list[512] = {0};
    
    const char *known_suid[] = {
        "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/passwd",
        "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/chsh",
        "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/lock",
        "/usr/bin/login", "/usr/sbin/ping", "/usr/sbin/traceroute",
        "/usr/local/bin/sudo", "/usr/local/bin/su",
        NULL
    };
    
    if (!s) return;
    
    check_start("SUID/SGID Binaries");
    
    fp = popen("find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null", "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (line[0] == '\0') continue;
        
        count++;
        
        int known = 0;
        for (int i = 0; known_suid[i] != NULL; i++) {
            if (strcmp(line, known_suid[i]) == 0) {
                known = 1;
                break;
            }
        }
        
        if (!known) {
            suspicious++;
            const char *basename = strrchr(line, '/');
            basename = basename ? basename + 1 : line;
            
            if (s->verbose) {
                check_item(basename, 1, "unexpected SUID/SGID");
            }
            
            if (strlen(suspicious_list) < sizeof(suspicious_list) - 64) {
                if (suspicious_list[0]) {
                    strncat(suspicious_list, ", ",
                            sizeof(suspicious_list) - strlen(suspicious_list) - 1);
                }
                strncat(suspicious_list, basename,
                        sizeof(suspicious_list) - strlen(suspicious_list) - 1);
            }
        } else if (s->verbose) {
            check_item(line, 0, "expected");
        }
    }
    pclose(fp);
    
    snprintf(buf, sizeof(buf), "%d SUID/SGID binaries found", count);
    
    if (suspicious > 0) {
        snprintf(buf, sizeof(buf), "%d unexpected: %s",
                 suspicious, suspicious_list);
        add_result(s, "SUID", "Unexpected Binaries", buf,
                   SEV_WARNING, STATUS_WARN,
                   "Review unexpected SUID/SGID binaries");
    } else {
        add_result(s, "SUID", "Binaries", buf,
                   SEV_INFO, STATUS_PASS, NULL);
    }
}

/* ============================================================
 * CHECK: LOGS
 * ============================================================ */

void syssec_check_logs(syssec_t *s) {
    const char *logs[] = {"/var/log/messages", "/var/log/auth.log",
                          "/var/log/secure", "/var/log/maillog",
                          "/var/log/cron", NULL};
    char buf[512];
    int found = 0;
    
    if (!s) return;
    
    check_start("System Logs");
    
    for (int i = 0; logs[i] != NULL; i++) {
        if (file_exists(logs[i])) {
            struct stat st;
            stat(logs[i], &st);
            snprintf(buf, sizeof(buf), "%ld bytes", (long)st.st_size);
            add_result(s, "Logs", logs[i], buf, SEV_INFO, STATUS_PASS, NULL);
            found++;
        } else if (s->verbose) {
            check_item(logs[i], 0, "missing");
        }
    }
    
    if (found == 0) {
        add_result(s, "Logs", "System Logs", "No standard logs found",
                   SEV_WARNING, STATUS_WARN,
                   "Check syslogd configuration");
    }
}

/* ============================================================
 * CHECK: UPDATES
 * ============================================================ */

void syssec_check_updates(syssec_t *s) {
    if (!s) return;
    
    check_start("System Updates");
    
    if (file_exists("/usr/sbin/freebsd-update")) {
        add_result(s, "Updates", "freebsd-update", "installed",
                   SEV_INFO, STATUS_PASS, "Run: freebsd-update fetch install");
    } else {
        add_result(s, "Updates", "freebsd-update", "not installed",
                   SEV_WARNING, STATUS_WARN,
                   "Consider installing freebsd-update");
    }
    
    if (file_exists("/usr/sbin/pkg")) {
        add_result(s, "Updates", "pkg", "installed",
                   SEV_INFO, STATUS_PASS, "Run: pkg upgrade");
    }
}

/* ============================================================
 * MAIN SCAN
 * ============================================================ */

void syssec_scan(syssec_t *s) {
    if (!s) return;
    
    syssec_log(LOG_INFO, "Starting security scan on %s", s->hostname);
    printf("\n");
    
    syssec_check_system(s);
    printf("\n");
    
    syssec_check_processes(s);
    printf("\n");
    
    syssec_check_users(s);
    printf("\n");
    
    syssec_check_filesystem(s);
    printf("\n");
    
    syssec_check_disks(s);
    printf("\n");
    
    syssec_check_dev(s);
    printf("\n");
    
    syssec_check_sys(s);
    printf("\n");
    
    syssec_check_ttys(s);
    printf("\n");
    
    syssec_check_network(s);
    printf("\n");
    
    syssec_check_network_deep(s); // NETWORK
    printf("\n");
    
    syssec_check_services(s);
    printf("\n");
    
    syssec_check_security(s);
    printf("\n");
    
    syssec_check_ssh(s);
    printf("\n");
    
    syssec_check_suid(s);
    printf("\n");
    
    syssec_check_logs(s);
    printf("\n");
    
    syssec_check_updates(s);
    printf("\n");

    syssec_check_deep_parse(s);
    printf("\n");
    
    syssec_log(LOG_INFO, "Scan complete: %d checks (%d passed, %d warnings, %d failed)",
               s->count, s->passed, s->warnings, s->failures);
}

/* ============================================================
 * REPORTING
 * ============================================================ */

void syssec_print_banner(void) {
    printf(COL_CYAN);
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    SYSSEC - Security Scanner                      ║\n");
    printf("║                    FreeBSD Security Audit                         ║\n");
    printf("║                    Version %-8s                              ║\n", SYSSEC_VERSION);
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf(COL_RESET);
}

void syssec_print_summary(syssec_t *s) {
    if (!s) return;
    
    printf("\n");
    printf(COL_BOLD "═══════════════════════════════════════════════════════════════\n");
    printf("                    SCAN SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════\n" COL_RESET);
    printf("\n");
    printf("  Hostname:   %s\n", s->hostname);
    printf("  Kernel:     %s\n", s->os_release);
    printf("  Timestamp:  %s", ctime(&s->timestamp));
    printf("\n");
    printf("  %s✓ Passed:%s   %d\n", COL_GREEN, COL_RESET, s->passed);
    printf("  %s⚠ Warnings:%s %d\n", COL_YELLOW, COL_RESET, s->warnings);
    printf("  %s✗ Failed:%s   %d\n", COL_RED, COL_RESET, s->failures);
    printf("  %sTotal:%s      %d\n", COL_BOLD, COL_RESET, s->count);
    printf("\n");
    
    if (s->failures > 0) {
        printf(COL_RED COL_BOLD);
        printf("  ⚠ %d CRITICAL issues found - address immediately!\n", s->failures);
        printf(COL_RESET);
    } else if (s->warnings > 0) {
        printf(COL_YELLOW "  ⚠ %d warnings found - review recommendations\n" COL_RESET,
               s->warnings);
    } else {
        printf(COL_GREEN "  ✓ All checks passed\n" COL_RESET);
    }
    printf("\n");
}

void syssec_print_results(syssec_t *s) {
    if (!s) return;
    
    printf(COL_BOLD "═══════════════════════════════════════════════════════════════\n");
    printf("                    DETAILED RESULTS\n");
    printf("═══════════════════════════════════════════════════════════════\n" COL_RESET);
    
    const char *last_category = "";
    
    for (int i = 0; i < s->count; i++) {
        result_t *r = &s->results[i];
        
        if (strcmp(r->category, last_category) != 0) {
            printf("\n" COL_BOLD "[%s]" COL_RESET "\n", r->category);
            last_category = r->category;
        }
        
        const char *color;
        const char *symbol;
        
        switch (r->status) {
            case STATUS_PASS: color = COL_GREEN;  symbol = "✓"; break;
            case STATUS_WARN: color = COL_YELLOW; symbol = "⚠"; break;
            case STATUS_FAIL: color = COL_RED;    symbol = "✗"; break;
            default:          color = COL_BLUE;   symbol = "?"; break;
        }
        
        printf("  %s%s %-25s%s %s\n",
               color, symbol, r->name, COL_RESET, r->description);
        
        if (r->recommendation[0] != '\0' &&
            (r->status == STATUS_FAIL || r->status == STATUS_WARN)) {
            printf("     " COL_DIM "→ %s" COL_RESET "\n", r->recommendation);
        }
    }
    printf("\n");
}

void syssec_print_critical(syssec_t *s) {
    if (!s) return;
    
    printf("\n" COL_BOLD "═══ CRITICAL ISSUES ═══\n" COL_RESET "\n");
    
    int found = 0;
    for (int i = 0; i < s->count; i++) {
        result_t *r = &s->results[i];
        if (r->status == STATUS_FAIL && r->severity == SEV_CRITICAL) {
            printf(COL_RED "  [CRITICAL] %s\n" COL_RESET, r->name);
            printf("    %s\n", r->description);
            if (r->recommendation[0]) {
                printf("    " COL_YELLOW "→ %s" COL_RESET "\n", r->recommendation);
            }
            printf("\n");
            found++;
        }
    }
    
    if (found == 0) {
        printf(COL_GREEN "  No critical issues found\n" COL_RESET);
    }
}

void syssec_print_recommendations(syssec_t *s) {
    if (!s) return;
    
    printf("\n" COL_BOLD "═══ RECOMMENDATIONS ═══\n" COL_RESET "\n");
    
    int found = 0;
    for (int i = 0; i < s->count; i++) {
        result_t *r = &s->results[i];
        if (r->status != STATUS_PASS && r->recommendation[0] != '\0') {
            const char *color = (r->status == STATUS_FAIL) ? COL_RED : COL_YELLOW;
            printf("  %s[%s]%s %s\n", color,
                   r->status == STATUS_FAIL ? "FAIL" : "WARN",
                   COL_RESET, r->name);
            printf("    → %s\n", r->recommendation);
            found++;
        }
    }
    
    if (found == 0) {
        printf(COL_GREEN "  No recommendations - system looks good\n" COL_RESET);
    }
    printf("\n");
}

/* ============================================================
 * SAVE REPORT
 * ============================================================ */

int syssec_save_report(syssec_t *s, const char *path) {
    FILE *fp;
    
    if (!s || !path) return -1;
    
    fp = fopen(path, "w");
    if (!fp) {
        syssec_log(LOG_ERROR, "Cannot open %s", path);
        return -1;
    }
    
    fprintf(fp, "<!DOCTYPE html>\n<html>\n<head>\n");
    fprintf(fp, "<meta charset=\"UTF-8\">\n");
    fprintf(fp, "<title>SYSSEC Report - %s</title>\n", s->hostname);
    fprintf(fp, "<style>\n");
    fprintf(fp, "body { font-family: monospace; margin: 40px; background: #f5f5f5; }\n");
    fprintf(fp, ".container { max-width: 1000px; margin: 0 auto; background: white; ");
    fprintf(fp, "padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n");
    fprintf(fp, "h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }\n");
    fprintf(fp, "h2 { color: #555; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }\n");
    fprintf(fp, ".summary { display: flex; gap: 20px; margin: 20px 0; }\n");
    fprintf(fp, ".summary-item { padding: 15px 25px; border-radius: 6px; }\n");
    fprintf(fp, ".pass { background: #d4edda; color: #155724; }\n");
    fprintf(fp, ".warn { background: #fff3cd; color: #856404; }\n");
    fprintf(fp, ".fail { background: #f8d7da; color: #721c24; }\n");
    fprintf(fp, ".check { margin: 10px 0; padding: 12px; border-left: 4px solid #ddd; ");
    fprintf(fp, "background: #fafafa; border-radius: 4px; }\n");
    fprintf(fp, ".check.pass { border-left-color: #4CAF50; }\n");
    fprintf(fp, ".check.warn { border-left-color: #FF9800; }\n");
    fprintf(fp, ".check.fail { border-left-color: #f44336; }\n");
    fprintf(fp, ".rec { background: #fff8e1; padding: 8px 12px; margin-top: 8px; ");
    fprintf(fp, "border-radius: 4px; font-size: 0.9em; }\n");
    fprintf(fp, "</style>\n</head>\n<body>\n");
    fprintf(fp, "<div class=\"container\">\n");
    fprintf(fp, "<h1>SYSSEC Security Report</h1>\n");
    fprintf(fp, "<p><strong>Hostname:</strong> %s</p>\n", s->hostname);
    fprintf(fp, "<p><strong>Kernel:</strong> %s</p>\n", s->os_release);
    fprintf(fp, "<p><strong>Timestamp:</strong> %s</p>\n", ctime(&s->timestamp));
    
    fprintf(fp, "<div class=\"summary\">\n");
    fprintf(fp, "<div class=\"summary-item pass\"><strong>✓ Passed:</strong> %d</div>\n", s->passed);
    fprintf(fp, "<div class=\"summary-item warn\"><strong>⚠ Warnings:</strong> %d</div>\n", s->warnings);
    fprintf(fp, "<div class=\"summary-item fail\"><strong>✗ Failed:</strong> %d</div>\n", s->failures);
    fprintf(fp, "<div class=\"summary-item\"><strong>Total:</strong> %d</div>\n", s->count);
    fprintf(fp, "</div>\n");
    
    const char *last_category = "";
    for (int i = 0; i < s->count; i++) {
        result_t *r = &s->results[i];
        
        if (strcmp(r->category, last_category) != 0) {
            if (last_category[0]) fprintf(fp, "</div>\n");
            fprintf(fp, "<h2>%s</h2>\n<div>\n", r->category);
            last_category = r->category;
        }
        
        const char *cls = "pass";
        const char *symbol = "✓";
        if (r->status == STATUS_WARN) { cls = "warn"; symbol = "⚠"; }
        if (r->status == STATUS_FAIL) { cls = "fail"; symbol = "✗"; }
        
        fprintf(fp, "<div class=\"check %s\">\n", cls);
        fprintf(fp, "<strong>%s %s</strong><br>\n", symbol, r->name);
        fprintf(fp, "%s\n", r->description);
        if (r->recommendation[0] && r->status != STATUS_PASS) {
            fprintf(fp, "<div class=\"rec\">→ %s</div>\n", r->recommendation);
        }
        fprintf(fp, "</div>\n");
    }
    if (last_category[0]) fprintf(fp, "</div>\n");
    
    fprintf(fp, "</div>\n</body>\n</html>\n");
    fclose(fp);
    
    syssec_log(LOG_INFO, "Report saved to %s", path);
    return 0;
}

/* ============================================================
 * USAGE & MAIN
 * ============================================================ */

static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\nOptions:\n");
    printf("  -v, --verbose     Verbose output (per-item checks)\n");
    printf("  -q, --quiet       Quiet mode\n");
    printf("  -o, --output FILE Save HTML report to FILE\n");
    printf("  -c, --critical    Show only critical issues\n");
    printf("  -h, --help        Show this help\n");
    printf("\nExamples:\n");
    printf("  sudo %s                    # Standard scan\n", prog);
    printf("  sudo %s -v                 # Verbose per-item output\n", prog);
    printf("  sudo %s -o report.html     # Save HTML report\n", prog);
    printf("  sudo %s -c                 # Show critical only\n", prog);
    printf("\n");
}

int main(int argc, char **argv) {
    syssec_t syssec;
    const char *output = NULL;
    int verbose = 0;
    int quiet = 0;
    int critical_only = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            quiet = 1;
            g_quiet = 1;
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--critical") == 0) {
            critical_only = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }
    
    if (verbose) {
        g_log_level = LOG_DEBUG;
    } else if (quiet) {
        g_log_level = LOG_ERROR;
    }
    
    if (!quiet && !critical_only) {
        syssec_print_banner();
    }
    
    if (geteuid() != 0) {
        syssec_log(LOG_WARNING, "Not running as root - some checks will be limited");
    }
    
    syssec_init(&syssec, verbose);
    syssec_scan(&syssec);
    
    if (critical_only) {
        syssec_print_critical(&syssec);
    } else if (verbose) {
        syssec_print_summary(&syssec);
        syssec_print_results(&syssec);
        syssec_print_recommendations(&syssec);
    } else if (!quiet) {
        syssec_print_summary(&syssec);
        syssec_print_recommendations(&syssec);
    }
    
    if (output) {
        if (syssec_save_report(&syssec, output) == 0) {
            if (!quiet) {
                printf(COL_GREEN "Report saved to: %s\n" COL_RESET, output);
            }
        }
    }
    
    int ret = (syssec.failures > 0) ? 1 : 0;
    syssec_free(&syssec);
    
    return ret;
}

void syssec_report_add(syssec_t *s, const char *category, const char *name, const char *desc,
                        severity_t sev, status_t status, const char *rec)
{
    add_result(s, category, name, desc, sev, status, rec);
}

/* ============================================================
 * CHECK: Deep Tree Parse + Binary Integrity
 * ============================================================ */

void syssec_check_deep_parse(syssec_t *s) {
    parse_result_t dev_result;
    parse_result_t sys_result;
    parse_result_t bin_result;
    binary_integrity_t integrity;
    
    if (!s) return;
    
    printf("\n");
    check_start("Deep Parse: /dev");
    parser_parse_dev(&dev_result, s->verbose);
    parser_print_result("/dev", &dev_result);
    
    printf("\n");
    check_start("Deep Parse: /sys");
    parser_parse_sys(&sys_result, s->verbose);
    parser_print_result("/sys", &sys_result);
    
    printf("\n");
    check_start("Deep Parse: /bin tree");
    parser_parse_bin(&bin_result, s->verbose);
    parser_print_result("/bin tree", &bin_result);
    
    printf("\n");
    check_start("Binary Integrity Check");
    parser_integrity_check_standard(&integrity, s->verbose);
    parser_integrity_report(s, &integrity);
}


