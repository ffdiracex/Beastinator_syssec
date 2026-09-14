/*
 * parser.c - Tree parser and binary integrity checker for SYSSEC
 * 
 * Compile: cc -Wall -Wextra -O2 -c parser.c -o parser.o
 */

#define __BSD_VISIBLE 1

#include "parser.h"
#include "syssec.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

/*
 * Compute SHA-256 of a file using the `sha256` command.
 * On FreeBSD, `sha256 -q <file>` outputs the hash.
 */
static int compute_sha256(const char *path, char *out_hash, size_t out_size) {
    char cmd[1024];
    FILE *fp;
    char line[256];
    
    if (!path || !out_hash || out_size < 65) return -1;
    out_hash[0] = '\0';
    
    snprintf(cmd, sizeof(cmd), "sha256 -q '%s' 2>/dev/null", path);
    fp = popen(cmd, "r");
    if (!fp) return -1;
    
    if (fgets(line, sizeof(line), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    
    /* Trim newline */
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';
    
    if (strlen(line) != 64) return -1;
    
    strncpy(out_hash, line, out_size - 1);
    out_hash[out_size - 1] = '\0';
    return 0;
}

/*
 * Format a mode string like "rwxr-xr-x"
 */
static void mode_to_string(mode_t mode, char *out, size_t size) {
    if (!out || size < 11) return;
    
    out[0] = (mode & S_IRUSR) ? 'r' : '-';
    out[1] = (mode & S_IWUSR) ? 'w' : '-';
    out[2] = (mode & S_IXUSR) ? 'x' : '-';
    out[3] = (mode & S_IRGRP) ? 'r' : '-';
    out[4] = (mode & S_IWGRP) ? 'w' : '-';
    out[5] = (mode & S_IXGRP) ? 'x' : '-';
    out[6] = (mode & S_IROTH) ? 'r' : '-';
    out[7] = (mode & S_IWOTH) ? 'w' : '-';
    out[8] = (mode & S_IXOTH) ? 'x' : '-';
    out[9] = '\0';
    
    /* Handle setuid/setgid/sticky */
    if (mode & S_ISUID) out[2] = (mode & S_IXUSR) ? 's' : 'S';
    if (mode & S_ISGID) out[5] = (mode & S_IXGRP) ? 's' : 'S';
    if (mode & S_ISVTX) out[8] = (mode & S_IXOTH) ? 't' : 'T';
}

/*
 * Indent prefix for verbose tree output
 */
static void print_indent(int depth) {
    for (int i = 0; i < depth; i++) {
        printf("  ");
    }
}

/* ============================================================
 * INTERNAL: Classify an entry
 * ============================================================ */

static void classify_entry(parsed_entry_t *e, struct stat *st) {
    if (!e || !st) return;
    
    e->is_dir        = S_ISDIR(st->st_mode);
    e->is_char       = S_ISCHR(st->st_mode);
    e->is_block      = S_ISBLK(st->st_mode);
    e->is_symlink    = S_ISLNK(st->st_mode);
    e->is_fifo       = S_ISFIFO(st->st_mode);
    e->is_socket     = S_ISSOCK(st->st_mode);
    e->is_regular    = S_ISREG(st->st_mode);
    
    e->mode   = st->st_mode;
    e->uid    = st->st_uid;
    e->gid    = st->st_gid;
    e->size   = st->st_size;
    
    if (e->is_char || e->is_block) {
        e->major = major(st->st_rdev);
        e->minor = minor(st->st_rdev);
    } else {
        e->major = -1;
        e->minor = -1;
    }
}

/*
 * Get type string for output
 */
static const char* entry_type_string(parsed_entry_t *e) {
    if (e->is_dir)     return "DIR";
    if (e->is_symlink) return "LNK";
    if (e->is_char)    return "CHR";
    if (e->is_block)   return "BLK";
    if (e->is_fifo)    return "FIFO";
    if (e->is_socket)  return "SOCK";
    if (e->is_regular) return "FILE";
    return "????";
}

/* ============================================================
 * TREE WALKING
 * ============================================================ */

static int walk_recursive(const char *path, int depth, int max_depth,
                          int verbose, parse_result_t *result) {
    DIR *dir;
    struct dirent *entry;
    char child[PARSER_MAX_PATH];
    
    if (!path || !result) return -1;
    if (max_depth > 0 && depth > max_depth) return 0;
    if (result->count >= PARSER_MAX_ENTRIES) return 0;
    
    dir = opendir(path);
    if (!dir) {
        if (verbose) {
            print_indent(depth);
            printf(COL_RED "✗ cannot open %s: %s" COL_RESET "\n",
                   path, strerror(errno));
        }
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0) continue;
        if (strcmp(entry->d_name, "..") == 0) continue;
        if (result->count >= PARSER_MAX_ENTRIES) break;
        
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if (lstat(child, &st) < 0) {
            if (verbose) {
                print_indent(depth);
                printf(COL_RED "✗ %s: %s" COL_RESET "\n", entry->d_name,
                       strerror(errno));
            }
            continue;
        }
        
        parsed_entry_t *e = &result->entries[result->count++];
        memset(e, 0, sizeof(*e));
        
        strncpy(e->path, child, sizeof(e->path) - 1);
        strncpy(e->name, entry->d_name, sizeof(e->name) - 1);
        classify_entry(e, &st);
        
        /* Read symlink target */
        if (e->is_symlink) {
            ssize_t len = readlink(child, e->target, sizeof(e->target) - 1);
            if (len > 0) e->target[len] = '\0';
        }
        
        /* Update counters */
        if (e->is_dir)          result->dirs++;
        if (e->is_regular)      result->files++;
        if (e->is_symlink)      result->symlinks++;
        if (e->is_char)         result->devices_char++;
        if (e->is_block)        result->devices_block++;
        if (e->is_fifo)         result->fifos++;
        if (e->is_socket)       result->sockets++;
        if (e->mode & S_ISUID)  result->setuid++;
        if (e->mode & S_ISGID)  result->setgid++;
        if (e->mode & S_IWOTH)  result->world_writable++;
        if (e->uid == 0)        result->root_owned++;
        
        /* Verbose output */
        if (verbose) {
            char perm[16];
            char extra[512];
            mode_to_string(e->mode & 07777, perm, sizeof(perm));
            
            extra[0] = '\0';
            if (e->is_symlink && e->target[0]) {
                snprintf(extra, sizeof(extra), " -> %s", e->target);
            } else if (e->is_char || e->is_block) {
                snprintf(extra, sizeof(extra), " [%d,%d]", e->major, e->minor);
            } else if (e->is_regular) {
                snprintf(extra, sizeof(extra), " %lld bytes", (long long)e->size);
            }
            
            const char *color = COL_RESET;
            if (e->mode & S_IWOTH)      color = COL_RED;
            else if (e->mode & S_ISUID) color = COL_MAGENTA;
            else if (e->mode & S_ISGID) color = COL_YELLOW;
            
            print_indent(depth);
            printf("  %s%-4s %s uid=%d gid=%d %s%s" COL_RESET "\n",
                   color,
                   entry_type_string(e),
                   perm,
                   e->uid,
                   e->gid,
                   e->name,
                   extra);
            fflush(stdout);
        }
        
        /* Recurse into directories */
        if (e->is_dir) {
            walk_recursive(child, depth + 1, max_depth, verbose, result);
        }
    }
    
    closedir(dir);
    return 0;
}

/* ============================================================
 * PUBLIC: parser_walk_dir
 * ============================================================ */

int parser_walk_dir(const char *root, int max_depth, int verbose,
                    parse_result_t *result) {
    if (!root || !result) return -1;
    
    memset(result, 0, sizeof(*result));
    
    if (verbose) {
        printf("\n" COL_BOLD COL_CYAN "═══════════════════════════════════════════════════════════════\n");
        printf("  Parsing tree: %s (max depth: %d)\n", root,
               max_depth == 0 ? -1 : max_depth);
        printf("═══════════════════════════════════════════════════════════════\n" COL_RESET);
    }
    
    return walk_recursive(root, 0, max_depth, verbose, result);
}

/* ============================================================
 * PUBLIC: parser_parse_dev
 * ============================================================ */

int parser_parse_dev(parse_result_t *result, int verbose) {
    if (!result) return -1;
    
    if (verbose) {
        printf("\n" COL_BOLD "═══ /dev Deep Parse ═══\n" COL_RESET);
    }
    
    return parser_walk_dir("/dev", 1, verbose, result);
}

/* ============================================================
 * PUBLIC: parser_parse_sys
 * ============================================================ */

int parser_parse_sys(parse_result_t *result, int verbose) {
    if (!result) return -1;
    
    if (verbose) {
        printf("\n" COL_BOLD "═══ /sys Deep Parse ═══\n" COL_RESET);
    }
    
    struct stat st;
    if (stat("/sys", &st) < 0) {
        if (verbose) {
            printf("  " COL_YELLOW "⚠ /sys not mounted (expected on FreeBSD)" COL_RESET "\n");
        }
        memset(result, 0, sizeof(*result));
        return 0;
    }
    
    return parser_walk_dir("/sys", 3, verbose, result);
}

/* ============================================================
 * PUBLIC: parser_parse_bin
 * ============================================================ */

int parser_parse_bin(parse_result_t *result, int verbose) {
    if (!result) return -1;
    
    memset(result, 0, sizeof(*result));
    
    const char *dirs[] = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", NULL};
    
    if (verbose) {
        printf("\n" COL_BOLD "═══ /bin Tree Deep Parse ═══\n" COL_RESET);
    }
    
    for (int i = 0; dirs[i] != NULL; i++) {
        struct stat st;
        if (stat(dirs[i], &st) < 0) continue;
        
        if (verbose) {
            printf("\n" COL_CYAN "▸ %s" COL_RESET "\n", dirs[i]);
        }
        
        /* Parse but limit entries to fit in result struct */
        parse_result_t tmp;
        parser_walk_dir(dirs[i], 1, verbose, &tmp);
        
        /* Merge into result */
        for (int j = 0; j < tmp.count && result->count < PARSER_MAX_ENTRIES; j++) {
            result->entries[result->count++] = tmp.entries[j];
        }
        result->dirs          += tmp.dirs;
        result->files         += tmp.files;
        result->symlinks      += tmp.symlinks;
        result->devices_char  += tmp.devices_char;
        result->devices_block += tmp.devices_block;
        result->fifos         += tmp.fifos;
        result->sockets       += tmp.sockets;
        result->setuid        += tmp.setuid;
        result->setgid        += tmp.setgid;
        result->world_writable+= tmp.world_writable;
        result->root_owned    += tmp.root_owned;
    }
    
    return 0;
}

/* ============================================================
 * PUBLIC: parser_print_result
 * ============================================================ */

void parser_print_result(const char *label, parse_result_t *result) {
    if (!result) return;
    
    printf("\n" COL_BOLD "─── %s summary ───" COL_RESET "\n", label ? label : "Parse");
    printf("  Entries:          %d\n", result->count);
    printf("  Directories:      %d\n", result->dirs);
    printf("  Regular files:    %d\n", result->files);
    printf("  Symlinks:         %d\n", result->symlinks);
    printf("  Char devices:     %d\n", result->devices_char);
    printf("  Block devices:    %d\n", result->devices_block);
    printf("  FIFOs:            %d\n", result->fifos);
    printf("  Sockets:          %d\n", result->sockets);
    printf("  Setuid:           %d\n", result->setuid);
    printf("  Setgid:           %d\n", result->setgid);
    printf("  World-writable:   %d\n", result->world_writable);
    printf("  Root-owned:       %d\n", result->root_owned);
}

/* ============================================================
 * BINARY INTEGRITY
 * ============================================================ */

/*
 * Standard FreeBSD binaries with their expected SHA-256 hashes.
 * 
 * In a real deployment, these would be populated from the output of:
 *   freebsd-update IDS
 * or from a known-good hash database like:
 *   /var/db/freebsd-update/
 * 
 * For this implementation, we check:
 *   1. The file exists
 *   2. The file is executable
 *   3. The file is not world-writable
 *   4. The file is owned by root
 *   5. The hash matches an expected value (if provided)
 * 
 * Since exact hashes vary per FreeBSD version, this checks the
 * structural integrity rather than exact byte-match (which would
 * need version-specific hash data).
 */

typedef struct {
    const char *name;
    const char *path;
    const char *expected_hash;  /* NULL = check structure only */
} std_binary_t;

/* Standard utility inventory */
static const std_binary_t STANDARD_BINARIES[] = {
    /* Core utilities in /bin */
    {"cat",       "/bin/cat",       NULL},
    {"chmod",     "/bin/chmod",     NULL},
    {"chown",     "/bin/chown",     NULL},
    {"cp",        "/bin/cp",        NULL},
    {"date",      "/bin/date",      NULL},
    {"dd",        "/bin/dd",        NULL},
    {"df",        "/bin/df",        NULL},
    {"echo",      "/bin/echo",      NULL},
    {"ed",        "/bin/ed",        NULL},
    {"expr",      "/bin/expr",      NULL},
    {"getfacl",   "/bin/getfacl",   NULL},
    {"hostname",  "/bin/hostname",  NULL},
    {"kill",      "/bin/kill",      NULL},
    {"ln",        "/bin/ln",        NULL},
    {"ls",        "/bin/ls",        NULL},
    {"mkdir",     "/bin/mkdir",     NULL},
    {"mv",        "/bin/mv",        NULL},
    {"pax",       "/bin/pax",       NULL},
    {"ps",        "/bin/ps",        NULL},
    {"pwd",       "/bin/pwd",       NULL},
    {"rcp",       "/bin/rcp",       NULL},
    {"rm",        "/bin/rm",        NULL},
    {"rmdir",     "/bin/rmdir",     NULL},
    {"setfacl",   "/bin/setfacl",   NULL},
    {"sh",        "/bin/sh",        NULL},
    {"sleep",     "/bin/sleep",     NULL},
    {"stty",      "/bin/stty",      NULL},
    {"sync",      "/bin/sync",      NULL},
    {"test",      "/bin/test",      NULL},
    {"uuidgen",   "/bin/uuidgen",   NULL},
    
    /* System utilities in /sbin */
    {"camcontrol","/sbin/camcontrol",NULL},
    {"devfs",     "/sbin/devfs",    NULL},
    {"dmesg",     "/sbin/dmesg",    NULL},
    {"fdisk",     "/sbin/fdisk",    NULL},
    {"fsck",      "/sbin/fsck",     NULL},
    {"ifconfig",  "/sbin/ifconfig", NULL},
    {"init",      "/sbin/init",     NULL},
    {"kldload",   "/sbin/kldload",  NULL},
    {"kldstat",   "/sbin/kldstat",  NULL},
    {"kldunload", "/sbin/kldunload",NULL},
    {"md5",       "/sbin/md5",      NULL},
    {"mount",     "/sbin/mount",    NULL},
    {"newfs",     "/sbin/newfs",    NULL},
    {"ping",      "/sbin/ping",     NULL},
    {"reboot",    "/sbin/reboot",   NULL},
    {"route",     "/sbin/route",    NULL},
    {"shutdown",  "/sbin/shutdown", NULL},
    {"sha256",    "/sbin/sha256",   NULL},
    {"sysctl",    "/sbin/sysctl",   NULL},
    {"umount",    "/sbin/umount",   NULL},
    
    /* /usr/bin utilities */
    {"awk",       "/usr/bin/awk",       NULL},
    {"basename",  "/usr/bin/basename",  NULL},
    {"bc",        "/usr/bin/bc",        NULL},
    {"cmp",       "/usr/bin/cmp",       NULL},
    {"cut",       "/usr/bin/cut",       NULL},
    {"diff",      "/usr/bin/diff",      NULL},
    {"dirname",   "/usr/bin/dirname",   NULL},
    {"du",        "/usr/bin/du",        NULL},
    {"env",       "/usr/bin/env",       NULL},
    {"expand",    "/usr/bin/expand",    NULL},
    {"file",      "/usr/bin/file",      NULL},
    {"find",      "/usr/bin/find",      NULL},
    {"finger",    "/usr/bin/finger",    NULL},
    {"ftp",       "/usr/bin/ftp",       NULL},
    {"grep",      "/usr/bin/grep",      NULL},
    {"head",      "/usr/bin/head",      NULL},
    {"id",        "/usr/bin/id",        NULL},
    {"less",      "/usr/bin/less",      NULL},
    {"logger",    "/usr/bin/logger",    NULL},
    {"login",     "/usr/bin/login",     NULL},
    {"mail",      "/usr/bin/mail",      NULL},
    {"more",      "/usr/bin/more",      NULL},
    {"netstat",   "/usr/bin/netstat",   NULL},
    {"passwd",    "/usr/bin/passwd",    NULL},
    {"printf",    "/usr/bin/printf",    NULL},
    {"sed",       "/usr/bin/sed",       NULL},
    {"sort",      "/usr/bin/sort",      NULL},
    {"ssh",       "/usr/bin/ssh",       NULL},
    {"su",        "/usr/bin/su",        NULL},
    {"sudo",      "/usr/local/bin/sudo",NULL},
    {"tail",      "/usr/bin/tail",      NULL},
    {"tar",       "/usr/bin/tar",       NULL},
    {"tee",       "/usr/bin/tee",       NULL},
    {"telnet",    "/usr/bin/telnet",    NULL},
    {"top",       "/usr/bin/top",       NULL},
    {"tr",        "/usr/bin/tr",        NULL},
    {"uname",     "/usr/bin/uname",     NULL},
    {"uniq",      "/usr/bin/uniq",      NULL},
    {"vi",        "/usr/bin/vi",        NULL},
    {"wc",        "/usr/bin/wc",        NULL},
    {"who",       "/usr/bin/who",       NULL},
    {"whoami",    "/usr/bin/whoami",    NULL},
    {"xargs",     "/usr/bin/xargs",     NULL},
    
    /* /usr/sbin utilities */
    {"arp",       "/usr/sbin/arp",      NULL},
    {"chown",     "/usr/sbin/chown",    NULL},
    {"cron",      "/usr/sbin/cron",     NULL},
    {"crond",     "/usr/sbin/crond",    NULL},
    {"ftpd",      "/usr/sbin/ftpd",     NULL},
    {"inetd",     "/usr/sbin/inetd",    NULL},
    {"lsof",      "/usr/sbin/lsof",     NULL},
    {"named",     "/usr/sbin/named",    NULL},
    {"newsyslog", "/usr/sbin/newsyslog",NULL},
    {"ntpd",      "/usr/sbin/ntpd",     NULL},
    {"pfctl",     "/usr/sbin/pfctl",    NULL},
    {"sockstat",  "/usr/sbin/sockstat", NULL},
    {"sshd",      "/usr/sbin/sshd",     NULL},
    {"syslogd",   "/usr/sbin/syslogd",  NULL},
    {"tcpdump",   "/usr/sbin/tcpdump",  NULL},
    {"traceroute","/usr/sbin/traceroute",NULL},
    
    {NULL, NULL, NULL}
};

/* ============================================================
 * PUBLIC: parser_binary_verify
 * ============================================================ */

int parser_binary_verify(const char *path, const char *expected_hash,
                         binary_check_t *check) {
    if (!path || !check) return -1;
    
    memset(check, 0, sizeof(*check));
    
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    strncpy(check->name, basename, sizeof(check->name) - 1);
    strncpy(check->path, path, sizeof(check->path) - 1);
    
    struct stat st;
    if (stat(path, &st) < 0) {
        check->exists = 0;
        return 0;
    }
    
    check->exists = 1;
    check->mode = st.st_mode;
    check->uid = st.st_uid;
    check->gid = st.st_gid;
    check->size = st.st_size;
    check->is_setuid = (st.st_mode & S_ISUID) != 0;
    check->is_setgid = (st.st_mode & S_ISGID) != 0;
    check->is_world_writable = (st.st_mode & S_IWOTH) != 0;
    
    /* Compute hash */
    if (S_ISREG(st.st_mode)) {
        if (compute_sha256(path, check->actual_hash,
                           sizeof(check->actual_hash)) != 0) {
            check->actual_hash[0] = '\0';
        }
        
        if (expected_hash && expected_hash[0]) {
            strncpy(check->expected_hash, expected_hash,
                    sizeof(check->expected_hash) - 1);
            check->hash_match = (strcasecmp(check->actual_hash,
                                            expected_hash) == 0);
        } else {
            check->hash_match = 1;  /* No expected hash — skip match */
        }
    }
    
    return 0;
}

/* ============================================================
 * PUBLIC: parser_integrity_check_standard
 * ============================================================ */

int parser_integrity_check_standard(binary_integrity_t *integrity, int verbose) {
    if (!integrity) return -1;
    
    memset(integrity, 0, sizeof(*integrity));
    
    printf("\n" COL_BOLD COL_CYAN "═══════════════════════════════════════════════════════════════\n");
    printf("  Binary Integrity Check — Standard Utilities\n");
    printf("═══════════════════════════════════════════════════════════════\n" COL_RESET);
    printf("\n");
    
    for (int i = 0; STANDARD_BINARIES[i].name != NULL; i++) {
        if (integrity->count >= 128) break;
        
        const std_binary_t *sb = &STANDARD_BINARIES[i];
        binary_check_t *bc = &integrity->binaries[integrity->count++];
        
        parser_binary_verify(sb->path, sb->expected_hash, bc);
        
        /* Determine status */
        int status = 0;  /* 0 = OK, 1 = warn, 2 = fail */
        const char *note = "";
        char note_buf[256];
        note_buf[0] = '\0';
        
        if (!bc->exists) {
            status = 2;
            note = "MISSING";
            integrity->missing++;
        } else {
            /* Check for structural integrity */
            if (bc->is_world_writable) {
                status = 2;
                snprintf(note_buf, sizeof(note_buf), "WORLD-WRITABLE");
                note = note_buf;
                integrity->suspicious++;
            } else if (bc->uid != 0) {
                status = 1;
                snprintf(note_buf, sizeof(note_buf), "owned by uid %d", bc->uid);
                note = note_buf;
                integrity->suspicious++;
            } else if (!(bc->mode & S_IXUSR)) {
                status = 1;
                note = "not executable";
                integrity->suspicious++;
            } else if (bc->expected_hash && !bc->hash_match) {
                status = 2;
                note = "HASH MISMATCH";
                integrity->modified++;
            } else {
                status = 0;
                note = "OK";
                integrity->verified++;
            }
        }
        
        /* Print result */
        if (verbose || status != 0) {
            const char *color;
            const char *symbol;
            
            switch (status) {
                case 0: color = COL_GREEN; symbol = "✓"; break;
                case 1: color = COL_YELLOW; symbol = "⚠"; break;
                case 2: color = COL_RED; symbol = "✗"; break;
                default: color = COL_RESET; symbol = "?"; break;
            }
            
            char perm[16] = "";
            if (bc->exists) {
                mode_to_string(bc->mode & 07777, perm, sizeof(perm));
                printf("    %s%s%s %-15s %-16s uid=%-4d gid=%-4d %s\n",
                       color, symbol, COL_RESET,
                       bc->name,
                       bc->path,
                       bc->uid,
                       bc->gid,
                       note);
            } else {
                printf("    %s%s%s %-15s %-16s %s\n",
                       color, symbol, COL_RESET,
                       bc->name,
                       bc->path,
                       note);
            }
            fflush(stdout);
        }
    }
    
    printf("\n");
    printf("  " COL_BOLD "Integrity Summary:" COL_RESET "\n");
    printf("    Checked:   %d\n", integrity->count);
    printf("    %sVerified:%s  %d\n", COL_GREEN, COL_RESET, integrity->verified);
    printf("    %sModified:%s  %d\n", COL_YELLOW, COL_RESET, integrity->modified);
    printf("    %sMissing:%s   %d\n", COL_RED, COL_RESET, integrity->missing);
    printf("    %sSuspicious:%s %d\n", COL_RED, COL_RESET, integrity->suspicious);
    printf("\n");
    
    return 0;
}

/* ============================================================
 * PUBLIC: parser_integrity_print
 * ============================================================ */

void parser_integrity_print(binary_integrity_t *integrity) {
    if (!integrity) return;
    
    printf("\n" COL_BOLD "─── Binary Integrity Report ───" COL_RESET "\n");
    printf("  Total checked:  %d\n", integrity->count);
    printf("  Verified:       %d\n", integrity->verified);
    printf("  Modified:       %d\n", integrity->modified);
    printf("  Missing:        %d\n", integrity->missing);
    printf("  Suspicious:     %d\n", integrity->suspicious);
}

/* ============================================================
 * PUBLIC: parser_integrity_report (bridge to syssec_t)
 * ============================================================ */

/*
 * We need a way to add results to the syssec_t structure from
 * parser.c. Because add_result() is static in syssec.c, we
 * expose it via a public function declared in syssec.h.
 * 
 * We declare syssec_report_add() in syssec.h and call it here.
 */
extern void syssec_report_add(syssec_t *s, const char *category,
                              const char *name, const char *desc,
                              severity_t sev, status_t status,
                              const char *rec);

void parser_integrity_report(syssec_t *s, binary_integrity_t *integrity) {
    char buf[512];
    
    if (!s || !integrity) return;
    
    /* Overall summary */
    snprintf(buf, sizeof(buf),
             "%d checked, %d verified, %d modified, %d missing, %d suspicious",
             integrity->count, integrity->verified, integrity->modified,
             integrity->missing, integrity->suspicious);
    
    severity_t sev = SEV_INFO;
    status_t status = STATUS_PASS;
    const char *rec = NULL;
    
    if (integrity->missing > 0 || integrity->modified > 0) {
        sev = SEV_CRITICAL;
        status = STATUS_FAIL;
        rec = "Reinstall missing or modified binaries from trusted sources";
    } else if (integrity->suspicious > 0) {
        sev = SEV_WARNING;
        status = STATUS_WARN;
        rec = "Review binaries with suspicious permissions";
    }
    
    syssec_report_add(s, "Integrity", "Standard Binaries", buf, sev, status, rec);
    
    /* Add individual critical entries for missing/world-writable */
    for (int i = 0; i < integrity->count; i++) {
        binary_check_t *bc = &integrity->binaries[i];
        
        if (!bc->exists) {
            snprintf(buf, sizeof(buf), "%s is MISSING", bc->path);
            syssec_report_add(s, "Integrity", bc->name, buf,
                              SEV_CRITICAL, STATUS_FAIL,
                              "Reinstall from trusted source immediately");
        } else if (bc->is_world_writable) {
            snprintf(buf, sizeof(buf), "%s is WORLD-WRITABLE", bc->path);
            syssec_report_add(s, "Integrity", bc->name, buf,
                              SEV_CRITICAL, STATUS_FAIL,
                              "Remove world-writable permission immediately");
        } else if (bc->uid != 0) {
            snprintf(buf, sizeof(buf), "%s owned by uid %d (not root)",
                     bc->path, bc->uid);
            syssec_report_add(s, "Integrity", bc->name, buf,
                              SEV_WARNING, STATUS_WARN,
                              "System binaries should be owned by root");
        }
    }
}
