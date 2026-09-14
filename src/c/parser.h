/*
 * parser.h - Tree parser and binary integrity checker for SYSSEC
 * 
 * Provides:
 * - Verbose /dev, /sys, /bin, /sbin, /usr/bin, /usr/sbin traversal
 * - Per-entry parsing with detailed output
 * - Binary integrity verification against known hashes
 * - Standard utility inventory
 * 
 * Copyright (c) 2026-2027 SYSSEC Project
 */

#ifndef SYSSEC_PARSER_H
#define SYSSEC_PARSER_H

#include "syssec.h"

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define PARSER_MAX_ENTRIES      4096
#define PARSER_MAX_PATH         512
#define PARSER_MAX_HASH         65      /* SHA-256 hex + null */

/* ============================================================
 * BINARY INTEGRITY STRUCTURES
 * ============================================================ */

typedef struct {
    char    name[64];           /* e.g., "ls" */
    char    path[256];          /* e.g., "/bin/ls" */
    char    expected_hash[PARSER_MAX_HASH];
    char    actual_hash[PARSER_MAX_HASH];
    int     exists;
    int     hash_match;
    int     is_setuid;
    int     is_setgid;
    int     is_world_writable;
    mode_t  mode;
    uid_t   uid;
    gid_t   gid;
    off_t   size;
} binary_check_t;

typedef struct {
    binary_check_t  binaries[128];
    int             count;
    int             verified;
    int             modified;
    int             missing;
    int             suspicious;
} binary_integrity_t;

/* ============================================================
 * TREE PARSING STRUCTURES
 * ============================================================ */

typedef struct {
    char    path[PARSER_MAX_PATH];
    char    name[256];
    mode_t  mode;
    uid_t   uid;
    gid_t   gid;
    off_t   size;
    int     is_dir;
    int     is_char;
    int     is_block;
    int     is_symlink;
    int     is_fifo;
    int     is_socket;
    int     is_regular;
    char    target[PARSER_MAX_PATH];  /* for symlinks */
    int     major;
    int     minor;
} parsed_entry_t;

typedef struct {
    parsed_entry_t  entries[PARSER_MAX_ENTRIES];
    int             count;
    int             dirs;
    int             files;
    int             symlinks;
    int             devices_char;
    int             devices_block;
    int             fifos;
    int             sockets;
    int             setuid;
    int             setgid;
    int             world_writable;
    int             root_owned;
} parse_result_t;

/* ============================================================
 * PUBLIC API - TREE PARSING
 * ============================================================ */

/*
 * parser_walk_dir - Recursively parse a directory tree with verbose output
 * 
 * @param root      - Root path to parse (e.g., "/dev", "/sys", "/bin")
 * @param max_depth - Maximum recursion depth (0 = unlimited)
 * @param verbose   - 1 for per-entry output
 * @param result    - Output result structure (caller-provided)
 * 
 * Returns: 0 on success, -1 on error
 */
int parser_walk_dir(const char *root, int max_depth, int verbose,
                    parse_result_t *result);

/*
 * parser_parse_dev - Deep parse /dev with device-type analysis
 * 
 * @param result  - Output result
 * @param verbose - 1 for verbose
 * 
 * Returns: 0 on success
 */
int parser_parse_dev(parse_result_t *result, int verbose);

/*
 * parser_parse_sys - Deep parse /sys with attribute display
 * 
 * @param result  - Output result
 * @param verbose - 1 for verbose
 * 
 * Returns: 0 on success
 */
int parser_parse_sys(parse_result_t *result, int verbose);

/*
 * parser_parse_bin - Deep parse /bin, /sbin, /usr/bin, /usr/sbin
 * 
 * @param result  - Output result
 * @param verbose - 1 for verbose
 * 
 * Returns: 0 on success
 */
int parser_parse_bin(parse_result_t *result, int verbose);

/*
 * parser_print_result - Print a summary of a parse result
 */
void parser_print_result(const char *label, parse_result_t *result);

/* ============================================================
 * PUBLIC API - BINARY INTEGRITY
 * ============================================================ */

/*
 * parser_binary_verify - Verify a single binary's hash
 * 
 * @param path - Path to binary
 * @param expected_hash - Expected SHA-256 (or NULL to just compute)
 * @param check - Output structure
 * 
 * Returns: 0 on success, -1 on error
 */
int parser_binary_verify(const char *path, const char *expected_hash,
                         binary_check_t *check);

/*
 * parser_integrity_check_standard - Check all standard utilities
 * 
 * @param integrity - Output structure
 * @param verbose - 1 for verbose output
 * 
 * Returns: 0 on success
 */
int parser_integrity_check_standard(binary_integrity_t *integrity, int verbose);

/*
 * parser_integrity_print - Print integrity report
 */
void parser_integrity_print(binary_integrity_t *integrity);

/*
 * parser_integrity_report - Add integrity findings to syssec results
 */
void parser_integrity_report(syssec_t *s, binary_integrity_t *integrity);

#endif /* SYSSEC_PARSER_H */
