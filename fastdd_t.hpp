/*
 * fastdd, v. 1.0.0, an open-ended forensic imaging tool
 * Copyright (C) 2013, Free Software Foundation, Inc.
 * written by Paolo Bertasi and Nicola Zago
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef _FASTDD_T_H
    #define _FASTDD_T_H

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <stdint.h>

using namespace std;

struct _buffer_t;

typedef struct _buffer_t buffer_t;

struct _buffer_t {
    unsigned char *buffer;
    uint64_t length;

    int tot_digests;
    EVP_MD_CTX *ctx;
    const EVP_MD **digest_type;
    unsigned char **hash;
    unsigned int *hash_len;

    bool is_full;
    bool is_empty;
    bool is_last;

    pthread_mutex_t buffer_mutex;
    pthread_cond_t is_not_full;
    pthread_cond_t *is_not_empty;

    int writer_entered;
    int writer_active;
    bool *already_write;
    bool *active;

    buffer_t *the_other_buffer;
};

typedef struct _fastdd_file_t {
    int idx;
    const char *file_name;
    int file_descriptor;
    int64_t total_size_in_byte;
    uint64_t skip_in_byte;
    int64_t byte_to_read;
    uint64_t byte_read;
    uint64_t current_position;

    int is_direct_o;
    int64_t b_compl;    // tra i buffer letti, quanti completi, quanti parziali
    int64_t b_part;

    int tot_digests;
    const EVP_MD **digest_type;
    EVP_MD_CTX *ctx;
    unsigned char **hash;
    unsigned int *hash_len;
} fastdd_file_t;

typedef struct _settings_t {
    string input_file_name;
    vector<string> output_file_name;
    int64_t bs;
    int64_t ibs;
    int64_t obs;
    int64_t count;
    int64_t skip;
    int64_t seek;
    string log_file;
    int reading_attempts;
    int64_t reread_bs;
    ofstream ofstream_log_file;

    vector<string> md_files;
    vector<string> md_blocks;
    bool is_md_file_in;
    bool is_md_files_out;
    bool is_md_blocks_check;
    bool is_md_blocks_save;
    string md_file_name;
    ofstream ofstream_md;

    bool full_block;
    int is_direct_i;
    int is_direct_o;
    int is_o_trunc;
    bool is_parallel;
    bool is_progress_bar;
    bool is_verbose;
    bool is_debug;
    bool ignore_module_error;

    bool is_get_partition;
    bool is_print_partition;
} settings_t;

#endif
