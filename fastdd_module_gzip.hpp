/*
 * fastdd, v. 1.1.0, an open-ended forensic imaging tool
 * Copyright (C) 2013-2020, Free Software Foundation, Inc.
 * written by Paolo Bertasi, Nicola Zago and Hans-Joachim Michl
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

#ifndef _FASTDD_MODULE_GZIP_H
    #define _FASTDD_MODULE_GZIP_H

#include <iostream>
#include <sstream>
#include <string>
#include <cstdio>
#include <stdint.h>
#include <cstring>
#include "fastdd_t.hpp"
#include "fastdd_module.hpp"
#include <zlib.h>

using namespace std;

class fastdd_module_gzip : public fastdd_module {
    private:
    int compression_level;
    int chunk;
    bool is_std_of;
    bool is_act;
    buffer_t *buffer_orig;
    settings_t *settings;
    int64_t buffer_l, buffer_max;
    unsigned char *local_buffer;
    string errore;
    z_stream strm;

    ////// SOURCE of the zlib code:
    /*-zpipe.c: example of proper use of zlib's inflate() and deflate()
   Not copyrighted -- provided to the public domain
   Version 1.4  11 December 2005  Mark Adler */
    /* report a zlib or i/o error */
 /*   void zerr(int ret)
    {
        switch (ret) {
        case Z_ERRNO:
            if (ferror(stdin))
                errore = "error reading stdin";
            if (ferror(stdout))
                errore = "error writing stdout";
            break;
        case Z_STREAM_ERROR:
            errore = "invalid compression level";
            break;
        case Z_DATA_ERROR:
            errore = "invalid or incomplete deflate data";
            break;
        case Z_MEM_ERROR:
            errore = "out of memory";
            break;
        case Z_VERSION_ERROR:
            errore = "zlib version mismatch";
        }
    }*/

    public:

    fastdd_module_gzip(settings_t *settings_, buffer_t *buffer_) {
        is_std_of = false;
        is_act = false;
        compression_level=6;
        settings = settings_;
        buffer_l = buffer_max = 0;
        chunk = -1;
        buffer_orig = buffer_;
        local_buffer = (unsigned char *) 0;
    }

    bool validate() {
        if (!is_act) return true;

        if (settings->bs<512) {
            errore = "compression requires bs>=512 bytes";
            is_act = false;
            return false;
        }

        // no direct I/O e seek in output
        if (settings->is_direct_o && settings->seek) {
            settings->is_direct_o = false;
            settings->seek=0;

            errore = "compression requires to disable direct I/O in output files (-o) and to not seek output files";
            is_act = false;
            return false;
        }

        if (chunk == -1) chunk = (settings->bs < 16384) ? settings->bs : 16384;

        if (chunk > settings->bs) {
            errore = "chunk is bigger than bs";
            return false;
        }

        buffer_max = settings->bs+262144;
        local_buffer = (unsigned char *) malloc(buffer_max*sizeof(unsigned char));

        // ingrandisco i buffer originali
        free(buffer_orig->buffer);
        free(buffer_orig->the_other_buffer->buffer);

        int t = posix_memalign( (void **) &(buffer_orig->buffer), 512, buffer_max);
        if (t) {
            errore = "couldn't reallocate buffers";
            is_act = false;
            return false;
        }

        t = posix_memalign( (void **) &(buffer_orig->the_other_buffer->buffer), 512, buffer_max);
        if (t) {
            errore = "couldn't reallocate buffers";
            is_act = false;
            return false;
        }

    /* allocate deflate state */
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        int ret = deflateInit2(&strm, compression_level, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        if (ret != Z_OK) {
            is_act = false;
            return false;
        }

        is_act = true;
        return true;
    }

    string get_name() { return "fastdd_module_gzip"; }

    bool is_active() { return is_act; }

    bool is_operand(string operand) {
        return (!operand.compare("compression") || !operand.compare("chunk"));
    }

    bool set_operand(string operand, string value) {
        if (!operand.compare("compression")) {
            compression_level = -1;

            compression_level = atoi(value.c_str());
            if (compression_level<0 || compression_level>9) {
                errore = "invalid compression level";
                return false;
            }
            is_act = true;
            return true;
        }
        else if (!operand.compare("chunk")) {
            chunk = atoi(value.c_str());
            if (chunk<4096) {
                errore = "invalid chunk (must be > 4096)";
                return false;
            }
            return true;
        }

        errore = "invalid operand";
        return false;
    }

    bool is_flag(string flag) {
        return false;
    }

    bool set_flag(string flag) {
        return false;
    }

    bool transform(buffer_t *buff) {
        int flush = (buff->is_last) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = buff->buffer;
        strm.avail_in = buff->length;

        int chunk_offset=0;

        do {
            strm.avail_out = chunk;
            strm.next_out = local_buffer+chunk_offset;
            int ret = deflate(&strm, flush);
            int have = chunk - strm.avail_out;
         //   cerr << chunk_offset << " -" << have << endl;
            chunk_offset += have;
        } while (strm.avail_out == 0);

  //      cerr << chunk_offset << endl;
        memcpy(buff->buffer, local_buffer, chunk_offset);
        buff->length = chunk_offset;

  //      cerr << buff->length << endl;

        if (buff->is_last) {
            (void)deflateEnd(&strm);
            is_act = false;
        }

        return true;
    }

    string get_error() {
        return errore;
    }

    string get_help() {
        stringstream ss;
        ss << "   COMPRESSION\n";
        ss << "   compression=LEVEL\n";
        ss << "      set the level of compression (LEVEL=0-9, default: 6). The module uses\n" <<
              "      level 8 of zlib memory usage\n";
        ss << "      Note that this module modifies the content of fastdd buffer, so hash\n";
        ss << "      checking among input and output files should not be used.\n";
        ss << "   chunk=BYTES\n";
        ss << "      set the compression window (default: min(16K,bs) )\n";

        cerr << ss.str() << endl;

        return ss.str();
    }

    ~fastdd_module_gzip() {
        if (local_buffer)
            free(local_buffer);
    }
};

#endif
