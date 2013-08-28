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

#ifndef _FASTDD_MODULE_CONV_H
    #define _FASTDD_MODULE_CONV_H

#include <iostream>
#include <sstream>
#include <string>
#include <ctype.h>
#include <stdint.h>
#include "fastdd_t.hpp"
#include "fastdd_module.hpp"

using namespace std;

/** Conversion-tables are taken from the dd's source code */

/* dd -- convert a file while copying it.
   Copyright (C) 1985, 1990-1991, 1995-2011 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Paul Rubin, David MacKenzie, and Stuart Kemp. */

static char const ascii_to_ebcdic[] =
{
  '\000', '\001', '\002', '\003', '\067', '\055', '\056', '\057',
  '\026', '\005', '\045', '\013', '\014', '\015', '\016', '\017',
  '\020', '\021', '\022', '\023', '\074', '\075', '\062', '\046',
  '\030', '\031', '\077', '\047', '\034', '\035', '\036', '\037',
  '\100', '\117', '\177', '\173', '\133', '\154', '\120', '\175',
  '\115', '\135', '\134', '\116', '\153', '\140', '\113', '\141',
  '\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
  '\370', '\371', '\172', '\136', '\114', '\176', '\156', '\157',
  '\174', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
  '\310', '\311', '\321', '\322', '\323', '\324', '\325', '\326',
  '\327', '\330', '\331', '\342', '\343', '\344', '\345', '\346',
  '\347', '\350', '\351', '\112', '\340', '\132', '\137', '\155',
  '\171', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
  '\210', '\211', '\221', '\222', '\223', '\224', '\225', '\226',
  '\227', '\230', '\231', '\242', '\243', '\244', '\245', '\246',
  '\247', '\250', '\251', '\300', '\152', '\320', '\241', '\007',
  '\040', '\041', '\042', '\043', '\044', '\025', '\006', '\027',
  '\050', '\051', '\052', '\053', '\054', '\011', '\012', '\033',
  '\060', '\061', '\032', '\063', '\064', '\065', '\066', '\010',
  '\070', '\071', '\072', '\073', '\004', '\024', '\076', '\341',
  '\101', '\102', '\103', '\104', '\105', '\106', '\107', '\110',
  '\111', '\121', '\122', '\123', '\124', '\125', '\126', '\127',
  '\130', '\131', '\142', '\143', '\144', '\145', '\146', '\147',
  '\150', '\151', '\160', '\161', '\162', '\163', '\164', '\165',
  '\166', '\167', '\170', '\200', '\212', '\213', '\214', '\215',
  '\216', '\217', '\220', '\232', '\233', '\234', '\235', '\236',
  '\237', '\240', '\252', '\253', '\254', '\255', '\256', '\257',
  '\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
  '\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
  '\312', '\313', '\314', '\315', '\316', '\317', '\332', '\333',
  '\334', '\335', '\336', '\337', '\352', '\353', '\354', '\355',
  '\356', '\357', '\372', '\373', '\374', '\375', '\376', '\377'
};

static char const ascii_to_ibm[] =
{
  '\000', '\001', '\002', '\003', '\067', '\055', '\056', '\057',
  '\026', '\005', '\045', '\013', '\014', '\015', '\016', '\017',
  '\020', '\021', '\022', '\023', '\074', '\075', '\062', '\046',
  '\030', '\031', '\077', '\047', '\034', '\035', '\036', '\037',
  '\100', '\132', '\177', '\173', '\133', '\154', '\120', '\175',
  '\115', '\135', '\134', '\116', '\153', '\140', '\113', '\141',
  '\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
  '\370', '\371', '\172', '\136', '\114', '\176', '\156', '\157',
  '\174', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
  '\310', '\311', '\321', '\322', '\323', '\324', '\325', '\326',
  '\327', '\330', '\331', '\342', '\343', '\344', '\345', '\346',
  '\347', '\350', '\351', '\255', '\340', '\275', '\137', '\155',
  '\171', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
  '\210', '\211', '\221', '\222', '\223', '\224', '\225', '\226',
  '\227', '\230', '\231', '\242', '\243', '\244', '\245', '\246',
  '\247', '\250', '\251', '\300', '\117', '\320', '\241', '\007',
  '\040', '\041', '\042', '\043', '\044', '\025', '\006', '\027',
  '\050', '\051', '\052', '\053', '\054', '\011', '\012', '\033',
  '\060', '\061', '\032', '\063', '\064', '\065', '\066', '\010',
  '\070', '\071', '\072', '\073', '\004', '\024', '\076', '\341',
  '\101', '\102', '\103', '\104', '\105', '\106', '\107', '\110',
  '\111', '\121', '\122', '\123', '\124', '\125', '\126', '\127',
  '\130', '\131', '\142', '\143', '\144', '\145', '\146', '\147',
  '\150', '\151', '\160', '\161', '\162', '\163', '\164', '\165',
  '\166', '\167', '\170', '\200', '\212', '\213', '\214', '\215',
  '\216', '\217', '\220', '\232', '\233', '\234', '\235', '\236',
  '\237', '\240', '\252', '\253', '\254', '\255', '\256', '\257',
  '\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
  '\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
  '\312', '\313', '\314', '\315', '\316', '\317', '\332', '\333',
  '\334', '\335', '\336', '\337', '\352', '\353', '\354', '\355',
  '\356', '\357', '\372', '\373', '\374', '\375', '\376', '\377'
};

static char const ebcdic_to_ascii[] =
{
  '\000', '\001', '\002', '\003', '\234', '\011', '\206', '\177',
  '\227', '\215', '\216', '\013', '\014', '\015', '\016', '\017',
  '\020', '\021', '\022', '\023', '\235', '\205', '\010', '\207',
  '\030', '\031', '\222', '\217', '\034', '\035', '\036', '\037',
  '\200', '\201', '\202', '\203', '\204', '\012', '\027', '\033',
  '\210', '\211', '\212', '\213', '\214', '\005', '\006', '\007',
  '\220', '\221', '\026', '\223', '\224', '\225', '\226', '\004',
  '\230', '\231', '\232', '\233', '\024', '\025', '\236', '\032',
  '\040', '\240', '\241', '\242', '\243', '\244', '\245', '\246',
  '\247', '\250', '\133', '\056', '\074', '\050', '\053', '\041',
  '\046', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
  '\260', '\261', '\135', '\044', '\052', '\051', '\073', '\136',
  '\055', '\057', '\262', '\263', '\264', '\265', '\266', '\267',
  '\270', '\271', '\174', '\054', '\045', '\137', '\076', '\077',
  '\272', '\273', '\274', '\275', '\276', '\277', '\300', '\301',
  '\302', '\140', '\072', '\043', '\100', '\047', '\075', '\042',
  '\303', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
  '\150', '\151', '\304', '\305', '\306', '\307', '\310', '\311',
  '\312', '\152', '\153', '\154', '\155', '\156', '\157', '\160',
  '\161', '\162', '\313', '\314', '\315', '\316', '\317', '\320',
  '\321', '\176', '\163', '\164', '\165', '\166', '\167', '\170',
  '\171', '\172', '\322', '\323', '\324', '\325', '\326', '\327',
  '\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
  '\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
  '\173', '\101', '\102', '\103', '\104', '\105', '\106', '\107',
  '\110', '\111', '\350', '\351', '\352', '\353', '\354', '\355',
  '\175', '\112', '\113', '\114', '\115', '\116', '\117', '\120',
  '\121', '\122', '\356', '\357', '\360', '\361', '\362', '\363',
  '\134', '\237', '\123', '\124', '\125', '\126', '\127', '\130',
  '\131', '\132', '\364', '\365', '\366', '\367', '\370', '\371',
  '\060', '\061', '\062', '\063', '\064', '\065', '\066', '\067',
  '\070', '\071', '\372', '\373', '\374', '\375', '\376', '\377'
};

static unsigned char trans_table[256];

class fastdd_module_conv : public fastdd_module {
    private:
    enum mode {NONE=0, ASCII_TO_EBCDIC=1, EBCDIC_TO_ASCII=2, ASCII_TO_IBM=4, TO_LOWER=8, TO_UPPER=16};
    
    bool is_act;
    int flags;
    
    string error;
    
    public:
    fastdd_module_conv() {
        is_act=false;
        flags=0;
        
        for (int a=0; a<256; a++)
            trans_table[a] = a;
    }

    bool validate(void) {
        if (flags) {
            is_act = true;
        
            if (flags & EBCDIC_TO_ASCII)
                for (int a=0; a<256; a++)
                    trans_table[a] = ebcdic_to_ascii[trans_table[a]];
                    
            if (flags & TO_UPPER) {
                for (int a=0; a<256; a++)
                    trans_table[a] = toupper(trans_table[a]);
            }
            else if (flags & TO_LOWER) {
                for (int a=0; a<256; a++)
                    trans_table[a] = tolower(trans_table[a]);
            }
            
            if (flags & ASCII_TO_EBCDIC)
                for (int a=0; a<256; a++)
                    trans_table[a] = ascii_to_ebcdic[trans_table[a]];
            
            if (flags & ASCII_TO_IBM)
                for (int a=0; a<256; a++)
                    trans_table[a] = ascii_to_ibm[trans_table[a]];
                    
        }
        
        return true;
    }

    string get_name(void) { return "fastdd_module_conv"; }

    bool is_active(void) { return is_act; }

    bool is_operand(string operand) { return false; }

    bool set_operand(string operand, string value) {
        error="this module does not have operands";
        return false;
    }

    bool is_flag(string flag) {
        return (!flag.compare("--to-upper-case") || !flag.compare("--to-lower-case") || !flag.compare("--ascii-to-ebcdic")
            || !flag.compare("--ebcdic-to-ascii") || !flag.compare("--ascii-to-ibm"));
    }

    bool set_flag(string flag) {
        if (!flag.compare("--to-upper-case")) {
            if (flags & TO_LOWER) {
                error = "--to-upper-case is not compatible with --to-lower-case";
                return false;
            }
            flags |= TO_UPPER;
            return true;
        }
        else if (!flag.compare("--to-lower-case")) {
            if (flags & TO_UPPER) {
                error = "--to-lower-case is not compatible with --to-upper-case";
                return false;
            }
            flags |= TO_LOWER;
            return true;
        }
        else if (!flag.compare("--ascii-to-ebcdic")) {
            if ((flags & ASCII_TO_IBM) || (flags & EBCDIC_TO_ASCII)) {
                error = "--ascii-to-ebcdic is not compatible with --ebcdic-to-ascii and --ascii-to-ibm";
                return false;
            }
            flags |= ASCII_TO_EBCDIC;
            return true;
        }
        else if (!flag.compare("--ebcdic-to-ascii")) {
            if ((flags & ASCII_TO_IBM) || (flags & ASCII_TO_EBCDIC)) {
                error = "--ebcdic-to-ascii is not compatible with --ascii-to-ebcdic and --ascii-to-ibm";
                return false;
            }
            flags |= EBCDIC_TO_ASCII;
            return true;
        }
        else if (!flag.compare("--ascii-to-ibm")) {
            if ((flags & ASCII_TO_EBCDIC) || (flags & EBCDIC_TO_ASCII)) {
                error = "--ascii-to-ibm is not compatible with --ebcdic-to-ascii and --ascii-to-ebcdic";
                return false;
            }
            flags |= ASCII_TO_IBM;
            return true;
        }
        
        error = flag+" is not a valid flag";
        return false;
    }

    bool transform(buffer_t *buff) {
        for (uint64_t a=0; a<buff->length; a++) {
            buff->buffer[a] = trans_table[buff->buffer[a]];
        }
        
        return true;
    }
    
    string get_error(void) {
        return error;
    }
    
    string get_help() {
        stringstream ss;
        ss << "   CONVERSIONS\n";
        ss << "   Flags:\n";
        ss << "   --to-lower-case\n";
        ss << "      convert upper case charactes to lower case\n";
        ss << "   --to-upper-case\n";
        ss << "      convert lower case charactes to upper case\n";
        ss << "   --ascii-to-ebcdic\n";
        ss << "      from ASCII to EBCDIC\n";
        ss << "   --ebcdic-to-ascii\n";
        ss << "      from EBCDIC to ASCII\n";
        ss << "   --ascii-to-ibm\n";
        ss << "      from ASCII to alternate EBCDIC\n"; 

        return ss.str();
    }

};

#endif
