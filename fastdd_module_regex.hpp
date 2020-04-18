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

#ifndef _FASTDD_MODULE_REGEX_H
    #define _FASTDD_MODULE_REGEX_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <iomanip>
#include <boost/regex.hpp>
#include <cstring>
#include <cerrno>
#include "fastdd_t.hpp"
#include "partition_manager.hpp"
#include "fastdd_module.hpp"


using namespace std;

class fastdd_module_regex : public fastdd_module {
    private:
    bool is_simple_regex_match;
    bool is_human_readable_regex_match;

    bool is_act;
    bool is_first_block;
    bool is_get_partition;
    uint64_t next_needed;
    ofstream ofstream_regex;
    vector<boost::regex> re;

    string error;

    partition_manager pm;
    fastdd_file_t **fi;
    settings_t *settings;
    uint64_t ibs;

    /** read regexes from file given with option find= */
    bool init_regexes_from_file(const char *file_with_regex) {
        ifstream fi;
        fi.open(file_with_regex);

        if (!fi.is_open()) {
            stringstream ss;
            ss << "can not open '" << file_with_regex << "'";
            error = ss.str();
            return false;
        }

        string line;

        getline ( fi, line);
        while (line.size()) {
            try {
                boost::regex temp;
                temp.assign(line, boost::regex_constants::normal);
                re.push_back(temp);
            }
            catch (boost::regex_error& e) {
                stringstream ss;
                ss << "\"" << line << "\" is not a valid regular expression (" << e.what() << ")";
                error = ss.str();
                return false;
            }
            getline ( fi, line);
        }

        fi.close();

        return true;
    }

    public:

    fastdd_module_regex(fastdd_file_t **fi_, settings_t *settings_) {
        is_act = true;
        is_first_block = true;
        is_get_partition = true;
        is_simple_regex_match = false;
        is_human_readable_regex_match = false;
        fi = fi_;
        settings = settings_;
    }

    bool validate() {
        if (re.size() && !(ofstream_regex.is_open())) {
            error = "pattern-matching-results not setted";
            return false;
        }
        if (!re.size())
            is_act = false;

        pm = partition_manager((*fi)->file_name);
        ibs = settings->ibs;

        return true;
    }

    string get_name(void) {
        return "fastdd_regex_module";
    }

    bool is_active(void) {
        return is_act;
    }

    bool is_operand(string operand) {
        return (!operand.compare("pattern-file") || !operand.compare("find-regex") || !operand.compare("pattern-matching-results"));
    }

    bool set_operand(string operand, string value) {

        if (!operand.compare("pattern-file")) {
            return init_regexes_from_file(value.c_str());
        }
        else if (!operand.compare("find-regex")) {
            boost::regex temp;
            try {
                temp.assign(value, boost::regex_constants::normal);
                re.push_back(temp);
            }
            catch (boost::regex_error& e) {
                stringstream ss;
                ss << "<" << value << "> is not a valid regular expression (" << e.what() << ")";
                error = ss.str();
                return false;
            }
            return true;
        }
        else if (!operand.compare("pattern-matching-results")) {
            ofstream_regex.open(value.c_str(), ios_base::out);
            if (!(ofstream_regex.is_open())) {
                stringstream ss;
                ss << "error opening pattern matching output file '"<< value <<"'";
                error = ss.str();
                return false;
            }
            return true;
        }

        return false;
    }

    bool is_flag(string flag) {
        return ( !flag.compare("--simple-regex-match") || !flag.compare("--human-readable-regex-match"));
    }

    bool set_flag(string flag) {
        if (!flag.compare("--simple-regex-match")) {
            is_simple_regex_match = true;
            is_get_partition = false;
            return true;
        }
        else if (!flag.compare("--human-readable-regex-match")) {
            is_human_readable_regex_match = true;
            return true;
        }

        return false;
    }

    bool transform(buffer_t *buff) {
        boost::smatch what;

        if (is_get_partition) {
            if (is_first_block) {
                next_needed = pm.update(buff->buffer, 0);
                is_first_block=false;
            }
            else if ((*fi)->current_position <= next_needed && next_needed < (*fi)->current_position + buff->length)  {
               // cout << fi->current_position << " " << next_needed << " " << fi->current_position + buff->length;
                next_needed = pm.update(buff->buffer+(next_needed - (*fi)->current_position), next_needed);
            }
            if (pm.is_error()) is_get_partition=false;
        }

        int j;
        string search_buffer(buff->buffer, buff->buffer+buff->length);
        int l=re.size();
        for (j=0; j<l; j++) {
            if (is_simple_regex_match) {  // write just if there is a match in this block
                bool result = boost::regex_search(search_buffer , what, re[j]);
                if (result) {
                    ofstream_regex << "matches found for regex "<<j<<" in input block " << setw(10)
                        << setfill(' ') <<setbase(10) <<((*fi)->current_position + what.position())
                        << ": " << setw(16) << setbase(16) << setfill('0') << (*fi)->current_position << "-"
                        << setw(16) << setbase(16) << setfill('0') << ((*fi)->current_position+buff->length) << endl;
                }
            }
            else { // print in find_file_output all information
                try {
                    boost::sregex_iterator m1(search_buffer.begin(), search_buffer.end(), re[j], boost::match_default | boost::match_partial);
                    boost::sregex_iterator m2;

                    if (m1==m2) continue;

                    do {
                        boost::smatch m = *m1;

                        if (m.length(0)>0) {
                            if (!m[0].matched) ofstream_regex << "? ";

                            ofstream_regex << setbase(10) << j << " " << (((*fi)->current_position+m.position())/ibs ) << " " <<
                                ((*fi)->current_position+m.position()) << " " << m.length(0) << " ";
                            if (is_human_readable_regex_match) {
                                string word = string(search_buffer, m.position(), m.length(0));
                                ofstream_regex << word;
                            }
                            else {
                                for (int temp=0; temp<m.length(0); temp++) {
                                    ofstream_regex << setw(2) << setfill('0') << setbase(16) << (buff->buffer[m.position()+temp] & 255);
                                }
                            }
                            ofstream_regex << " " << pm.get_partition_at((*fi)->current_position+m.position()) << endl;
                        }
                        m1++;
                    } while ( !(m1 == m2));

                }
                catch (boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<std::runtime_error> >& e) {
                    stringstream ss;
                    ss << "error while parsing data (" << e.what() << ")";
                    error = ss.str();
                    return false;
                }
            }
        }
        return true;
    }

    string get_error(void) {
        return error;
    }

    string get_help() {
        stringstream ss;
        ss << "   PATTERN MATCHING\n";
        ss << "   Operands:\n";
        ss << "   pattern-file=FILE\n";
        ss << "      search in blocks for occurences of regexes specified one per line in FILE\n";
        ss << "   find-regex=REGEX\n";
        ss << "      search in blocks for REGEX\n";
        ss << "   pattern-matching-results=FILE\n";
        ss << "      save the matches of regexes in FILE in the format:\n";
        ss << "         idx_regex in_block_no offset length matching_string partition\n";
        ss << "      where:\n";
        ss << "         idx_regex        is the index of the regex\n";
        ss << "         in_block_no      is the block number where regex has been found\n";
        ss << "         offset           is the start point of the match from the beginning of\n";
        ss << "                          the input file\n";
        ss << "         length           is the length of the match\n";
        ss << "         matching_string  is the string that matched the regex (in hexadecimal)\n";
        ss << "         partition        is the partition where regex has been found\n";
        ss << "      Partial matches found at the end of blocks are reported with a '?' at the\n";
        ss << "      begin of the line\n";
        ss << "      See --simple-regex-match to save matches in less detailed format.\n";
        ss << "   Flags:\n";
        ss << "   --simple-regex-match\n";
        ss << "      for each block just specify which regexes it contains\n";
        ss << "   --human-readable-regex-match\n";
        ss << "      write matching regexes in ascii instead of in hexadecimal\n";

        return ss.str();
    }
};

#endif
