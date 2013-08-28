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

#ifndef _FASTDD_MODULE_H
    #define _FASTDD_MODULE_H

#include <iostream>
#include "fastdd_t.hpp"

using namespace std;

class fastdd_module {
    public:

    // validate the module after the command line arguments reading
    virtual bool validate(void) { return false; }

    // get the module name
    virtual string get_name(void) { return ""; }

    // fastdd will use this module only if is active (the programmer can disable
    // the module when a transfor error occurs)
    virtual bool is_active(void) { return false; }

    // true if 'operand' is a fastdd command line operand (operand=value)
    virtual bool is_operand(string operand) { return false; }
    // set 'operand' equals to value, true on success
    virtual bool set_operand(string operand, string value) { return false; }

    // true if 'flag' is a fastdd command line flag (--flag)
    virtual bool is_flag(string flag) { return false; }
    // set flag=true (--flag), true on success
    virtual bool set_flag(string flag) { return false; }


    // transform buffer buff, according to the command line flags and operands
    // return true if no error occur
    virtual bool transform(buffer_t *buff) { return false; }
    // get error occurred after transform
    virtual string get_error(void) { return ""; }
    
    // get a brief help for the fastdd --help flag
    virtual string get_help(void) { return ""; }
    
    virtual ~fastdd_module() { }
};

#endif
