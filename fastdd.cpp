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
#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <map>
#include <iomanip>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <linux/fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <openssl/evp.h>

using namespace std;

#ifndef TOT_BUFFERS
#define TOT_BUFFERS 2
#endif

#define MAX(X,Y)	(((X)>(Y)) ? (X) : (Y))
#define MIN(X,Y)	(((X)<(Y)) ? (X) : (Y))

#include "fastdd_t.hpp"
#include "partition_manager.hpp"
#include "fastdd_module.hpp"
#include "fastdd_module_regex.hpp"
#include "fastdd_module_conv.hpp"
#include "fastdd_module_gzip.hpp"

// variables
map<string,uint64_t> hum_str2int;   // change suffixes KB,MB ecc in int64_t
map<uint64_t,string> hum_int2str;   // and viceversa

uint64_t t_start;

class progress_bar {
    private:
    uint64_t s_off, e_off, curr_pos;
    int s_o, e_o, c_o;
    string barra;
    
    public:
    progress_bar() { }
    
    progress_bar(uint64_t start_offset, uint64_t end_offset) {
        s_off = start_offset;
        e_off = end_offset;
        curr_pos = start_offset;
        c_o = s_o = 1;
        e_o = 51;
        barra = "|                                                  |";
    }
    
    string get_barra() {
        stringstream ss;
        
        int perc = (curr_pos - s_off)*100 / (e_off-s_off);
        ss << barra << setw(5) << perc << "% ";
        
        struct timeval t_2;
        gettimeofday(&t_2, NULL);
        uint64_t t = t_2.tv_sec-t_start/1000000;
        
        t = t * (e_off-curr_pos) / (curr_pos - s_off);
        
        int sec = t%60;
        t/=60;
        int min = t%60;
        int h = t/60;
        
        ss << " (" << h << ":" << setw(2) << setfill('0')<< min << ":" << setw(2) << setfill('0')<< sec << " sec. left)";
        
        return ss.str();
    }
    
    void add_pos(uint64_t n) {
        curr_pos += n;
        c_o = (curr_pos - s_off) * 50 / (e_off - s_off);
        
        for (int a=1; a<c_o+1; a++)
            if (barra[a]==' ') barra[a]='=';
    }
    
    void add_err(uint64_t offset) {
        offset = (offset - s_off) * 50 / (e_off - s_off);
        if (offset==0) offset=1;
        
        switch (barra[offset]) {
            case 'x':
                barra[offset] = 'X';
                break;
            case ' ': case '=':
                barra[offset] = 'x';
                break;
            default:
                break;
        }
    }
};

partition_manager pm;
progress_bar pb;
vector<fastdd_module *> modules;

settings_t settings;   // configuration of the program
buffer_t buffer[TOT_BUFFERS];
fastdd_file_t *fi_common, *fo_common;
int tot_output_file;
//ofstream couttime;
//uint64_t t_start;

// variables
const char *program_name;

#define PROGRAM_NAME "fastdd"
#define VERSION_MAJOR "1"
#define VERSION_MINOR "0"
#define VERSION_REVISION "0"

// function signatures
void help(void);
void version(void);

void init_default_settings() {
    settings.bs=-1;
    settings.ibs=-1;
    settings.obs=-1;
    settings.count=-1;
    settings.skip=0;
    settings.seek=0;
    settings.reading_attempts = 1;
    settings.reread_bs = 512;
    settings.is_md_file_in = false;
    settings.is_md_files_out = false;
    settings.is_md_blocks_check = false;
    settings.is_md_blocks_save = false;
    settings.ignore_module_error = false;
    settings.is_direct_i = O_DIRECT;
    settings.is_direct_o = O_DIRECT;
    settings.is_o_trunc = O_TRUNC;
    settings.full_block = false;
    settings.is_parallel = true;
    settings.is_progress_bar = true;
    settings.is_verbose = false;
    settings.is_debug = false;
    settings.is_get_partition=false;
    settings.is_print_partition=false;
}

/** Convert a number string with literal suffix (K, M...) in int64_t*/
int64_t init_read_suffixed_number(string number) {
    int64_t suffix = 1;
    int start=0, end=number.size();
    
    int64_t suf = 1;
    // detect suffix by map hum_str2int
    if (end-start>1 && number[number.size()-1] > '9' && number[number.size()-2] > '9') {
        suf = hum_str2int[number.substr(number.size()-2,2)];
        end-=2;
    }
    else if (end-start>0 && number[number.size()-1] > '9') {
        suf = hum_str2int[number.substr(number.size()-1,1)];
        end--;
    }
        
    if (suf==0) {
        cerr << program_name << ": error: unknown suffix in '" << number << "'\n";
        exit(-1);
    }
    suffix *= suf;

    int64_t num=0;
    while (start<end) {
        if (number[start]<'0' || number[start]>'9') {
            cerr << program_name << ": invalid number\n";
            exit(1);
        }
        num = num*10 + ((int)number[start++]-'0');
    }

    num = suffix*num;
    
    return num;
}

void init_translation_maps() {
    hum_str2int["K"]=1LL<<10;
    hum_str2int["M"]=1LL<<20;
    hum_str2int["G"]=1LL<<30;
    hum_str2int["T"]=1LL<<40;
    hum_str2int["P"]=1LL<<50;
    hum_str2int["KB"]=1000LL;
    hum_str2int["MB"]=1000000LL;
    hum_str2int["GB"]=1000000000LL;
    hum_str2int["TB"]=1000000000000LL;
    hum_str2int["PB"]=1000000000000000LL;
}

/** decodifica un flag */
void init_read_flag(string flag) {
    if (!flag.compare("--hash-blocks-check") || !flag.compare("-c")) {
        settings.is_md_blocks_check = true;
    }
    else if (!flag.compare("--hash-file-all") || !flag.compare("-f")) {
        settings.is_md_files_out = true;
        settings.is_md_file_in = true;
    }
    else if (!flag.compare("--hash-file-in")) {
        settings.is_md_file_in = true;
    }
    else if (!flag.compare("--hash-file-out")) {
        settings.is_md_files_out = true;
    }
    else if (!flag.compare("--direct-input-disabled") || !flag.compare("-i")) {
        settings.is_direct_i = 0;
    }
    else if (!flag.compare("--direct-output-disabled") || !flag.compare("-o")) {
        settings.is_direct_o = 0;
    }
    else if (!flag.compare("--no-progress-bar")) {
        settings.is_progress_bar = false;
    }
    else if (!flag.compare("--ignore-modules-errors")) {
        settings.ignore_module_error = true;
    }
    else if (!flag.compare("--no-parallel") || !flag.compare("-p")) {
        settings.is_parallel = false;
    }
    else if (!flag.compare("--fast")) {
        settings.reading_attempts=0;
        settings.bs = 1<<24;
    }
    else if (!flag.compare("--full-block")) {
        settings.full_block = true;
    }
    else if (!flag.compare("--get-partition-table")) {
        if (settings.skip > 0) {
            cerr << program_name << ": skipping blocks of input is incompatible with partition table creation" << endl;
            exit(1);
        }
        settings.is_get_partition=true;
        settings.is_print_partition=true;
    }
    else if (!flag.compare("--debug")) {
        settings.is_debug = settings.is_verbose = true;
    }
    else {
        for (int i=0; i<modules.size(); i++) {
            if (modules[i]->is_flag(flag)) {
                bool ok = modules[i]->set_flag(flag);
                
                if (ok)
                    return;
                else {
                    cerr << modules[i]->get_name() << ": " << modules[i]->get_error() << endl;
                    exit(-1);
                }
            }
        }
        
        cerr << program_name << ": error: unknown flag '" << flag << "'." << endl;
        exit(-1);
    }
}

/** tokenize the string right using comma as dividing symbol */
void add_to_vector(vector<string> &a_vec, string right) {
    replace( right.begin(), right.end(), ',', ' ');
    istringstream in(right, istringstream::in);
    
    while (in.good()) {
        string temp;
        in >> temp;
        a_vec.push_back(temp);
    }
}

/** decodifica un operando */
void init_read_operand(string op) {
    const char *op_c = op.c_str();
    
    int i=0;
    while (i<op.length() && op_c[i] != 0 && op_c[i] != '=') i++;
    
    if (i==op.length() || op_c[i]==0 || op_c[i+1]==0) {
        cerr << program_name << ": invalid operand '" << op << "'\n";
        exit(1);
    }
    
    string left = op.substr(0,i);
    string right = op.substr(i+1, op.size()-i-1);
    
    if (!left.compare("if")) {
        settings.input_file_name = right;
    }
    else if (!left.compare("of")) {
        settings.output_file_name.push_back(right);
    }
    else if (!left.compare("bs")) {
        if (settings.ibs != -1 || settings.obs != -1) {
            cerr << program_name << ": error: bs is incompatible with ibs and obs options\n" << endl;
            exit(1);
        }
        settings.bs = init_read_suffixed_number(right);
        
        if (settings.bs & 511)      // disable O_DIRECT if bs%512 != 0
            settings.is_direct_i = settings.is_direct_o = 0;
    }
    else if (!left.compare("ibs")) {
        if (settings.bs != -1) {
            cerr << program_name << ": error: ibs is incompatible with bs option\n" << endl;
            exit(1);
        }
        settings.ibs = init_read_suffixed_number(right);
        
        if (settings.ibs & 511)      // disable O_DIRECT if bs%512 != 0
            settings.is_direct_i = settings.is_direct_o = 0;
    }
    else if (!left.compare("obs")) {
        if (settings.bs != -1) {
            cerr << program_name << ": error: obs is incompatible with bs option\n" << endl;
            exit(1);
        }
        settings.obs = init_read_suffixed_number(right);
        
        if (settings.obs & 511)      // disable O_DIRECT if bs%512 != 0
            settings.is_direct_i = settings.is_direct_o = 0;
    }
    else if (!left.compare("count")) {
        settings.count = init_read_suffixed_number(right);
    }
    else if (!left.compare("seek")) {
        settings.seek = init_read_suffixed_number(right);
        settings.is_o_trunc = 0;
    }
    else if (!left.compare("skip")) {
        if (settings.is_get_partition) {
            cerr << program_name << ": skipping blocks of input is incompatible with partition table creation" << endl;
            exit(1);
        }
        settings.skip = init_read_suffixed_number(right);
    }
    else if (!left.compare("log")) {
        settings.log_file = right;
        settings.ofstream_log_file.open(right.c_str(), ios_base::out ); 
        settings.is_verbose = true;
        if (!(settings.ofstream_log_file.is_open())) {
            cerr << program_name << ": error: error while opening log file '" << right << "'\n";
            exit(1);
        }
        settings.ofstream_log_file << "fastdd v. " << VERSION_MAJOR << "." << VERSION_MINOR << "." << VERSION_REVISION << " (last modified: " << __TIMESTAMP__ << ", compiled " << __TIME__ << ")\n";
        
        struct tm *local;
        time_t t;
        t = time(NULL);
        local = localtime(&t);
        settings.ofstream_log_file << "start job: " << asctime(local) << "\n";
    }
    else if (!left.compare("reading-attempts")) {
        settings.reading_attempts = atoi(right.c_str());
        if (settings.reading_attempts < 0) {
            cerr << program_name << ": error: argument of --reading-attempts is less than 0.\n";
            exit(1);
        }
    }
    else if (!left.compare("hash-blocks-save")) {
        settings.is_md_blocks_save = true;
        
        settings.ofstream_md.open(right.c_str(), ios_base::out);
        if (!(settings.ofstream_md.is_open())) {
            cerr << program_name << ": error: opening blocks hash output file '"<< right <<"'\n";
            exit(1);
        }
        settings.md_file_name = right;
    }
    else if (!left.compare("reread-bs")) {
        settings.reread_bs = init_read_suffixed_number(right);
        if (settings.reading_attempts < 0) {
            cerr << program_name << ": error: reread-bs is less than 0.\n";
            exit(1);
        }
    }
    else if (!left.compare("hash-blocks")) {
        add_to_vector(settings.md_blocks, right);
    }
    else if (!left.compare("hash-files")) {
        add_to_vector(settings.md_files, right);
    }
    else {
        for (int i=0; i<modules.size(); i++) {
            if (modules[i]->is_operand(left)) {
                bool ok = modules[i]->set_operand(left,right);
                
                if (ok)
                    return;
                else {
                    cerr << modules[i]->get_name() << ": " << modules[i]->get_error() << endl;
                    exit(-1);
                }
            }
        }
        
        cerr << program_name << ": error: unknow operand '" << left << "'\n";
        exit(-1);
    }
}

// read the setting from arguments
void init_read_arguments_settings(int argc, char *argv[]) {
    vector<string> args(argv, argv+argc);

    program_name = argv[0];

    if (find(args.begin(), args.end(), "--help")!=args.end() || 
        find(args.begin(), args.end(), "-h")!=args.end()) {
        help();
        exit(0);
    }
    
    if (find(args.begin(), args.end(), "--version")!=args.end()) {
        version();
        exit(0);
    }
    
    init_translation_maps();
    
    ////////////////// leggo operandi e flags
    for (int i=1; i<argc; i++) {
        if (args[i][0]=='-') init_read_flag(args[i]);
        else init_read_operand(args[i]);
    }

//////////////////// determino buffer
    if (settings.bs>0)
        settings.ibs = settings.obs = settings.bs;
    else if (settings.ibs>0 || settings.obs > 0) {
        settings.bs = MAX(settings.ibs,settings.obs);
        if (settings.ibs==-1)
            settings.ibs=512;
        if (settings.obs==-1)
            settings.obs=512;
    }
    else
        settings.ibs = settings.obs = settings.bs = 512;


    ////////////////////////
    if (settings.bs%settings.ibs!=0 && settings.bs%settings.obs!=0) {
        cerr << program_name << ": obs must be a multiple of ibs or viceversa.\n";
        exit(1);
    }
    
    if ((settings.is_verbose || settings.is_debug) && !(settings.ofstream_log_file.is_open())) {
        cerr << program_name << ": log=FILE must be specified when --debug or --verbose are enabled.\n";
        exit(1);
    }

    if ((settings.ibs % 512 != 0 || settings.obs%512!=0) && settings.is_print_partition) {
        cerr << program_name << ": buffers must be multiple of 512 to enable partition detection.\n";
        exit(1);
    }

    /////// hash di default
    if (settings.md_files.size() < 1) settings.md_files.push_back("md5");
    if (settings.md_blocks.size() < 1) settings.md_blocks.push_back("md5");
    
    if (settings.is_debug) {
        settings.ofstream_log_file << "OPERANDS:\n";
        settings.ofstream_log_file << "\tinput: " << settings.input_file_name << endl;
        for (int i=0; i<settings.output_file_name.size(); i++)
            settings.ofstream_log_file << "\toutput[" << i << "]: " << settings.output_file_name[i] << endl;
        settings.ofstream_log_file << "\tbs: " << settings.bs << endl;
        settings.ofstream_log_file << "\treread_bs: " << settings.reread_bs << endl;
        settings.ofstream_log_file << "\treading-attempts: " << settings.reading_attempts << endl;
        settings.ofstream_log_file << "\tibs: " << settings.ibs << endl;
        settings.ofstream_log_file << "\tobs: " << settings.obs << endl;
        settings.ofstream_log_file << "\tskip: " << settings.skip << endl;
        settings.ofstream_log_file << "\tseek: " << settings.seek << endl;
        settings.ofstream_log_file << "\tcount: " << settings.count << endl;
        settings.ofstream_log_file << "\toutput file for md blocks: " << settings.md_file_name << endl;
        settings.ofstream_log_file << "\t\t is file ready: " << settings.ofstream_md.is_open() << endl;
        settings.ofstream_log_file << "\tlog file: "<< settings.log_file << endl;
        settings.ofstream_log_file << "\t\tis file ready: "<< settings.ofstream_log_file.is_open() << endl;
        
        settings.ofstream_log_file << "\thashes for blocks: ";
        for (int i=0; i<settings.md_blocks.size(); i++)
            settings.ofstream_log_file << settings.md_blocks[i] << " ";
        settings.ofstream_log_file << endl;
        
        settings.ofstream_log_file << "\thashes for files: ";
        for (int i=0; i<settings.md_files.size(); i++)
            settings.ofstream_log_file << settings.md_files[i] << " ";
        settings.ofstream_log_file << endl;
        
        settings.ofstream_log_file << "\treading attempts: " << settings.reading_attempts << endl;
        
        settings.ofstream_log_file << "\nFLAGS:\n";
        settings.ofstream_log_file << "\tmd file in: " << settings.is_md_file_in << endl;
        settings.ofstream_log_file << "\tmd files out: " << settings.is_md_files_out << endl;
        settings.ofstream_log_file << "\tmd blocks check: " << settings.is_md_blocks_check << endl;
        settings.ofstream_log_file << "\tmd blocks save: " << settings.is_md_blocks_save << endl;
        settings.ofstream_log_file << "\tdirect input: " << settings.is_direct_i << endl;
        settings.ofstream_log_file << "\tdirect output: " << settings.is_direct_o << endl;
        settings.ofstream_log_file << "\tparallel: " << settings.is_parallel << endl;
        settings.ofstream_log_file << "\tprogress bar: " << settings.is_progress_bar << endl;
        settings.ofstream_log_file << "\tverbose: "<< settings.is_verbose << endl;
        settings.ofstream_log_file << "\tdebug: "<< settings.is_debug << endl;
    }
    else if (settings.is_verbose) {
        settings.ofstream_log_file << "input: " << settings.input_file_name << endl;
        for (int i=0; i<settings.output_file_name.size(); i++)
            settings.ofstream_log_file << "output[" << i << "]: " << settings.output_file_name[i] << endl;
        settings.ofstream_log_file << "bs: " << settings.bs << endl;
        settings.ofstream_log_file << "reread_bs: " << settings.reread_bs << endl;
        settings.ofstream_log_file << "reading-attempts: " << settings.reading_attempts << endl;
        settings.ofstream_log_file << "ibs: " << settings.ibs << endl;
        settings.ofstream_log_file << "obs: " << settings.obs << endl;
        settings.ofstream_log_file << "skip: " << settings.skip << endl;
        settings.ofstream_log_file << "seek: " << settings.seek << endl;
        settings.ofstream_log_file << "count: " << settings.count << endl;
    }
}

void init_buffers() {
    int tot;
    if (settings.is_parallel)
        tot = TOT_BUFFERS;
    else
        tot = 1;

    for (int i=0; i<tot; i++) {
        int t = posix_memalign( (void **) &(buffer[i].buffer), 512, settings.bs);
        if (t) {
            cerr << program_name << ": error: allocating buffer " << i << ": " << strerror(errno) << endl;
            exit(1);
        }
        buffer[i].length = 0;
        buffer[i].is_full = false;
        buffer[i].is_empty = true;
        buffer[i].is_last = false;
        
        pthread_mutex_init(&(buffer[i].buffer_mutex), NULL);
        pthread_cond_init (&(buffer[i].is_not_full), NULL);
        buffer[i].is_not_empty = (pthread_cond_t *) malloc(MAX(settings.output_file_name.size(), 1) * sizeof(pthread_cond_t));
        buffer[i].writer_entered = 0;
        buffer[i].writer_active = 0;
        buffer[i].active = (bool *) malloc(MAX(settings.output_file_name.size(), 1)* sizeof(bool));
        buffer[i].already_write = (bool *) malloc(MAX(settings.output_file_name.size(), 1) * sizeof(bool));       // how many writers have finished this buffer
        
        for (int j=0; j<MAX(settings.output_file_name.size(), 1); j++) {
            pthread_cond_init (&(buffer[i].is_not_empty[j]), NULL);
            buffer[i].active[j] = true;
            buffer[i].already_write[j] = false;
        }
    
        buffer[i].tot_digests = 0;
        if (settings.is_md_blocks_check || settings.is_md_blocks_save) {
            buffer[i].tot_digests = settings.md_blocks.size();
            buffer[i].ctx = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX) * buffer[i].tot_digests);
            buffer[i].digest_type = (const EVP_MD **) malloc(sizeof(const EVP_MD *) * buffer[i].tot_digests);
            buffer[i].hash = (unsigned char **) malloc(sizeof(unsigned char *) * buffer[i].tot_digests);
            buffer[i].hash_len = (unsigned int *) malloc(buffer[i].tot_digests * sizeof(unsigned int) );
            
            for (int j=0; j<buffer[i].tot_digests; j++) {
                buffer[i].digest_type[j] = EVP_get_digestbyname(settings.md_blocks[j].c_str());
                        
                if(!(buffer[i].digest_type[j])) {
                        cerr << program_name << ": unknown message digest "<< settings.md_blocks[j] << endl;
                        exit(1);
                }
                EVP_MD_CTX_init(&(buffer[i].ctx[j]));
                EVP_DigestInit_ex(&(buffer[i].ctx[j]), buffer[i].digest_type[j], NULL);
                
                buffer[i].hash[j] = (unsigned char *) malloc(EVP_MAX_MD_SIZE * sizeof(unsigned char));
                memset(buffer[i].hash[j], 0, EVP_MAX_MD_SIZE);
            }
        }
        
        buffer[i].the_other_buffer = &buffer[(i+1)%tot];
    }
}

/** Determine if file is a character device */
bool is_char_dev(const char *name) {
    struct stat sb;
    
    int fd = open(name, O_RDWR|O_CREAT|O_LARGEFILE, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);    // se esiste con questi flag non lo modifica
    if (fd == -1) {
        cerr  << program_name << ": error opening " << name << " (" << strerror(errno) << ")" << endl;
        exit(1);
    }
    
    if (fstat(fd, &sb) == -1) {
        cerr  << program_name << ": error getting information for " << name << " (" << strerror(errno) << ")" << endl;
        exit(1);
    }
    
    if ((sb.st_mode & S_IFMT) == S_IFREG || (sb.st_mode & S_IFMT) == S_IFBLK) {     // regular file or block device
        return false;
    }
    
    close(fd);
    // char device
    return true;
}

/** Determine size of input file */
int64_t get_file_size(int fd) {
    struct stat sb;
    
    if (fstat(fd, &sb) == -1) {
        cerr  << program_name << ": error getting size (" << strerror(errno) << ")" << endl;
        exit(1);
    }
    
    if ((sb.st_mode & S_IFMT) == S_IFREG) {     // regular file
        return sb.st_size;
    }
    else if ((sb.st_mode & S_IFMT) == S_IFBLK) {    // block device
        int64_t numblocks=0;

        ioctl(fd, BLKGETSIZE, &numblocks);
        
        return numblocks<<9;
    }
    
    // char device
    return -1;
}

bool is_block_device(int fd) {
    struct stat sb;
    
    if (fstat(fd, &sb) == -1) {
        cerr << program_name << ": error getting device type (" << strerror(errno) << ")" << endl;
        exit(1);
    }
    
    if ((sb.st_mode & S_IFMT) == S_IFREG) {     // regular file
        return false;
    }
    else if ((sb.st_mode & S_IFMT) == S_IFBLK) {    // block device
        return true;
    }
    
    // char device
    return false;
}

fastdd_file_t *init_input_file() {
    fastdd_file_t *ris = (fastdd_file_t *) malloc(sizeof(fastdd_file_t));

    if (settings.input_file_name.length() > 0) {                  // apertura del file di input
        ris->file_name = settings.input_file_name.c_str();
        
        if (settings.is_direct_i && is_char_dev(ris->file_name))
            settings.is_direct_i = false;

        ris->file_descriptor = open(ris->file_name, O_RDWR|settings.is_direct_i|O_LARGEFILE);
        if(ris->file_descriptor == -1) {
            cerr <<  program_name << ": error while opening \""<< ris->file_name <<"\"\n(" << strerror(errno) << ")\n";
            exit(1);
        }
        
        ris->total_size_in_byte = get_file_size(ris->file_descriptor);
        if (settings.is_verbose) {
            if (ris->total_size_in_byte >= 0)
                settings.ofstream_log_file << "input size: " << ris->total_size_in_byte << " bytes" << endl;
            else
                settings.ofstream_log_file << "input size: is a character device" << endl;
        }
        
        // prima dello skip controllo di poterlo fare
        ris->skip_in_byte = (uint64_t)settings.ibs*settings.skip;
        if (ris->total_size_in_byte >= 0 && ris->skip_in_byte >= ris->total_size_in_byte) {
            cerr << program_name << ": end of input reached while skipping first " << settings.skip<< " blocks ("
                << (uint64_t)settings.ibs*settings.skip  << " " << ris->total_size_in_byte << ")\n";
            exit(1);
        }
        
        // se é una device a blocchi uso lseek
        if (ris->total_size_in_byte >= 0) {
            ris->current_position = 0;

            errno=0;
            ris->current_position = lseek(ris->file_descriptor, ((uint64_t)settings.ibs)*settings.skip, SEEK_CUR);
        }
        else {  // altrimenti read successivi
            ris->current_position = 0;
            for (int i=0; i<settings.skip; i++) {
                ris->current_position += read(ris->file_descriptor, (void *) (buffer[i].buffer), settings.ibs);
            }
        }
    
        if (errno!=0) {
            cerr << program_name << ": unable to reach block "<<settings.skip<<" (byte "<< ((uint64_t)settings.ibs*settings.skip) << ") of input file\n";
            cerr << "reached byte " << ris->current_position << " (" << strerror(errno) << ")\n";
            exit(1);
        }
        
        // disabilito progress bar se non so la lunghezza
        if (ris->total_size_in_byte<0 && settings.count < 0) {
            settings.is_progress_bar = false;
        }
        
        if (settings.count < 0) 
            ris->byte_to_read = -1;
        else
            ris->byte_to_read = ((uint64_t)settings.count)*settings.ibs;
        
        ris->byte_read = 0;

        if (settings.is_verbose) {
            settings.ofstream_log_file << "input file '" << ris->file_name << "' opened, "<< ris->current_position << " bytes skipped\n";
        }
    }
    else {
        ris->file_name = "stdin";
        ris->file_descriptor = 0;	// stdin
        
        ris->current_position = 0;
        for (int i=0; i<settings.skip; i++) {
            ris->current_position += read(ris->file_descriptor, (void *) (buffer[i].buffer), settings.ibs);
        }
    
        if (errno!=0) {
            cerr << program_name << ": unable to reach block "<<settings.skip<<" (byte "<< settings.ibs*settings.skip << ") of input file\n";
            cerr << "reached byte " << ris->current_position << " (" << strerror(errno) << ")\n";
            exit(1);
        }
        
        if (ris->total_size_in_byte<0) {
            settings.is_progress_bar = false;
        }

        if (settings.count < 0) 
            ris->byte_to_read = -1;
        else
            ris->byte_to_read = ((uint64_t)settings.count)*settings.ibs;
        ris->byte_read = 0;
        if (settings.is_verbose) {
            settings.ofstream_log_file << "stdin setted ad input file, "<< ris->current_position << " bytes skipped" << endl;
        }
    }
    ris->b_compl = ris->b_part = 0;
    
    ris->tot_digests = 0;
    if (settings.is_md_file_in) {
        ris->tot_digests = settings.md_files.size();
        
        ris->ctx = (EVP_MD_CTX *) malloc(ris->tot_digests * sizeof(EVP_MD_CTX) );
        ris->digest_type = (const EVP_MD **) malloc(ris->tot_digests * sizeof(const EVP_MD *) );
        ris->hash = (unsigned char **) malloc(ris->tot_digests * sizeof(unsigned char *) );
        ris->hash_len = (unsigned int *) malloc(ris->tot_digests * sizeof(unsigned int) );
        
        for (int i=0; i<ris->tot_digests; i++) {
            ris->digest_type[i] = EVP_get_digestbyname(settings.md_files[i].c_str());
            
            if(!(ris->digest_type[i])) {
                    cerr << program_name << ": unknown message digest "<< settings.md_files[i] << endl;
                    exit(1);
            }
            EVP_MD_CTX_init(&(ris->ctx[i]));
            EVP_DigestInit_ex(&(ris->ctx[i]), ris->digest_type[i], NULL);
            
            ris->hash[i] = (unsigned char *) malloc(EVP_MAX_MD_SIZE * sizeof( unsigned char));
            memset(ris->hash[i], 0, EVP_MAX_MD_SIZE);
        }
    }
    
    return ris;
}

fastdd_file_t *init_output_file() {
    fastdd_file_t *ris;

    if (settings.output_file_name.size() == 0) {
        tot_output_file = 1;
        ris = (fastdd_file_t *) malloc(sizeof(fastdd_file_t));
        ris[0].idx = 0;
        ris[0].file_name = "stdout";
        ris[0].file_descriptor = 1;
        ris[0].total_size_in_byte = -1;
        if (settings.is_md_blocks_check ||settings.is_md_files_out) {
            cerr << program_name << ": error: hash check is not compatible with characters output device 'stdout'." << endl;
            exit(1);
        }

        ris[0].current_position = 0;
        ris[0].byte_read = 0;
        ris[0].is_direct_o = 0;
        
        if (settings.is_parallel) {
            for (int j=0; j<TOT_BUFFERS; j++)
                buffer[j].active[0] = true;
        }
        else
            buffer[0].active[0] = true;
            
        if (settings.is_verbose)
            settings.ofstream_log_file << "stdout setted as output file, possible seek options have been ignored." << endl;
    }
    else {
        tot_output_file = settings.output_file_name.size();
        ris = (fastdd_file_t *) malloc(tot_output_file*sizeof(fastdd_file_t));
        for (int i=0; i<tot_output_file; i++) {
            ris[i].idx = i;
            ris[i].file_name = settings.output_file_name[i].c_str();
            ris[i].is_direct_o = settings.is_direct_o;
            if (ris[i].is_direct_o && is_char_dev(ris[i].file_name))
                ris[i].is_direct_o = false;
            ris[i].file_descriptor = open(ris[i].file_name, O_RDWR|O_CREAT|ris[i].is_direct_o|settings.is_o_trunc|O_LARGEFILE, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            if(ris[i].file_descriptor == -1) {
                cerr << program_name << ": error: opening output file \""<< ris[i].file_name <<"\".\n" << strerror(errno) << endl;
                exit(1);
            }
            
            ris[i].total_size_in_byte = get_file_size(ris[i].file_descriptor);
            if (settings.is_verbose) {
                if (ris[i].total_size_in_byte >= 0)
                    settings.ofstream_log_file << "output file "<<ris[i].file_name << " size: " << ris[i].total_size_in_byte << endl;
                else
                    settings.ofstream_log_file << "output file "<<ris[i].file_name << " size: is a character device" << endl;
            }
            
            if ((settings.is_md_blocks_check || settings.is_md_files_out) && ris[i].total_size_in_byte<0) {
                cerr << program_name << ": error: hash check is not compatible with characters output device '" << ris[i].file_name << "'" << endl;
                exit(1);
            }
            
            if (ris[i].total_size_in_byte<0 && settings.seek != 0) {
                cerr << program_name << ": error: seek is not compatible with characters output device '" << ris[i].file_name << "'" << endl;
                exit(1);
            }
            
            if (is_block_device(ris[i].file_descriptor) && settings.seek*settings.obs >= ris[i].total_size_in_byte) {
                cerr << program_name << ": error: end of device " << ris[i].file_name << " reached while seeking first " << settings.seek << " blocks" << endl;
                exit(1);
            }
            
            ris[i].current_position = 0;
            if (ris[i].total_size_in_byte>=0  && settings.seek != 0) {
                ris[i].current_position = lseek(ris[i].file_descriptor, settings.seek*settings.obs, SEEK_CUR);
                if (ris[i].current_position != settings.seek*settings.obs) {
                    cerr << program_name << ": error: seeking first " << settings.seek << " blocks of device " << ris[i].file_name << endl;
                    exit(1);
                }
            }

            ris[i].byte_read = 0;
            
            ///////////////////////////////
            ris[i].tot_digests = 0;
            if (settings.is_md_files_out) {
                ris[i].tot_digests = settings.md_files.size();
                
                ris[i].ctx = (EVP_MD_CTX *) malloc(ris[i].tot_digests * sizeof(EVP_MD_CTX) );
                ris[i].digest_type = (const EVP_MD **) malloc(ris[i].tot_digests * sizeof(const EVP_MD *) );
                ris[i].hash = (unsigned char **) malloc(ris[i].tot_digests * sizeof(unsigned char *) );
                ris[i].hash_len = (unsigned int *) malloc(ris[i].tot_digests * sizeof(unsigned int) );
                
                for (int j=0; j<ris[i].tot_digests; j++) {
                    ris[i].digest_type[j] = EVP_get_digestbyname(settings.md_files[j].c_str());
                    
                    if(!(ris[i].digest_type[j])) {
                            cerr << program_name << ": unknown message digest "<< settings.md_files[j] << endl;
                            exit(1);
                    }
                    EVP_MD_CTX_init(&(ris[i].ctx[j]));
                    EVP_DigestInit_ex(&(ris[i].ctx[j]), ris[i].digest_type[j], NULL);
                    
                    ris[i].hash[j] = (unsigned char *) malloc(EVP_MAX_MD_SIZE * sizeof(unsigned char));
                    memset(ris[i].hash[j], 0, EVP_MAX_MD_SIZE);
                }
            }
            //////////////////////////////////
            
            ris[i].b_compl = ris[i].b_part = 0;
            if (settings.is_parallel) {
                for (int j=0; j<TOT_BUFFERS; j++)
                    buffer[j].active[i] = true;
            }
            else
                buffer[0].active[i] = true;
        }
    }
    
    return ris;
}

string num2str(int64_t n, int base, int length, char fill) {
    stringstream ss (stringstream::in | stringstream::out);
    ss << setbase(base) << setw(length) <<setfill(fill) << n;
    string ris;
    ris = ss.str();
    
    return ris;
}
int64_t read_blocks(int file_descriptor, uint64_t pos_file, buffer_t *buff, uint64_t pos_buff, uint64_t da_leggere) {
    int64_t letti_tot, letti_cur;
    int64_t bytes_read = 0;
    
    if (settings.is_verbose) {
        settings.ofstream_log_file << "reading block " << num2str(pos_file,16,16,'0') << "-"
            << num2str(pos_file+da_leggere,16,16,'0') << " sector-by-sector" << endl;
//         cerr << "reading block " << num2str(pos_file,16,16,'0') << "-"
//             << num2str(pos_file+da_leg,16,16,'0') << " with 512-bytes step" << endl;
    }
    
    lseek(file_descriptor, pos_file, SEEK_SET);
    for (int b=0; b<da_leggere; b+=512) {
 //       cerr << (pos_file+b) << endl;
        int attempts = settings.reading_attempts;
        
        letti_tot = letti_cur = read(file_descriptor, buff->buffer+(pos_buff+b), 512);
        while (letti_cur>0 && letti_tot<512) {
            letti_cur = read(file_descriptor, buff->buffer+(pos_buff+b+letti_tot), 512-letti_tot);
            letti_tot+=letti_cur;
        }
        
        if (letti_cur==0) {
            buff->is_last = true;
            bytes_read+=b+letti_tot;
            return bytes_read;
        }
        
        if (letti_cur==-1) {
            while (letti_cur==-1 && --attempts > 0) {
                letti_tot=0;
                if (settings.is_verbose) {
                    settings.ofstream_log_file << "error reading sector " << num2str(pos_file+b,16,16,'0') << "-"
                        << num2str(pos_file+b+512,16,16,'0') << " (" << strerror(errno) << "), " << (attempts+1) <<
                        "attempt(s) left"<< endl;
//                    cerr << "error reading block " << num2str(pos_file+b,16,16,'0') << "-"
//                        << num2str(pos_file+b+512,16,16,'0') << " (" << strerror(errno) << "), " << (attempts+1) <<
//                        "attempt(s) left"<< endl;
                }
                lseek(file_descriptor, pos_file+b, SEEK_SET);
                letti_cur = read(file_descriptor, buff->buffer+(pos_buff+b), 512);
            }
            
            if (letti_cur==-1) {
                pb.add_err(pos_file+b);
                if (settings.is_verbose) {
                    settings.ofstream_log_file << "unable to read block " << num2str(pos_file+b,16,16,'0') << "-"
                        << num2str(pos_file+b+512,16,16,'0') << " (" << strerror(errno) << ")" << endl;
                }
                cerr << '\r' << "                                                                                "
                    << '\r' << "unable to read block " << num2str(pos_file+b,16,16,'0') << "-"
                        << num2str(pos_file+b+512,16,16,'0') << " (" << strerror(errno) << ")" << endl;
                memset((void *) (buff->buffer+(pos_buff+b)), 0 , 512);
                lseek(file_descriptor, pos_file+b+512, SEEK_SET);
            }
            
            letti_tot=512;
        }
        
        bytes_read += letti_tot;
    }
    
    return bytes_read;
}

/* leggo a blocchi di reread-bs */
int64_t read_slow(int file_descriptor, uint64_t pos_file, buffer_t *buff, uint64_t pos_buff, uint64_t da_leggere) {
    lseek(file_descriptor, pos_file, SEEK_SET);
    
    if (settings.is_verbose) {
        settings.ofstream_log_file << "switching to buffer size " << settings.reread_bs << endl;
    //    cerr << "switching to buffer size " << settings.reread_bs << endl;
    }
    
    int64_t bytes_read = 0;
    for (int64_t a=0; a<da_leggere; a+=settings.reread_bs) {
  //      cerr << pos_file << endl;
        int64_t da_leg = MIN(settings.reread_bs,da_leggere-bytes_read);
        int64_t letti_cur = read(file_descriptor, buff->buffer+(pos_buff+a), da_leg);       // con read
        int64_t letti_tot = letti_cur;                                                      // accumula fino a reread_bs
        while (letti_tot < da_leg && letti_cur>0) {
            letti_cur = read(file_descriptor, buff->buffer+(pos_buff+a+letti_tot), da_leg-letti_tot);
            letti_tot+=letti_cur;
        }
        
        if (letti_cur==0) {
            buff->is_last = true;
            bytes_read+=letti_tot;
            return bytes_read;
        }
        
        if (letti_cur==-1) {        // leggo 'piano'
            if (settings.is_verbose) {
                settings.ofstream_log_file << "error reading block " << num2str(pos_file,16,16,'0') << "-"
                    << num2str(pos_file+da_leg,16,16,'0') << " (" << strerror(errno) << ")" << endl;
          //      cerr << "error reading block " << num2str(pos_file,16,16,'0') << "-"
           //         << num2str(pos_file+da_leg,16,16,'0') << " (" << strerror(errno) << ")" << endl;
            }
            
            letti_tot = read_blocks(file_descriptor, pos_file, buff, pos_buff+a, da_leg);
            if (settings.is_verbose)
                    settings.ofstream_log_file << "returning to " << settings.reread_bs << " byte buffer size" <<  endl;
        }

        bytes_read += letti_tot;
        pos_file += letti_tot;
    }

    return bytes_read;
}

void *thread_read(void *arg) {
    fastdd_file_t *fi = (fastdd_file_t *) arg;
    
    buffer_t *buff = buffer;
    
    int64_t bs= settings.bs;
    int64_t ibs= settings.ibs;
    int64_t count= settings.count;    
    
    pb = progress_bar(fi->skip_in_byte,
        ( (fi->byte_to_read > 0) ? (fi->skip_in_byte+fi->byte_to_read) : fi->total_size_in_byte ) );
    int64_t last_update=-100000000;
    
 //   struct timeval t_1;
    int64_t next_needed;
    pm = partition_manager(fi->file_name);
    
    int continue_on_error=-1;   // -1=not set, 0=no, 1=yes
    if (settings.ignore_module_error) continue_on_error=1;
 //   int64_t t1=t_start, t2, t3;
    do {
   //     cerr << "read: blocco buffer" << endl;
        pthread_mutex_lock(&buff->buffer_mutex);
        while (buff->is_full && !buff->is_last) {
 //           cerr << "read: aspetto sia vuoto" << endl;
            pthread_cond_wait (&buff->is_not_full, &buff->buffer_mutex);
        }
        
        if (buff->is_last) {
            pthread_mutex_unlock(&buff->buffer_mutex);
            break;
        }
      //  cerr << "read: dentro" << endl;

        int64_t tot_read = 0;
        int64_t bytes_read, temp=1;
        
        //memset((void *) buff->buffer, 0, bs);
        
        int64_t current_blocks = fi->b_part+fi->b_compl;
        
        for (int j=0; (count<0 || (count>=0 && fi->b_compl+fi->b_part<count)) && j<bs; j+=bytes_read) {
            int64_t da_leggere = MIN(ibs,bs-tot_read);
       //     gettimeofday(&t_1, NULL);
        //    t2 = t_1.tv_sec*1000000+t_1.tv_usec;
            temp = bytes_read = read(fi->file_descriptor, buff->buffer+j, da_leggere);
        //    gettimeofday(&t_1, NULL);
        //    t3 = t_1.tv_sec*1000000+t_1.tv_usec;
        //    couttime << "read "<< (t2-t1) << " " << (t3-t2) << " " << endl;
        //    t1 = t3;
            while (temp>0 && bytes_read<da_leggere) {
                temp = read(fi->file_descriptor, buff->buffer+j+bytes_read, da_leggere-bytes_read);
                if (temp==0) {
                    buff->is_last = true;
                    break;
                }
                bytes_read += temp;
            }
            
            if (temp==-1) {
                if (settings.is_verbose) {
                    settings.ofstream_log_file << program_name << ": error reading block " <<
                        num2str(fi->current_position, 16, 16, '0') << "-" <<
                        num2str(fi->current_position+da_leggere, 16, 16, '0') << "-" <<
                        "(" << strerror(errno) << ")" << endl;
                //    cerr << program_name << ": error reading block " <<
                //        num2str(fi->current_position, 16, 16, '0') << "-" <<
                //        num2str(fi->current_position+da_leggere, 16, 16, '0') << "-" <<
                //        "(" << strerror(errno) << ")" << endl;
                }
                temp=0;
                if (settings.reading_attempts) {
                    if (settings.reread_bs > 512 && settings.bs > settings.reread_bs)
                        bytes_read = read_slow(fi->file_descriptor, fi->current_position+j, buff, j, da_leggere);
                    else
                        bytes_read = read_blocks(fi->file_descriptor, fi->current_position+j, buff, j, da_leggere);
                                    
                    if (settings.is_verbose)
                        settings.ofstream_log_file << "returning to normal buffer size" <<  endl;
                }
                else {
                    lseek(fi->file_descriptor, fi->current_position+j+da_leggere, SEEK_SET);
                    memset(buff->buffer+j, 0, da_leggere);
                    
                    bytes_read=da_leggere;
                    pb.add_err(fi->current_position+j);
                    if (settings.is_verbose) {
                        settings.ofstream_log_file << "unable to read block " << num2str(fi->current_position+j,16,16,'0') << "-"
                            << num2str(fi->current_position+j+da_leggere,16,16,'0') << " (" << strerror(errno) << ")" << endl;
                    }
                    cerr << '\r' << "                                                                                "
                        << '\r' << "unable to read block " << num2str(fi->current_position+j,16,16,'0') << "-"
                            << num2str(fi->current_position+j+da_leggere,16,16,'0') << " (" << strerror(errno) << ")" << endl;
                }
                
                if (bytes_read) {
                    if (!buff->is_last) 
                        temp=1;
                }
                else buff->is_last = true;
            }
                
            if (bytes_read==ibs)
                fi->b_compl++;
            else if (bytes_read)
                fi->b_part++;
                
            tot_read+=bytes_read;
            
            if ((count>0 && fi->b_compl+fi->b_part >= count) || !bytes_read) {
                buff->is_last = true;
            }
            
            if (buff->is_last)
                break;
        }
        
        buff->length = tot_read;
        buff->is_full = true;
        buff->is_empty = false;
        //cerr << "read: letti " << buff->length << endl;
        
        ///////////////////////////////////////// MD
        if (settings.is_md_blocks_save) {           // calcolo e scrivo su file i digest dei blocchi
            EVP_MD_CTX mdctx;
            unsigned char md_value[EVP_MAX_MD_SIZE];
            unsigned int md_len;
            
            for (int i=0; i<tot_read; i+=ibs) {
                for (int i1=0; i1<buff->tot_digests; i1++) {
                    EVP_MD_CTX_init(&mdctx);
                    EVP_DigestInit_ex(&mdctx, buff->digest_type[i1], NULL);
                    EVP_DigestUpdate(&mdctx, buff->buffer+i, MIN(ibs,tot_read-i));
                    EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
                    stringstream ss;
                    for (int i2=0; i2<md_len; i2++) {
                        ss << setfill('0') << setw(2) << setbase(16) << (unsigned int) md_value[i2];
                    }

                    settings.ofstream_md << "block " << num2str(current_blocks+i/ibs,10,8,' ')<<": "
                        <<num2str(fi->current_position,16,16,'0')<<"-"<<num2str(fi->current_position+MIN(ibs,tot_read-i),16,16,'0')<<": "
                        << settings.md_blocks[i1] << " - " << ss.str() << endl;
                }
            }
        }

        // digest complessivo del file
        for (int i1=0; i1<fi->tot_digests; i1++) {
            if (settings.is_md_file_in) {
                EVP_DigestUpdate(&(fi->ctx[i1]), buff->buffer, tot_read);
            }
        }
        
        // digest per il confronto
        for (int i1=0; i1<buff->tot_digests; i1++) {
            if (settings.is_md_blocks_check) {
                EVP_MD_CTX_init(&buff->ctx[i1]);
                EVP_DigestInit_ex(&buff->ctx[i1], buff->digest_type[i1], NULL);
                EVP_DigestUpdate(&buff->ctx[i1], buff->buffer, tot_read);
                EVP_DigestFinal_ex(&buff->ctx[i1], buff->hash[i1], &buff->hash_len[i1]);
            }
        }
        
        //////////////////////////////// partition table
        if (settings.is_get_partition) {
            if (current_blocks==0)
                next_needed = pm.update(buff->buffer, 0);
            else if (fi->current_position <= next_needed && next_needed < fi->current_position + buff->length)  {
               // cout << fi->current_position << " " << next_needed << " " << fi->current_position + buff->length;
                next_needed = pm.update(buff->buffer+(next_needed - fi->current_position), next_needed);
            }
            if (pm.is_error()) settings.is_get_partition=false;
        }
        
        // -------------------------------- use modules
        for (int i_mod=0; i_mod<modules.size(); i_mod++) {
            if (!modules[i_mod]->is_active()) continue;

            bool ok = modules[i_mod]->transform(buff);
            
            if (!ok && continue_on_error<0) {
                if (settings.is_verbose)
                    settings.ofstream_log_file << modules[i_mod]->get_name() << ": " << modules[i_mod]->get_error() << endl;
                cerr << "\r" << flush;
                cerr << modules[i_mod]->get_name() << ": " << modules[i_mod]->get_error() << endl;
                continue_on_error=-2;
                while (continue_on_error<-1) {
                    cerr << "Do you want to continue with the execution? (y=yes/n=no/a=ignore all): " << flush;
                    string risp;
                    cin >> risp;
                    if (risp=="n" || risp=="N") {
                        buff->is_last=true;
                        continue_on_error=0;
                    }
                    else if (risp=="y" || risp=="Y") {
                        continue_on_error=-1;
                    }
                    else if (risp=="a" || risp=="A") {
                        continue_on_error=1;
                    }
                }
                if (!continue_on_error) break;
            }
        }
        
        // -------------------------------- fatto
        fi->current_position+=tot_read;
        fi->byte_read+=tot_read;
        
        if (settings.is_progress_bar) {
            pb.add_pos(tot_read);
            if (fi->current_position - last_update >= 1048576) {
                cerr << '\r';
                cerr << pb.get_barra() << flush;
                last_update = fi->current_position;
            }
        }

        for (int j=0; j<tot_output_file; j++) {
            pthread_cond_signal(&buff->is_not_empty[j]);
        }

        pthread_mutex_unlock(&buff->buffer_mutex);
        
        if (buff->is_last) {
    //        cerr << "read: ----------------- LAST" << endl;
            break;
        }
        
   //     cerr << "read: " << (fi->b_compl + fi->b_part) << endl;
        buff = buff->the_other_buffer;
    } while(true);
    
  //  cerr << "read: esco" << endl;
    
    pthread_exit(NULL);
}

bool secure_next_buffer(buffer_t *buff, int id, bool close_thread) {
    int ret = 0;
    pthread_mutex_lock(&buff->buffer_mutex);
    if (close_thread) {
        buff->active[id] = false;
        buff->writer_active--;
        buff = buff->the_other_buffer;

        while (buff->active[id]) {
            pthread_mutex_lock(&buff->buffer_mutex);
            buff->active[id]=false;
            buff->writer_active--;
            pthread_mutex_unlock(&buff->buffer_mutex);
            buff = buff->the_other_buffer;
        }
    }
    
    buff->already_write[id] = true;
    
    // attenzione, qui non prendo il lock dell'altro buffer

    bool esci = true;           // hanno tutti terminato?
    bool buffer_ok = true;      // se tutti quelli attivi l'hanno già scritto
    for (int j=0; j<tot_output_file; j++) {
        if (buff->active[j]) esci = false;
        if (buff->active[j] && !buff->already_write[j]) buffer_ok=false;
    }
    
    if (esci) {
        buff->is_last = true;
    }
    
    if (esci || buffer_ok) {
        buff->length = 0;
        buff->is_empty = true;
        buff->is_full = false;
        for (int j=0; j<tot_output_file; j++)
            buff->already_write[j] = false;
        pthread_cond_signal(&buff->is_not_full);
    }
    // else non è l'ultimo, non deve vuotare il buffer
    
    pthread_mutex_unlock(&buff->buffer_mutex);
    
    return buff->is_last;
}

void *thread_write(void *arg) {
    fastdd_file_t *fo = (fastdd_file_t *) arg;
    int id = fo->idx;

    buffer_t *buff = buffer;
    
    unsigned char *local_buffer;
    if (settings.is_md_blocks_check || settings.is_md_files_out) {
        int t = posix_memalign( (void **) &(local_buffer), 512, settings.bs);
        if (t) {
            if (settings.is_verbose) {
                settings.ofstream_log_file << program_name << "error allocating buffer for " << fo->file_name << " (" <<
                    strerror(errno) << ")\n";
            }
            cerr << program_name << ": error: allocating buffer for " << fo->file_name << " (" <<
                    strerror(errno) << ")\n";

            while (buff->active[id]) {
                pthread_mutex_lock(&buff->buffer_mutex);
                buff->active[id]=false;
                buff->writer_active--;
                pthread_mutex_unlock(&buff->buffer_mutex);
                buff = buff->the_other_buffer;
            }

            pthread_exit(NULL);
        }
    }
    
    int64_t bs= settings.bs;
    int64_t obs= settings.obs;
    int64_t count= settings.count;
 //   struct timeval t_1;
  //  int64_t t1=t_start, t2, t3;
    
    do {
    //    cerr << fo->file_name << " aspetto" << endl;
        pthread_mutex_lock(&buff->buffer_mutex);
        if (buff->is_empty || buff->already_write[id]) {
    //        cerr << fo->file_name << " aspetto che il buffer si riempia" << endl;
            pthread_cond_wait (&buff->is_not_empty[id], &buff->buffer_mutex);
        }
        if (buff->is_last && buff->length==0) {
            pthread_mutex_unlock(&buff->buffer_mutex);
            break;
        }
        buff->writer_entered++;
        pthread_mutex_unlock(&buff->buffer_mutex);
        
  //      cerr << fo->file_name << " dentro" << endl;
        
        // --------------------------- riapri file senza o_direct se serve
        if (fo->is_direct_o && (buff->length&511)) {
            int oldflags = fcntl (fo->file_descriptor, F_GETFL, 0);

            if (oldflags == -1) {
                if (settings.is_verbose)
                    settings.ofstream_log_file << program_name << ": error: while changing O_DIRECT flag in output file '"<<
                        fo->file_name << "'" << endl;
                secure_next_buffer(buff, id, true);
                pthread_exit(NULL);
            }
            
            
            oldflags &= ~O_DIRECT;

            oldflags = fcntl(fo->file_descriptor, F_SETFL, oldflags);
            if (oldflags == -1) {
                if (settings.is_verbose)
                    settings.ofstream_log_file << program_name << ": error: while changing O_DIRECT flag in output file '"<<
                        fo->file_name << "'" << endl;
                secure_next_buffer(buff, id, true);
                pthread_exit(NULL);
            }
            
            fo->is_direct_o = 0;
        //    cerr << fo->file_name << " -------------- riaperto" << endl;
        }
        
        // ----------------------------- scrivo
        int64_t bytes_written = 0, temp;
        for (int64_t j=0; j<buff->length; j+=MIN(obs, buff->length-j)) {
          //  gettimeofday(&t_1, NULL);
         //   t2 = t_1.tv_sec*1000000+t_1.tv_usec;
            temp = write(fo->file_descriptor, buff->buffer+j, MIN(obs, buff->length-j));
          //  gettimeofday(&t_1, NULL);
          //  t3 = t_1.tv_sec*1000000+t_1.tv_usec;
         //   couttime << "write "<< (t2-t1) << " " << (t3-t2) << endl;
         //   t1=t3;
            
            if (temp==-1)
                exit(1);
                
            if (temp==obs) {
             //   printf("%ld %ld %ld C\n",j,buff->length, temp);
                fo->b_compl++;
            }
            else if (temp) {
             //   printf("%ld %ld %ld P\n",j,buff->length, temp);
                fo->b_part++;
            }
            bytes_written += temp;
        }
    //    cerr << fo->file_name << " scritti " << bytes_written << endl;
        
        // -------------------------------- rileggo
        if (settings.is_md_blocks_check || settings.is_md_files_out) {
            int64_t pos = lseek(fo->file_descriptor, -bytes_written, SEEK_CUR);	// torno a monte del buffer appena scritto
            int64_t current_read=0;
            memset((void *) local_buffer, 0, bs);
            
            for (int t=0; t<buff->length; t+=MIN(obs, buff->length-t)) {
    //            cerr << ">>" << MIN(obs, buff->length-t) << endl;
                int64_t t2 = read(fo->file_descriptor, local_buffer+t, MIN(obs, buff->length-t));
    //            cerr << "riletti: " << buff->length << " " << t2 << endl;
                if (t2==-1) {                   // ho trovato un blocco danneggiato, lo salto
                    if (settings.is_verbose)
                        settings.ofstream_log_file << program_name << ": error: re-reading block "<<num2str(pos,16,16,'0')<<"-"
                            <<num2str(pos+MIN(obs, buff->length-t),16,16,'0')<<" ("<< strerror(errno) << ")\n";
                    secure_next_buffer(buff, id, true);
                
                    pthread_exit(NULL);
                }
                else {
                    current_read += t2;
                }
                pos+=t2;
            }

            if (current_read != buff->length) {
                if (settings.is_verbose)
                    settings.ofstream_log_file << program_name << ": error: unable to load data just written in '"<< fo->file_name <<"' (read only " << current_read << " bytes)\n";
                cerr << program_name << ": error: unable to load data just written in '"<< fo->file_name <<"' (read only " << current_read << " bytes)\n";
                
                secure_next_buffer(buff, id, true);
                
                pthread_exit(NULL);
            }
            
            // a questo punto ho riletto senza errori (quindi il supporto non è fisicamente danneggiato)
            // ma se l'md5 diverge esco subito
            ///////////////////////////////////////// MD
            if (settings.is_md_files_out) {
                for (int i1=0; i1<fo->tot_digests; i1++) {
                    EVP_DigestUpdate(&(fo->ctx[i1]), local_buffer, current_read);
                }
            }
        
            if (settings.is_md_blocks_check) {           // calcolo e scrivo su file i digest dei blocchi
                EVP_MD_CTX mdctx;
                unsigned char md_value[EVP_MAX_MD_SIZE];
                unsigned int md_len;

                for (int i1=0; i1<buff->tot_digests; i1++) {
                    EVP_MD_CTX_init(&mdctx);
                    EVP_DigestInit_ex(&mdctx, buff->digest_type[i1], NULL);
                    EVP_DigestUpdate(&mdctx, local_buffer, current_read);
                    EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
                    
                    bool uguali = true;
                    for (int i2=0; i2<md_len; i2++) {
                        if (md_value[i2] != buff->hash[i1][i2])
                            uguali = false;
                    }
                    
                    if (!uguali) {
                        if (settings.is_verbose) {
                            settings.ofstream_log_file << program_name << ": error: " << settings.md_blocks[i1] << " block check failed"<<endl;
                            
                            stringstream ss2;
                            for (int i2=0; i2<md_len; i2++) {
                                ss2 << setw(2) << setfill('0') << setbase(16) << (unsigned int) buff->hash[i1][i2];
                            }
                            
                            settings.ofstream_log_file << ss2.str() << " - " << num2str(fi_common->current_position-buff->length,16,16,'0')<<"-"<<
                                num2str(fi_common->current_position,16,16,'0')<<" - " << fi_common->file_name << endl;
                            
                            stringstream ss;
                            for (int i2=0; i2<md_len; i2++) {
                                ss << setw(2) << setfill('0') << setbase(16) << (unsigned int) md_value[i2];
                            }
                            
                            settings.ofstream_log_file << ss.str() << " - " << settings.md_blocks[i1] << " - " << num2str(pos-buff->length,16,16,'0')<<"-"<<
                                num2str(pos,16,16,'0')<<" - "<< fo->file_name << endl;
                        }
                        
                        secure_next_buffer(buff, id, true);
                    
                        pthread_exit(NULL);
                    }
                }
            }
        }
     //   cerr << "write: " << (fo->b_compl+fo->b_part) << endl;
        // ------------------------------ fatto
        
        bool esci = buff->is_last;
        secure_next_buffer(buff, id, false);
        if (esci) break;
        
        buff = buff->the_other_buffer;
        
    } while(true);
    
    //cerr << fo->file_name << " " << fo->b_compl << "+" << fo->b_part << endl;
    pthread_exit(NULL);
}

void no_parallel(fastdd_file_t *fi, fastdd_file_t *fo) {
  /*  fi->b_part = fi->b_compl = 0;
    
    buffer_t *buff = buffer;
    
    int64_t bs= settings.bs;
    int64_t ibs= settings.ibs;
    int64_t obs= settings.obs;
    int64_t count= settings.count;
    
    unsigned char **local_buffer;
    if (settings.is_md_blocks_check || settings.is_md_files_out) {
        local_buffer = (unsigned char **) malloc(tot_output_file*sizeof(unsigned char *));
        
        for (int i=0; i<tot_output_file; i++) {
            int t = posix_memalign( (void **) &(local_buffer[i]), 512, settings.bs);
            if (t) {
                if (settings.is_verbose) {
                    settings.ofstream_log_file << program_name << "error allocating buffer for " << fo[i].file_name << " (" <<
                        strerror(errno) << ")\n";
                }
                cerr << program_name << ": error: allocating buffer for " << fo[i].file_name << " (" <<
                        strerror(errno) << ")\n";

                buffer[0].active[i] = false;
            }
        }
    } 
    
    bool is_find = (settings.total_regexes > 0);
    
    int64_t tot_read;
    int64_t bytes_read, temp;
    while ((count<0 || (count>=0 && fi->b_compl+fi->b_part<count)) && !buff->is_last) {
        tot_read = 0;
      //  cerr << "read: " << fi->b_compl << "+" << fi->b_part << endl;
        ////////////////////////////////////////////// leggi
        int64_t current_blocks = fi->b_compl+fi->b_part;
        for (int j=0; (count<0 || (count>=0 && fi->b_compl+fi->b_part<count)) && j<bs; j+=bytes_read) {
            if (!settings.full_block) {
                bytes_read = read(fi->file_descriptor, buff->buffer+j, MIN(ibs,bs-tot_read));
            }
            else {
                int64_t da_leggere = MIN(ibs,bs-tot_read);
                temp = bytes_read = read(fi->file_descriptor, buff->buffer+j, da_leggere);
                while (temp>0 && bytes_read<da_leggere) {
                    temp = read(fi->file_descriptor, buff->buffer+j+bytes_read, da_leggere-bytes_read);
                    if (temp==0) {
                        buff->is_last = true;
                        break;
                    }
                    bytes_read += temp;
                }
                if (temp==-1)
                    bytes_read = -1;
            }
            
            if (bytes_read==-1) {
                cerr << program_name << ": error: " << strerror(errno) << endl;
                exit(1);
            }
                
            if (bytes_read==ibs)
                fi->b_compl++;
            else if (bytes_read)
                fi->b_part++;
                
            tot_read+=bytes_read;
            
            if ((count>0 && fi->b_compl+fi->b_part >= count) || !bytes_read) {
                buff->is_last = true;
            }
            
            if (buff->is_last)
                break;
        }
        buff->length = tot_read;
        
        ///////////////////////////////////////// MD
        
        if (settings.is_md_blocks_save) {           // calcolo e scrivo su file i digest dei blocchi
            EVP_MD_CTX mdctx;
            unsigned char md_value[EVP_MAX_MD_SIZE];
            unsigned int md_len;
            
            for (int i=0; i<tot_read; i+=ibs) {
                for (int i1=0; i1<buff->tot_digests; i1++) {
                    EVP_MD_CTX_init(&mdctx);
                    EVP_DigestInit_ex(&mdctx, buff->digest_type[i1], NULL);
                    EVP_DigestUpdate(&mdctx, buff->buffer+i, MIN(ibs,tot_read-i));
                    EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
                    stringstream ss;
                    for (int i2=0; i2<md_len; i2++) {
                        ss << setfill('0') << setw(2) << setbase(16) << (unsigned int) md_value[i2];
                    }

                    settings.ofstream_md << "block " << num2str(current_blocks+i/ibs,10,8,' ')<<": "
                        <<num2str(fi->current_position,16,16,'0')<<"-"<<num2str(fi->current_position+MIN(ibs,tot_read-i),16,16,'0')<<": "
                        << settings.md_blocks[i1] << " - " << ss.str() << endl;
                }
            }
        }

        for (int i1=0; i1<fi->tot_digests; i1++) {
            if (settings.is_md_file_in) {
                EVP_DigestUpdate(&(fi->ctx[i1]), buff->buffer, tot_read);
            }
        }
        
        for (int i1=0; i1<buff->tot_digests; i1++) {
            if (settings.is_md_blocks_check) {
                EVP_MD_CTX_init(&buff->ctx[i1]);
                EVP_DigestInit_ex(&buff->ctx[i1], buff->digest_type[i1], NULL);
                EVP_DigestUpdate(&buff->ctx[i1], buff->buffer, tot_read);
                EVP_DigestFinal_ex(&buff->ctx[i1], buff->hash[i1], &buff->hash_len[i1]);
            }
        }
        // -------------------------------- find
        if (is_find) {               /////////////////////////// FIND REGEX
            string search_buffer(buff->buffer, buff->buffer+buff->length);
            for (int j2=0; j2<settings.total_regexes; j2++) {
                if (settings.is_simple_regex_match) {  // write just if there is a match in this block
                    bool result = boost::regex_search(search_buffer , what, settings.re[j2]);
                    if (result) {
                        out_find << "matches found for regex "<<j2<<" in input block "<<num2str(current_blocks + what.position()/ibs,10,8,' ')
                            << ": " << num2str(fi->current_position,16,16,'0') << "-" << num2str(fi->current_position+buff->length,16,16,'0') << "\n";
                    }
                }
                else { // print in find_file_output all information
                    boost::sregex_iterator m1(search_buffer.begin(), search_buffer.end(), settings.re[j2], boost::match_default | boost::match_partial);
                    boost::sregex_iterator m2;
                    
                    if (m1==m2) continue;
                    
                    do {
                        boost::smatch m = *m1;
                        
                        if (!m[0].matched) out_find << "? ";
                        
                        out_find << setbase(10) << j2 << " " << ( current_blocks+m.position()/ibs ) << " " << (fi->current_position+m.position()) << " " << m.length(0) << " ";
                        for (int temp1=0; temp1<m.length(0); temp1++) {
                            out_find << num2str((int)(buff->buffer[m.position()+temp1] & 255),16,2,'0');
                        }
                        out_find << endl;
                        
                        m1++;
                    } while ( !(m1 == m2));
                    
                }
            }
        }
        
        fi->current_position+=tot_read;
        fi->byte_read+=tot_read;
        
        // ---------------------- scrive
        for (int id=0; id<tot_output_file; id++) {
            if (!buff->active[id]) continue;
            
            //// se serve riapro
            if (fo[id].is_direct_o && (buff->length&511)) {
                int oldflags = fcntl (fo[id].file_descriptor, F_GETFL, 0);

                if (oldflags == -1) {
                    if (settings.is_verbose)
                        settings.ofstream_log_file << program_name << ": error: while changing O_DIRECT flag in output file '"<<
                            fo[id].file_name << "'" << endl;
                    buff->active[id] = false;
                    continue;
                }
                
                
                oldflags &= ~O_DIRECT;

                oldflags = fcntl(fo[id].file_descriptor, F_SETFL, oldflags);
                if (oldflags == -1) {
                    if (settings.is_verbose)
                        settings.ofstream_log_file << program_name << ": error: while changing O_DIRECT flag in output file '"<<
                            fo[id].file_name << "'" << endl;
                    buff->active[id] = false;
                    continue;
                }
                
                fo[id].is_direct_o = 0;
                //cerr << fo[id].file_name << " -------------- riaperto" << endl;
            }
            
            // ----------------------------- scrivo
            int64_t bytes_written = 0, temp1;
            for (int64_t j=0; j<buff->length; j+=MIN(obs, bs-j)) {
                temp1 = write(fo[id].file_descriptor, buff->buffer+j, MIN(obs, buff->length-j));
                
                if (temp1==-1){
                    buff->active[id] = false;
                    break;
                }
                    
                if (temp1==obs)
                    fo[id].b_compl++;
                else if (temp1) {
                    fo[id].b_part++;
                }
                bytes_written += temp1;
            }
            if (temp1==-1) continue;
        //    cerr << fo[id].file_name << " scritti " << bytes_written << endl;
            
            if (bytes_written != tot_read) {
                cerr << "errore: letti " << tot_read << " scritti " << bytes_written << " bytes" << endl;
                buff->active[id] = false;
                continue;
            }
            
            // -------------------------------- rileggo
            if (settings.is_md_blocks_check || settings.is_md_files_out) {
                int64_t pos = lseek(fo[id].file_descriptor, -bytes_written, SEEK_CUR);	// torno a monte del buffer appena scritto
                int64_t current_read=0;
                memset((void *) local_buffer[id], 0, bs);
                
                for (int t=0; t<buff->length; t+=MIN(obs, bs-t)) {
        //            cerr << ">>" << MIN(obs, buff->length-t) << endl;
                    int64_t t2 = read(fo[id].file_descriptor, local_buffer[id]+t, MIN(obs, buff->length-t));
        //            cerr << "riletti: " << buff->length << " " << t2 << endl;
                    if (t2==-1) {                   // ho trovato un blocco danneggiato, lo salto
                        if (settings.is_verbose)
                            settings.ofstream_log_file << program_name << ": error: re-reading block "<<num2str(pos,16,16,'0')<<"-"
                                <<num2str(pos+MIN(obs, buff->length-t),16,16,'0')<<" ("<< strerror(errno) << ")\n";
                        buff->active[id] = false;
                        break;
                    }
                    else {
                        current_read += t2;
                    }
                    pos+=t2;
                }

                if (!buff->active[id])
                    continue;
                    
                if (current_read != buff->length) {
                    if (settings.is_verbose)
                        settings.ofstream_log_file << program_name << ": error: unable to load data just written in '"<< fo[id].file_name <<"' (read only " << current_read << " bytes)\n";
                    cerr << program_name << ": error: unable to load data just written in '"<< fo[id].file_name <<"' (read only " << current_read << " bytes)\n";
                    
                    buff->active[id] = false;
                    continue;
                }
                
                // a questo punto ho riletto senza errori (quindi il supporto non è fisicamente danneggiato)
                // ma se l'md5 diverge esco subito
                
                ///////////////////// Hash Output
                if (settings.is_md_files_out) {
                    for (int i1=0; i1<fo[id].tot_digests; i1++) {
                        EVP_DigestUpdate(&(fo[id].ctx[i1]), local_buffer[id], current_read);
                    }
                }
        
                if (settings.is_md_blocks_check) {           // calcolo e scrivo su file i digest dei blocchi
                    EVP_MD_CTX mdctx;
                    unsigned char md_value[EVP_MAX_MD_SIZE];
                    unsigned int md_len;

                    for (int i1=0; i1<buff->tot_digests; i1++) {
                        EVP_MD_CTX_init(&mdctx);
                        EVP_DigestInit_ex(&mdctx, buff->digest_type[i1], NULL);
                        EVP_DigestUpdate(&mdctx, local_buffer[id], current_read);
                        EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
                        
                        bool uguali = true;
                        for (int i2=0; i2<md_len; i2++) {
                            if (md_value[i2] != buff->hash[i1][i2])
                                uguali = false;
                        }
                        
                        if (!uguali) {
                            if (settings.is_verbose) {
                                settings.ofstream_log_file << program_name << ": error: " << settings.md_blocks[i1] << " block check failed"<<endl;
                                
                                stringstream ss2;
                                for (int i2=0; i2<md_len; i2++) {
                                    ss2 << setw(2) << setfill('0') << setbase(16) << (unsigned int) buff->hash[i1][i2];
                                }
                                
                                settings.ofstream_log_file << ss2.str() << " - " << num2str(fi_common->current_position-buff->length,16,16,'0')<<"-"<<
                                    num2str(fi_common->current_position,16,16,'0')<<" - " << fi_common->file_name << endl;
                                
                                stringstream ss;
                                for (int i2=0; i2<md_len; i2++) {
                                    ss << setw(2) << setfill('0') << setbase(16) << (unsigned int) md_value[i2];
                                }
                                
                                settings.ofstream_log_file << ss.str() << " - " << settings.md_blocks[i1] << " - " << num2str(pos-buff->length,16,16,'0')<<"-"<<
                                    num2str(pos,16,16,'0')<<" - "<< fo->file_name << endl;
                            }
                            
                            buff->active[id]=false;
                            
                            bool tutti_finito=true;
                            for (int i1=0; i1<tot_output_file; i1++)
                                if (buff->active[i1]) tutti_finito=false;
                                
                            if (tutti_finito) buff->is_last = true;
                        }
                    }
                }
                ///////////////////// Fine Hash Output
            }
        }
    }*/
}

string to_human_readable(double num) {
    double num2 = num;
    int i=0;
    
    while (num2>=1024) {
        i++;
        num2/=1024;
    }
    
    ostringstream temp;
    temp << num2;
    
    char un[] = " KMGTPE";
    
    temp << " ";
    if (i>0 && i<6)
        temp << un[i];
    
    return temp.str();
}

void final_stat() {
    if (settings.is_progress_bar) {
        cerr << endl;
    }
    else
        cerr << '\r';
    
    cerr << fi_common->file_name << ": " << fi_common->b_compl << "+" << fi_common->b_part << " blocks in" << endl;
    for (int i=0; i<tot_output_file; i++) {
        cerr << fo_common[i].file_name << ": " << fo_common[i].b_compl << "+" << fo_common[i].b_part <<  " blocks out" << endl;
    }
    
    struct timeval t_2;
    gettimeofday(&t_2, NULL);
    int64_t diff = t_2.tv_sec*1000000+t_2.tv_usec-t_start;
    cerr << fi_common->byte_read << " bytes read, " << (diff/1000000.0) << " sec., " << to_human_readable(fi_common->byte_read*1000000.0/diff) << "B/sec" <<endl;
}

void on_ctrlc(int sig) {
    final_stat();

    exit(1);
}

void on_ctrlslash(int sig) {
    final_stat();
}

void init_modules() {
    fastdd_module_regex *temp_regex = new fastdd_module_regex(&fi_common, &settings);
    fastdd_module *temp = (fastdd_module *)temp_regex;
    modules.push_back(temp);    
    
    fastdd_module_conv *temp_conv = new fastdd_module_conv();
    temp = (fastdd_module *)temp_conv;
    modules.push_back(temp);
    
    fastdd_module_gzip *temp_gzip = new fastdd_module_gzip(&settings, (buffer_t *) &buffer[0]);
    temp = (fastdd_module *)temp_gzip;
    modules.push_back(temp);
}

void fin_modules() {
    for (int i=0; i<modules.size(); i++) {
        bool ok = modules[i]->validate();
        
        if (!ok) {
            cerr << modules[i]->get_name() << ": " << modules[i]->get_error() << endl;
            exit(1);
        }
    }
}

int main(int argc, char *argv[]) {
    (void) signal(SIGINT, on_ctrlc);
    (void) signal(SIGQUIT, on_ctrlslash);
    
    struct timeval t_2;
    gettimeofday(&t_2, NULL);
    t_start = t_2.tv_sec*1000000+t_2.tv_usec;
//    t_start = t_1.tv_sec*1000000+t_1.tv_usec;
    
    init_modules();
    
    init_default_settings();
    
    init_read_arguments_settings(argc, argv);
    
    OpenSSL_add_all_digests();
    
    init_buffers();
    
    fi_common = init_input_file();
    fo_common = init_output_file();
    
    fin_modules();
    
    if (settings.is_parallel) {
        pthread_t threads[1+tot_output_file];
        pthread_attr_t attr;

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

        // avvio i thread
        pthread_create(&threads[0], &attr, thread_read, (void *) fi_common);
        //cerr << "input thread started\n";
        
        for (int i=0; i<tot_output_file; i++) {
            //cerr << "starting " << fo[i].file_name << endl;
            for (int j=0; j<TOT_BUFFERS; j++)
                buffer[j].writer_active++;
            pthread_create(&threads[1+i], &attr, thread_write, (void *) (fo_common+i));
        }
        //cerr << tot_output_file << " output threads started\n";
        
        // attendo che tutti finiscano
        for (int i=0; i<1+tot_output_file; i++) {
            pthread_join(threads[i], NULL);
        }
    }
    else {
        //cerr << "no_parallel" << endl;
        no_parallel(fi_common, fo_common);
    }
    
    if (settings.is_progress_bar) {
        cerr << endl;
    }
    
    final_stat();
    
    if (settings.is_md_file_in) {
        for (int i1=0; i1<fi_common->tot_digests; i1++) {
            EVP_DigestFinal_ex(&fi_common->ctx[i1], fi_common->hash[i1], &fi_common->hash_len[i1]);

            stringstream ss;
            for (int i2=0; i2<fi_common->hash_len[i1]; i2++)
                ss << setw(2) << setfill('0') << setbase(16) << (unsigned int)fi_common->hash[i1][i2];
                
            if (settings.is_verbose)
                settings.ofstream_log_file << ss.str() << " - " << settings.md_files[i1] << " - " << fi_common->file_name << endl;
            cerr << ss.str() << " - " << settings.md_files[i1] << " - " << fi_common->file_name << endl;
        }
    }
    
    if (settings.is_md_files_out) {
        for (int i=0; i<tot_output_file; i++) {
            for (int i1=0; i1<fo_common[i].tot_digests; i1++) {
                EVP_DigestFinal_ex(&fo_common[i].ctx[i1], fo_common[i].hash[i1], &fo_common[i].hash_len[i1]);
                stringstream ss;
                for (int i2=0; i2<fo_common[i].hash_len[i1]; i2++)
                    ss << setw(2) << setfill('0') << setbase(16) << (unsigned int) fo_common[i].hash[i1][i2];
                    
                if (settings.is_verbose)
                    settings.ofstream_log_file << ss.str() << " - " << settings.md_files[i1] << " - " << fo_common[i].file_name << endl;
                cerr << ss.str() << " - " << settings.md_files[i1] << " - " << fo_common[i].file_name << endl;
            }
        }
    }
    
    if (settings.is_print_partition) {
        load_partition_types();
        vector<part> temp_pm = pm.get_partitions();
        int max_nome=6;
        for (int a=0; a<temp_pm.size(); a++)
            if (temp_pm[a].nome.size() > max_nome)
                max_nome = temp_pm[a].nome.size();
        
        if (temp_pm.size()>0)
            cerr << setw(max_nome) << setfill(' ') << "device" << "  boot           start             end          length  type  description" << endl;
        else
            cerr << "unable to read partition table" << endl;
        
        for (int a=0; a<temp_pm.size(); a++) {
            cerr << setw(max_nome) << setfill(' ') << temp_pm[a].nome
                << setw(5) << setfill(' ') << ( (temp_pm[a].is_bootable) ? "*" : " ")
                << setw(17) << setfill(' ') << setbase(10) << (temp_pm[a].start_block>>9)
                << setw(16) << setfill(' ') <<  (temp_pm[a].end_block>>9)
                << setw(16) << setfill(' ') << (temp_pm[a].blocks>>9)
                << setw(6) << setfill(' ') << setbase(16) << temp_pm[a].type
                << "  " << partition_types[temp_pm[a].type] << endl;
        }
    }
}

void help() {
    cout << "NAME\n";
    cout << "   " << program_name << " - a tool to read, transform and copy efficiently" << endl;
    cout  << setw(strlen(program_name)+6) << setfill(' ') << " " << "a file in multiple destinations" << endl;
    cout << "SYNOPSIS\n    fastdd [OPERANDS] [OPTIONS]\n\n";
    cout << "OPERANDS\n";
    cout << "   if=FILE\n";
    cout << "      specify input file, default stdin\n";
    cout << "   of=FILE\n";
    cout << "      specify output file, default stdout. Can be used more than once.\n";
    cout << "   bs=BYTES\n";
    cout << "      read and write BYTES bytes at time\n";
    cout << "   ibs=BYTES\n";
    cout << "      read BYTES bytes at time (must be multiple or submultiple of obs)\n";
    cout << "   obs=BYTES\n";
    cout << "      write BYTES bytes at time (must be multiple or submultiple of ibs)\n";
    cout << "   count=BLOCKS\n";
    cout << "      number of input block ibs-sized to read\n";
    cout << "   skip=BLOCKS\n";
    cout << "      number of input block ibs-sized to skip\n";
    cout << "   seek=BLOCKS\n";
    cout << "      number of output block obs-sized to seek (padded with '\\0' in new files)\n";
    cout << "   log=FILE\n";
    cout << "      enable verbose mode and save output produced in FILE\n";
    cout << "   reread-bs=BYTES\n";
    cout << "      when a input reading error occurs, re-read the current input block with\n";
    cout << "      this block size (to mantain an high reading speed). When one of these\n";
    cout << "      blocks have an error will be read at 512-bytes blocks. Default: 512.\n";
    cout << "   reading-attempts=N\n";
    cout << "      try to read N times a 512-bytes sector before considering it unreadeble\n";
    cout << "      (default: 1). Use reading-attempts=0 to avoid any further reading of\n";
    cout << "      damaged blocks (just pad it with \\0)\n";
    cout << "   hash-blocks=ALGORITHM1[,ALGORITHM2,...]\n";
    cout << "      use the specified hash algorithms to check input and output blocks\n";
    cout << "   hash-files=ALGORITHM1[,ALGORITHM2,...]\n";
    cout << "      use the specified hash algorithms to check input and output files\n";
    cout << "   hash-blocks-save=FILE\n";
    cout << "      save in FILE the hash of the input blocks\n";
    cout << "\nOPTIONS\n";
    cout << "   --hash-blocks-check, -c\n";
    cout << "      re-read every written block and check its hashes with the corrisponding\n" <<
            "      input block. Exit on re-reading error\n";
    cout << "   --hash-file-in\n";
    cout << "      print hashes of input file at the end of computation\n";
    cout << "   --hash-file-out\n";
    cout << "      print hashes of output file at the end of computation\n";
    cout << "   --hash-file-all, -f\n";
    cout << "      print hashes of all files at the end of computation\n";
    cout << "   --direct-input-disabled, -i\n";
    cout << "      disable O_DIRECT flag in opening input file\n";
    cout << "   --direct-output-disabled, -o\n";
    cout << "      disable O_DIRECT flag in opening output file\n";
    cout << "   --get-partition-table\n";
    cout << "       print the partition table contained in the input file (if any)\n";
    cout << "   --fast\n";
    cout << "      same as 'reading-attempts=0 bs=16M'\n";
    cout << "   --no-parallel, -p\n";
    cout << "      make every read/write action sequentially, without using multi-threading\n";
    cout << "   --no-progress-bar\n";
    cout << "      disable progress bar\n";
    cout << "   --ignore-modules-errors\n";
    cout << "      ignore errors occurred in the execution of modules (otherwise it asks how\n";
    cout << "      to procede, stopping the copy until an answer is given)\n";
    cout << "   --debug\n";
    cout << "      debug mode, it is ignored if a log file is not specified.\n";
    cout << "   --help, -h\n";
    cout << "      show this help\n\n";
    cout << "   BYTES and BLOCKS accept multiplicative suffixes: K=1024, KB=1000,\n";
    cout << "   M=1024*1024, MB=1000*1000, G=1024*1024*1024, GB=1000*1000*1000,\n";
    cout << "   T=1024^4 and TB=1000^4.\n\n";
    cout << "MODULES" << endl;
    cout << "   fastdd's capabilities can be easily expanded by createing a new module" << endl;
    cout << "   implementing fastdd_module.hpp interface, and adding it to the main program" << endl;
    cout << "   with few code lines in init_modules() and fin_modules() functions." << endl;
    cout << "   Here the actually available modules.\n" << endl;

    for (int a=0; a<modules.size(); a++) {
        
        string temp = modules[a]->get_help();
        cout << temp << endl;
    }
    
    cout << "EXAMPLES OF USE\n";
    cout << "   fastdd if=\"input file\" of=\"file with spaces\" of=another\\ one of=file3\n"
         << "          bs=1M hash-files=sha1,sha256 hash-blocks=md5 --hash-blocks-check\n"
         << "          --hash-files-all\n";
    cout << "      copy content of file \"input file\" in files \"file with spaces\",\n";
    cout << "      \"another one\" and \"file3\", showing sha1 and sha256 of all files\n";
    cout << "      and checking the equality of md5 of blocks copied for early stop." << endl;
}

void version() {
    cout << "fastdd, version 1.0.0\n Copyright (C) 2013, Free Software Foundation, Inc." << endl;
    cout << "Licence GPL2: GNU GPL version 2 <http://www.gnu.org/licenses/gpl-2.0.html>" << endl;
    cout << "This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you" << endl;
    cout << "are welcome to redistribute it under conditions specified in www.gnu.org site." << endl;
    cout << "Authors: Paolo Bertasi, Nicola Zago" << endl;
    cout << "Email: paolo.bert@gmail.com, zago.nicola@gmail.com" << endl;
}
