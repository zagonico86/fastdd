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

#ifndef _FASTDD_PARTITIONS_H
    #define _FASTDD_PARTITIONS_H

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <stdint.h>
#include <string.h>

using namespace std;

class part {
    public:
    string nome;
    bool is_bootable;
    int64_t start_block;
    int64_t end_block;
    int64_t blocks;
    int type;

    /* per le partizioni fisiche */
    part(unsigned char *m, char *nome_c, int idx) {
        stringstream ss;
        ss << nome_c << idx;
        nome = ss.str();
        
        is_bootable = (m[0]==0x80);
        type = m[4];

        start_block = m[8]|(m[9]<<8)|(m[10]<<16)|(m[11]<<24);
        blocks = m[12]|(m[13]<<8)|(m[14]<<16)|(m[15]<<24);
        end_block = blocks + start_block-1;
    }

    /* per le logiche */
    part(unsigned char *m, char *nome_c, int idx, long next_offset) {
        stringstream ss;
        ss << nome_c << idx;
        nome = ss.str();
        
        is_bootable = (m[0]==0x80);
        type = m[4];

        start_block = (m[8]|(m[9]<<8)|(m[10]<<16)|(m[11]<<24)) + next_offset;
        blocks = (m[12]|(m[13]<<8)|(m[14]<<16)|(m[15]<<24));
        end_block = blocks + start_block-1;
    }

    /* per i puntatori della lista di blocchi per la partizione estesa */
     part(unsigned char *m, int64_t next_offset) {
        is_bootable = (m[0]==0x80);
        type = m[4];

        start_block = (m[8]|(m[9]<<8)|(m[10]<<16)|(m[11]<<24)) + next_offset;
        blocks = (m[12]|(m[13]<<8)|(m[14]<<16)|(m[15]<<24));
        end_block = blocks + start_block-1;
    }
};

class partition_manager {
    private:
    vector<part> partitions;
    int64_t next_byte_needed;
    int64_t limit_known;
    int64_t offset_ebr;
    bool error;
    int last_id;
    char *name;
    
    public:
    partition_manager() : next_byte_needed(0), limit_known(0) { name = NULL; error=false;}
    
    partition_manager(const char *nome) : next_byte_needed(0), limit_known(0) { 
        int l = strlen(nome) + 1;
        
        name = new char[l];
        for (int a=0; a<l; a++)
            name[a] = nome[a];
            
        error=false;
    }
    
    ~partition_manager() {
        if (name!=NULL)
            delete[] name;
    }
    
    bool is_error() {
        return error;
    }
    
    partition_manager& operator= (const partition_manager & other)
    {
        if (this != &other)
        {
            next_byte_needed = other.next_byte_needed;
            limit_known = other.limit_known;
            partitions = other.partitions;
            
            if (name!=NULL)
                delete[] name;
            
            int l = strlen(other.name)+1;   // copio anche 0 finale
            name = new char[l];
            for (int a=0; a<l; a++) {
                name[a] = other.name[a];
            }
        }
        
        return *this;
    }
    
    int64_t update(unsigned char *block, uint64_t pos) {
     //   cout << "update pos:"<< pos << " needed:" << next_byte_needed << endl;
        
        if (pos != next_byte_needed) return -1;
        if (block[510]!=0x55 || block[511]!=0xaa) {
            error = true;
            return -1;
        }
        
        if (pos == 0) {
     //       cout << "-->" << endl;
            for (int a=0; a<4; a++) {			// leggo le partizioni primarie
                part temp(block+(446+a*16),name,a+1);
                temp.start_block<<=9;
                temp.end_block<<=9;
                temp.blocks<<=9;
                if (temp.type == 0)
                    break;
                
                partitions.push_back(temp);
                
                if (partitions[a].type == 0x5 || partitions[a].type == 0xf || partitions[a].type == 0x85) {
                    next_byte_needed = partitions[a].start_block;
                    offset_ebr = partitions[a].start_block>>9;
                    break;
                }
            }
            
            if (next_byte_needed==0)
                next_byte_needed = -1;
            last_id = 5;
        }
        else {
    //        cout << "==>" << endl;
            part temp(block+446, name, last_id++, next_byte_needed>>9);
            temp.start_block<<=9;
            temp.end_block<<=9;
            temp.blocks<<=9;
            if (temp.type == 0) {
        //        cout << "error" << endl;
                return -1;
            }
            partitions.push_back(temp);
            
            part temp2(block+462, offset_ebr);
            temp2.start_block<<=9;
            temp2.end_block<<=9;
            temp2.blocks<<=9;
            
            if (temp2.type == 0x5 || temp2.type == 0xf || temp2.type == 0x85)
                next_byte_needed = temp2.start_block;
            else
                next_byte_needed = -1;
        }
        
    /*    for (int a=0; a<partitions.size(); a++) {
            cout << partitions[a].nome << " " << partitions[a].start_block << " " << partitions[a].end_block << endl;
        }*/
        
        return next_byte_needed;
    }
    
    int64_t next_needed() { return next_byte_needed; }
    
    string get_partition_at(uint64_t pos) {
      //  cout << "get pos:"<< pos << " needed:" << next_byte_needed << endl;
        
        if (error) return " ";
        
        for (int a=partitions.size()-1; a>=0; a--) {
            if (pos > (partitions[a].end_block)) {
                stringstream ss;
                ss << "unallocate after " << partitions[a].nome;
                return ss.str();
            }
            if (pos<=(partitions[a].end_block) && pos >= (partitions[a].start_block))
                return partitions[a].nome;
        }
        
        stringstream ss;
        ss << "unallocate before " << partitions[0].nome;
        return ss.str();
    }
    
    vector<part> get_partitions() {
        return partitions;
    }
};

string *partition_types;

void load_partition_types() {
    partition_types = new string[256];
    
    for (int i=0; i<256; i++) {
        stringstream ss;
        ss << "invalid code " << i;
        partition_types[i] = ss.str();
    }
    
    partition_types[0x00] = "Empty partition";
    partition_types[0x01] = "FAT12";
    partition_types[0x02] = "XENIX root";
    partition_types[0x03] = "XENIX usr";
    partition_types[0x04] = "FAT16 with less than 65536 sectors (32 MB)";
    partition_types[0x05] = "Extended partition with CHS addressing";
    partition_types[0x06] = "FAT16 with 65536 or more sectors";
    partition_types[0x07] = "HPFS or NTFS or exFAT";
    partition_types[0x08] = "AIX";
    partition_types[0x09] = "AIX bootable";
    partition_types[0x0A] = "OS/2 Boot Manager";
    partition_types[0x0B] = "FAT32 with CHS addressing";
    partition_types[0x0C] = "FAT32 with LBA";
    partition_types[0x0E] = "FAT16 with LBA";
    partition_types[0x0F] = "Extended partition with LBA";
    partition_types[0x11] = "Hidden FAT12";
    partition_types[0x12] = "Compaq diagnostics (FAT) or another OEM partition";
    partition_types[0x14] = "Hidden FAT16";
    partition_types[0x17] = "Hidden HPFS or hidden NTFS";
    partition_types[0x1B] = "Hidden FAT32";
    partition_types[0x1C] = "Hidden FAT32 with LBA";
    partition_types[0x1D] = "Hidden FAT16 with LBA";
    partition_types[0x20] = "Windows Mobile update XIP";
    partition_types[0x23] = "Windows Mobile boot XIP";
    partition_types[0x25] = "Windows Mobile IMGFS";
    partition_types[0x27] = "Windows recovery partition (hidden NTFS)";
    partition_types[0x3C] = "PqRP (PartitionMagic in progress)";
    partition_types[0x64] = "NetWare File System 286";
    partition_types[0x65] = "NetWare File System 386";
    partition_types[0x78] = "XOSL bootloader filesystem";
    partition_types[0x80] = "Old Minix file system";
    partition_types[0x81] = "MINIX file system";
    partition_types[0x82] = "Linux swap space or Solaris";
    partition_types[0x83] = "Native Linux file system";
    partition_types[0x84] = "Hibernation (suspend to disk, S2D)";
    partition_types[0x85] = "Linux extended[6]";
    partition_types[0x86] = "Legacy FT FAT16";
    partition_types[0x87] = "Legacy FT NTFS";
    partition_types[0x88] = "Linux plaintext";
    partition_types[0x89] = "Linux LVM";
    partition_types[0x8B] = "Legacy FT FAT32";
    partition_types[0x8C] = "Legacy FT FAT32 with LBA";
    partition_types[0xA0] = "Diagnostic partition for HP laptops";
    partition_types[0xA5] = "BSD slice[7]";
    partition_types[0xDE] = "Dell diagnostic partition";
    partition_types[0xEB] = "BFS (BeOS or Haiku)";
    partition_types[0xEE] = "EFI protective MBR";
    partition_types[0xEF] = "EFI System partition can be a FAT file system";
    partition_types[0xFB] = "VMware VMFS";
    partition_types[0xFC] = "VMware VMKCORE";
    partition_types[0xFD] = "Linux RAID auto";
    partition_types[0xFE] = "IBM IML partition";
}

#endif
