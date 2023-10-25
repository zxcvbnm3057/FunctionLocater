/*
 *  Copyright (c) 2023 Fengying <zxcvbnm3057@outlook.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

#include <algorithm>
#include <cstring>
#include <forward_list>
#include <limits.h>
#include <unordered_map>
#include <iostream>
#include <queue>
#include <cassert>

#include "FunctionLocater.hpp";

#ifdef _WIN64

uint64_t JPT_Locater::ds;
JPT_Locater FunctionLocater::jpt_locater;

bool is_msvc_debug_align(uint8_t *p)
{
    for (; (uint64_t)p % 0x10 != 0; p++)
    {
        if (*p != 0xcc)
        {
            return false;
        }
    }
    return (uint64_t)p % 16 != 0;
}

#endif // _WIN64

void FunctionLocater::getTargetAddress(TLengthDisasm instr, uint8_t *address, uint64_t &target, bool &skip_below)
{
    target = 0x00;
    skip_below = false;
    if (instr.Length == 5 && instr.ImmediateDataSize == 4)
    {
        // 0xe8 short call
        // 0xe9 short jmp
        if (instr.Opcode[0] == 0xe8)
            target = ((uint64_t)address >> 32 << 32) | ((uint64_t)(address + instr.Length + instr.ImmediateData.ImmediateData32) << 32 >> 32);
        if (instr.Opcode[0] == 0xe9)
        {
            target = ((uint64_t)address >> 32 << 32) | ((uint64_t)(address + instr.Length + instr.ImmediateData.ImmediateData32) << 32 >> 32);
            skip_below = true;
        }
    }
    else if (instr.Length == 6 && instr.DisplacementSize == 4)
    {
        // ff15 call
        // ff25 jmp
        if (instr.Opcode[0] == 0xff && instr.ModRMByte == 0x15)
        {
            target = *(uint64_t *)(address + instr.Length + instr.AddressDisplacement.Displacement32);
        }
        if (instr.Opcode[0] == 0xff && instr.ModRMByte == 0x25)
        {
            target = *(uint64_t *)(address + instr.Length + instr.AddressDisplacement.Displacement32);
            skip_below = true;
        }
    }
}

int FunctionLocater::getLeaOrMovSignature(TLengthDisasm instr, uint8_t *mov_instr, uint8_t *address, SectionArea rodata)
{
    uint8_t *mov_instr_p = mov_instr;
    uint8_t *db_addr;

    if (instr.Opcode[0] == 0x8d && instr.MODRM.Mod == 0x00 && instr.MODRM.Rm == 0x05) // lea
    {

        if (instr.Flags & F_REX)
        {
            *mov_instr_p = instr.REXByte;
            mov_instr_p++;
        }
        switch (instr.MODRM.Reg)
        {
        case 0b000: // rax
            *mov_instr_p = 0xb8;
            break;
        case 0b001: // rcx
            *mov_instr_p = 0xb9;
            break;
        case 0b010: // rdx
            *mov_instr_p = 0xba;
            break;
        case 0b011: // rbx
            *mov_instr_p = 0xbb;
            break;
        case 0b100: // rsp
            *mov_instr_p = 0xbc;
            break;
        case 0b101: // rbp
            *mov_instr_p = 0xbd;
            break;
        case 0b110: // rsi
            *mov_instr_p = 0xbe;
            break;
        case 0b111: // rdi
            *mov_instr_p = 0xbf;
            break;
        default:
            break;
        }
        mov_instr_p++;
        db_addr = address + instr.Length + instr.AddressDisplacement.Displacement32;
    }
    else if (instr.Opcode[0] >= 0xb8 && instr.Opcode[0] <= 0xf8) // mov
    {
        if (instr.Flags & F_REX)
        {
            *mov_instr_p = instr.REXByte;
            mov_instr_p++;
        }
        *mov_instr_p = instr.Opcode[0];
        mov_instr_p++;
        db_addr = (uint8_t *)instr.ImmediateData.ImmediateData32;
    }

    if (mov_instr_p == mov_instr || !(db_addr > rodata.start && db_addr < rodata.end))
    {
        return 0;
    }

    while (*db_addr != 0x00 && mov_instr_p < mov_instr + (instr.Flags & F_REX ? 7 : 6))
    {
        *mov_instr_p = *db_addr;
        db_addr++;
        mov_instr_p++;
    }

    return mov_instr_p - mov_instr;
}

void FunctionLocater::MatchFunctions(std::unordered_map<uint8_t *, std::unordered_map<uint8_t *, int>> &data, std::unordered_map<uint8_t *, uint8_t *> &match)
{
    std::unordered_map<uint8_t *, int> src_val;
    std::unordered_map<uint8_t *, int> dst_val;
    std::unordered_map<uint8_t *, uint8_t *> pre;
    std::unordered_map<uint8_t *, bool> visited;
    std::unordered_map<uint8_t *, int> slack;

    uint8_t *x, *y;

    for (auto dst_it = data.begin(); dst_it != data.end(); dst_it++)
    {
        visited.clear();
        pre.clear();
        slack.clear();
        x = nullptr;
        y = data.begin()->second.begin()->first;
        uint8_t *yy = nullptr;
        match[y] = dst_it->first;
        do
        {
            int d = INT_MAX;
            x = match[y];
            visited[y] = true;
            for (auto src_it = ++dst_it->second.begin(); src_it != dst_it->second.end(); src_it++)
            {
                if (visited[src_it->first])
                    continue;
                if (slack[src_it->first] > src_val[x] + dst_val[src_it->first] - data[x][src_it->first])
                {
                    slack[src_it->first] = src_val[x] + dst_val[src_it->first] - data[x][src_it->first];
                    pre[src_it->first] = y;
                }
                if (slack[src_it->first] < d)
                {
                    d = slack[src_it->first];
                    yy = src_it->first;
                }
            }
            for (auto src_it = dst_it->second.begin(); src_it != dst_it->second.end(); src_it++)
            {
                if (visited[src_it->first])
                    src_val[match[src_it->first]] -= d, dst_val[src_it->first] += d;
                else
                    slack[src_it->first] -= d;
            }
            y = yy;
        } while (match[y]);

        while (pre[y])
        {
            match[y] = match[pre[y]];
            y = pre[y];
        }
    }
    match.erase(y);
}

int FunctionLocater::LCS(const uint8_t *x, int xlen, const uint8_t *y, int ylen)
{
    int curr[SIGN_SIZE + 1] = {0};
    int prev = 0;

    for (int i = 1; i <= xlen; i++)
    {
        prev = curr[0];
        for (int j = 1; j <= ylen; j++)
        {
            int backup = curr[j];
            if (x[i - 1] == y[j - 1])
                curr[j] = prev + 1;
            else
                curr[j] = std::max({curr[j], curr[j - 1]});
            prev = backup;
        }
    }

    return curr[ylen];
}

int FunctionLocater::GetSignatureLCS(std::forward_list<Sign> *A, std::forward_list<Sign> *B)
{
    int xlen = std::distance(A->begin(), A->end()) + 1;
    int ylen = std::distance(B->begin(), B->end()) + 1;

    int curr[SIGN_SIZE + 1] = {0};

    {
        int prev = 0;
        int i = 1;

        for (auto x_it = A->begin(); x_it != A->end(); x_it++)
        {
            int j = 1;

            prev = curr[0];
            for (auto y_it = B->begin(); y_it != B->end(); y_it++)
            {
                int backup = curr[j];

                switch (x_it->type & y_it->type)
                {
                case STATEMENT:
                    curr[j] = std::max({curr[j], curr[j - 1], prev + LCS((uint8_t *)x_it->p, x_it->length, (uint8_t *)y_it->p, y_it->length)});
                    break;
                case FUNCTION:
                    curr[j] = std::max({curr[j], curr[j - 1], prev + GetSignatureLCS((std::forward_list<Sign> *)x_it->p, (std::forward_list<Sign> *)y_it->p)});
                    break;
                default:
                    curr[j] = std::max(curr[j], curr[j - 1]);
                }

                prev = backup;
                j++;
            }
            i++;
        }
    }

    return curr[ylen - 1];
}

int FunctionLocater::GetFunctionSignature(uint8_t *address, std::forward_list<Sign> *signature, SectionArea &rodata, int count)
{
    assert(count <= SIGN_SIZE);

    TLengthDisasm instr;
    int sign_len = 0;
    int instr_len;

#ifdef _WIN64
    bool after_align = false;
    for (; count > 0; count--)
    {
        if (after_align && jpt_locater.isJPT((uint64_t)address))
        {
            address += jpt_locater.getJPTSize((uint64_t)address);
            continue;
        }

        if (is_msvc_debug_align(address))
        {
            address = (uint8_t *)((((uint64_t)address >> 4) + 1) << 4);
            after_align = true;
            continue;
        }

        LengthDisasm(address, true, &instr);
        if (instr.Length == 0)
        {
            address++;
            continue;
        }

        if ((instr.OpcodeSize == 2 && instr.Opcode[1] == 0x1F && (instr.Flags & F_MODRM)) || instr.Opcode[0] == 0x90)
        {
            address += instr.Length;
            after_align = true;
            continue;
        }
        after_align = false;
#else
    for (; count > 0; count--)
    {
        LengthDisasm(address, true, &instr);
#endif
        instr_len = instr.Length;
        // wrong instruction
        if (instr_len == 0 || (instr.Opcode[0] == 0x00 && (!(instr.Flags & F_MODRM) || instr_len != 3)))
            break;
        // 	No Operation, just for align
        if ((instr.OpcodeSize == 2 && instr.Opcode[1] == 0x1F && (instr.Flags & F_MODRM)) || instr.Opcode[0] == 0x90)
        {
            address += instr_len;
            continue;
        }

        uint64_t addr;
        bool short_circuit; // jmp action wont execute any instruction behind this, we call it short-circuit

        // if this is a call or jmp action, we follow the instruction target.
        getTargetAddress(instr, address, addr, short_circuit);
        if (addr)
        {
            std::forward_list<Sign> *sub_func_sign = new std::forward_list<Sign>();
            if (short_circuit)
            {
                sign_len += GetFunctionSignature((uint8_t *)addr, signature, rodata, count);
                break;
            }
            else
            {
                sign_len += GetFunctionSignature((uint8_t *)addr, sub_func_sign, rodata, 3);
                signature->push_front(Sign{sub_func_sign, FUNCTION, 0});
            }
        }
        else
        {
            int sign_length = 0;
            uint8_t mov_instr[7] = {0x00};
            sign_length = getLeaOrMovSignature(instr, mov_instr, address, rodata);
            if (sign_length) // this is a valid lea/mov action and source operand is an address in .rodata section
            {
                uint8_t *copy = (uint8_t *)malloc(sizeof(uint8_t) * sign_length);
                memcpy(copy, mov_instr, sizeof(uint8_t) * sign_length);
                signature->push_front(Sign{copy, STATEMENT, sign_length});
                sign_len += sign_length;
            }
            else // normal case
            {
                uint8_t *copy = (uint8_t *)malloc(sizeof(uint8_t) * instr_len);
                memcpy(copy, address, sizeof(uint8_t) * instr_len);
                signature->push_front(Sign{copy, STATEMENT, instr_len});
                sign_len += instr_len;
            }
        }

        address += instr_len;

        if ((*address == 0xC3))
        {
            break;
        }
    }

    return sign_len;
}

void FunctionLocater::DelSign(std::forward_list<Sign> *signature)
{
    for (auto it = signature->begin(); it != signature->end(); it++)
    {
        switch (it->type)
        {
        case STATEMENT:
            free(it->p);
            break;
        case FUNCTION:
            DelSign((std::forward_list<Sign> *)it->p);
            break;
        }
    }
    delete signature;
}

void FunctionLocater::GetFunctionEntry(std::unordered_set<uint8_t *> &entry_list, SectionArea &text)
{
    TLengthDisasm instr;
    std::unordered_set<uint8_t *> caller_list;

#ifdef _WIN64
    bool after_align = false;
    JPT_Locater jpt_locater;
    uint64_t ds = (uint64_t)text.start >> 16 << 16;
    // for (uint8_t* p = (uint8_t*)0x7FF7609B2918; p <= text.end;)
    for (uint8_t *p = text.start; p <= text.end;)
    {
        if (after_align && jpt_locater.isJPT((uint64_t)p - ds))
        {
            p += jpt_locater.getJPTSize((uint64_t)p - ds);
            continue;
        }

        if (is_msvc_debug_align(p))
        {
            p = (uint8_t *)((((uint64_t)p >> 4) + 1) << 4);
            after_align = true;
            continue;
        }

        LengthDisasm(p, true, &instr);
        if (instr.Length == 0)
        {
            p++;
            continue;
        }

        if ((instr.OpcodeSize == 2 && instr.Opcode[1] == 0x1F && (instr.Flags & F_MODRM)) || instr.Opcode[0] == 0x90)
        {
            p += instr.Length;
            after_align = true;
            continue;
        }
        after_align = false;
#else
    for (uint8_t *p = text.start; p <= text.end;)
    {
        LengthDisasm(p, true, &instr);
#endif
        uint8_t *addr = 0x0;
        if (instr.Length == 5 && instr.ImmediateDataSize == 4 && (instr.Opcode[0] == 0xe8 || instr.Opcode[0] == 0xe9))
        {
            addr = (uint8_t *)(((uint64_t)p >> 32 << 32) | ((uint64_t)(p + instr.Length + instr.ImmediateData.ImmediateData32) << 32 >> 32));
        }
        else if (instr.Length == 6 && instr.DisplacementSize == 4 && instr.Opcode[0] == 0xff && (instr.ModRMByte == 0x15 || instr.ModRMByte == 0x25))
        {
            addr = (uint8_t *)*(uint64_t *)(p + instr.Length + instr.AddressDisplacement.Displacement32);
        }
        if (addr && addr >= text.start && addr <= text.end)
        {
            entry_list.insert(addr);
            caller_list.insert(p);
        }
#ifdef _WIN64
        else
        {
            jpt_locater.updateInstruction(p, instr);
        }
#endif
        p += instr.Length;
    }
}

#ifdef __linux__
void FunctionLocater::GetSectionArea(char *file_path, SectionArea *text, SectionArea *rodata, uint64_t offset)
{
    FILE *fp;
    Elf64_Ehdr ehdr;
    fp = fopen(file_path, "rb");

    // read elf header
    fseek(fp, 0, SEEK_SET);
    fread(&ehdr, sizeof(Elf64_Ehdr), 1, fp);

    // read section headers
    int count = ehdr.e_shnum;
    Elf64_Shdr shdr[count];
    fseek(fp, ehdr.e_shoff, SEEK_SET);
    fread(shdr, sizeof(Elf64_Shdr), count, fp);

    // read section name table
    char strtable[shdr[ehdr.e_shstrndx].sh_size];
    fseek(fp, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
    fread(strtable, 1, shdr[ehdr.e_shstrndx].sh_size, fp);

    for (int i = 0; i < count; ++i)
    {
        if (strcmp(strtable + shdr[i].sh_name, ".text") == 0 && text != nullptr)
        {
            text->start = (uint8_t *)(offset + shdr[i].sh_addr);
            text->end = (uint8_t *)(offset + shdr[i].sh_addr + shdr[i].sh_size);
        }
        else if (strcmp(strtable + shdr[i].sh_name, ".rodata") == 0 && rodata != nullptr)
        {
            rodata->start = (uint8_t *)(offset + shdr[i].sh_addr);
            rodata->end = (uint8_t *)(offset + shdr[i].sh_addr + shdr[i].sh_size);
        }
    }
    fclose(fp);
}
#elif _WIN64
void FunctionLocater::GetSectionArea(char *file_path, SectionArea *text, SectionArea *rodata, uint64_t offset) // hModule is the handle to a loaded Module (.exe or .dll)
{
    // get the location of the module's IMAGE_NT_HEADERS structure
    IMAGE_NT_HEADERS *pNtHdr = ::ImageNtHeader(file_path);

    // section table immediately follows the IMAGE_NT_HEADERS
    IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *)(pNtHdr + 1);

    const char *imageBase = (const char *)file_path;
    char scnName[sizeof(pSectionHdr->Name) + 1];
    scnName[sizeof(scnName) - 1] = '\0'; // enforce nul-termination for scn names that are the whole length of pSectionHdr->Name[]

    for (int scn = 0; scn < pNtHdr->FileHeader.NumberOfSections; ++scn)
    {
        // Note: pSectionHdr->Name[] is 8 bytes long. If the scn name is 8 bytes long, ->Name[] will
        // not be nul-terminated. For this reason, copy it to a local buffer that's nul-terminated
        // to be sure we only print the real scn name, and no extra garbage beyond it.
        strncpy(scnName, (const char *)pSectionHdr->Name, sizeof(pSectionHdr->Name));

        if (strcmp(scnName, ".text") == 0 && text != nullptr)
        {
            text->start = (uint8_t *)(file_path + pSectionHdr->VirtualAddress);
            text->end = (uint8_t *)(imageBase + pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize);
        }
        else if (strcmp(scnName, ".data") == 0 && rodata != nullptr)
        {
            rodata->start = (uint8_t *)(file_path + pSectionHdr->VirtualAddress);
            rodata->end = (uint8_t *)(imageBase + pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize);
        }
        ++pSectionHdr;
    }
}
#endif