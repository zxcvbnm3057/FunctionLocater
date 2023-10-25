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

#include <forward_list>
#include <unordered_set>
#include <unordered_map>
#include <utility>

#ifdef _WIN64
#include <string>
#define NOMINMAX
#include <Windows.h>
#include <DbgHelp.h>

#include "jpt.hpp"

#elif __linux__
#include <elf.h>
#endif

#include "LengthDisasm/LengthDisasm.h"

#define SIGN_SIZE 30
#define MAX_SINGLE_INSTR_LENGTH 15
#define STATEMENT 1 << 0
#define FUNCTION 1 << 1

class FunctionLocater
{
public:
    struct SectionArea
    {
        uint8_t *start = (uint8_t *)0xFFFFFFFF;
        uint8_t *end = (uint8_t *)0x0;
    };

    struct Sign
    {
        void *p;
        int type;
        int length;
    };

    struct Entry
    {
        uint8_t *address;
        std::forward_list<Sign> *sign;
    };

private:
    static JPT_Locater jpt_locater;

    /**
     * @brief   get mov/lea signature with data from pointer of instruction target register.
     *
     * @param   instr       the instruction now analyzing
     * @param   address     the address of instruction
     * @param   target      target address of instruction
     * @param   skip_below  if the instr is jmp action
     * @result              instruction signature length
     * @note    for somehow operand address is 32bit in exe but 64bit in so.
     *          it will be mov for 32bit but lea for 64bit
     *          so if this is a lea action, transform it to mov.
     *          this make them more similar in signature.
     */
    static int getLeaOrMovSignature(TLengthDisasm instr, uint8_t *mov_instr, uint8_t *address, SectionArea rodata);

    /**
     * @brief   Get target address of jmp and call instruction
     * @param   instr       the instruction now analyzing
     * @param   address     the address of instruction
     * @param   target      target address of instruction
     * @param   skip_below  if the instr is jmp action
     */
    static void getTargetAddress(TLengthDisasm instr, uint8_t *address, uint64_t &target, bool &skip_below);

    /**
     * @brief   basical <Longest Common Subsequence> algorithm
     */
    static int LCS(const uint8_t *x, int xlen, const uint8_t *y, int ylen);

public:
    /**
     * @brief       Match function signature from exe and so.
     * @param       data    a pointer to a two dimensional map
     *                      In the first dimension, key is function address in exe_file
     *                      In the second dimension, key is function aadress in so_file, and value is relevance of these two address. Basically it is return by @see GetSignatureLCS
     * @param       match   a pointer to the result map
     *                      Key:    best matched address in exe_file
     *                      Value:  template function address
     * @note        in fact, you can pass any address as keys in data, as long as they have a similarity value.
     *              for example: you can set origin address as first key, and target address as second key in a hook using. Just ensure the similarity value is right.
     * @attention   this is a variant of Kuhn-Munkres algorithm. Depending on your file size, this funtion might take quite a long time.
     */
    static void MatchFunctions(std::unordered_map<uint8_t *, std::unordered_map<uint8_t *, std::pair<int, std::string>>> &data, std::unordered_map<uint8_t *, uint8_t *> &match);

    /**
     * @brief   Get <Longest Common Subsequence> of two signature
     */
    static int GetSignatureLCS(std::forward_list<Sign> *A, std::forward_list<Sign> *B);

    /**
     * @brief   Get signature of a function
     * @param   address     start address of the function
     * @param   signature   function signature return
     * @param   count       total count of instructions using to generate Signature
     */
    static void GetFunctionSignature(uint8_t *address, std::forward_list<Sign> *signature, SectionArea &rodata, int count);

    static void DelSign(std::forward_list<Sign> *signature);

    /**
     * @brief   Get all function start locations in given .text section address area
     * @param   entry_list  all function address will be filled into this variable
     */
    static void GetFunctionEntry(std::unordered_set<uint8_t *> &entry_list, SectionArea &text);

    /**
     * @brief   Read .text and .rodata section physical address area in memory
     */
    static void GetSectionArea(char *file_path, SectionArea *text, SectionArea *rodata, uint64_t offset);

#ifdef _DEBUG
    static void DumpHex(uint8_t *data, int len, std::string indent)
    {
        printf("%s", indent.c_str());
        for (int i = 0; i < len; i++)
        {
            printf("%02x", *(data + i));
        }
        printf("\n");
    }

    static void DumpSign(std::forward_list<Sign> *data, std::string indent)
    {
        data->reverse();
        for (auto it = data->begin(); it != data->end(); it++)
        {
            switch (it->type)
            {
            case STATEMENT:
                DumpHex((uint8_t *)it->p, it->length, indent);
                break;
            case FUNCTION:
                DumpSign((std::forward_list<Sign> *)it->p, indent + "\t");
                break;
            }
        }
    }
#endif
};
