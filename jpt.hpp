/**
 * Copyright 2023 Fengying <zxcvbnm3057@outlook.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unordered_map>

#include "LengthDisasm/LengthDisasm.h"

//			cmp     eax, 3Fh				; switch 64 cases
//			ja      def_14004B6FD			; jumptable 000000014004B6FD default case, cases 3, 5 - 7, 9 - 15, 17 - 31, 33 - 63
//			lea     rdx, cs:140000000h		; optional
//			movzx   eax, ds:(byte_14004B7F0 - 140000000h)[rdx + rax]		; indirect table for switch statement
//			mov     ecx, ds:(jpt_14004B6FD - 140000000h)[rdx + rax * 4]		; jump table for switch statement
//			add     rcx, rdx
//			jmp     rcx						; switch jump

class JPT_Locater
{
public:
    static uint64_t ds;

    bool isJPT(uint64_t p)
    {
        return jpt.count(p - ds);
    }

    uint16_t getJPTSize(uint64_t p)
    {
        return jpt[p - ds];
    }

    void updateInstruction(uint8_t *p, TLengthDisasm instr)
    {
        switch (instr.OpcodeSize)
        {
        case 1:
            switch (instr.Opcode[0])
            {
            case 0x83: // cmp
                if (progress == NIL && instr.MODRM.Reg == 0x07)
                {
                    progress = CMP;
                    cases = instr.ImmediateData.ImmediateData08 + 1;
                    return;
                }
                break;
            case 0x77: // ja
                if (progress == CMP)
                {
                    progress = JA;
                    return;
                }
                break;
            case 0x8d:                                                                   // lea
                if (progress == JA && instr.MODRM.Mod == 0x00 && instr.MODRM.Rm == 0x05) // lea
                {
                    // progress = LEA;
                    return;
                }
                break;
            case 0x8B: // mov
                if (progress == JA)
                {
                    progress = MOV;
                    jpt_current.first = instr.AddressDisplacement.Displacement32;
                    if (jpt_current.second == 0)
                    {
                        jpt_current.second = jpt_current.first + (cases << 2);
                    }
                    return;
                }
                break;
            case 0x03: // add
                if (progress == MOV)
                {
                    progress = ADD;
                    return;
                }
                break;
            case 0xff: // jmp
                if (progress == ADD)
                {
                    jpt.insert(std::make_pair(jpt_current.first, jpt_current.second - jpt_current.first));
                    progress = NIL;
                    jpt_current.first = 0;
                    jpt_current.second = 0;
                    return;
                }
                break;
            case 0x98: // cdqe
                if (progress == JA)
                {
                    return;
                }
                break;
            case 0x63: // movsxd
                if (progress == JA)
                {
                    return;
                }
                break;
            }
            break;
        case 2:
            switch (instr.Opcode[1])
            {
            case 0x87: // ja
                if (progress == CMP)
                {
                    progress = JA;
                    return;
                }
                break;
            case 0xb6: // movzx
                if (progress == JA)
                {
                    jpt_current.second = instr.AddressDisplacement.Displacement32 + cases;
                    return;
                }
                break;
            }
            break;
        }
        progress = NIL;
        jpt_current.first = 0;
        jpt_current.second = 0;
    }

private:
    static enum instructions {
        NIL,
        CMP,
        JA,
        // LEA,
        // MOVZX,
        MOV,
        ADD
    };
    uint8_t cases = 0;
    instructions progress = NIL;
    std::unordered_map<uint32_t, uint16_t> jpt;
    std::pair<uint32_t, uint32_t> jpt_current;
};
