#pragma once

__forceinline DWORD ARM64_ReadBits(DWORD value, int h, int l)
{
    return (value >> l) & ((1 << (h - l + 1)) - 1);
}

__forceinline int ARM64_SignExtend(DWORD value, int numBits)
{
    DWORD mask = 1 << (numBits - 1);
    if (value & mask)
        value |= ~((1 << numBits) - 1);
    return (int)value;
}

__forceinline int ARM64_ReadBitsSignExtend(DWORD insn, int h, int l)
{
    return ARM64_SignExtend(ARM64_ReadBits(insn, h, l), h - l + 1);
}

__forceinline BOOL ARM64_IsInRange(int value, int bitCount)
{
    int minVal = -(1 << (bitCount - 1));
    int maxVal = (1 << (bitCount - 1)) - 1;
    return value >= minVal && value <= maxVal;
}

__forceinline UINT_PTR ARM64_Align(UINT_PTR value, UINT_PTR alignment)
{
    return value & ~(alignment - 1);
}

__forceinline BOOL ARM64_IsCBZW(DWORD insn) { return ARM64_ReadBits(insn, 31, 24) == 0b00110100; }
__forceinline BOOL ARM64_IsCBNZW(DWORD insn) { return ARM64_ReadBits(insn, 31, 24) == 0b00110101; }
__forceinline BOOL ARM64_IsB(DWORD insn) { return ARM64_ReadBits(insn, 31, 26) == 0b000101; }
__forceinline BOOL ARM64_IsBL(DWORD insn) { return ARM64_ReadBits(insn, 31, 26) == 0b100101; }
__forceinline BOOL ARM64_IsADRP(DWORD insn) { return (ARM64_ReadBits(insn, 31, 24) & ~0b01100000) == 0b10010000; }
__forceinline BOOL ARM64_IsMOVZW(DWORD insn) { return ARM64_ReadBits(insn, 31, 23) == 0b010100101; }
__forceinline BOOL ARM64_IsSTRBIMM(DWORD insn) { return ARM64_ReadBits(insn, 31, 22) == 0b0011100100; }

__forceinline DWORD* ARM64_FollowCBNZW(DWORD* pInsnCBNZW)
{
	DWORD insnCBNZW = *pInsnCBNZW;
	if (!ARM64_IsCBNZW(insnCBNZW))
		return NULL;
	int imm19 = ARM64_ReadBitsSignExtend(insnCBNZW, 23, 5);
	return pInsnCBNZW + imm19; // offset = imm19 * 4
}

__forceinline DWORD* ARM64_FollowB(DWORD* pInsnB)
{
    DWORD insnB = *pInsnB;
    if (!ARM64_IsB(insnB))
        return NULL;
    int imm26 = ARM64_ReadBitsSignExtend(insnB, 25, 0);
    return pInsnB + imm26; // offset = imm26 * 4
}

__forceinline DWORD* ARM64_FollowBL(DWORD* pInsnBL)
{
    DWORD insnBL = *pInsnBL;
    if (!ARM64_IsBL(insnBL))
        return NULL;
    int imm26 = ARM64_ReadBitsSignExtend(insnBL, 25, 0);
    return pInsnBL + imm26; // offset = imm26 * 4
}

__forceinline DWORD ARM64_MakeB(int imm26)
{
    if (!ARM64_IsInRange(imm26, 26))
        return 0;
    return 0b000101 << 26 | imm26 & (1 << 26) - 1;
}

__forceinline DWORD ARM64_CBZWToB(DWORD insnCBZW)
{
    if (!ARM64_IsCBZW(insnCBZW))
        return 0;
    int imm19 = ARM64_ReadBitsSignExtend(insnCBZW, 23, 5);
    return ARM64_MakeB(imm19);
}

__forceinline DWORD ARM64_CBNZWToB(DWORD insnCBNZW)
{
    if (!ARM64_IsCBNZW(insnCBNZW))
        return 0;
    int imm19 = ARM64_ReadBitsSignExtend(insnCBNZW, 23, 5);
    return ARM64_MakeB(imm19);
}

__forceinline DWORD ARM64_DecodeADD(DWORD insnADD)
{
    DWORD imm12 = ARM64_ReadBits(insnADD, 21, 10);
    DWORD shift = ARM64_ReadBits(insnADD, 22, 22);
    return imm12 << (shift * 12);
}

__forceinline DWORD ARM64_DecodeSTRBIMM(DWORD insnSTRBIMM)
{
    if (ARM64_ReadBits(insnSTRBIMM, 31, 22) != 0b0011100100)
        return (DWORD)-1;
    DWORD imm12 = ARM64_ReadBits(insnSTRBIMM, 21, 10);
    return imm12;
}

__forceinline DWORD ARM64_DecodeLDRBIMM(DWORD insnLDRBIMM)
{
    if (ARM64_ReadBits(insnLDRBIMM, 31, 22) != 0b0011100101)
        return (DWORD)-1;
    DWORD imm12 = ARM64_ReadBits(insnLDRBIMM, 21, 10);
    return imm12;
}

inline UINT_PTR ARM64_DecodeADRL(UINT_PTR offset, DWORD insnADRP, DWORD insnADD)
{
    if (!ARM64_IsADRP(insnADRP))
        return 0;

    UINT_PTR page = ARM64_Align(offset, 0x1000);

    DWORD adrp_immlo = ARM64_ReadBits(insnADRP, 30, 29);
    DWORD adrp_immhi = ARM64_ReadBits(insnADRP, 23, 5);
    DWORD adrp_imm = ((adrp_immhi << 2) | adrp_immlo) << 12;

    DWORD add_imm = ARM64_DecodeADD(insnADD);

    return page + adrp_imm + add_imm;
}
