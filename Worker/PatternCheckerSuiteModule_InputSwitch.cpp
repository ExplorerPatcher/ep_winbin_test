#include "PatternCheckerSuiteModule_InputSwitch.h"

#include "AssemblyUtils.h"

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_InputSwitch::ElementDefs[] =
{
	{ L"IMECM", L"CTsfHandler::_OnOopImeContextMenu() legacy context menu" },
};

CPatternCheckerSuiteModule_InputSwitch::CPatternCheckerSuiteModule_InputSwitch()
	: CPatternCheckerSuiteModule_Base(L"InputSwitch.dll", ElementDefs)
{
}

void CPatternCheckerSuiteModule_InputSwitch::CheckPatterns(
	PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	INIT_MATCH_INFO_VARS(LegacyContextMenu);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 44 38 ?? ?? 74 ?? ?? 8B CE E8 ?? ?? ?? ?? 85 C0
		//             ^^ Change jz into jmp
		// Ref: CTsfHandler::_OnOopImeContextMenu()
		matchLegacyContextMenu = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x44\x38\x00\x00\x74\x00\x00\x8B\xCE\xE8\x00\x00\x00\x00\x85\xC0",
			"xx??x??xxx????xx",
			&numMatchesLegacyContextMenu
		);
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// A8 43 40 39 C8 04 00 34 E0 03 ?? AA
		//             ^^^^^^^^^^^ Change CBZ to B
		// Ref: CTsfHandler::_OnOopImeContextMenu()
		usingPatternLegacyContextMenu = 1;
		matchLegacyContextMenu = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\xA8\x43\x40\x39\xC8\x04\x00\x34\xE0\x03\x00\xAA",
			"xxxxxxxxxx?x",
			&numMatchesLegacyContextMenu
		);
		if (!matchLegacyContextMenu)
		{
			// GetContextMenuResourceId() inlined
			// MOV W19/W20, #15305
			// W19: 0b01010010100_0011101111001001_10011 = 52877933 = 33 79 87 52
			// W20: 0b01010010100_0011101111001001_10100 = 52877934 = 34 79 87 52
			// P:   0b01010010100_0011101111001001_10??? = 52877930 = 30 79 87 52
			// M:   0b11111111111_1111111111111111_11000 = FFFFFFF8 = F8 FF FF FF
			// Ref: CTsfHandler::_OnOopImeContextMenu()
			usingPatternLegacyContextMenu = 2;
			matchLegacyContextMenu = (PBYTE)FindPatternBitMask_4_(
				pFile,
				dwSize,
				"\x30\x79\x87\x52",
				"\xF8\xFF\xFF\xFF",
				4,
				&numMatchesLegacyContextMenu
			);
			if (matchLegacyContextMenu)
			{
				PBYTE pAfterMov = matchLegacyContextMenu + 4;

				// We might be a jmp, follow it if so
				PBYTE pJmpTarget = (PBYTE)ARM64_FollowB((DWORD*)pAfterMov);
				if (pJmpTarget)
				{
					pAfterMov = pJmpTarget;
				}

				if (*(DWORD*)pAfterMov == 0x52800033)
				{
					// Change to 0x52800013 (MOV W19, #0)
				}
				else if (*(DWORD*)pAfterMov == 0x52800034)
				{
					// Change to 0x52800014 (MOV W20, #0)
				}
				else
				{
					matchLegacyContextMenu = nullptr;
					numMatchesLegacyContextMenu = 0;
				}
			}
		}
	}
	PUBLISH_MATCH_INFO(LegacyContextMenu);
}

bool CPatternCheckerSuiteModule_InputSwitch::ShouldIncludeFile(const FileInfo& fileInfo) const
{
	if (!CPatternCheckerSuiteModule_Base::ShouldIncludeFile(fileInfo))
		return false;

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	return build > 22000 || (build == 22000 && ubr >= 65);
}

/*void CPatternCheckerSuiteModule_InputSwitch::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);
}*/
