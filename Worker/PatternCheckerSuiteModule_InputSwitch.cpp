#include "PatternCheckerSuiteModule_InputSwitch.h"

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
		matchLegacyContextMenu = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\xA8\x43\x40\x39\xC8\x04\x00\x34\xE0\x03\x00\xAA",
			"xxxxxxxxxx?x",
			&numMatchesLegacyContextMenu
		);
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
