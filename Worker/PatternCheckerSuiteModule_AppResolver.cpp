#include "PatternCheckerSuiteModule_AppResolver.h"

#include "AssemblyUtils.h"

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_AppResolver::ElementDefs[] =
{
	{ L"AUPSTS", L"CAppResolverCacheBuilder::_AddUserPinnedShortcutToStart()" },
};

CPatternCheckerSuiteModule_AppResolver::CPatternCheckerSuiteModule_AppResolver()
	: CPatternCheckerSuiteModule_Base(L"AppResolver.dll", ElementDefs)
{
}

void CPatternCheckerSuiteModule_AppResolver::CheckPatterns(
	PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	// CAppResolverCacheBuilder::_AddUserPinnedShortcutToStart()
	INIT_MATCH_INFO_VARS(AddUserPinnedShortcutToStart);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 8B ? 48 8B D3 E8 ? ? ? ? 48 8B 8D
		//                  ^^^^^^^
		// Ref: CAppResolverCacheBuilder::_AddShortcutToCache()
		matchAddUserPinnedShortcutToStart = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x8B\x00\x48\x8B\xD3\xE8\x00\x00\x00\x00\x48\x8B\x8D",
			"x?xxxx????xxx",
			&numMatchesAddUserPinnedShortcutToStart
		);
		if (matchAddUserPinnedShortcutToStart)
		{
			matchAddUserPinnedShortcutToStart += 5;
			matchAddUserPinnedShortcutToStart += 5 + *(int*)(matchAddUserPinnedShortcutToStart + 1);
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// 7F 23 03 D5  FD 7B BC A9  F3 53 01 A9  F5 5B 02 A9  F7 1B 00 F9  FD 03 00 91  ?? ?? ?? ??  FF 43 01 D1  F7 03 00 91  30 00 80 92  F0 1A 00 F9  ?? 03 01 AA  ?? 03 02 AA  FF ?? 00 F9
		// ----------- PACIBSP, don't scan for this because it's everywhere
		matchAddUserPinnedShortcutToStart = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\xFD\x7B\xBC\xA9\xF3\x53\x01\xA9\xF5\x5B\x02\xA9\xF7\x1B\x00\xF9\xFD\x03\x00\x91\x00\x00\x00\x00\xFF\x43\x01\xD1\xF7\x03\x00\x91\x30\x00\x80\x92\xF0\x1A\x00\xF9\x00\x03\x01\xAA\x00\x03\x02\xAA\xFF\x00\x00\xF9",
			"xxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxx?xxx?xxxx?xx",
			&numMatchesAddUserPinnedShortcutToStart
		);
		if (matchAddUserPinnedShortcutToStart)
		{
			matchAddUserPinnedShortcutToStart -= 4;
		}
	}
	PUBLISH_MATCH_INFO(AddUserPinnedShortcutToStart);
}

bool CPatternCheckerSuiteModule_AppResolver::ShouldIncludeFile(const FileInfo& fileInfo) const
{
	if (!CPatternCheckerSuiteModule_Base::ShouldIncludeFile(fileInfo))
		return false;

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	return build >= 22621;
}

/*void CPatternCheckerSuiteModule_AppResolver::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);
}*/
