#include "PatternCheckerSuiteModule_UxTheme.h"

#include "AssemblyUtils.h"

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_UxTheme::ElementDefs[] =
{
	{ L"POTDFF", L"PrivateOpenThemeDataFromFile" },
	{ L"LADM", L"CVSUnpack::LoadAnimationDataMap" },
};

CPatternCheckerSuiteModule_UxTheme::CPatternCheckerSuiteModule_UxTheme()
	: CPatternCheckerSuiteModule_Base(L"UxTheme.dll", ElementDefs)
{
}

void CPatternCheckerSuiteModule_UxTheme::CheckPatterns(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	INIT_MATCH_INFO_VARS(PrivateOpenThemeDataFromFile);
	PBYTE OpenThemeDataFromFile = (PBYTE)GetExportedFunctionAddress(pFileRaw, MAKEINTRESOURCEA(16));
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		PBYTE matchAndEax2 = (PBYTE)FindPattern(
			OpenThemeDataFromFile,
			256,
			"\x83\xE0\x02",
			"xxx",
			nullptr
		);
		if (matchAndEax2)
		{
			matchPrivateOpenThemeDataFromFile = (PBYTE)FindPattern(
				matchAndEax2 + 3,
				32,
				"\xE8\x00\x00\x00\x00\x48\x8B\xD8",
				"x????xxx",
				&numMatchesPrivateOpenThemeDataFromFile
			);
			if (matchPrivateOpenThemeDataFromFile)
			{
				matchPrivateOpenThemeDataFromFile += 5 + *(int*)(matchPrivateOpenThemeDataFromFile + 1);
			}
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// E1 03 ?? AA E0 03 ?? AA ?? ?? ?? ?? ?? 03 00 AA
		//                         ^^^^^^^^^^^
		matchPrivateOpenThemeDataFromFile = (PBYTE)FindPattern(
			OpenThemeDataFromFile,
			256,
			"\xE1\x03\x00\xAA\xE0\x03\x00\xAA\x00\x00\x00\x00\x00\x03\x00\xAA",
			"xx?xxx?x?????xxx",
			&numMatchesPrivateOpenThemeDataFromFile
		);
		if (matchPrivateOpenThemeDataFromFile)
		{
			matchPrivateOpenThemeDataFromFile += 8;
			matchPrivateOpenThemeDataFromFile = (PBYTE)ARM64_FollowBL((DWORD*)matchPrivateOpenThemeDataFromFile);
		}
	}
	PUBLISH_MATCH_INFO(PrivateOpenThemeDataFromFile);

	INIT_MATCH_INFO_VARS(CVSUnpackLoadAnimationDataMap);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 48 8B 53 20 48 8B ?? E8 ?? ?? ?? ?? 8B ?? 48 8B
		//                         ^^^^^^^^^^^
		matchCVSUnpackLoadAnimationDataMap = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x48\x8B\x53\x20\x48\x8B\x00\xE8\x00\x00\x00\x00\x8B\x00\x48\x8B",
			"xxxxxx?x????x?xx",
			&numMatchesCVSUnpackLoadAnimationDataMap
		);
		if (matchCVSUnpackLoadAnimationDataMap)
		{
			matchCVSUnpackLoadAnimationDataMap += 7;
			matchCVSUnpackLoadAnimationDataMap += 5 + *(int*)(matchCVSUnpackLoadAnimationDataMap + 1);
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// 12 40 F9 E0 03 ?? AA ?? ?? ?? ?? ?? 03 00 2A E0 03 ?? AA
		//                      ^^^^^^^^^^^
		matchCVSUnpackLoadAnimationDataMap = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x12\x40\xF9\xE0\x03\x00\xAA\x00\x00\x00\x00\x00\x03\x00\x2A\xE0\x03\x00\xAA",
			"xxxxx?x?????xxxxx?x",
			&numMatchesCVSUnpackLoadAnimationDataMap
		);
		if (matchCVSUnpackLoadAnimationDataMap)
		{
			matchCVSUnpackLoadAnimationDataMap += 7;
			matchCVSUnpackLoadAnimationDataMap = (PBYTE)ARM64_FollowBL((DWORD*)matchCVSUnpackLoadAnimationDataMap);
		}
	}
	PUBLISH_MATCH_INFO(CVSUnpackLoadAnimationDataMap);
}

void CPatternCheckerSuiteModule_UxTheme::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	// anything before 15063, mark as don't care (numMatches = -1)
	if (build < 15063)
	{
		for (PatternMatchInfo& match : *matches)
		{
			match.numMatches = -1;
		}
	}
}
