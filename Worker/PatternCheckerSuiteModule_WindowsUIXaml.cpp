#include "PatternCheckerSuiteModule_WindowsUIXaml.h"

#include "AssemblyUtils.h"

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_WindowsUIXaml::ElementDefs[] =
{
	{ L"TLXRH", L"CCoreServices::TryLoadXamlResourceHelper()" },
	{ L"SOUND", L"DirectUI::ElementSoundPlayerService::ShouldPlaySound() disregard XboxUtility::IsOnXbox()" },
};

CPatternCheckerSuiteModule_WindowsUIXaml::CPatternCheckerSuiteModule_WindowsUIXaml()
	: CPatternCheckerSuiteModule_Base(L"Windows.UI.Xaml.dll", ElementDefs)
{
}

void CPatternCheckerSuiteModule_WindowsUIXaml::CheckPatterns(
	PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	INIT_MATCH_INFO_VARS(TryLoadXamlResourceHelper);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 48 8B 45 ?? 49 89 43 C8 E8 ?? ?? ?? ?? 85 C0
		//                            ^^^^^^^^^^^
		// Ref: CCoreServices::LoadXamlResource()
		usingPatternTryLoadXamlResourceHelper = 1;
		matchTryLoadXamlResourceHelper = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x48\x8B\x45\x00\x49\x89\x43\xC8\xE8\x00\x00\x00\x00\x85\xC0",
			"xxx?xxxxx????xx",
			&numMatchesTryLoadXamlResourceHelper
		);
		if (matchTryLoadXamlResourceHelper)
		{
			matchTryLoadXamlResourceHelper += 7;
			matchTryLoadXamlResourceHelper += 5 + *(int*)(matchTryLoadXamlResourceHelper + 1);
		}
		else
		{
			// 29553+
			// 48 8B 45 48 48 89 44 24 ?? E8 ?? ?? ?? ?? 85 C0
			//                               ^^^^^^^^^^^
			// Ref: CCoreServices::LoadXamlResource()
			usingPatternTryLoadXamlResourceHelper = 2;
			matchTryLoadXamlResourceHelper = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x48\x8B\x45\x48\x48\x89\x44\x24\x00\xE8\x00\x00\x00\x00\x85\xC0",
				"xxxxxxxx?x????xx",
				&numMatchesTryLoadXamlResourceHelper
			);
			if (matchTryLoadXamlResourceHelper)
			{
				matchTryLoadXamlResourceHelper += 9;
				matchTryLoadXamlResourceHelper += 5 + *(int*)(matchTryLoadXamlResourceHelper + 1);
			}
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// E1 0B 40 F9 05 00 80 D2 04 00 80 D2 E3 03 ?? AA E2 03 ?? AA E0 03 ?? AA ?? ?? ?? ?? ?? 03 00 2A
		//                                                                         ^^^^^^^^^^^
		// Ref: CoreServices_TryGetApplicationResource()
		matchTryLoadXamlResourceHelper = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\xE1\x0B\x40\xF9\x05\x00\x80\xD2\x04\x00\x80\xD2\xE3\x03\x00\xAA\xE2\x03\x00\xAA\xE0\x03\x00\xAA\x00\x00\x00\x00\x00\x03\x00\x2A",
			"xxxxxxxxxxxxxx?xxx?xxx?x?????xxx",
			&numMatchesTryLoadXamlResourceHelper
		);
		if (matchTryLoadXamlResourceHelper)
		{
			matchTryLoadXamlResourceHelper += 24;
			matchTryLoadXamlResourceHelper = (PBYTE)ARM64_FollowBL((DWORD*)matchTryLoadXamlResourceHelper);
		}
	}
	PUBLISH_MATCH_INFO(TryLoadXamlResourceHelper);

	// Patch DirectUI::ElementSoundPlayerService::ShouldPlaySound() to disregard XboxUtility::IsOnXbox() check
	// Do not forget to update the Windhawk mod too
	INIT_MATCH_INFO_VARS(XamlSounds);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 74 ?? 39 59 ?? 75 ?? E8 ?? ?? ?? ?? 84 C0 75
		//                                           ^^ change jnz to jmp
		matchXamlSounds = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x74\x00\x39\x59\x00\x75\x00\xE8\x00\x00\x00\x00\x84\xC0\x75",
			"x?xx?x?x????xxx",
			&numMatchesXamlSounds
		);
		if (matchXamlSounds)
		{
			matchXamlSounds += 14; // Point to jnz
		}
		else
		{
			// 29553+
			// 83 79 ?? 02 74 ?? 83 79 ?? 00 75 ?? E8 ?? ?? ?? ?? 84 C0 75
			//                                                          ^^ change jnz to jmp
			matchXamlSounds = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x83\x79\x00\x02\x74\x00\x83\x79\x00\x00\x75\x00\xE8\x00\x00\x00\x00\x84\xC0\x75",
				"xx?xx?xx?xx?x????xxx",
				&numMatchesXamlSounds
			);
			if (matchXamlSounds)
			{
				matchXamlSounds += 19; // Point to jnz
			}
		}
	}
	else if (machineType == IMAGE_FILE_MACHINE_ARM64)
	{
		// 08 ?? ?? B9 1F 09 00 71 ?? ?? ?? 54 ?? 00 00 35 ?? ?? ?? ??
		//                                                 ^^^^^^^^^^^ BL -> MOV W0, #1
		// BL:
		// P: 0b100101_00000000000000000000000000 = 94000000 = 00 00 00 94
		// M: 0b111111_00000000000000000000000000 = FC000000 = 00 00 00 FC
		matchXamlSounds = (PBYTE)FindPatternBitMask_4_(
			pFile,
			dwSize,
			"\x08\x00\x00\xB9\x1F\x09\x00\x71\x00\x00\x00\x54\x00\x00\x00\x35\x00\x00\x00\x94",
			"\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\x00\xFF\xFF\xFF\x00\x00\x00\xFC",
			20,
			&numMatchesXamlSounds
		);
		if (matchXamlSounds)
		{
			matchXamlSounds += 16;
			DWORD currentInsn = *(DWORD*)matchXamlSounds;
			DWORD newInsn = true || ARM64_IsBL(currentInsn) ? 0x52800020 : 0; // MOV W0, #1
			if (!newInsn)
			{
				matchXamlSounds = nullptr;
				numMatchesXamlSounds = 0;
			}
		}
	}
	PUBLISH_MATCH_INFO(XamlSounds);
}

bool CPatternCheckerSuiteModule_WindowsUIXaml::ShouldIncludeFile(const FileInfo& fileInfo) const
{
	if (!CPatternCheckerSuiteModule_Base::ShouldIncludeFile(fileInfo))
		return false;

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	return true;
	return build > 22000 || (build == 22000 && ubr >= 65);
}

void CPatternCheckerSuiteModule_WindowsUIXaml::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	if (!(build > 22000 || (build == 22000 && ubr >= 65)))
	{
		// (*matches)[0].numMatches = -1;
	}
}
