#include "PatternCheckerSuiteModule_TwinUIPCShell.h"

#include "AssemblyUtils.h"

inline BOOL FollowJump(PBYTE pInstr, BYTE shortOpcode, BYTE longOpcodeExt, DWORD* pInstrSize, PBYTE* pTarget)
{
	// Check long
	if (pInstr[0] == 0x0F && pInstr[1] == longOpcodeExt)
	{
		*pTarget = pInstr + 6 + *(int*)(pInstr + 2);
		*pInstrSize = 6;
		return TRUE;
	}
	// Check short
	if (pInstr[0] == shortOpcode)
	{
		*pTarget = pInstr + 2 + *(char*)(pInstr + 1);
		*pInstrSize = 2;
		return TRUE;
	}
	return FALSE;
}

inline BOOL FollowJnz(PBYTE pInstr, PBYTE* pTarget, DWORD* pInstrSize)
{
	return FollowJump(pInstr, 0x75, 0x85, pInstrSize, pTarget);
}

inline BOOL FollowJz(PBYTE pInstr, PBYTE* pTarget, DWORD* pInstrSize)
{
	return FollowJump(pInstr, 0x74, 0x84, pInstrSize, pTarget);
}

inline BOOL FollowJmp(PBYTE pInstr, PBYTE* pTarget, DWORD* pInstrSize)
{
	// Check long
	if (pInstr[0] == 0xE9)
	{
		*pTarget = pInstr + 5 + *(int*)(pInstr + 1);
		*pInstrSize = 5;
		return TRUE;
	}
	// Check short
	if (pInstr[0] == 0xEB)
	{
		*pTarget = pInstr + 2 + *(char*)(pInstr + 1);
		*pInstrSize = 2;
		return TRUE;
	}
	return FALSE;
}

const CPatternCheckerSuiteModule_Base::ElementDef CPatternCheckerSuiteModule_TwinUIPCShell::ElementDefs[] =
{
	{ L"ISB1", L"CImmersiveShellBuilder Vtable for IImmersiveShellBuilder" },
	{ L"VAR1", L"CImmersiveContextMenuOwnerDrawHelper::s_ContextMenuWndProc" },
	{ L"VAR2", L"ImmersiveContextMenuHelper::ApplyOwnerDrawToMenu" },
	{ L"VAR3", L"ImmersiveContextMenuHelper::RemoveOwnerDrawFromMenu" },
	{ L"VAR4", L"CLauncherTipContextMenu::_ExecuteShutdownCommand" },
	{ L"VAR5", L"CLauncherTipContextMenu::_ExecuteCommand" },
	{ L"VAR6", L"CMultitaskingViewManager::_CreateXamlMTVHost" },
	{ L"VAR7", L"CMultitaskingViewManager::_CreateDCompMTVHost" },
	{ L"SMA1", L"Vtable" },
	{ L"SMA2", L"SingleViewShellExperienceFields" },
	{ L"SMA3", L"AnimationHelperFields" },
	{ L"SMA4", L"TransitioningToCortanaField" },
	{ L"SMA5", L"GetMonitorInformation" },
	{ L"SMA6", L"AnimationBegin" },
	{ L"SMA7", L"AnimationEnd" },
	{ L"SMA8", L"HideA" },
	{ L"SMA9", L"HideB" },
	{ L"JVP1", L"OffsetTrayStuckPlace" },
	{ L"JVP2", L"OffsetRcWorkArea" },
	{ L"JVP3", L"EnsureWindowPosition" },
	// { L"CTBP_CI", L"CTaskbandPinCreateInstance" },
};

CPatternCheckerSuiteModule_TwinUIPCShell::CPatternCheckerSuiteModule_TwinUIPCShell()
	: CPatternCheckerSuiteModule_Base(L"Twinui.PCShell.dll", ElementDefs)
{
}

void CPatternCheckerSuiteModule_TwinUIPCShell::CheckPatterns(
	PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	CheckPatterns_Various(pFileRaw, dwSizeRaw, pFile, dwSize, machineType, matches);
	CheckPatterns_SMA(pFileRaw, dwSizeRaw, pFile, dwSize, machineType, matches);
	CheckPatterns_JVP(pFileRaw, dwSizeRaw, pFile, dwSize, machineType, matches);
}

void CPatternCheckerSuiteModule_TwinUIPCShell::CheckPatterns_Various(
	PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	// ### s_rgShellComponent
	INIT_MATCH_INFO_VARS(ISCBVtable);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		/*usingPatternShellComponentsArray = 1;
		matchShellComponentsArray = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x72\x0C\xBB\x0B\x00\x00\x80\xBA\x00\x00\x00\x00\xEB\x00\x48\x8D\x1C\x76\x48\x8D\x35\x00\x00\x00\x00\x48\x8B\x04\xDE",
			"xxxxxxxx????x?xxxxxxx????xxxx",
			&numMatchesShellComponentsArray
		);

		if (matchShellComponentsArray)
		{
			int cShellComponents = 0;
			auto isBeforeCmpEsiOkay = [](PBYTE anchor) -> bool
			{
				return *(anchor - 7) == 0x8B && *(anchor - 6) == 0xC3 && *(anchor - 5) == 0xE9;
			};
			// Check long cmp esi (81 FE ?? ?? ?? ??)
			if (*(matchShellComponentsArray - 6) == 0x81
				&& *(matchShellComponentsArray - 5) == 0xFE
				&& isBeforeCmpEsiOkay(matchShellComponentsArray - 6))
			{
				cShellComponents = *(int*)(matchShellComponentsArray - 4);
			}
			// Check short cmp esi (83 FE ??)
			else if (*(matchShellComponentsArray - 3) == 0x83
				&& *(matchShellComponentsArray - 2) == 0xFE
				&& *(matchShellComponentsArray - 1) <= 0x7F
				&& isBeforeCmpEsiOkay(matchShellComponentsArray - 3))
			{
				cShellComponents = *(matchShellComponentsArray - 1);
			}

			if (!cShellComponents)
			{
				matchShellComponentsArray = nullptr;
			}
		}
		else*/
		{
			// Germanium sizeof(ImmersiveComponentInfo) == 40
			// 39 43 20 0F 85 ?? ?? ?? ?? 81 FF ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? 48 8D 14 BF 4C 8D 15 ?? ?? ?? ??
			// Ref: CImmersiveShellCreationBehavior::CreateComponent()
			/*usingPatternShellComponentsArray = 3;
			matchShellComponentsArray = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x39\x43\x20\x0F\x85\x00\x00\x00\x00\x81\xFF\x00\x00\x00\x00\x0F\x83\x00\x00\x00\x00\x48\x8D\x14\xBF\x4C\x8D\x15",
				"xxxxx????xx????xx????xxxxxxx",
				&numMatchesShellComponentsArray
			);
			if (matchShellComponentsArray)
			{
				// TODO Handling
			}
			else
			{
				// Nickel 5025+ Germanium 3585+ sizeof(ImmersiveComponentInfo) == 32
				// 39 43 20 0F 85 ?? ?? ?? ?? 81 FF ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 8B D7 48 C1 E2 05
				// Ref: CImmersiveShellCreationBehavior::CreateComponent()
				usingPatternShellComponentsArray = 4;
				matchShellComponentsArray = (PBYTE)FindPattern(
					pFile, dwSize,
					"\x39\x43\x20\x0F\x85\x00\x00\x00\x00\x81\xFF\x00\x00\x00\x00\x0F\x83\x00\x00\x00\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x8B\xD7\x48\xC1\xE2\x05",
					"xxxxx????xx????xx????xxx????xxxxxxx",
					&numMatchesShellComponentsArray
				);
				if (matchShellComponentsArray)
				{
					// TODO Handling
				}
			}*/

			/*usingPatternShellComponentsArray = 2; // Determine as 3 or 4 later to be more specific about the size

			// Find anchor in CImmersiveShellCreationBehavior:CreateComponent() that matches on both Nickel and Germanium
			// 48 8B ?? 0F 84 ?? ?? ?? ?? 48 FF 15 ?? ?? ?? ?? 0F 1F 44 00 00 39 ?? 20 0F 85 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 0F 83 ?? ?? ?? ??
			matchShellComponentsArray = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x48\x8B\x00\x0F\x84\x00\x00\x00\x00\x48\xFF\x15\x00\x00\x00\x00\x0F\x1F\x44\x00\x00\x39\x00\x20\x0F\x85\x00\x00\x00\x00\x81\x00\x00\x00\x00\x00\x0F\x83",
				"xx?xx????xxx????xxxxxx?xxx????x?????xx",
				&numMatchesShellComponentsArray
			);
			if (matchShellComponentsArray)
			{
				matchShellComponentsArray += 42;

				// Test if size is 24 (22000.51, 22621.1174)
				// 48 8D 05 ?? ?? ?? ?? 48 8D 0C 5B 48 8D 14 C8
				PBYTE matchTestSize24 = (PBYTE)FindPattern(
					matchShellComponentsArray, 15,
					"\x48\x8D\x05\x00\x00\x00\x00\x48\x8D\x0C\x5B\x48\x8D\x14\xC8",
					"xxx????xxxxxxx",
					nullptr
				);
				if (matchTestSize24)
				{
					usingPatternShellComponentsArray = 24;
				}
				else
				{
					// Test if size is 32 (22621.1028)
					// 48 8D 0D ?? ?? ?? ?? 48 8B C3 48 C1 E0 05
					PBYTE matchTestSize32 = (PBYTE)FindPattern(
						matchShellComponentsArray, 14,
						"\x48\x8D\x0D\x00\x00\x00\x00\x48\x8B\xC3\x48\xC1\xE0\x05",
						"xxx????xxxxxxx",
						nullptr
					);
					if (matchTestSize32)
					{
						usingPatternShellComponentsArray = 32;
					}
					else
					{
						// Test if size is 40 (Nickel old + Germanium old)
						// 48 8D 05 ?? ?? ?? ?? 48 8D 0C 9B
						PBYTE matchTestSize40Nickel = (PBYTE)FindPattern(
							matchShellComponentsArray, 11,
							"\x48\x8D\x05\x00\x00\x00\x00\x48\x8D\x0C\x9B",
							"xxx????xxxx",
							nullptr
						);
						if (matchTestSize40Nickel)
						{
							usingPatternShellComponentsArray = 40;
						}
						else
						{
							matchShellComponentsArray = nullptr;
							numMatchesShellComponentsArray = 0;
						}
					}
				}
			}*/
		}

		// RS4+
		// 48 89 03 48 8D 05 ?? ?? ?? ?? 48 89 43 20 48 8B C3 48 83 63 38 00 83 63 40 00
		//                   ^^^^^^^^^^^
		// Ref: CImmersiveShellCreationBehavior::CImmersiveShellCreationBehavior()
		usingPatternISCBVtable = 1;
		matchISCBVtable = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x89\x03\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x43\x20\x48\x8B\xC3\x48\x83\x63\x38\x00\x83\x63\x40\x00",
			"xxxxxx????xxxxxxxxxxxxxxxx",
			&numMatchesISCBVtable
		);
		if (matchISCBVtable)
		{
			matchISCBVtable += 3;
			matchISCBVtable += 7 + *(int*)(matchISCBVtable + 3);
		}
		else
		{
			// Cobalt+
			// 48 89 03 48 8D 05 ?? ?? ?? ?? 48 89 43 20 C6 43 30 00 48 83 63 38 00
			//                   ^^^^^^^^^^^
			// Ref: CImmersiveShellCreationBehavior::CImmersiveShellCreationBehavior()
			usingPatternISCBVtable = 2;
			matchISCBVtable = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x48\x89\x03\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x43\x20\xC6\x43\x30\x00\x48\x83\x63\x38\x00",
				"xxxxxx????xxxxxxxxxxxxx",
				&numMatchesISCBVtable
			);
			if (matchISCBVtable)
			{
				matchISCBVtable += 3;
				matchISCBVtable += 7 + *(int*)(matchISCBVtable + 3);
			}
			else
			{
				// 27938+
				// 48 89 03 48 8D 05 ?? ?? ?? ?? 48 89 43 20 C6 43 30 00 48 C7 43 38 00 00 00 00
				//                   ^^^^^^^^^^^
				// Ref: CImmersiveShellCreationBehavior::CImmersiveShellCreationBehavior()
				usingPatternISCBVtable = 3;
				matchISCBVtable = (PBYTE)FindPattern(
					pFile, dwSize,
					"\x48\x89\x03\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x43\x20\xC6\x43\x30\x00\x48\xC7\x43\x38\x00\x00\x00\x00",
					"xxxxxx????xxxxxxxxxxxxxxxx",
					&numMatchesISCBVtable
				);
				if (matchISCBVtable)
				{
					matchISCBVtable += 3;
					matchISCBVtable += 7 + *(int*)(matchISCBVtable + 3);
				}
			}
		}
	}
	else
	{
		// Cobalt+
		// 1F 20 03 D5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 00 F9 ?? C2 00 39 ?? 12 00 F9 ?? 1E 00 F9 ?? 22 01 91
		//                                     ^^^^^^^^^^^+^^^^^^^^^^^
		// Ref: CImmersiveShellCreationBehavior::CImmersiveShellCreationBehavior()
		usingPatternISCBVtable = 1;
		matchISCBVtable = (PBYTE)FindPattern_4_(
			pFile, dwSize,
			"\x1F\x20\x03\xD5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xF9\x00\xC2\x00\x39\x00\x12\x00\xF9\x00\x1E\x00\xF9\x00\x22\x01\x91",
			"xxxx?????????????????xxx?xxx?xxx?xxx?xxx",
			&numMatchesISCBVtable
		);
		if (matchISCBVtable)
		{
			matchISCBVtable += 12;
			matchISCBVtable = (PBYTE)ARM64_DecodeADRL((UINT_PTR)matchISCBVtable, *(DWORD*)matchISCBVtable, *(DWORD*)(matchISCBVtable + 4));
		}
		else
		{
			// Germanium+
			// 68 02 00 F9 ?? ?? ?? ?? ?? ?? ?? ?? 7F C2 00 39 68 12 00 F9 7F 1E 00 F9
			//             ^^^^^^^^^^^+^^^^^^^^^^^
			// Ref: CImmersiveShellCreationBehavior::CImmersiveShellCreationBehavior()
			usingPatternISCBVtable = 2;
			matchISCBVtable = (PBYTE)FindPattern_4_(
				pFile, dwSize,
				"\x68\x02\x00\xF9\x00\x00\x00\x00\x00\x00\x00\x00\x7F\xC2\x00\x39\x68\x12\x00\xF9\x7F\x1E\x00\xF9",
				"xxxx????????xxxxxxxxxxxx",
				&numMatchesISCBVtable
			);
			if (matchISCBVtable)
			{
				matchISCBVtable += 4;
				matchISCBVtable = (PBYTE)ARM64_DecodeADRL((UINT_PTR)matchISCBVtable, *(DWORD*)matchISCBVtable, *(DWORD*)(matchISCBVtable + 4));
			}
		}
	}
	PUBLISH_MATCH_INFO(ISCBVtable); // ISB1

	// ### CImmersiveContextMenuOwnerDrawHelper::s_ContextMenuWndProc()
	INIT_MATCH_INFO_VARS(ContextMenuWndProc);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 48 8B 49 08 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 89
		//             ^^^^^^^^^^^
		matchContextMenuWndProc = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x8B\x49\x08\xE8\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x48\x8B\x89",
			"xxxxx????x????xxx",
			&numMatchesContextMenuWndProc
		);
		if (matchContextMenuWndProc)
		{
			matchContextMenuWndProc += 4;
			matchContextMenuWndProc = matchContextMenuWndProc + 5 + *(int*)(matchContextMenuWndProc + 1);
		}
	}
	else
	{
		// ?? ?? 00 71 ?? ?? 00 54 ?? ?? 40 F9 E3 03 ?? AA E2 03 ?? AA E1 03 ?? 2A ?? ?? ?? ??
		//                                                                         ^^^^^^^^^^^
		matchContextMenuWndProc = (PBYTE)FindPattern_4_(
			pFile + 2, dwSize - 2,
			"\x00\x71\x00\x00\x00\x54\x00\x00\x40\xF9\xE3\x03\x00\xAA\xE2\x03\x00\xAA\xE1\x03\x00\x2A",
			"xx??xx??xxxx?xxx?xxx?x",
			&numMatchesContextMenuWndProc
		);
		if (matchContextMenuWndProc)
		{
			matchContextMenuWndProc += 22;
			matchContextMenuWndProc = (PBYTE)ARM64_FollowBL((DWORD*)matchContextMenuWndProc);
		}
	}
	PUBLISH_MATCH_INFO(ContextMenuWndProc); // VAR1

	// ### ImmersiveContextMenuHelper::ApplyOwnerDrawToMenu()
	INIT_MATCH_INFO_VARS(ApplyOwnerDrawToMenu);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B ? ? ? ? ? 41 8B C1
		matchApplyOwnerDrawToMenu = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x85\x00\x00\x00\x00\x4C\x8B\x00\x00\x00\x00\x00\x41\x8B\xC1",
			"xxxxxxxxxxxxxxxxx????xxx????xxx????xxxxxx????xx?????xxx",
			&numMatchesApplyOwnerDrawToMenu
		);
	}
	else
	{
		// ?? ?? 40 F9 43 03 1C 32 E4 03 ?? AA ?? ?? FF 97
		//                                     ^^^^^^^^^^^
		usingPatternApplyOwnerDrawToMenu = 1;
		matchApplyOwnerDrawToMenu = (PBYTE)FindPattern_4_(
			pFile + 2, dwSize - 2,
			"\x40\xF9\x43\x03\x1C\x32\xE4\x03\x00\xAA\x00\x00\xFF\x97",
			"xxxxxxxx?x??xx",
			&numMatchesApplyOwnerDrawToMenu
		);
		if (matchApplyOwnerDrawToMenu)
		{
			matchApplyOwnerDrawToMenu += 10;
			matchApplyOwnerDrawToMenu = (PBYTE)ARM64_FollowBL((DWORD*)matchApplyOwnerDrawToMenu);
		}
		else
		{
			// 43 03 1C 32 E4 03 ?? AA E2 03 ?? AA ?? ?? FF 97
			//                                     ^^^^^^^^^^^
			usingPatternApplyOwnerDrawToMenu = 2;
			matchApplyOwnerDrawToMenu = (PBYTE)FindPattern_4_(
				pFile, dwSize,
				"\x43\x03\x1C\x32\xE4\x03\x00\xAA\xE2\x03\x00\xAA\x00\x00\xFF\x97",
				"xxxxxx?xxx?x??xx",
				&numMatchesApplyOwnerDrawToMenu
			);
			if (matchApplyOwnerDrawToMenu)
			{
				matchApplyOwnerDrawToMenu += 12;
				matchApplyOwnerDrawToMenu = (PBYTE)ARM64_FollowBL((DWORD*)matchApplyOwnerDrawToMenu);
			}
		}
	}
	PUBLISH_MATCH_INFO(ApplyOwnerDrawToMenu); // VAR2

	// ### ImmersiveContextMenuHelper::RemoveOwnerDrawFromMenu()
	INIT_MATCH_INFO_VARS(RemoveOwnerDrawFromMenu);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 48 89 5C 24 ? 48 89 7C 24 ? 55 48 8B EC 48 83 EC 60 48 8B FA 48 8B D9 E8
		matchRemoveOwnerDrawFromMenu = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x89\x5C\x24\x00\x48\x89\x7C\x24\x00\x55\x48\x8B\xEC\x48\x83\xEC\x60\x48\x8B\xFA\x48\x8B\xD9\xE8",
			"xxxx?xxxx?xxxxxxxxxxxxxxx",
			&numMatchesRemoveOwnerDrawFromMenu
		);
	}
	else
	{
		// 7F 23 03 D5 F3 53 BF A9 FD 7B BB A9 FD 03 00 91 ?? 03 00 AA ?? 03 01 AA ?? ?? ?? ?? FF ?? 03 A9
		// ----------- PACIBSP, don't scan for this because it's everywhere
		matchRemoveOwnerDrawFromMenu = (PBYTE)FindPattern_4_(
			pFile, dwSize,
			"\xF3\x53\xBF\xA9\xFD\x7B\xBB\xA9\xFD\x03\x00\x91\x00\x03\x00\xAA\x00\x03\x01\xAA\x00\x00\x00\x00\xFF\x00\x03\xA9",
			"xxxxxxxxxxxx?xxx?xxx????x?xx",
			&numMatchesRemoveOwnerDrawFromMenu
		);
		if (matchRemoveOwnerDrawFromMenu)
		{
			matchRemoveOwnerDrawFromMenu -= 4;
		}
	}
	PUBLISH_MATCH_INFO(RemoveOwnerDrawFromMenu); // VAR3

	// ### CLauncherTipContextMenu::_ExecuteShutdownCommand()
	INIT_MATCH_INFO_VARS(ExecuteShutdownCommand);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 48 8B ? E8 ? ? ? ? 4C 8B ? 48 8B ? 48 8B CE E8 ? ? ? ? 90
		//                                                ^^^^^^^
		usingPatternExecuteShutdownCommand = 1;
		matchExecuteShutdownCommand = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x8B\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x48\x8B\x00\x48\x8B\xCE\xE8\x00\x00\x00\x00\x90",
			"xx?x????xx?xx?xxxx????x",
			&numMatchesExecuteShutdownCommand
		);
		if (matchExecuteShutdownCommand)
		{
			matchExecuteShutdownCommand += 17;
			matchExecuteShutdownCommand = matchExecuteShutdownCommand + 5 + *(int*)(matchExecuteShutdownCommand + 1);
		}
		else
		{
			// 48 8B ? E8 ? ? ? ? 4C 8D 47 ? 48 8B ? 48 8B CE E8 ? ? ? ? 90
			//                                                   ^^^^^^^
			usingPatternExecuteShutdownCommand = 2;
			matchExecuteShutdownCommand = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x48\x8B\x00\xE8\x00\x00\x00\x00\x4C\x8D\x47\x00\x48\x8B\x00\x48\x8B\xCE\xE8\x00\x00\x00\x00\x90",
				"xx?x????xxx?xx?xxxx????x",
				&numMatchesExecuteShutdownCommand
			);
			if (matchExecuteShutdownCommand)
			{
				matchExecuteShutdownCommand += 18;
				matchExecuteShutdownCommand = matchExecuteShutdownCommand + 5 + *(int*)(matchExecuteShutdownCommand + 1);
			}
		}
	}
	else
	{
		// ?? 0A 40 F9 ?? 02 40 F9 ?? ?? 00 F9 ?? ?? ?? ?? ?? 62 00 91 ?? ?? 00 91 E0 03 ?? AA ?? ?? ?? ?? 1F 20 03 D5
		//                                                                                     ^^^^^^^^^^^
		matchExecuteShutdownCommand = (PBYTE)FindPattern_4_(
			pFile + 1, dwSize - 1,
			"\x0A\x40\xF9\x00\x02\x40\xF9\x00\x00\x00\xF9\x00\x00\x00\x00\x00\x62\x00\x91\x00\x00\x00\x91\xE0\x03\x00\xAA\x00\x00\x00\x00\x1F\x20\x03\xD5",
			"xxx?xxx??xx?????xxx??xxxx?x????xxxx",
			&numMatchesExecuteShutdownCommand
		);
		if (matchExecuteShutdownCommand)
		{
			matchExecuteShutdownCommand += 27;
			matchExecuteShutdownCommand = (PBYTE)ARM64_FollowBL((DWORD*)matchExecuteShutdownCommand);
		}
	}
	PUBLISH_MATCH_INFO(ExecuteShutdownCommand); // VAR4

	// ### CLauncherTipContextMenu::_ExecuteCommand()
	INIT_MATCH_INFO_VARS(ExecuteCommand);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// Cobalt:
		// 48 89 46 ? 48 8B CB E8 ? ? ? ? 48 8B D3 48 8B CF E8 ? ? ? ? 90
		usingPatternExecuteCommand = 1;
		matchExecuteCommand = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x48\x89\x46\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8B\xD3\x48\x8B\xCF\xE8\x00\x00\x00\x00\x90",
			"xxx?xxxx????xxxxxxx????x",
			&numMatchesExecuteCommand
		);
		if (matchExecuteCommand)
		{
			matchExecuteCommand += 18;
			matchExecuteCommand = matchExecuteCommand + 5 + *(int*)(matchExecuteCommand + 1);
		}
		else
		{
			// Nickel+:
			// 48 89 03 48 8B CB E8 ? ? ? ? 48 8B D3 48 8B CF E8 ? ? ? ? 90
			usingPatternExecuteCommand = 2;
			matchExecuteCommand = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x48\x89\x03\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8B\xD3\x48\x8B\xCF\xE8\x00\x00\x00\x00\x90",
				"xxxxxxx????xxxxxxx????x",
				&numMatchesExecuteCommand
			);
			if (matchExecuteCommand)
			{
				matchExecuteCommand += 17;
				matchExecuteCommand = matchExecuteCommand + 5 + *(int*)(matchExecuteCommand + 1);
			}
		}
	}
	else
	{
		// 08 09 40 F9 ?? ?? 00 F9 ?? ?? ?? ?? ?? ?? 00 91 E0 03 ?? AA ?? ?? ?? ?? 1F 20 03 D5
		//                                            ^^^^^^^^^^^
		matchExecuteCommand = (PBYTE)FindPattern_4_(
			pFile, dwSize,
			"\x08\x09\x40\xF9\x00\x00\x00\xF9\x00\x00\x00\x00\x00\x00\x00\x91\xE0\x03\x00\xAA\x00\x00\x00\x00\x1F\x20\x03\xD5",
			"xxxx??xx??????xxxx?x????xxxx",
			&numMatchesExecuteCommand
		);
		if (matchExecuteCommand)
		{
			matchExecuteCommand += 20;
			matchExecuteCommand = (PBYTE)ARM64_FollowBL((DWORD*)matchExecuteCommand);
		}
	}
	PUBLISH_MATCH_INFO(ExecuteCommand); // VAR5

	// ### CMultitaskingViewManager::_CreateXamlMTVHost()
	INIT_MATCH_INFO_VARS(CreateXamlMTVHost);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// Inlined GetMTVHostKind()
		// 4C 89 74 24 ?? ?? 8B ?? ?? 8B ?? 8B D7 48 8B CE E8 ?? ?? ?? ?? 8B
		usingPatternCreateXamlMTVHost = 1;
		matchCreateXamlMTVHost = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x4C\x89\x74\x24\x00\x00\x8B\x00\x00\x8B\x00\x8B\xD7\x48\x8B\xCE\xE8\x00\x00\x00\x00\x8B",
			"xxxx??x??x?xxxxxx????x",
			&numMatchesCreateXamlMTVHost
		);
		if (matchCreateXamlMTVHost)
		{
			matchCreateXamlMTVHost += 16;
			matchCreateXamlMTVHost = matchCreateXamlMTVHost + 5 + *(int*)(matchCreateXamlMTVHost + 1);
		}
		else
		{
			// Non-inlined GetMTVHostKind()
			// 8B CF E8 ?? ?? ?? ?? ?? 89 ?? 24 ?? ?? 8B ?? ?? 8B ?? 8B D7 48 8B CE 83 F8 01 <jnz>
			usingPatternCreateXamlMTVHost = 2;
			matchCreateXamlMTVHost = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x8B\xCF\xE8\x00\x00\x00\x00\x00\x89\x00\x24\x00\x00\x8B\x00\x00\x8B\x00\x8B\xD7\x48\x8B\xCE\x83\xF8\x01",
				"xxx?????x?x??x??x?xxxxxxxx",
				&numMatchesCreateXamlMTVHost
			);
			if (matchCreateXamlMTVHost)
			{
				PBYTE target = nullptr;
				DWORD jnzSize = 0;
				if (FollowJnz(matchCreateXamlMTVHost + 26, &target, &jnzSize))
				{
					matchCreateXamlMTVHost += 26 + jnzSize;
					if (*matchCreateXamlMTVHost == 0xE8)
					{
						matchCreateXamlMTVHost = matchCreateXamlMTVHost + 5 + *(int*)(matchCreateXamlMTVHost + 1);
					}
					else
					{
						matchCreateXamlMTVHost = nullptr;
					}
				}
				else
				{
					matchCreateXamlMTVHost = nullptr;
				}
			}
		}
	}
	else
	{
		// F3 53 BE A9  F5 5B 01 A9  FD 7B ?? A9  FD 03 00 91  30 00 80 92  ?? 03 04 AA  B0 ?? 00 F9  ?? 03 00 AA  ?? 02 00 F9  ?? 2E 40 F9  ?? 03 03 AA  ?? 23 02 A9  ?? ?? ?? B5
		matchCreateXamlMTVHost = (PBYTE)FindPattern_4_(
			pFile, dwSize,
			"\xF3\x53\xBE\xA9\xF5\x5B\x01\xA9\xFD\x7B\x00\xA9\xFD\x03\x00\x91\x30\x00\x80\x92\x00\x03\x04\xAA\xB0\x00\x00\xF9\x00\x03\x00\xAA\x00\x02\x00\xF9\x00\x2E\x40\xF9\x00\x03\x03\xAA\x00\x23\x02\xA9\x00\x00\x00\xB5",
			"xxxxxxxxxx?xxxxxxxxx?xxxx?xx?xxx?xxx?xxx?xxx?xxx???x",
			&numMatchesCreateXamlMTVHost
		);
		if (matchCreateXamlMTVHost)
		{
			matchCreateXamlMTVHost -= 4; // include PAC
		}
	}
	PUBLISH_MATCH_INFO(CreateXamlMTVHost); // VAR6

	// ### CMultitaskingViewManager::_CreateDCompMTVHost()
	INIT_MATCH_INFO_VARS(CreateDCompMTVHost);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// Inlined GetMTVHostKind()
		// 4C 89 74 24 ?? ?? 8B ?? ?? 8B ?? 8B D7 48 8B CE E8 ?? ?? ?? ?? 90
		usingPatternCreateDCompMTVHost = 1;
		matchCreateDCompMTVHost = (PBYTE)FindPattern(
			pFile, dwSize,
			"\x4C\x89\x74\x24\x00\x00\x8B\x00\x00\x8B\x00\x8B\xD7\x48\x8B\xCE\xE8\x00\x00\x00\x00\x90",
			"xxxx??x??x?xxxxxx????x",
			&numMatchesCreateDCompMTVHost
		);
		if (matchCreateDCompMTVHost)
		{
			matchCreateDCompMTVHost += 16;
			matchCreateDCompMTVHost = matchCreateDCompMTVHost + 5 + *(int*)(matchCreateDCompMTVHost + 1);
		}
		else
		{
			// Non-inlined GetMTVHostKind()
			// 8B CF E8 ?? ?? ?? ?? ?? 89 ?? 24 ?? ?? 8B ?? ?? 8B ?? 8B D7 48 8B CE 83 F8 01 <jnz>
			usingPatternCreateDCompMTVHost = 2;
			matchCreateDCompMTVHost = (PBYTE)FindPattern(
				pFile, dwSize,
				"\x8B\xCF\xE8\x00\x00\x00\x00\x00\x89\x00\x24\x00\x00\x8B\x00\x00\x8B\x00\x8B\xD7\x48\x8B\xCE\x83\xF8\x01",
				"xxx?????x?x??x??x?xxxxxxxx",
				&numMatchesCreateDCompMTVHost
			);
			if (matchCreateDCompMTVHost)
			{
				PBYTE target = nullptr;
				DWORD jnzSize = 0;
				if (FollowJnz(matchCreateDCompMTVHost + 26, &target, &jnzSize) && target && *target == 0xE8)
				{
					matchCreateDCompMTVHost = target + 5 + *(int*)(target + 1);
				}
				else
				{
					matchCreateDCompMTVHost = nullptr;
				}
			}
		}
	}
	else
	{
		// F3 53 BC A9  F5 5B 01 A9  F7 13 00 F9  F9 17 00 F9  FB 1B 00 F9  FD 7B BC A9  FD 03 00 91  FF ?? 00 D1  30 00 80 92  ?? 03 04 AA
		matchCreateDCompMTVHost = (PBYTE)FindPattern_4_(
			pFile, dwSize,
			"\xF3\x53\xBC\xA9\xF5\x5B\x01\xA9\xF7\x13\x00\xF9\xF9\x17\x00\xF9\xFB\x1B\x00\xF9\xFD\x7B\xBC\xA9\xFD\x03\x00\x91\xFF\x00\x00\xD1\x30\x00\x80\x92\x00\x03\x04\xAA",
			"xxxxxxxxxxxxxxxxxxxxxxxxxxxxx?xxxxxx?xxx",
			&numMatchesCreateDCompMTVHost
		);
		if (matchCreateDCompMTVHost)
		{
			matchCreateDCompMTVHost -= 4; // include PAC
		}
	}
	PUBLISH_MATCH_INFO(CreateDCompMTVHost); // VAR7
}

void CPatternCheckerSuiteModule_TwinUIPCShell::CheckPatterns_SMA(
	PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	// ### CStartExperienceManager::`vftable'{for `SingleViewShellExperienceEventHandler'}
	INIT_MATCH_INFO_VARS(Vtable);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// ```
		// 48 89 46 48 48 8D 05 ?? ?? ?? ?? 48 89 46 60 48 8D 4E 68 E8
		//                      ^^^^^^^^^^^
		// ```
		// Ref: CStartExperienceManager::CStartExperienceManager()
		matchVtable = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x48\x89\x46\x48\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x46\x60\x48\x8D\x4E\x68\xE8",
			"xxxxxxx????xxxxxxxxx",
			&numMatchesVtable
		);
		// constexpr auto test = FindLargestArray(ConstStr("\x48\x89\x46\x48\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x46\x60\x48\x8D\x4E\x68\xE8"), 7, ConstStr("xxxxxxx????xxxxxxxxx"), 20);
		// (void)test.first;
		if (matchVtable)
		{
			matchVtable += 4;
			matchVtable += 7 + *(int*)(matchVtable + 3);
		}
	}
	else
	{
		// * Pattern for Cobalt and Nickel
		//   ```
		//   69 A2 03 A9 ?? ?? 00 ?? 08 ?? ?? 91 ?? ?? 00 ?? 29 ?? ?? 91 ?? 32 00 F9 60 ?? ?? 91 ?? 26 00 F9 ?? ?? ?? ?? 1F 20 03 D5
		//               ^^^^^^^^^^^+^^^^^^^^^^^
		//   ```
		// Ref: CStartExperienceManager::CStartExperienceManager()
		usingPatternVtable = 1;
		matchVtable = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\x69\xA2\x03\xA9\x00\x00\x00\x00\x08\x00\x00\x91\x00\x00\x00\x00\x29\x00\x00\x91\x00\x32\x00\xF9\x60\x00\x00\x91\x00\x26\x00\xF9\x00\x00\x00\x00\x1F\x20\x03\xD5",
			"xxxx??x?x??x??x?x??x?xxxx??x?xxx????xxxx",
			&numMatchesVtable
		);
		if (matchVtable)
		{
			matchVtable += 4;
			matchVtable = (PBYTE)ARM64_DecodeADRL((UINT_PTR)matchVtable, *(DWORD*)matchVtable, *(DWORD*)(matchVtable + 4));
		}
		else
		{
			// * Pattern for Germanium
			//   ```
			//   ?? 22 04 A9 ?? ?? 00 ?? 08 ?? ?? 91 ?? A2 01 91 ?? 32 00 F9
			//               ^^^^^^^^^^^+^^^^^^^^^^^
			//   ```
			// Ref: CStartExperienceManager::CStartExperienceManager()
			usingPatternVtable = 2;
			matchVtable = (PBYTE)FindPattern_4_(
				pFile + 1,
				dwSize - 1,
				"\x22\x04\xA9\x00\x00\x00\x00\x08\x00\x00\x91\x00\xA2\x01\x91\x00\x32\x00\xF9",
				"xxx??x?x??x?xxx?xxx",
				&numMatchesVtable
			);
			if (matchVtable)
			{
				matchVtable += 3;
				matchVtable = (PBYTE)ARM64_DecodeADRL((UINT_PTR)matchVtable, *(DWORD*)matchVtable, *(DWORD*)(matchVtable + 4));
			}
		}
	}
	PUBLISH_MATCH_INFO(Vtable); // SMA1

	// ### Offset of SingleViewShellExperience instance and its event handler
	INIT_MATCH_INFO_VARS(SingleViewShellExperienceFields);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// ```
		// 48 8D 8E ?? ?? ?? ?? 44 8D 45 41 48 8D 56 60 E8
		//          ^^^^^^^^^^^ SVSE                 ^^ SVSEEH (hardcoded to 0x60, included in pattern for sanity check)
		// ```
		// Ref: CStartExperienceManager::CStartExperienceManager()
		matchSingleViewShellExperienceFields = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x48\x8D\x8E\x00\x00\x00\x00\x44\x8D\x45\x41\x48\x8D\x56\x60\xE8",
			"xxx????xxxxxxxxx",
			&numMatchesSingleViewShellExperienceFields
		);
		if (matchSingleViewShellExperienceFields)
		{
			// Assign offsets
		}
	}
	else
	{
		// ```
		// 22 08 80 52 ?? 82 01 91 ?? ?? ?? 91 ?? ?? ?? ?? 1F 20 03 D5
		//             ^^^SVSEEH^^ ^^^^^^^^^^^ SVSE
		// ```
		// Ref: CStartExperienceManager::CStartExperienceManager()
		matchSingleViewShellExperienceFields = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\x22\x08\x80\x52\x00\x82\x01\x91\x00\x00\x00\x91\x00\x00\x00\x00\x1F\x20\x03\xD5",
			"xxxx?xxx???x????xxxx",
			&numMatchesSingleViewShellExperienceFields
		);
		if (matchSingleViewShellExperienceFields)
		{
			// Assign offsets
		}
	}
	PUBLISH_MATCH_INFO(SingleViewShellExperienceFields); // SMA2

	// ### Offsets of Animation Helpers
	INIT_MATCH_INFO_VARS(AnimationHelperFields);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// ```
		// 40 88 AE ?? ?? ?? ?? C7 86 ?? ?? ?? ?? 38 00 00 00
		//          ^^^^^^^^^^^ AH1
		// ```
		// Ref: CStartExperienceManager::CStartExperienceManager()
		// AH2 is located right after AH1. AH is 32 bytes
		if (matchSingleViewShellExperienceFields)
		{
			matchAnimationHelperFields = (PBYTE)FindPattern(
				matchSingleViewShellExperienceFields + 16,
				128,
				"\x40\x88\xAE\x00\x00\x00\x00\xC7\x86\x00\x00\x00\x00\x38\x00\x00\x00",
				"xxx????xx????xxxx",
				&numMatchesAnimationHelperFields
			);
		}
		if (matchAnimationHelperFields)
		{
			// Assign offsets
		}
	}
	else
	{
		// ```
		// 08 07 80 52 ?? ?? ?? 39 ?? ?? ?? B9
		//             ^^^^^^^^^^^ AH1
		// ```
		// Ref: CStartExperienceManager::CStartExperienceManager()
		// AH2 is located right after AH1. AH is 32 bytes
		if (matchSingleViewShellExperienceFields)
		{
			matchAnimationHelperFields = (PBYTE)FindPattern_4_(
				matchSingleViewShellExperienceFields + 20,
				128,
				"\x08\x07\x80\x52\x00\x00\x00\x39\x00\x00\x00\xB9",
				"xxxx???x???x",
				&numMatchesAnimationHelperFields
			);
		}
		if (matchAnimationHelperFields)
		{
			int openingAnimation = (int)ARM64_DecodeSTRBIMM(*(DWORD*)(matchAnimationHelperFields + 4));
			if (openingAnimation != -1)
			{
				// Assign offsets
			}
			else
			{
				matchAnimationHelperFields = nullptr;
			}
		}
	}
	PUBLISH_MATCH_INFO(AnimationHelperFields); // SMA3

	// ### Offset of bTransitioningToCortana
	INIT_MATCH_INFO_VARS(TransitioningToCortanaField);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// `(CStartExperienceManager *)((char *)this - 40)` after field access
		// ```
		// 80 B9 ?? ?? ?? ?? 00 75 ?? 48 83 C1 D8
		//       ^^^^^^^^^^^ bTransitioningToCortana
		// ```
		// Ref: CStartExperienceManager::DimStart()
		usingPatternTransitioningToCortanaField = 1;
		matchTransitioningToCortanaField = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x80\xB9\x00\x00\x00\x00\x00\x75\x00\x48\x83\xC1\xD8",
			"xx????xx?xxxx",
			&numMatchesTransitioningToCortanaField
		);
		if (!matchTransitioningToCortanaField)
		{
			// `(CStartExperienceManager *)((char *)this - 40)` before field access
			// ```
			// 48 83 C1 ?? 80 B9 ?? ?? ?? ?? 00 75 ?? 41 B0 01
			//                   ^^^^^^^^^^^ bTransitioningToCortana
			// ```
			// Ref: CStartExperienceManager::DimStart()
			usingPatternTransitioningToCortanaField = 2;
			matchTransitioningToCortanaField = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x48\x83\xC1\x00\x80\xB9\x00\x00\x00\x00\x00\x75\x00\x41\xB0\x01",
				"xxx?xx????xx?xxx",
				&numMatchesTransitioningToCortanaField
			);
		}
		if (matchTransitioningToCortanaField)
		{
			// Assign offset
		}
	}
	else
	{
		// ```
		// ?? ?? ?? 39 E8 00 00 35 ?? ?? ?? ?? 01 ?? ?? 91 22 00 80 52
		// ^^^^^^^^^^^ bTransitioningToCortana
		// ```
		// Ref: CStartExperienceManager::DimStart()
		matchTransitioningToCortanaField = (PBYTE)FindPattern_4_(
			pFile + 3,
			dwSize - 3,
			"\x39\xE8\x00\x00\x35\x00\x00\x00\x00\x01\x00\x00\x91\x22\x00\x80\x52",
			"xxxxx????x??xxxxx",
			&numMatchesTransitioningToCortanaField
		);
		if (matchTransitioningToCortanaField)
		{
			int off = (int)ARM64_DecodeLDRBIMM(*(DWORD*)(matchTransitioningToCortanaField - 3));
			if (off != -1)
			{
				// Assign offset
			}
			else
			{
				matchTransitioningToCortanaField = nullptr;
			}
		}
	}
	PUBLISH_MATCH_INFO(TransitioningToCortanaField); // SMA4

	// ### Offset of CStartExperienceManager::GetMonitorInformation()
	INIT_MATCH_INFO_VARS(GetMonitorInformation);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// ```
		// 48 8B ?? E8 ?? ?? ?? ?? 8B ?? 85 C0 0F 88 ?? ?? ?? ?? C6 44 24 ?? 01
		//             ^^^^^^^^^^^
		// ```
		// Ref: CStartExperienceManager::PositionMenu()
		matchGetMonitorInformation = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x48\x8B\x00\xE8\x00\x00\x00\x00\x8B\x00\x85\xC0\x0F\x88\x00\x00\x00\x00\xC6\x44\x24\x00\x01",
			"xx?x????x?xxxx????xxx?x",
			&numMatchesGetMonitorInformation
		);
		if (matchGetMonitorInformation)
		{
			matchGetMonitorInformation += 3;
			matchGetMonitorInformation += 5 + *(int*)(matchGetMonitorInformation + 1);
		}
	}
	else
	{
		// * Pattern for 22000 and 226xx, CSingleViewShellExperience* first arg *not* passed (E1 03 14 AA)
		//   ```
		//   ?? ?? ?? A9 E4 ?? ?? ?? E3 ?? ?? 91 E2 ?? ?? 91 E0 03 ?? AA ?? ?? ?? ?? ?? 03 00 2A
		//                                                               ^^^^^^^^^^^
		//   ```
		// Ref: CStartExperienceManager::PositionMenu()
		usingPatternGetMonitorInformation = 1;
		matchGetMonitorInformation = (PBYTE)FindPattern_4_(
			pFile + 3,
			dwSize - 3,
			"\xA9\xE4\x00\x00\x00\xE3\x00\x00\x91\xE2\x00\x00\x91\xE0\x03\x00\xAA\x00\x00\x00\x00\x00\x03\x00\x2A",
			"xx???x??xx??xxx?x?????xxx",
			&numMatchesGetMonitorInformation
		);
		if (matchGetMonitorInformation)
		{
			matchGetMonitorInformation += 17;
			matchGetMonitorInformation = (PBYTE)ARM64_FollowBL((DWORD*)matchGetMonitorInformation);
		}
		if (!matchGetMonitorInformation)
		{
			// * Pattern for 226xx, CSingleViewShellExperience* first arg passed (E1 03 14 AA)
			//   ```
			//   ?? ?? ?? A9 E4 ?? ?? ?? E3 ?? ?? 91 E2 ?? ?? 91 E1 03 14 AA E0 03 13 AA ?? ?? ?? ?? ?? 03 00 2A
			//                                                                           ^^^^^^^^^^^
			//   ```
			// Ref: CStartExperienceManager::PositionMenu()
			usingPatternGetMonitorInformation = 2;
			matchGetMonitorInformation = (PBYTE)FindPattern_4_(
				pFile + 3,
				dwSize - 3,
				"\xA9\xE4\x00\x00\x00\xE3\x00\x00\x91\xE2\x00\x00\x91\xE1\x03\x14\xAA\xE0\x03\x13\xAA\x00\x00\x00\x00\x00\x03\x00\x2A",
				"xx???x??xx??xxxxxxxxx?????xxx",
				&numMatchesGetMonitorInformation
			);
			if (matchGetMonitorInformation)
			{
				matchGetMonitorInformation += 21;
				matchGetMonitorInformation = (PBYTE)ARM64_FollowBL((DWORD*)matchGetMonitorInformation);
			}
		}
		if (!matchGetMonitorInformation)
		{
			// * Pattern for 26100.1, 265, 470, 560, 670, 712, 751, 863, 1000, 1150
			//   ```
			//   E2 82 00 91 E1 03 13 AA E0 03 14 AA ?? ?? ?? ??
			//                                       ^^^^^^^^^^^
			//   ```
			// Ref: CStartExperienceManager::PositionMenu()
			usingPatternGetMonitorInformation = 3;
			matchGetMonitorInformation = (PBYTE)FindPattern_4_(
				pFile,
				dwSize,
				"\xE2\x82\x00\x91\xE1\x03\x13\xAA\xE0\x03\x14\xAA",
				"xxxxxxxxxxxx",
				&numMatchesGetMonitorInformation
			);
			if (matchGetMonitorInformation)
			{
				matchGetMonitorInformation += 12;
				matchGetMonitorInformation = (PBYTE)ARM64_FollowBL((DWORD*)matchGetMonitorInformation);
			}
		}
		if (!matchGetMonitorInformation)
		{
			// * Pattern for 26100.961, 1252, 1301, 1330, 1340, 1350, 1591, ...
			//   ```
			//   FF 02 00 39 E2 82 00 91 E0 03 13 AA ?? ?? ?? ??
			//                                       ^^^^^^^^^^^
			//   ```
			// Ref: CStartExperienceManager::PositionMenu()
			usingPatternGetMonitorInformation = 4;
			matchGetMonitorInformation = (PBYTE)FindPattern_4_(
				pFile,
				dwSize,
				"\xFF\x02\x00\x39\xE2\x82\x00\x91\xE0\x03\x13\xAA",
				"xxxxxxxxxxxx",
				&numMatchesGetMonitorInformation
			);
			if (matchGetMonitorInformation)
			{
				matchGetMonitorInformation += 12;
				matchGetMonitorInformation = (PBYTE)ARM64_FollowBL((DWORD*)matchGetMonitorInformation);
			}
		}
	}
	if (matchGetMonitorInformation)
	{
		// Prepare the function for hooking
	}
	PUBLISH_MATCH_INFO(GetMonitorInformation); // SMA5

	// ### Offset of CExperienceManagerAnimationHelper::Begin()
	INIT_MATCH_INFO_VARS(AnimationBegin);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// * Pattern 1, used when all arguments are available:
		//   ```
		//   44 8B C7                      E8 ?? ?? ?? ?? 85 C0 79 19
		//                                    ^^^^^^^^^^^
		//   ```
		// * Pattern 2, used when a4, a5, and a6 are optimized out (e.g. 26020, 26058):
		//   ```
		//   44 8B C7 48 8D 8B ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 79 19
		//                                    ^^^^^^^^^^^
		//   ```
		// Ref: CJumpViewExperienceManager::OnViewUncloaking()
		usingPatternAnimationBegin = 1;
		matchAnimationBegin = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x44\x8B\xC7\xE8\x00\x00\x00\x00\x85\xC0\x79\x19",
			"xxxx????xxxx",
			&numMatchesAnimationBegin
		);
		if (matchAnimationBegin)
		{
			matchAnimationBegin += 3;
			matchAnimationBegin += 5 + *(int*)(matchAnimationBegin + 1);
		}
		else
		{
			usingPatternAnimationBegin = 2;
			matchAnimationBegin = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x44\x8B\xC7\x48\x8D\x8B\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x85\xC0\x79\x19",
				"xxxxxx????x????xxxx",
				&numMatchesAnimationBegin
			);
			if (matchAnimationBegin)
			{
				matchAnimationBegin += 10;
				matchAnimationBegin += 5 + *(int*)(matchAnimationBegin + 1);
			}
		}
	}
	else
	{
		// * Pattern 1, used when all arguments are available:
		//   ```
		//   04 00 80 D2 03 00 80 D2 60 C2 05 91 ?? ?? ?? ?? E3 03 00 2A
		//                                       ^^^^^^^^^^^
		//   ```
		// Ref: CJumpViewExperienceManager::OnViewUncloaking()
		usingPatternAnimationBegin = 1;
		matchAnimationBegin = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\x04\x00\x80\xD2\x03\x00\x80\xD2\x60\xC2\x05\x91\x00\x00\x00\x00\xE3\x03\x00\x2A",
			"xxxxxxxxxxxx????xxxx",
			&numMatchesAnimationBegin
		);
		if (matchAnimationBegin)
		{
			matchAnimationBegin += 12;
			matchAnimationBegin = (PBYTE)ARM64_FollowBL((DWORD*)matchAnimationBegin);
		}
		else
		{
			// * Pattern 2, used when a4, a5, and a6 are optimized out (e.g. 26020, 26058):
			//   ```
			//   ?? 02 0B 32 ?? ?? ?? 91 ?? ?? ?? 91 ?? ?? ?? ?? E3 03 00 2A
			//                                       ^^^^^^^^^^^
			//   ```
			// Ref: CJumpViewExperienceManager::OnViewUncloaking()
			usingPatternAnimationBegin = 2;
			matchAnimationBegin = (PBYTE)FindPattern_4_(
				pFile + 1,
				dwSize - 1,
				"\x02\x0B\x32\00\x00\x00\x91\x00\x00\x00\x91\x00\x00\x00\x00\xE3\x03\x00\x2A",
				"xxx???x???x????xxxx",
				&numMatchesAnimationBegin
			);
			if (matchAnimationBegin)
			{
				matchAnimationBegin += 11;
				matchAnimationBegin = (PBYTE)ARM64_FollowBL((DWORD*)matchAnimationBegin);
			}
		}
	}
	if (matchAnimationBegin)
	{
		// Assign function global variable
	}
	PUBLISH_MATCH_INFO(AnimationBegin); // SMA6

	// ### Offset of CExperienceManagerAnimationHelper::End()
	INIT_MATCH_INFO_VARS(AnimationEnd);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// ```
		// 40 53 48 83 EC 20 80 39 00 74
		// ```
		matchAnimationEnd = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x40\x53\x48\x83\xEC\x20\x80\x39\x00\x74",
			"xxxxxxxxxx",
			&numMatchesAnimationEnd
		);
	}
	else
	{
		// ```
		// 7F 23 03 D5 F3 0F 1F F8 FD 7B BF A9 FD 03 00 91 08 00 40 39
		// ----------- PACIBSP, don't scan for this because it's everywhere
		// ```
		matchAnimationEnd = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\xF3\x0F\x1F\xF8\xFD\x7B\xBF\xA9\xFD\x03\x00\x91\x08\x00\x40\x39",
			"xxxxxxxxxxxxxxxx",
			&numMatchesAnimationEnd
		);
		if (matchAnimationEnd)
		{
			matchAnimationEnd -= 4;
		}
	}
	if (matchAnimationEnd)
	{
		// Assign function global variable
	}
	PUBLISH_MATCH_INFO(AnimationEnd); // SMA7

	// ### CStartExperienceManager::Hide()
	INIT_MATCH_INFO_VARS(HideA);
	INIT_MATCH_INFO_VARS(HideB);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// * Pattern 1, mov [rbx+2A3h], r12b:
		//   ```
		//   74 ?? ?? 03 00 00 00 44 88
		//   ^^ Turn jz into jmp
		//   ```
		// * Pattern 2, mov byte ptr [rbx+2A3h], 1:
		//   ```
		//   74 ?? ?? 03 00 00 00 C6 83
		//   ^^ Turn jz into jmp
		//   ```
		// Perform on exactly two matches
		/*usingPatternHideA = 1;
		usingPatternHideB = 1;
		matchHideA = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x74\x00\x00\x03\x00\x00\x00\x44\x88",
			"x??xxxxxx",
			nullptr
		);
		if (matchHideA)
		{
			matchHideB = (PBYTE)FindPattern(
				matchHideA + 14,
				dwSize - (matchHideA + 14 - (PBYTE)pFile),
				"\x74\x00\x00\x03\x00\x00\x00\x44\x88",
				"x??xxxxxx",
				&numMatchesHideB
			);
		}

		if (!matchHideA || !matchHideB)
		{
			usingPatternHideA = 2;
			usingPatternHideB = 2;
			matchHideA = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x74\x00\x00\x03\x00\x00\x00\xC6\x83",
				"x??xxxxxx",
				nullptr
			);
			matchHideB = nullptr;
			if (matchHideA)
			{
				matchHideB = (PBYTE)FindPattern(
					matchHideA + 14,
					dwSize - (matchHideA + 14 - (PBYTE)pFile),
					"\x74\x00\x00\x03\x00\x00\x00\xC6\x83",
					"x??xxxxxx",
					&numMatchesHideB
				);
			}
		}*/

		// Find for nop targets:
		// - ?? 03 00 00 00 44 88 ?? ?? ?? 00 00
		//   mov     e??, 3
		//   mov     [r??+???h], r12b
		// OR (26100.916, 26231-26244):
		// - ?? 03 00 00 00 C6 83 ?? ?? 00 00 01
		//                     !! Note 1
		//   mov     e??, 3
		//   mov     byte ptr [rbx+???h], 1
		//   Note 1: Do not turn into a mask or there will be matches in
		//           winrt::Windows::Internal::Shell::implementation::TabProxyWindow::SetWindowLivePreviewAsync$_ResumeCoro$1
		// Nop if followed by a Hide() call
		//   48 8D ?? ?? ?? 00 00 8B ?? E8 ?? ?? ?? ?? 8B ?? 85 C0
		// Perform on exactly two matches
		// Fortunately both are 12 bytes
		auto hide_findForOne = [](PBYTE pBegin, SIZE_T cbSearch, int* outUsingPattern, int* outNumMatches) -> PBYTE
		{
			*outUsingPattern = 1;
			PBYTE pMovMov = (PBYTE)FindPattern(
				pBegin,
				cbSearch,
				"\x03\x00\x00\x00\x44\x88\x00\x00\x00\x00\x00",
				"xxxxxx???xx",
				outNumMatches
			);
			if (!pMovMov)
			{
				*outUsingPattern = 2;
				pMovMov = (PBYTE)FindPattern(
					pBegin,
					cbSearch,
					"\x03\x00\x00\x00\xC6\x83\x00\x00\x00\x00\x01",
					"xxxxxx??xxx",
					outNumMatches
				);
			}
			if (pMovMov)
			{
				pMovMov -= 1; // Point to `mov e??, 3`

				PBYTE pAfterMovMov = pMovMov + 12;

				// We might be a jmp, follow it if so
				PBYTE pJmpTarget = nullptr;
				DWORD cbJmpInstr = 0;
				if (FollowJmp(pAfterMovMov, &pJmpTarget, &cbJmpInstr))
				{
					pAfterMovMov = pJmpTarget;
				}

				// Now test
				bool bThisIsHideCall = FindPattern(
					pAfterMovMov,
					18, // Pattern size
					"\x48\x8D\x00\x00\x00\x00\x00\x8B\x00\xE8\x00\x00\x00\x00\x8B\x00\x85\xC0",
					"xx???xxx?x????x?xx",
					nullptr
				) == pAfterMovMov;
				if (!bThisIsHideCall)
				{
					pMovMov = nullptr; // No, not this one
				}
			}
			return pMovMov;
			// @Note: We don't retry searches because the "No, not this one" blocks are never executed during testing
			// with a variety of twinui.pcshell.dll binaries
		};
		/*auto doForOne = [](PBYTE pMovMov) -> void
		{
			DWORD dwOldProtect;
			if (VirtualProtect(pMovMov, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			{
				memset(pMovMov, 0x90, 12);
				VirtualProtect(pMovMov, 12, dwOldProtect, &dwOldProtect);
			}
		};*/
		matchHideA = hide_findForOne(pFile, dwSize, &usingPatternHideA, nullptr);
		matchHideB = nullptr;
		if (matchHideA)
		{
			matchHideB = hide_findForOne(matchHideA + 12, dwSize - (matchHideA + 12 - (PBYTE)pFile), &usingPatternHideB, &numMatchesHideB);
		}
		numMatchesHideA = matchHideA ? 1 : 0;
		// numMatchesHideB = matchHideB ? 1 : 0; // comment if you add num matches check to the new x64 logic
	}
	else
	{
#if 0
		// E1 03 ?? 2A ?? ?? 04 91 ?? ?? ?? ?? ?? 03 00 2A
		// Check two instructions before, and NOP these:
		// MOV             W??, #3
		// STRB            W??, [X??,#0x???]
		// Perform on exactly two matches
		auto findTheIfBody = [](PBYTE pAnchor) -> PBYTE
		{
			// 27881.1000+ has CBNZ before us, follow it if it is.
			// Otherwise, just check the two instructions before.
			PBYTE pMaybeFollowed = (PBYTE)ARM64_FollowCBNZW((DWORD*)(pAnchor - 4));
			PBYTE pIfBlockBegin = pMaybeFollowed ? pMaybeFollowed : pAnchor - 8;

			DWORD insnMovzw = *(DWORD*)pIfBlockBegin;
			if (!ARM64_IsMOVZW(insnMovzw))
				return nullptr;

			DWORD movzwImm16 = ARM64_ReadBitsSignExtend(insnMovzw, 20, 5);
			if (movzwImm16 != 3)
				return nullptr;

			DWORD insnStrbimm = *(DWORD*)(pIfBlockBegin + 4);
			if (!ARM64_IsSTRBIMM(insnStrbimm))
				return nullptr;

			return pIfBlockBegin;
		};
		PBYTE matchHideAAfter = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\xE1\x03\x00\x2A\x00\x00\x04\x91\x00\x00\x00\x00\x00\x03\x00\x2A",
			"xx?x??xx?????xxx",
			nullptr
		);
		if (matchHideAAfter)
		{
			matchHideA = findTheIfBody(matchHideAAfter);
		}
		if (matchHideA)
		{
			PBYTE matchHideBAfter = (PBYTE)FindPattern_4_(
				matchHideAAfter + 16,
				1024,
				"\xE1\x03\x00\x2A\x00\x00\x04\x91\x00\x00\x00\x00\x00\x03\x00\x2A",
				"xx?x??xx?????xxx",
				&numMatchesHideB
			);
			if (matchHideBAfter)
			{
				matchHideB = findTheIfBody(matchHideBAfter);
			}
		}
		numMatchesHideA = matchHideA ? 1 : 0;
		// numMatchesHideB = matchHideB ? 1 : 0;
#endif
		// Find for nop targets:
		//   MOV             W??, #3
		//     P: 010100101_00_0000000000000011_00000 = 52800060 = 60 00 80 52
		//     M: 111111111_11_1111111111111111_00000 = FFFFFFE0 = E0 FF FF FF
		//   STRB            W??, [X??,#0x???]
		//     22000.2899 0011100100_001010001011_10101_11011
		//     22621.1918 0011100100_001010100011_10011_11011
		//     26100.5551 0011100100_001011010011_10100_11010
		//     29553.1000 0011100100_001011010011_10101_10100
		//     P:         0011100100_001010000011_10000_10000 = 390A0E10 = 10 0E 0A 39
		//     M:         1111111111_111110000111_11000_10000 = FFFE1F10 = 10 1F FE FF
		// Nop if followed by a Hide() call
		//   E1 03 ?? 2A ?? ?? 04 91 ?? ?? ?? ?? ?? 03 00 2A
		// Perform on exactly two matches
		auto hide_findForOne = [](PBYTE pBegin, SIZE_T cbSearch, int* outUsingPattern, int* outNumMatches) -> PBYTE
		{
			PBYTE pMovStrb = (PBYTE)FindPatternBitMask_4_(
				pBegin,
				cbSearch,
				"\x60\x00\x80\x52\x10\x0E\x0A\x39",
				"\xE0\xFF\xFF\xFF\x10\x1F\xFE\xFF",
				8,
				outNumMatches
			);
			if (pMovStrb)
			{
				PBYTE pAfterMovStrb = pMovStrb + 8;

				// We might be a jmp, follow it if so
				PBYTE pJmpTarget = (PBYTE)ARM64_FollowB((DWORD*)pAfterMovStrb);
				if (pJmpTarget)
				{
					pAfterMovStrb = pJmpTarget;
				}

				// Now test
				bool bThisIsHideCall = FindPattern_4_(
					pAfterMovStrb,
					16, // Pattern size
					"\xE1\x03\x00\x2A\x00\x00\x04\x91\x00\x00\x00\x00\x00\x03\x00\x2A",
					"xx?x??xx?????xxx",
					nullptr
				) == pAfterMovStrb;
				if (!bThisIsHideCall)
				{
					pMovStrb = nullptr; // No, not this one
				}
			}
			return pMovStrb;
			// @Note: We don't retry searches because the "No, not this one" blocks are never executed during testing
			// with a variety of twinui.pcshell.dll binaries
		};
		matchHideA = hide_findForOne(pFile, dwSize, &usingPatternHideA, nullptr);
		matchHideB = nullptr;
		if (matchHideA)
		{
			matchHideB = hide_findForOne(matchHideA + 8, dwSize - (matchHideA + 8 - (PBYTE)pFile), &usingPatternHideB, &numMatchesHideB);
		}
		numMatchesHideA = matchHideA ? 1 : 0;
		// numMatchesHideB = matchHideB ? 1 : 0;
	}
	PUBLISH_MATCH_INFO(HideA); // SMA8
	PUBLISH_MATCH_INFO(HideB); // SMA9
}

void CPatternCheckerSuiteModule_TwinUIPCShell::CheckPatterns_JVP(
	PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches)
{
	// == JUMP VIEW POSITIONING PATCHES ==

	// Offset sanity checks

	// EDGEUI_TRAYSTUCKPLACE CJumpViewExperienceManager::m_trayStuckPlace
	INIT_MATCH_INFO_VARS(OffsetTrayStuckPlace);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 8B 8B ?? ?? 00 00 BF 5C 00 00 00 85 C9
		//       ^^^^^^^^^^^
		// Ref: CJumpViewExperienceManager::OnViewUncloaking()
		matchOffsetTrayStuckPlace = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x8B\x8B\x00\x00\x00\x00\xBF\x5C\x00\x00\x00\x85\xC9",
			"xx??xxxxxxxxx",
			&numMatchesOffsetTrayStuckPlace
		);
	}
	else
	{
		// ?? ?? 41 B9 89 0B 80 52 A8 01 00 34 1F 05 00 71 20 01 00 54 1F 09 00 71 A0 00 00 54 1F 0D 00 71 01 01 00 54 69 0B 80 52
		// ^^^^^^^^^^^       Important instr. to distinguish from MeetNowExperienceManager::OnViewUncloaking() in GE > !!!!!!!!!!!
		// Ref: CJumpViewExperienceManager::OnViewCloaking()
		usingPatternOffsetTrayStuckPlace = 1;
		matchOffsetTrayStuckPlace = (PBYTE)FindPattern_4_(
			pFile + 2,
			dwSize - 2,
			"\x41\xB9\x89\x0B\x80\x52\xA8\x01\x00\x34\x1F\x05\x00\x71\x20\x01\x00\x54\x1F\x09\x00\x71\xA0\x00\x00\x54\x1F\x0D\x00\x71\x01\x01\x00\x54\x69\x0B\x80\x52",
			"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			&numMatchesOffsetTrayStuckPlace
		);
		if (!matchOffsetTrayStuckPlace)
		{
			// 29553+
			// ?? ?? 41 B9 C8 01 00 34 1F 05 00 71 40 01 00 54 1F 09 00 71 C0 00 00 54 89 0B 80 52
			// ^^^^^^^^^^^
			// Ref: CJumpViewExperienceManager::OnViewCloaking()
			usingPatternOffsetTrayStuckPlace = 2;
			matchOffsetTrayStuckPlace = (PBYTE)FindPattern_4_(
				pFile + 2,
				dwSize - 2,
				"\x41\xB9\xC8\x01\x00\x34\x1F\x05\x00\x71\x40\x01\x00\x54\x1F\x09\x00\x71\xC0\x00\x00\x54\x89\x0B\x80\x52",
				"xxxxxxxxxxxxxxxxxxxxxxxxxx",
				&numMatchesOffsetTrayStuckPlace
			);
		}
	}
	PUBLISH_MATCH_INFO(OffsetTrayStuckPlace);

	// ----------------------------------------

	// RECT CJumpViewExperienceManager::m_rcWorkArea
	INIT_MATCH_INFO_VARS(OffsetRcWorkArea);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// 48 8B 53 70 48 8D 83 ?? ?? ?? ??
		//          --          ^^^^^^^^^^^
		// Ref: CJumpViewExperienceManager::OnViewUncloaking()
		// Note: The ref function belongs to SingleViewShellExperienceEventHandler so `this` is +0x40.
		//       As long as the above sanity check passes, hardcoding it should be fine.
		if (matchOffsetTrayStuckPlace)
		{
			matchOffsetRcWorkArea = (PBYTE)FindPattern(
				matchOffsetTrayStuckPlace + 13,
				256,
				"\x48\x8B\x53\x70\x48\x8D\x83",
				"xxxxxxx",
				&numMatchesOffsetRcWorkArea
			);
		}
	}
	else
	{
		if (matchOffsetTrayStuckPlace)
		{
			// Without Feature_TaskbarJumplistOnHover (48980211)
			// 01 38 40 F9 07 00 07 91
			// ----------- ^^^^^^^^^^^
			//   ADD             X7, X??, #0x???
			//     P: 10010001_00_000000000000_00000_00111 = 91000007 = 07 00 00 91
			//     M: 11111111_11_000000000000_00000_11111 = FFC0001F = 1F 00 C0 FF
			// Ref: CJumpViewExperienceManager::OnViewCloaking()
			usingPatternOffsetRcWorkArea = 1;
			matchOffsetRcWorkArea = (PBYTE)FindPatternBitMask_4_(
				matchOffsetTrayStuckPlace + 38,
				128,
				"\x01\x38\x40\xF9\x07\x00\x00\x91",
				"\xFF\xFF\xFF\xFF\x1F\x00\xC0\xFF",
				8,
				&numMatchesOffsetRcWorkArea
			);
			if (!matchOffsetRcWorkArea)
			{
				// With Feature_TaskbarJumplistOnHover (48980211)
				// 22 01 03 32 67 32 07 91
				//             ^^^^^^^^^^^
				//   ADD             X7, X??, #0x???
				//     P: 10010001_00_000000000000_00000_00111 = 91000007 = 07 00 00 91
				//     M: 11111111_11_000000000000_00000_11111 = FFC0001F = 1F 00 C0 FF
				// Ref: CJumpViewExperienceManager::OnViewCloaking()
				usingPatternOffsetRcWorkArea = 2;
				matchOffsetRcWorkArea = (PBYTE)FindPatternBitMask_4_(
					matchOffsetTrayStuckPlace + 38,
					128,
					"\x22\x01\x03\x32\x07\x00\x00\x91",
					"\xFF\xFF\xFF\xFF\x1F\x00\xC0\xFF",
					8,
					&numMatchesOffsetRcWorkArea
				);
			}
		}
	}
	PUBLISH_MATCH_INFO(OffsetRcWorkArea);

	// ----------------------------------------

	// CJumpViewExperienceManager::EnsureWindowPosition()
	INIT_MATCH_INFO_VARS(EnsureWindowPosition);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// Base Nickel and Germanium
		// 8D 4E C0 48 8B ?? E8 ?? ?? ?? ?? 8B
		//                      ^^^^^^^^^^^
		// Ref: CJumpViewExperienceManager::OnViewPropertiesChanging()
		usingPatternEnsureWindowPosition = 1;
		matchEnsureWindowPosition = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x8D\x4E\xC0\x48\x8B\x00\xE8\x00\x00\x00\x00\x8B",
			"xxxxx?x????x",
			&numMatchesEnsureWindowPosition
		);
		if (matchEnsureWindowPosition)
		{
			matchEnsureWindowPosition += 6;
			matchEnsureWindowPosition += 5 + *(int*)(matchEnsureWindowPosition + 1);
		}
		if (!matchEnsureWindowPosition)
		{
			// Nickel with Feature_TaskbarJumplistOnHover (48980211)
			// - 22621.3930, 3936, 4000, 4010, 4076, 4082, 4110, 4145, ...
			// 4C 8D 76 C0 48 8B D3 49 8B CE E8 ?? ?? ?? ?? 8B
			//                                  ^^^^^^^^^^^
			// Ref: CJumpViewExperienceManager::OnViewPropertiesChanging()
			usingPatternEnsureWindowPosition = 2;
			matchEnsureWindowPosition = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x4C\x8D\x76\xC0\x48\x8B\xD3\x49\x8B\xCE\xE8\x00\x00\x00\x00\x8B",
				"xxxxxxxxxxx????x",
				&numMatchesEnsureWindowPosition
			);
			if (matchEnsureWindowPosition)
			{
				matchEnsureWindowPosition += 10;
				matchEnsureWindowPosition += 5 + *(int*)(matchEnsureWindowPosition + 1);
			}
		}
		if (!matchEnsureWindowPosition)
		{
			// Germanium with Feature_TaskbarJumplistOnHover (48980211)
			// - 26100.1350, 1591, ...
			// 48 8B D7 49 8D 4E C0 E8 ?? ?? ?? ?? 8B
			//                         ^^^^^^^^^^^
			// Ref: CJumpViewExperienceManager::OnViewPropertiesChanging()
			usingPatternEnsureWindowPosition = 3;
			matchEnsureWindowPosition = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x48\x8B\xD7\x49\x8D\x4E\xC0\xE8\x00\x00\x00\x00\x8B",
				"xxxxxxxx????x",
				&numMatchesEnsureWindowPosition
			);
			if (matchEnsureWindowPosition)
			{
				matchEnsureWindowPosition += 7;
				matchEnsureWindowPosition += 5 + *(int*)(matchEnsureWindowPosition + 1);
			}
		}
	}
	else
	{
		// E1 03 ?? AA ?? 02 01 D1 ?? ?? ?? ?? ?? 03 00 2A
		//                         ^^^^^^^^^^^
		// Ref: CJumpViewExperienceManager::OnViewPropertiesChanging()
		matchEnsureWindowPosition = (PBYTE)FindPattern_4_(
			pFile,
			dwSize,
			"\xE1\x03\x00\xAA\x00\x02\x01\xD1\x00\x00\x00\x00\x00\x03\x00\x2A",
			"xx?x?xxx?????xxx",
			&numMatchesEnsureWindowPosition
		);
		if (matchEnsureWindowPosition)
		{
			matchEnsureWindowPosition += 8;
			matchEnsureWindowPosition = (PBYTE)ARM64_FollowBL((DWORD*)matchEnsureWindowPosition);
		}
	}
	PUBLISH_MATCH_INFO(EnsureWindowPosition);

	// == CPINNEDLIST HACK ==

	// CTaskbandPin_CreateInstance
	/*INIT_MATCH_INFO_VARS(CTaskbandPinCreateInstance);
	if (machineType == IMAGE_FILE_MACHINE_AMD64)
	{
		// Method 1: Direct function preamble (dangerous; breaks if they modify the fields of CTaskbandPin or its superclass(es))
		// 40 53 48 83 EC 20 48 8B D9 48 8D 15 ?? ?? ?? ?? B9 80 00 00 00 E8 ?? ?? ?? ?? 48 85 C0
		/*matchCTaskbandPinCreateInstance = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x8D\x15\x00\x00\x00\x00\xB9\x80\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x85\xC0",
			"xxxxxxxxxxxx????xxxxxx????xxx",
			&numMatchesCTaskbandPinCreateInstance
		);#1#

		// Method 2: winrt::Windows::Internal::Shell::implementation::PinManager::IsItemPinned
		// 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 83 64 24 ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 85 C0
		//                                                                   ^^^^^^^^^^^
		usingPatternCTaskbandPinCreateInstance = 1;
		matchCTaskbandPinCreateInstance = (PBYTE)FindPattern(
			pFile,
			dwSize,
			"\x48\x8D\x4C\x24\x00\xE8\x00\x00\x00\x00\x48\x83\x64\x24\x00\x00\x48\x8D\x4C\x24\x00\xE8\x00\x00\x00\x00\x48\x8B\x8D\x00\x00\x00\x00\x85\xC0",
			"xxxx?x????xxxx??xxxx?x????xxx????xx",
			&numMatchesCTaskbandPinCreateInstance
		);
		if (matchCTaskbandPinCreateInstance)
		{
			matchCTaskbandPinCreateInstance += 21;
			matchCTaskbandPinCreateInstance += 5 + *(int*)(matchCTaskbandPinCreateInstance + 1);
		}

		if (!matchCTaskbandPinCreateInstance)
		{
			// wil::out_param() is inlined
			// 0F 1F 44 00 00 48 83 64 24 ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 85 C0
			//                                                    ^^^^^^^^^^^
			usingPatternCTaskbandPinCreateInstance = 2;
			matchCTaskbandPinCreateInstance = (PBYTE)FindPattern(
				pFile,
				dwSize,
				"\x0F\x1F\x44\x00\x00\x48\x83\x64\x24\x00\x00\x48\x8D\x4C\x24\x00\xE8\x00\x00\x00\x00\x48\x8B\x8D\x00\x00\x00\x00\x85\xC0",
				"xxxxxxxxx??xxxx?x????xxx????xx",
				&numMatchesCTaskbandPinCreateInstance
			);
			if (matchCTaskbandPinCreateInstance)
			{
				matchCTaskbandPinCreateInstance += 16;
				matchCTaskbandPinCreateInstance += 5 + *(int*)(matchCTaskbandPinCreateInstance + 1);
			}
		}
	}
	else
	{
		// No ARM64 :hehehaha:
	}
	PUBLISH_MATCH_INFO(CTaskbandPinCreateInstance);*/

	// END CPINNEDLIST HACK
}

bool CPatternCheckerSuiteModule_TwinUIPCShell::ShouldIncludeFile(const FileInfo& fileInfo) const
{
	if (!CPatternCheckerSuiteModule_Base::ShouldIncludeFile(fileInfo))
		return false;

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	return true; // Temporary
	// return build == 26100 && ubr == 961;
	// return build == 29553 && ubr == 1000;
}

void CPatternCheckerSuiteModule_TwinUIPCShell::PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches)
{
	CPatternCheckerSuiteModule_Base::PostProcess(fileInfo, matches);

	DWORD ls = (fileInfo.fileVersion >> 0) & 0xFFFFFFFF;
	DWORD ms = (fileInfo.fileVersion >> 32) & 0xFFFFFFFF;
	WORD build = HIWORD(ls);
	WORD ubr = LOWORD(ls);

	// anything before 22000.65, mark as don't care (numMatches = -1)
	if (build < 22000 || (build == 22000 && ubr < 65))
	{
		for (PatternMatchInfo& match : *matches)
		{
			match.numMatches = -1;
		}
	}

	// [arm64] anything before 22621, mark indices 4 5 6 7 17 18 19 as don't care
	// (var4 5 6 7, jvp1 2 3)
	if (fileInfo.machineType == IMAGE_FILE_MACHINE_ARM64 && build < 22621)
	{
		(*matches)[4].numMatches = -1;
		(*matches)[5].numMatches = -1;
		(*matches)[6].numMatches = -1;
		(*matches)[7].numMatches = -1;
		(*matches)[17].numMatches = -1;
		(*matches)[18].numMatches = -1;
		(*matches)[19].numMatches = -1;
	}

	// [arm64] anything 26100 or newer, if index 13 has 3 matches then green it (numMatches = 1)
	if (fileInfo.machineType == IMAGE_FILE_MACHINE_ARM64 && build >= 26100 && (*matches)[13].numMatches == 3)
	{
		(*matches)[13].numMatches = 1;
	}
}
