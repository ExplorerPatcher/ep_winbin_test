#pragma once

#include "PatternCheckerSuiteModule_Base.h"

class CPatternCheckerSuiteModule_WindowsUIXaml final : public CPatternCheckerSuiteModule_Base
{
	static const ElementDef ElementDefs[];

public:
	CPatternCheckerSuiteModule_WindowsUIXaml();

	void CheckPatterns(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches) override;
	bool ShouldIncludeFile(const FileInfo& fileInfo) const override;
	void PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches) override;
};
