#pragma once

#include "PatternCheckerSuiteModule_Base.h"

class CPatternCheckerSuiteModule_UxTheme final : public CPatternCheckerSuiteModule_Base
{
    static const ElementDef ElementDefs[];

public:
    CPatternCheckerSuiteModule_UxTheme();

    void CheckPatterns(PBYTE pFileRaw, DWORD dwSizeRaw, PBYTE pFile, DWORD dwSize, WORD machineType, std::vector<PatternMatchInfo>* matches) override;
    void PostProcess(const FileInfo& fileInfo, std::vector<PatternMatchInfo>* matches) override;
};
