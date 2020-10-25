# Generated by CMake

if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" LESS 2.5)
   message(FATAL_ERROR "CMake >= 2.6.0 required")
endif()
cmake_policy(PUSH)
cmake_policy(VERSION 2.6)
#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Protect against multiple inclusion, which would fail when already imported targets are added once more.
set(_targetsDefined)
set(_targetsNotDefined)
set(_expectedTargets)
foreach(_expectedTarget clangBasic clangLex clangParse clangAST clangDynamicASTMatchers clangASTMatchers clangCrossTU clangSema clangCodeGen clangAnalysis clangEdit clangRewrite clangARCMigrate clangDriver clangSerialization clangRewriteFrontend clangFrontend clangFrontendTool clangToolingCore clangToolingInclusions clangToolingRefactoring clangToolingASTDiff clangToolingSyntax clangDependencyScanning clangTransformer clangTooling clangDirectoryWatcher clangIndex clangStaticAnalyzerCore clangStaticAnalyzerCheckers clangStaticAnalyzerFrontend clangFormat clang clang-format clangHandleCXX clangHandleLLVM clang-import-test clang-offload-bundler clang-offload-wrapper clang-scan-deps clang-rename clang-refactor clang-cpp clang-check clang-extdef-mapping clangApplyReplacements clang-apply-replacements clangReorderFields clang-reorder-fields modularize clangTidy clangTidyAndroidModule clangTidyAbseilModule clangTidyBoostModule clangTidyBugproneModule clangTidyCERTModule clangTidyCppCoreGuidelinesModule clangTidyDarwinModule clangTidyFuchsiaModule clangTidyGoogleModule clangTidyHICPPModule clangTidyLinuxKernelModule clangTidyLLVMModule clangTidyMiscModule clangTidyModernizeModule clangTidyMPIModule clangTidyObjCModule clangTidyOpenMPModule clangTidyPerformanceModule clangTidyPortabilityModule clangTidyReadabilityModule clangTidyZirconModule clangTidyPlugin clang-tidy clangTidyUtils clangChangeNamespace clang-change-namespace clangDoc clang-doc clangIncludeFixer clangIncludeFixerPlugin clang-include-fixer findAllSymbols find-all-symbols clangMove clang-move clangQuery clang-query pp-trace clangDaemon clangDaemonTweaks clangd libclang)
  list(APPEND _expectedTargets ${_expectedTarget})
  if(NOT TARGET ${_expectedTarget})
    list(APPEND _targetsNotDefined ${_expectedTarget})
  endif()
  if(TARGET ${_expectedTarget})
    list(APPEND _targetsDefined ${_expectedTarget})
  endif()
endforeach()
if("${_targetsDefined}" STREQUAL "${_expectedTargets}")
  unset(_targetsDefined)
  unset(_targetsNotDefined)
  unset(_expectedTargets)
  set(CMAKE_IMPORT_FILE_VERSION)
  cmake_policy(POP)
  return()
endif()
if(NOT "${_targetsDefined}" STREQUAL "")
  message(FATAL_ERROR "Some (but not all) targets in this export set were already defined.\nTargets Defined: ${_targetsDefined}\nTargets not yet defined: ${_targetsNotDefined}\n")
endif()
unset(_targetsDefined)
unset(_targetsNotDefined)
unset(_expectedTargets)


# Compute the installation prefix relative to this file.
get_filename_component(_IMPORT_PREFIX "${CMAKE_CURRENT_LIST_FILE}" PATH)
get_filename_component(_IMPORT_PREFIX "${_IMPORT_PREFIX}" PATH)
get_filename_component(_IMPORT_PREFIX "${_IMPORT_PREFIX}" PATH)
get_filename_component(_IMPORT_PREFIX "${_IMPORT_PREFIX}" PATH)
if(_IMPORT_PREFIX STREQUAL "/")
  set(_IMPORT_PREFIX "")
endif()

# Create imported target clangBasic
add_library(clangBasic STATIC IMPORTED)

set_target_properties(clangBasic PROPERTIES
  INTERFACE_LINK_LIBRARIES "LLVMCore;LLVMMC;LLVMSupport"
)

# Create imported target clangLex
add_library(clangLex STATIC IMPORTED)

set_target_properties(clangLex PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;LLVMSupport"
)

# Create imported target clangParse
add_library(clangParse STATIC IMPORTED)

set_target_properties(clangParse PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangLex;clangSema;LLVMFrontendOpenMP;LLVMMC;LLVMMCParser;LLVMSupport"
)

# Create imported target clangAST
add_library(clangAST STATIC IMPORTED)

set_target_properties(clangAST PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;clangLex;LLVMBinaryFormat;LLVMCore;LLVMFrontendOpenMP;LLVMSupport"
)

# Create imported target clangDynamicASTMatchers
add_library(clangDynamicASTMatchers STATIC IMPORTED)

set_target_properties(clangDynamicASTMatchers PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;LLVMSupport"
)

# Create imported target clangASTMatchers
add_library(clangASTMatchers STATIC IMPORTED)

set_target_properties(clangASTMatchers PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;LLVMSupport"
)

# Create imported target clangCrossTU
add_library(clangCrossTU STATIC IMPORTED)

set_target_properties(clangCrossTU PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangFrontend;clangIndex;LLVMSupport"
)

# Create imported target clangSema
add_library(clangSema STATIC IMPORTED)

set_target_properties(clangSema PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangAnalysis;clangBasic;clangEdit;clangLex;LLVMFrontendOpenMP;LLVMSupport"
)

# Create imported target clangCodeGen
add_library(clangCodeGen STATIC IMPORTED)

set_target_properties(clangCodeGen PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangFrontend;clangLex;clangSerialization;LLVMAnalysis;LLVMBitReader;LLVMBitWriter;LLVMCore;LLVMCoroutines;LLVMCoverage;LLVMFrontendOpenMP;LLVMipo;LLVMIRReader;LLVMAggressiveInstCombine;LLVMInstCombine;LLVMInstrumentation;LLVMLTO;LLVMLinker;LLVMMC;LLVMObjCARCOpts;LLVMObject;LLVMPasses;LLVMProfileData;LLVMRemarks;LLVMScalarOpts;LLVMSupport;LLVMTarget;LLVMTransformUtils;Polly"
)

# Create imported target clangAnalysis
add_library(clangAnalysis STATIC IMPORTED)

set_target_properties(clangAnalysis PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;LLVMSupport"
)

# Create imported target clangEdit
add_library(clangEdit STATIC IMPORTED)

set_target_properties(clangEdit PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangLex;LLVMSupport"
)

# Create imported target clangRewrite
add_library(clangRewrite STATIC IMPORTED)

set_target_properties(clangRewrite PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;clangLex;LLVMSupport"
)

# Create imported target clangARCMigrate
add_library(clangARCMigrate STATIC IMPORTED)

set_target_properties(clangARCMigrate PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangAnalysis;clangBasic;clangEdit;clangFrontend;clangLex;clangRewrite;clangSema;clangSerialization;LLVMSupport"
)

# Create imported target clangDriver
add_library(clangDriver STATIC IMPORTED)

set_target_properties(clangDriver PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;LLVMBinaryFormat;LLVMOption;LLVMProfileData;LLVMSupport"
)

# Create imported target clangSerialization
add_library(clangSerialization STATIC IMPORTED)

set_target_properties(clangSerialization PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangLex;clangSema;LLVMBitReader;LLVMBitstreamReader;LLVMSupport"
)

# Create imported target clangRewriteFrontend
add_library(clangRewriteFrontend STATIC IMPORTED)

set_target_properties(clangRewriteFrontend PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangEdit;clangFrontend;clangLex;clangRewrite;clangSerialization;LLVMSupport"
)

# Create imported target clangFrontend
add_library(clangFrontend STATIC IMPORTED)

set_target_properties(clangFrontend PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangDriver;clangEdit;clangLex;clangParse;clangSema;clangSerialization;LLVMBitReader;LLVMBitstreamReader;LLVMOption;LLVMProfileData;LLVMSupport"
)

# Create imported target clangFrontendTool
add_library(clangFrontendTool STATIC IMPORTED)

set_target_properties(clangFrontendTool PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;clangCodeGen;clangDriver;clangFrontend;clangRewriteFrontend;clangARCMigrate;clangStaticAnalyzerFrontend;LLVMOption;LLVMSupport"
)

# Create imported target clangToolingCore
add_library(clangToolingCore STATIC IMPORTED)

set_target_properties(clangToolingCore PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangLex;clangRewrite;LLVMSupport"
)

# Create imported target clangToolingInclusions
add_library(clangToolingInclusions STATIC IMPORTED)

set_target_properties(clangToolingInclusions PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;clangLex;clangRewrite;clangToolingCore;LLVMSupport"
)

# Create imported target clangToolingRefactoring
add_library(clangToolingRefactoring STATIC IMPORTED)

set_target_properties(clangToolingRefactoring PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangFormat;clangIndex;clangLex;clangRewrite;clangToolingCore;LLVMSupport"
)

# Create imported target clangToolingASTDiff
add_library(clangToolingASTDiff STATIC IMPORTED)

set_target_properties(clangToolingASTDiff PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;clangAST;clangLex;LLVMSupport"
)

# Create imported target clangToolingSyntax
add_library(clangToolingSyntax STATIC IMPORTED)

set_target_properties(clangToolingSyntax PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangFrontend;clangLex;clangToolingCore;LLVMSupport"
)

# Create imported target clangDependencyScanning
add_library(clangDependencyScanning STATIC IMPORTED)

set_target_properties(clangDependencyScanning PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangDriver;clangFrontend;clangFrontendTool;clangLex;clangParse;clangSerialization;clangTooling;LLVMCore;LLVMSupport"
)

# Create imported target clangTransformer
add_library(clangTransformer STATIC IMPORTED)

set_target_properties(clangTransformer PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangToolingCore;clangToolingRefactoring;LLVMSupport"
)

# Create imported target clangTooling
add_library(clangTooling STATIC IMPORTED)

set_target_properties(clangTooling PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangDriver;clangFormat;clangFrontend;clangLex;clangRewrite;clangSerialization;clangToolingCore;LLVMOption;LLVMSupport"
)

# Create imported target clangDirectoryWatcher
add_library(clangDirectoryWatcher STATIC IMPORTED)

set_target_properties(clangDirectoryWatcher PROPERTIES
  INTERFACE_LINK_LIBRARIES "LLVMSupport;-lpthread"
)

# Create imported target clangIndex
add_library(clangIndex STATIC IMPORTED)

set_target_properties(clangIndex PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangFormat;clangFrontend;clangLex;clangRewrite;clangSerialization;clangToolingCore;LLVMCore;LLVMSupport"
)

# Create imported target clangStaticAnalyzerCore
add_library(clangStaticAnalyzerCore STATIC IMPORTED)

set_target_properties(clangStaticAnalyzerCore PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangAnalysis;clangBasic;clangCrossTU;clangFrontend;clangLex;clangRewrite;LLVMSupport"
)

# Create imported target clangStaticAnalyzerCheckers
add_library(clangStaticAnalyzerCheckers STATIC IMPORTED)

set_target_properties(clangStaticAnalyzerCheckers PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangAnalysis;clangBasic;clangLex;clangStaticAnalyzerCore;LLVMSupport"
)

# Create imported target clangStaticAnalyzerFrontend
add_library(clangStaticAnalyzerFrontend STATIC IMPORTED)

set_target_properties(clangStaticAnalyzerFrontend PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangAnalysis;clangBasic;clangCrossTU;clangFrontend;clangLex;clangStaticAnalyzerCheckers;clangStaticAnalyzerCore;LLVMSupport"
)

# Create imported target clangFormat
add_library(clangFormat STATIC IMPORTED)

set_target_properties(clangFormat PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;clangLex;clangToolingCore;clangToolingInclusions;LLVMSupport"
)

# Create imported target clang
add_executable(clang IMPORTED)
set_property(TARGET clang PROPERTY ENABLE_EXPORTS 1)

# Create imported target clang-format
add_executable(clang-format IMPORTED)

# Create imported target clangHandleCXX
add_library(clangHandleCXX STATIC IMPORTED)

set_target_properties(clangHandleCXX PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangBasic;clangCodeGen;clangFrontend;clangLex;clangSerialization;clangTooling;LLVMAArch64CodeGen;LLVMAArch64AsmParser;LLVMAArch64Desc;LLVMAArch64Disassembler;LLVMAArch64Info;LLVMAArch64Utils;LLVMAMDGPUCodeGen;LLVMAMDGPUAsmParser;LLVMAMDGPUDesc;LLVMAMDGPUDisassembler;LLVMAMDGPUInfo;LLVMAMDGPUUtils;LLVMARMCodeGen;LLVMARMAsmParser;LLVMARMDesc;LLVMARMDisassembler;LLVMARMInfo;LLVMARMUtils;LLVMBPFCodeGen;LLVMBPFAsmParser;LLVMBPFDesc;LLVMBPFDisassembler;LLVMBPFInfo;LLVMHexagonCodeGen;LLVMHexagonAsmParser;LLVMHexagonDesc;LLVMHexagonDisassembler;LLVMHexagonInfo;LLVMLanaiCodeGen;LLVMLanaiAsmParser;LLVMLanaiDesc;LLVMLanaiDisassembler;LLVMLanaiInfo;LLVMMipsCodeGen;LLVMMipsAsmParser;LLVMMipsDesc;LLVMMipsDisassembler;LLVMMipsInfo;LLVMMSP430CodeGen;LLVMMSP430AsmParser;LLVMMSP430Desc;LLVMMSP430Disassembler;LLVMMSP430Info;LLVMNVPTXCodeGen;LLVMNVPTXDesc;LLVMNVPTXInfo;LLVMPowerPCCodeGen;LLVMPowerPCAsmParser;LLVMPowerPCDesc;LLVMPowerPCDisassembler;LLVMPowerPCInfo;LLVMRISCVCodeGen;LLVMRISCVAsmParser;LLVMRISCVDesc;LLVMRISCVDisassembler;LLVMRISCVInfo;LLVMRISCVUtils;LLVMSparcCodeGen;LLVMSparcAsmParser;LLVMSparcDesc;LLVMSparcDisassembler;LLVMSparcInfo;LLVMSystemZCodeGen;LLVMSystemZAsmParser;LLVMSystemZDesc;LLVMSystemZDisassembler;LLVMSystemZInfo;LLVMWebAssemblyCodeGen;LLVMWebAssemblyAsmParser;LLVMWebAssemblyDesc;LLVMWebAssemblyDisassembler;LLVMWebAssemblyInfo;LLVMX86CodeGen;LLVMX86AsmParser;LLVMX86Desc;LLVMX86Disassembler;LLVMX86Info;LLVMX86Utils;LLVMXCoreCodeGen;LLVMXCoreDesc;LLVMXCoreDisassembler;LLVMXCoreInfo;LLVMSupport"
)

# Create imported target clangHandleLLVM
add_library(clangHandleLLVM STATIC IMPORTED)

set_target_properties(clangHandleLLVM PROPERTIES
  INTERFACE_LINK_LIBRARIES "LLVMAnalysis;LLVMCodeGen;LLVMCore;LLVMExecutionEngine;LLVMipo;LLVMIRReader;LLVMMC;LLVMMCJIT;LLVMObject;LLVMRuntimeDyld;LLVMSelectionDAG;LLVMSupport;LLVMTarget;LLVMTransformUtils;LLVMX86CodeGen;LLVMX86AsmParser;LLVMX86Desc;LLVMX86Disassembler;LLVMX86Info;LLVMX86Utils"
)

# Create imported target clang-import-test
add_executable(clang-import-test IMPORTED)

# Create imported target clang-offload-bundler
add_executable(clang-offload-bundler IMPORTED)

# Create imported target clang-offload-wrapper
add_executable(clang-offload-wrapper IMPORTED)

# Create imported target clang-scan-deps
add_executable(clang-scan-deps IMPORTED)

# Create imported target clang-rename
add_executable(clang-rename IMPORTED)

# Create imported target clang-refactor
add_executable(clang-refactor IMPORTED)

# Create imported target clang-cpp
add_library(clang-cpp SHARED IMPORTED)

# Create imported target clang-check
add_executable(clang-check IMPORTED)

# Create imported target clang-extdef-mapping
add_executable(clang-extdef-mapping IMPORTED)

# Create imported target clangApplyReplacements
add_library(clangApplyReplacements STATIC IMPORTED)

set_target_properties(clangApplyReplacements PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangRewrite;clangToolingCore;clangToolingRefactoring;LLVMSupport"
)

# Create imported target clang-apply-replacements
add_executable(clang-apply-replacements IMPORTED)

# Create imported target clangReorderFields
add_library(clangReorderFields STATIC IMPORTED)

set_target_properties(clangReorderFields PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangIndex;clangLex;clangSerialization;clangToolingCore;LLVMSupport"
)

# Create imported target clang-reorder-fields
add_executable(clang-reorder-fields IMPORTED)

# Create imported target modularize
add_executable(modularize IMPORTED)

# Create imported target clangTidy
add_library(clangTidy STATIC IMPORTED)

set_target_properties(clangTidy PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangFormat;clangFrontend;clangLex;clangRewrite;clangSema;clangSerialization;clangTooling;clangToolingCore;LLVMSupport;\$<LINK_ONLY:clangStaticAnalyzerCore>;\$<LINK_ONLY:clangStaticAnalyzerFrontend>"
)

# Create imported target clangTidyAndroidModule
add_library(clangTidyAndroidModule STATIC IMPORTED)

set_target_properties(clangTidyAndroidModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyAbseilModule
add_library(clangTidyAbseilModule STATIC IMPORTED)

set_target_properties(clangTidyAbseilModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyBoostModule
add_library(clangTidyBoostModule STATIC IMPORTED)

set_target_properties(clangTidyBoostModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyBugproneModule
add_library(clangTidyBugproneModule STATIC IMPORTED)

set_target_properties(clangTidyBugproneModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyCppCoreGuidelinesModule;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyCERTModule
add_library(clangTidyCERTModule STATIC IMPORTED)

set_target_properties(clangTidyCERTModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyBugproneModule;clangTidyGoogleModule;clangTidyMiscModule;clangTidyPerformanceModule;clangTidyReadabilityModule;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyCppCoreGuidelinesModule
add_library(clangTidyCppCoreGuidelinesModule STATIC IMPORTED)

set_target_properties(clangTidyCppCoreGuidelinesModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangSerialization;clangTidy;clangTidyMiscModule;clangTidyModernizeModule;clangTidyReadabilityModule;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyDarwinModule
add_library(clangTidyDarwinModule STATIC IMPORTED)

set_target_properties(clangTidyDarwinModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyFuchsiaModule
add_library(clangTidyFuchsiaModule STATIC IMPORTED)

set_target_properties(clangTidyFuchsiaModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyGoogleModule;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyGoogleModule
add_library(clangTidyGoogleModule STATIC IMPORTED)

set_target_properties(clangTidyGoogleModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyReadabilityModule;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyHICPPModule
add_library(clangTidyHICPPModule STATIC IMPORTED)

set_target_properties(clangTidyHICPPModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangSerialization;clangTidy;clangTidyBugproneModule;clangTidyCppCoreGuidelinesModule;clangTidyGoogleModule;clangTidyMiscModule;clangTidyModernizeModule;clangTidyPerformanceModule;clangTidyReadabilityModule;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyLinuxKernelModule
add_library(clangTidyLinuxKernelModule STATIC IMPORTED)

set_target_properties(clangTidyLinuxKernelModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyLLVMModule
add_library(clangTidyLLVMModule STATIC IMPORTED)

set_target_properties(clangTidyLLVMModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyReadabilityModule;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyMiscModule
add_library(clangTidyMiscModule STATIC IMPORTED)

set_target_properties(clangTidyMiscModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangLex;clangSerialization;clangTidy;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyModernizeModule
add_library(clangTidyModernizeModule STATIC IMPORTED)

set_target_properties(clangTidyModernizeModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyReadabilityModule;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyMPIModule
add_library(clangTidyMPIModule STATIC IMPORTED)

set_target_properties(clangTidyMPIModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;clangTooling;clangStaticAnalyzerCheckers;LLVMSupport"
)

# Create imported target clangTidyObjCModule
add_library(clangTidyObjCModule STATIC IMPORTED)

set_target_properties(clangTidyObjCModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyOpenMPModule
add_library(clangTidyOpenMPModule STATIC IMPORTED)

set_target_properties(clangTidyOpenMPModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangTidy;clangTidyUtils;LLVMFrontendOpenMP;LLVMSupport"
)

# Create imported target clangTidyPerformanceModule
add_library(clangTidyPerformanceModule STATIC IMPORTED)

set_target_properties(clangTidyPerformanceModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangAnalysis;clangBasic;clangLex;clangTidy;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyPortabilityModule
add_library(clangTidyPortabilityModule STATIC IMPORTED)

set_target_properties(clangTidyPortabilityModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyReadabilityModule
add_library(clangTidyReadabilityModule STATIC IMPORTED)

set_target_properties(clangTidyReadabilityModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;clangTooling;LLVMSupport"
)

# Create imported target clangTidyZirconModule
add_library(clangTidyZirconModule STATIC IMPORTED)

set_target_properties(clangTidyZirconModule PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangTidy;clangTidyUtils;LLVMSupport"
)

# Create imported target clangTidyPlugin
add_library(clangTidyPlugin STATIC IMPORTED)

set_target_properties(clangTidyPlugin PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangFrontend;clangSema;clangTidy;clangTooling;clangTidyAndroidModule;clangTidyAbseilModule;clangTidyBoostModule;clangTidyBugproneModule;clangTidyCERTModule;clangTidyCppCoreGuidelinesModule;clangTidyDarwinModule;clangTidyFuchsiaModule;clangTidyGoogleModule;clangTidyHICPPModule;clangTidyLinuxKernelModule;clangTidyLLVMModule;clangTidyMiscModule;clangTidyModernizeModule;clangTidyObjCModule;clangTidyOpenMPModule;clangTidyPerformanceModule;clangTidyPortabilityModule;clangTidyReadabilityModule;clangTidyZirconModule;clangTidyMPIModule;LLVMSupport"
)

# Create imported target clang-tidy
add_executable(clang-tidy IMPORTED)

# Create imported target clangTidyUtils
add_library(clangTidyUtils STATIC IMPORTED)

set_target_properties(clangTidyUtils PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangLex;clangSema;clangTidy;clangTransformer;LLVMSupport"
)

# Create imported target clangChangeNamespace
add_library(clangChangeNamespace STATIC IMPORTED)

set_target_properties(clangChangeNamespace PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangFormat;clangFrontend;clangLex;clangSerialization;clangTooling;clangToolingCore;LLVMSupport"
)

# Create imported target clang-change-namespace
add_executable(clang-change-namespace IMPORTED)

# Create imported target clangDoc
add_library(clangDoc STATIC IMPORTED)

set_target_properties(clangDoc PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangFrontend;clangIndex;clangLex;clangTooling;clangToolingCore;LLVMSupport;LLVMBitstreamReader"
)

# Create imported target clang-doc
add_executable(clang-doc IMPORTED)

# Create imported target clangIncludeFixer
add_library(clangIncludeFixer STATIC IMPORTED)

set_target_properties(clangIncludeFixer PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangFormat;clangFrontend;clangLex;clangParse;clangSema;clangSerialization;clangTooling;clangToolingCore;findAllSymbols;LLVMSupport"
)

# Create imported target clangIncludeFixerPlugin
add_library(clangIncludeFixerPlugin STATIC IMPORTED)

set_target_properties(clangIncludeFixerPlugin PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangFrontend;clangIncludeFixer;clangParse;clangSema;clangTooling;-lpthread;LLVMSupport"
)

# Create imported target clang-include-fixer
add_executable(clang-include-fixer IMPORTED)

# Create imported target findAllSymbols
add_library(findAllSymbols STATIC IMPORTED)

set_target_properties(findAllSymbols PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangFrontend;clangLex;clangTooling;LLVMSupport"
)

# Create imported target find-all-symbols
add_executable(find-all-symbols IMPORTED)

# Create imported target clangMove
add_library(clangMove STATIC IMPORTED)

set_target_properties(clangMove PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAnalysis;clangAST;clangASTMatchers;clangBasic;clangFormat;clangFrontend;clangLex;clangSerialization;clangTooling;clangToolingCore;LLVMSupport"
)

# Create imported target clang-move
add_executable(clang-move IMPORTED)

# Create imported target clangQuery
add_library(clangQuery STATIC IMPORTED)

set_target_properties(clangQuery PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangDynamicASTMatchers;clangFrontend;clangSerialization;LLVMLineEditor;LLVMSupport"
)

# Create imported target clang-query
add_executable(clang-query IMPORTED)

# Create imported target pp-trace
add_executable(pp-trace IMPORTED)

# Create imported target clangDaemon
add_library(clangDaemon STATIC IMPORTED)

set_target_properties(clangDaemon PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangASTMatchers;clangBasic;clangDriver;clangFormat;clangFrontend;clangIndex;clangLex;clangSema;clangSerialization;clangTidy;clangTooling;clangToolingCore;clangToolingInclusions;clangToolingRefactoring;clangToolingSyntax;-lpthread;clangTidyAndroidModule;clangTidyAbseilModule;clangTidyBoostModule;clangTidyBugproneModule;clangTidyCERTModule;clangTidyCppCoreGuidelinesModule;clangTidyDarwinModule;clangTidyFuchsiaModule;clangTidyGoogleModule;clangTidyHICPPModule;clangTidyLinuxKernelModule;clangTidyLLVMModule;clangTidyMiscModule;clangTidyModernizeModule;clangTidyObjCModule;clangTidyOpenMPModule;clangTidyPerformanceModule;clangTidyPortabilityModule;clangTidyReadabilityModule;clangTidyZirconModule;clangTidyMPIModule;LLVMSupport;LLVMAArch64Info;LLVMAMDGPUInfo;LLVMARMInfo;LLVMBPFInfo;LLVMHexagonInfo;LLVMLanaiInfo;LLVMMipsInfo;LLVMMSP430Info;LLVMNVPTXInfo;LLVMPowerPCInfo;LLVMRISCVInfo;LLVMSparcInfo;LLVMSystemZInfo;LLVMWebAssemblyInfo;LLVMX86Info;LLVMXCoreInfo"
)

# Create imported target clangDaemonTweaks
add_library(clangDaemonTweaks STATIC IMPORTED)

set_target_properties(clangDaemonTweaks PROPERTIES
  INTERFACE_LINK_LIBRARIES "clangAST;clangBasic;clangDaemon;clangLex;clangToolingCore;clangToolingRefactoring;clangToolingSyntax;LLVMSupport"
)

# Create imported target clangd
add_executable(clangd IMPORTED)

# Create imported target libclang
add_library(libclang SHARED IMPORTED)

if(CMAKE_VERSION VERSION_LESS 2.8.12)
  message(FATAL_ERROR "This file relies on consumers using CMake 2.8.12 or greater.")
endif()

# Load information for each installed configuration.
get_filename_component(_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)
file(GLOB CONFIG_FILES "${_DIR}/ClangTargets-*.cmake")
foreach(f ${CONFIG_FILES})
  include(${f})
endforeach()

# Cleanup temporary variables.
set(_IMPORT_PREFIX)

# Loop over all imported files and verify that they actually exist
foreach(target ${_IMPORT_CHECK_TARGETS} )
  foreach(file ${_IMPORT_CHECK_FILES_FOR_${target}} )
    if(NOT EXISTS "${file}" )
      message(FATAL_ERROR "The imported target \"${target}\" references the file
   \"${file}\"
but this file does not exist.  Possible reasons include:
* The file was deleted, renamed, or moved to another location.
* An install or uninstall procedure did not complete successfully.
* The installation package was faulty and contained
   \"${CMAKE_CURRENT_LIST_FILE}\"
but not all the files it references.
")
    endif()
  endforeach()
  unset(_IMPORT_CHECK_FILES_FOR_${target})
endforeach()
unset(_IMPORT_CHECK_TARGETS)

# Make sure the targets which have been exported in some other 
# export set exist.
unset(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE_targets)
foreach(_target "LLVMCore" "LLVMMC" "LLVMSupport" "LLVMFrontendOpenMP" "LLVMMCParser" "LLVMBinaryFormat" "LLVMAnalysis" "LLVMBitReader" "LLVMBitWriter" "LLVMCoroutines" "LLVMCoverage" "LLVMipo" "LLVMIRReader" "LLVMAggressiveInstCombine" "LLVMInstCombine" "LLVMInstrumentation" "LLVMLTO" "LLVMLinker" "LLVMObjCARCOpts" "LLVMObject" "LLVMPasses" "LLVMProfileData" "LLVMRemarks" "LLVMScalarOpts" "LLVMTarget" "LLVMTransformUtils" "Polly" "LLVMOption" "LLVMBitstreamReader" "LLVMAArch64CodeGen" "LLVMAArch64AsmParser" "LLVMAArch64Desc" "LLVMAArch64Disassembler" "LLVMAArch64Info" "LLVMAArch64Utils" "LLVMAMDGPUCodeGen" "LLVMAMDGPUAsmParser" "LLVMAMDGPUDesc" "LLVMAMDGPUDisassembler" "LLVMAMDGPUInfo" "LLVMAMDGPUUtils" "LLVMARMCodeGen" "LLVMARMAsmParser" "LLVMARMDesc" "LLVMARMDisassembler" "LLVMARMInfo" "LLVMARMUtils" "LLVMBPFCodeGen" "LLVMBPFAsmParser" "LLVMBPFDesc" "LLVMBPFDisassembler" "LLVMBPFInfo" "LLVMHexagonCodeGen" "LLVMHexagonAsmParser" "LLVMHexagonDesc" "LLVMHexagonDisassembler" "LLVMHexagonInfo" "LLVMLanaiCodeGen" "LLVMLanaiAsmParser" "LLVMLanaiDesc" "LLVMLanaiDisassembler" "LLVMLanaiInfo" "LLVMMipsCodeGen" "LLVMMipsAsmParser" "LLVMMipsDesc" "LLVMMipsDisassembler" "LLVMMipsInfo" "LLVMMSP430CodeGen" "LLVMMSP430AsmParser" "LLVMMSP430Desc" "LLVMMSP430Disassembler" "LLVMMSP430Info" "LLVMNVPTXCodeGen" "LLVMNVPTXDesc" "LLVMNVPTXInfo" "LLVMPowerPCCodeGen" "LLVMPowerPCAsmParser" "LLVMPowerPCDesc" "LLVMPowerPCDisassembler" "LLVMPowerPCInfo" "LLVMRISCVCodeGen" "LLVMRISCVAsmParser" "LLVMRISCVDesc" "LLVMRISCVDisassembler" "LLVMRISCVInfo" "LLVMRISCVUtils" "LLVMSparcCodeGen" "LLVMSparcAsmParser" "LLVMSparcDesc" "LLVMSparcDisassembler" "LLVMSparcInfo" "LLVMSystemZCodeGen" "LLVMSystemZAsmParser" "LLVMSystemZDesc" "LLVMSystemZDisassembler" "LLVMSystemZInfo" "LLVMWebAssemblyCodeGen" "LLVMWebAssemblyAsmParser" "LLVMWebAssemblyDesc" "LLVMWebAssemblyDisassembler" "LLVMWebAssemblyInfo" "LLVMX86CodeGen" "LLVMX86AsmParser" "LLVMX86Desc" "LLVMX86Disassembler" "LLVMX86Info" "LLVMX86Utils" "LLVMXCoreCodeGen" "LLVMXCoreDesc" "LLVMXCoreDisassembler" "LLVMXCoreInfo" "LLVMCodeGen" "LLVMExecutionEngine" "LLVMMCJIT" "LLVMRuntimeDyld" "LLVMSelectionDAG" "LLVMLineEditor" )
  if(NOT TARGET "${_target}" )
    set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE_targets "${${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE_targets} ${_target}")
  endif()
endforeach()

if(DEFINED ${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE_targets)
  if(CMAKE_FIND_PACKAGE_NAME)
    set( ${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
    set( ${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "The following imported targets are referenced, but are missing: ${${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE_targets}")
  else()
    message(FATAL_ERROR "The following imported targets are referenced, but are missing: ${${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE_targets}")
  endif()
endif()
unset(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE_targets)

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
cmake_policy(POP)
