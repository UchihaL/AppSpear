/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The "dexdump" tool is intended to mimic "objdump".  When possible, use
 * similar command-line arguments.
 *
 * TODO: rework the "plain" output format to be more regexp-friendly
 *
 * Differences between XML output and the "current.xml" file:
 * - classes in same package are not all grouped together; generally speaking
 *   nothing is sorted
 * - no "deprecated" on fields and methods
 * - no "value" on fields
 * - no parameter names
 * - no generic signatures on parameters, e.g. type="java.lang.Class&lt;?&gt;"
 * - class shows declared fields and methods; does not show inherited fields
 */

#include "libdex/DexFile.h"

#include "libdex/CmdUtils.h"
#include "libdex/DexCatch.h"
#include "libdex/DexClass.h"
#include "libdex/DexDebugInfo.h"
#include "libdex/DexOpcodes.h"
#include "libdex/DexProto.h"
#include "libdex/InstrUtils.h"
#include "libdex/SysUtil.h"
#include "Bits.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>



enum OutputFormat {
    OUTPUT_PLAIN = 0,               /* default */
    OUTPUT_XML,                     /* fancy */
};

/* command-line options */
struct Options {
    bool checksumOnly;
    bool disassemble;
    bool showFileHeaders;
    bool showSectionHeaders;
    bool ignoreBadChecksum;
    bool dumpRegisterMaps;
    OutputFormat outputFormat;
    const char* tempFileName;
    bool exportsOnly;
    bool verbose;
};



/* basic info about a field or method */
struct FieldMethodInfo {
    const char* classDescriptor;
    const char* name;
    const char* signature;
};



/*
 * Flag for use with createAccessFlagStr().
 */
enum AccessFor {
    kAccessForClass = 0, kAccessForMethod = 1, kAccessForField = 2,
    kAccessForMAX
};



/*
 * Dump the file header.
 */
void dumpFileHeader(const DexFile* pDexFile);

/*
 * Dump the "table of contents" for the opt area.
 */
void dumpOptDirectory(const DexFile* pDexFile);

/*
 * Dump a class_def_item.
 */
void dumpClassDef(DexFile* pDexFile, int idx);

/*
 * Dump an interface that a class declares to implement.
 */
void dumpInterface(const DexFile* pDexFile, const DexTypeItem* pTypeItem,
    int i);

/*
 * Dump the catches table associated with the code.
 */
void dumpCatches(DexFile* pDexFile, const DexCode* pCode);



/*
 * Dump the positions list.
 */
void dumpPositions(DexFile* pDexFile, const DexCode* pCode,
        const DexMethod *pDexMethod);



/*
 * Dump the locals list.
 */
void dumpLocals(DexFile* pDexFile, const DexCode* pCode,
        const DexMethod *pDexMethod);


/*
 * Get information about a method.
 */
bool getMethodInfo(DexFile* pDexFile, u4 methodIdx, FieldMethodInfo* pMethInfo);


/*
 * Get information about a field.
 */
bool getFieldInfo(DexFile* pDexFile, u4 fieldIdx, FieldMethodInfo* pFieldInfo);



/*
 * Look up a class' descriptor.
 */
const char* getClassDescriptor(DexFile* pDexFile, u4 classIdx);


/*
 * Dump a single instruction.
 */
void dumpInstruction(DexFile* pDexFile, const DexCode* pCode, int insnIdx,
    int insnWidth, const DecodedInstruction* pDecInsn);

/*
 * Dump a bytecode disassembly.
 */
void dumpBytecodes(DexFile* pDexFile, const DexMethod* pDexMethod);


/*
 * Dump a "code" struct.
 */
void dumpCode(DexFile* pDexFile, const DexMethod* pDexMethod);

/*
 * Dump a method.
 */
void dumpMethod(DexFile* pDexFile, const DexMethod* pDexMethod, int i);


/*
 * Dump a static (class) field.
 */
void dumpSField(const DexFile* pDexFile, const DexField* pSField, int i);


/*
 * Dump an instance field.
 */
void dumpIField(const DexFile* pDexFile, const DexField* pIField, int i);


/*
 * Dump the class.
 *
 * Note "idx" is a DexClassDef index, not a DexTypeId index.
 *
 * If "*pLastPackage" is NULL or does not match the current class' package,
 * the value will be replaced with a newly-allocated string.
 */
void dumpClass(DexFile* pDexFile, int idx, char** pLastPackage);


/*
 * Advance "ptr" to ensure 32-bit alignment.
 */
static inline const u1* align32(const u1* ptr)
{
    return (u1*) (((uintptr_t) ptr + 3) & ~0x03);
}


/*
 * Dump a map in the "differential" format.
 *
 * TODO: show a hex dump of the compressed data.  (We can show the
 * uncompressed data if we move the compression code to libdex; otherwise
 * it's too complex to merit a fast & fragile implementation here.)
 */
void dumpDifferentialCompressedMap(const u1** pData);


/*
 * Dump register map contents of the current method.
 *
 * "*pData" should point to the start of the register map data.  Advances
 * "*pData" to the start of the next map.
 */
void dumpMethodMap(DexFile* pDexFile, const DexMethod* pDexMethod, int idx,
    const u1** pData);

/*
 * Dump the contents of the register map area.
 *
 * These are only present in optimized DEX files, and the structure is
 * not really exposed to other parts of the VM itself.  We're going to
 * dig through them here, but this is pretty fragile.  DO NOT rely on
 * this or derive other code from it.
 */
void dumpRegisterMaps(DexFile* pDexFile);

/*
 * Dump the requested sections of the file.
 */
void processDexFile( DexFile* pDexFile);

void processDexdump( FILE* fp, DexFile* pDexFile);


/*
 * Process one file.
 */

