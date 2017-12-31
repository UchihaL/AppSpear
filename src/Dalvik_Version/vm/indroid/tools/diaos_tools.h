#ifndef _DIAOS_TOOLS_H_
#define _DIAOS_TOOLS_H_

#include "libdex/DexClass.h"
//#include "libdex/DexFile.h"
#include "libdex/Leb128.h"
#include "bytestream.h"
#include "Dalvik.h"
#include <vector>
#include <map>


//using namespace gossip_loccs;

namespace gossip_loccs
{
	void dexbuild(DvmDex* pDvmDex,const char* filename,const char* dirname, Object* loader);
} // end of namespace gossip_loccs

#endif

