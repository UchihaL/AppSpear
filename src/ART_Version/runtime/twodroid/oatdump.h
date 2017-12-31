#ifndef ART_RUNTIME_TWODROID_OATDUMP_H_
#define ART_RUNTIME_TWODROID_OATDUMP_H_

#include <list>
#include <string>
#include <vector>

#include "interpreter/interpreter_common.h"

namespace gossip {

	void test();
	void openOat(const std::string& filename, const std::string& location);


	void OatTracer(const std::string & apkDir_, const std::string & filename);
	void ClassDump(art::mirror::Class* myclass,const char * cn) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);

	void log_insns(const art::DexFile::CodeItem* code);
}

#endif