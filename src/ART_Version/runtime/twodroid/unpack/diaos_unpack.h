#ifndef ART_RUNTIME_TWODROID_UNPACK_DIAOS_UNPACK_H_
#define ART_RUNTIME_TWODROID_UNPACK_DIAOS_UNPACK_H_

#include <list>
#include <string>
#include <vector>

#include "interpreter/interpreter_common.h"

namespace gossip {

	void dexbuild(art::mirror::ArtMethod*  method, const char* filename, const char* dirname); //SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
}

#endif