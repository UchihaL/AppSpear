#ifndef ART_RUNTIME_TWODROID_TRACER_UNPACKTRACER_H_
#define ART_RUNTIME_TWODROID_TRACER_UNPACKTRACER_H_

#include "twodroid/tracer/Tracer.h"
#include "twodroid/Constant.h"
#include "interpreter/interpreter_common.h"

namespace gossip{

class UnpackTracer : public Tracer
{
public:
	~UnpackTracer			();
	bool init			( const std::string & apkDir );
	void unpack	( art::mirror::ArtMethod*  method ); //SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	FILE* get_traceFile ();
	std::string get_traceFileName		();

private:
	//bool init_traceFile	();
	//std::string     unpackFile;
	std::string dirFile;
};


}//end of namespace

#endif