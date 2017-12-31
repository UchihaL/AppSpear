#ifndef ART_RUNTIME_TWODROID_TRACER_FUNCTRACER_H_
#define ART_RUNTIME_TWODROID_TRACER_FUNCTRACER_H_

#include "twodroid/tracer/Tracer.h"
#include "twodroid/Constant.h"

namespace gossip{

class FuncTracer : public Tracer
{
public:
	~FuncTracer			();
	bool init			( const std::string & apkDir );
	void record_func	( const char * myclass, const char* mymethod, const char* retype , uint32_t mid);
	FILE* get_traceFile ();
	std::string get_traceFileName		();

private:
	//bool init_traceFile	();
};


}//end of namespace

#endif