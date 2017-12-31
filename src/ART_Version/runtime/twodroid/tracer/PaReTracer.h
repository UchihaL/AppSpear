#ifndef ART_RUNTIME_TWODROID_TRACER_PARETRACER_H_
#define ART_RUNTIME_TWODROID_TRACER_PARETRACER_H_


#include "twodroid/tracer/Tracer.h"
#include "twodroid/Constant.h"
	
using std::string;

namespace gossip
{	
	class PaReTracer : public Tracer
	{
	public:
		~PaReTracer			();
		bool init			( const std::string & apkDir );
		void record_para		( art::mirror::ArtMethod* method, u4* pr) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	    void record_para_art(art::mirror::ArtMethod* method, art::ShadowFrame& shadow_frame, const art::Instruction* inst, uint16_t inst_data, bool is_range) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
		FILE* get_traceFile ();
	    std::string get_traceFileName		();

	private:
		
	};

}

#endif