#include "twodroid/tracer/Tracer.h"

#include <cstdio>
#include <fstream>

#include "interpreter/interpreter_common.h"

namespace gossip{
	using std::string;
    using std::set;
    using std::ifstream;

	Tracer::~Tracer()
	{
		// destruct only when process ends.
		if ( traceFile_ != NULL )
			fclose ( traceFile_ );
	}

	bool Tracer::init_traceFile() 
	{
		// init trace file for Tracer
		// should not use append mode, because a tracer is a single static class instance.
		traceFile_ = fopen ( traceFileName_.c_str(), "wb" );

		if ( traceFile_ == NULL )
		{
			return false;
		}
		return true;
	}
	
	void Tracer::flush_traceFile() 
	{
		fflush( traceFile_ );
	}

}//end of namespace