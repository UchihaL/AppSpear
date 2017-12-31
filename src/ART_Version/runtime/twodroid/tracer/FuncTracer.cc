#include "twodroid/tracer/FuncTracer.h"

#include <cstdio>
using std::string;

namespace gossip{
	FuncTracer::~FuncTracer()
	{
	}

	bool FuncTracer::init( const string & apkDir ) 
	{
		apkDir_ = apkDir;
		char f[MaxLineLen] = {0};

		// generates opcodes.bin full name
		snprintf ( f, MaxLineLen, "%s/func_%d.bin", apkDir_.c_str(), getpid() );
		traceFileName_ = string(f);
		return Tracer::init_traceFile();
	}
	
	void FuncTracer::record_func ( const char * myclass, const char* mymethod, const char* retype ,uint32_t mid )
	{
		//fprintf( traceFile_, "instUid %u||", instUid );
		fprintf ( traceFile_, "%s||%s||%s||%d\n", myclass, mymethod, retype ,mid); 
		fflush ( traceFile_);
	}

	FILE* FuncTracer::get_traceFile()
	{
		return traceFile_;
	}

	string FuncTracer::get_traceFileName()
	{
		return traceFileName_;
	}

}//end of namespace