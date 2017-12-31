#include "twodroid/tracer/UnpackTracer.h"
#include "twodroid/unpack/diaos_unpack.h"

#include <cstdio>
using std::string;

namespace gossip{
	UnpackTracer::~UnpackTracer()
	{
	}

	bool UnpackTracer::init( const string & apkDir ) 
	{
		apkDir_ = apkDir;
		char f[MaxLineLen] = {0};

		// generates opcodes.bin full name
		snprintf ( f, MaxLineLen, "%s/unpack_%d.bin", apkDir_.c_str(), getpid() );
		traceFileName_ = string(f);
		snprintf ( f, MaxLineLen, "%s", apkDir_.c_str());
		dirFile = string(f);
		return Tracer::init_traceFile();
	}
	
	void UnpackTracer::unpack	( art::mirror::ArtMethod*  method )
	{
		LOG(WARNING) << "UCHIHALART UnpackTracer::unpack  ";
		const char* filename = traceFileName_.c_str();
		const char* dirfilename = dirFile.c_str();
		//LOG(WARNING) << "UCHIHALART  unpack: "<<filename;
		fclose(traceFile_);
		fflush( traceFile_ );
		dexbuild(method, filename, dirfilename);
		//fprintf ( traceFile_, "%s",  method->GetName());
		//fflush ( traceFile_);

	}

	FILE* UnpackTracer::get_traceFile()
	{
		return traceFile_;
	}

	string UnpackTracer::get_traceFileName()
	{
		return traceFileName_;
	}

}//end of namespace