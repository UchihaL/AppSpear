#include "indroid/tracer/UnpackTracer.h"
#include "libdex/DexClass.h"




#include <cstdio>

// define YWB message output macro
#define DIAOS_DBG 1
#if defined(DIAOS_DBG)
# define GOSSIP(...) ALOG( LOG_VERBOSE, "LBD", __VA_ARGS__)
#else
# define GOSSIP(...) (void(0)) 
#endif

using std::string;


namespace gossip_loccs
{
	

	UnpackTracer::~UnpackTracer()
	{

	}

	bool UnpackTracer::init( const string & apkDir ) 
	{
		apkDir_ = apkDir;
		char f[MaxLineLen] = {0};

		// generates opcodes.bin full name
		snprintf ( f, MaxLineLen, "%s/unpack_%d.dex", apkDir_.c_str(), getpid() );
		traceFileName_ = string(f);
		snprintf ( f, MaxLineLen, "%s/simpleUnpack_%d.dex", apkDir_.c_str(), getpid() );
		simpleUnpackFile = string(f);
		snprintf ( f, MaxLineLen, "%s/anotherUnpack_%d.dex", apkDir_.c_str(), getpid() );
		anotherUnpackFile = string(f);

		//lbd
		snprintf ( f, MaxLineLen, "%s/lbd_%d.dex", apkDir_.c_str(), getpid() );
		//snprintf ( f, MaxLineLen, "%s/lbd_%d", apkDir_.c_str(), getpid() );
		lbdFile = string(f);

		snprintf ( f, MaxLineLen, "%s", apkDir_.c_str());
		dirFile = string(f);

		snprintf ( f, MaxLineLen, "%s/odexOut_%d.odex", apkDir_.c_str(), getpid() );
		odexFile = string(f);


		return Tracer::init_traceFile();
	}

	void UnpackTracer::simpleUnpack(const Method * const method)
	{
		
		FILE *fptest = fopen(simpleUnpackFile.c_str(), "wb");
		if (fptest == NULL)
		{
			//GOSSIP("unpack simple file open error");
			return;
		}

		ClassObject* c = NULL;
		c = method->clazz;
		//GOSSIP("=========================");
		//GOSSIP("unpacker: %s, %s", c->descriptor, method->name);
		if (c)
		{
			DexFile* df = c->pDvmDex->pDexFile;
			const DexHeader *dh = c->pDvmDex->pHeader;
			
			u4 dexLength = dh -> fileSize;
			//GOSSIP("unpacker file size %d", dexLength);
			const u1* filestart = df->baseAddr;
			/*
			GOSSIP("unpacker file base address %x", (unsigned int)filestart);
			GOSSIP("unpacker file header size %d", dh->headerSize);
			GOSSIP("unpacker file memory mapping: %p", (c->pDvmDex->memMap.addr));
			GOSSIP("unpacker file memory length: %x", c->pDvmDex->memMap.length);
			GOSSIP("unpacker file memory baseAddr: %p", (c->pDvmDex->memMap.baseAddr));
			GOSSIP("unpacker file memory baseLength: %x", c->pDvmDex->memMap.baseLength);
			*/
			fwrite(filestart, 1, dexLength, fptest);
			
			
		}
		fclose(fptest);

	}

	void UnpackTracer::anotherUnpack(const Method * const method)
	{
		FILE *fptest = fopen(anotherUnpackFile.c_str(), "wb");
		if (fptest == NULL)
		{
			//GOSSIP("unpack another file open error");
			return;
		}

		ClassObject* c = NULL;
		c = method->clazz;
		//GOSSIP("=========================");
		//GOSSIP("unpacker: %s, %s", c->descriptor, method->name);
		if (c)
		{
			DexFile* df = c->pDvmDex->pDexFile;
			//const DexHeader *dh = c->pDvmDex->pHeader;
			
			//u4 dexLength = dh -> fileSize;
			//GOSSIP("unpacker file size %d", dexLength);
			//const u1* filestart = df->baseAddr;
			//GOSSIP("unpacker file base address %p", filestart);
			
			//dumpFileHeader(df);
			processDexdump(fptest, df);
			//GOSSIP("unpacker fh point %p", df->pHeader);
			
			
		}
		fclose(fptest);
	}

	void UnpackTracer::odexOut(const Method * const method)
	{
		FILE *fptest = fopen(odexFile.c_str(), "wb");
		
		if (fptest == NULL)
		{
			GOSSIP("odex unpack file open error");
			return;
		}

		ClassObject* c = NULL;
		c = method->clazz;
		GOSSIP("===========odex dump==============");
		GOSSIP("unpacker: %s, %s", c->descriptor, method->name);
		if (c)
		{
			DexFile* df = c->pDvmDex->pDexFile;
			const DexOptHeader* h = df->pOptHeader;
			const u1* filestart = (u1*)h;
			size_t odexLength = h->optOffset + h->optLength;
			GOSSIP("odexheader address %p", h);
			GOSSIP("dexfile address %p", df);
			GOSSIP("unpacker odex file size %d", odexLength);
			
			fwrite(filestart, 1, odexLength, fptest);
			
			
		}
		fclose(fptest);

	}



	void UnpackTracer::lbdUnpack(const Method * const method)
	{
        ALOG(LOG_VERBOSE,"LBD","lbdUnpack");

        //FILE *fptest = fopen(lbdFile.c_str(), "wb");
        const char* filename = lbdFile.c_str();
		const char* dirname = dirFile.c_str();
        /*
        if (fptest == NULL)
		{
			ALOG(LOG_VERBOSE,"LBD","open file error");
			return;
		}*/

		ClassObject* c = NULL;
		c = method->clazz;
        if (c)
		{
			const DexFile* df = c->pDvmDex->pDexFile;
			const DexHeader *dh = c->pDvmDex->pHeader;
			Object* loader = method->clazz->classLoader;

			GOSSIP("unpacker file name %s", filename);
			
			u4 dexLength = dh -> fileSize;
            GOSSIP("unpacker file size %d", dexLength);
			const u1* filestart = df->baseAddr;
			GOSSIP("unpacker file base address %p", filestart);

			
			dexbuild(c->pDvmDex,filename,dirname, loader);		
			
		}
		//fclose(fptest);
        GOSSIP("unpacker file name %s", filename);
	}
	

	



}
