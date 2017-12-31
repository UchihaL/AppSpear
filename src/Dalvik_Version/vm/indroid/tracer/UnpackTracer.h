#ifndef _DIAOS_UNPACK_TRACER_H_
#define _DIAOS_UNPACK_TRACER_H_

#include <string>
#include <map>

#include "indroid/tracer/Tracer.h"
#include "indroid/Constant.h"
#include "DexUnpack.h"
#include "indroid/tools/diaos_tools.h"


namespace gossip_loccs
{	

class UnpackTracer : public Tracer
{
public:
	~UnpackTracer			();
	bool init			( const std::string & apkDir );
	void simpleUnpack(const Method * const method);
	void anotherUnpack(const Method * const method);
	void lbdUnpack(const Method * const method);
	void odexOut(const Method* const method);
	

private:
	//bool init_traceFile	();
	std::string		simpleUnpackFile;
	std::string 	anotherUnpackFile;
	//lbd
	std::string     lbdFile;
	std::string		dirFile;
	std::string     odexFile;
};


} // end of namespace loccs

#endif
