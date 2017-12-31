#ifndef ART_RUNTIME_TWODROID_TRACER_TRACER_H_
#define ART_RUNTIME_TWODROID_TRACER_TRACER_H_

#include "interpreter/interpreter_common.h"
#include "twodroid/Constant.h"

namespace gossip{

	class Tracer
	{
	public:
		virtual ~Tracer					();
		virtual bool init_traceFile		();
		virtual void flush_traceFile		();


	protected:
		std::string		apkDir_;
		std::string		traceFileName_;
		FILE *			traceFile_;
	};
}//end of namespace

#endif