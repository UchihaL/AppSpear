#include "indroid/tracer/PaReTracer.h"

#include <cstdio>


// define YWB message output macro
#define DIAOS_DBG 1
#if defined(DIAOS_DBG)
# define GOSSIP(...) ALOG( LOG_VERBOSE, "YWB", __VA_ARGS__)
#else
# define GOSSIP(...) (void(0)) 
#endif

using std::string;
extern gossip_loccs::FuncTracer funcTracer;
extern gossip_loccs::Filter filter;

namespace gossip_loccs
{
	PaReTracer::~PaReTracer()
	{
	}

	bool PaReTracer::init() 
	{
		traceFile_ = funcTracer.get_traceFile();
		traceFileName_ = funcTracer.get_traceFileName();
		retjval = 0;

		if (traceFile_ == NULL)
			return false;
		return true;
	}

	void PaReTracer::record_para( const Method * const m, u4* pr )
	{

		/*
		shorty's length may not match with parameter's number, which is method's insSize;
		in InterpC-portable we can see insSize == count(or vsrc1), out[]'s length;
		if so, we according to shorty's number, omit the first outs[];
		so pr begins with 0 or 1(not match);
		shorty is begin with the second letter cause first letter is retval;

		*/

		const char *s = m->shorty;
		int shortyLen = strlen( s ) - 1, argNum = m->insSize, outIndex = 0;
		int DJcount = 0;

		for (int t = 1; t <= shortyLen; t++)
		{
			if (s[t] == 'J' || s[t] == 'D')
				DJcount ++;
		}

		if (argNum != shortyLen + DJcount)
		{
			outIndex = 1;
		}

		//GOSSIP("parameter number %d, shortyLen %d", argNum, shortyLen);


		for ( int i = 1, j = outIndex ; i <= shortyLen; i++, j++ )
		{
			fprintf(traceFile_, "p[%d]: ", i);
			if ( s[i] == 'L' )
			{
				Object* o = (Object*) pr[j];
				//GOSSIP("%s, %s, %s, %p, %d, %d, %d, %d\n", m->shorty, m->clazz->descriptor, m->name, o,i, m->outsSize, m->registersSize, m->insSize);
				record_all_obj(o);
				/*
				if ( filter.object_should_be_traced(o) )
				{
					//record_obj(o);
					record_all_obj(o);
				}
				else
					fprintf(traceFile_, "\n");*/
			}
			else
			{

				//GOSSIP("para file: %p", traceFile_);
				this->record_normal(s[i], pr + j/*, BASIC_TYPE*/);
				//GOSSIP("para file: %p", traceFile_);
				if (s[i] == 'D' || s[i] == 'J')
					j++;
			}

				
			//fprintf(traceFile_, "\n" );
		}
		fflush(traceFile_);
	}

	void PaReTracer::record_retval()
	{
		/*
		if (! (recordFlag_ & 0x02))
			return ;
		*/
		//const char * sn = m->shorty;

		fprintf( traceFile_, "rv: " );
		if (shortyName[0] == 'L')
		{
			Object* o = (Object*) retjval;
			record_all_obj(o);
			/*
			if ( filter.object_should_be_traced(o) )
			{
				record_all_obj(o);
			}	
			else
				fprintf(traceFile_, "\n");*/
		}
		else
		{
			union myunion m;
			m.s = retjval;
			record_normal( shortyName[0], m.u/*, BASIC_TYPE */);
		}

		className.clear();
		methodName.clear();
		shortyName.clear();
			
		//fprintf(traceFile_, "\n" );
		fflush(traceFile_);
	}

	void PaReTracer::record_temp_info ( const Method * const m, s8& rj )
	{
		retjval = rj;
		className = m->clazz->descriptor;
		methodName = m->name;
		shortyName = m->shorty;
		//GOSSIP("%s %s %s", m->clazz->descriptor, m->name, m->shorty);
		/*
		snprintf( className, ClassNameMaxLen, "%s", m->clazz->descriptor );
		snprintf( methodName, MethodNameMaxLen, "%s", m->name );
		snprintf( shortyName, ShortyNameMaxLen, "%s", m->shorty );
		*/

	}

	const char* PaReTracer::get_className()
	{
		return className.c_str();
	}

	const char* PaReTracer::get_methodName()
	{
		return methodName.c_str();
	}
}