#include "indroid/Probe.h"
#include "indroid/tracer/OpcodeTracer.h"
#include "indroid/tracer/RegTracer.h"
#include "indroid/tracer/FuncTracer.h"
#include "indroid/tracer/ObjTracer.h"
#include "indroid/tracer/PaReTracer.h"
#include "indroid/tracer/UnpackTracer.h"
#include "indroid/filter/Filter.h"
#include "indroid/utils/Utilproc.h"

using namespace std;
using namespace gossip_loccs;

// init a uidmap via util class firstly
UtilProc util;

// init a filter for class name and method name filtering
Filter filter;

// init tracers to record runtime data.

OpcodeTracer opcodeTracer;
RegTracer regTracer;
FuncTracer funcTracer;
ObjTracer objTracer;
PaReTracer pareTracer;
UnpackTracer unpackTracer;


// define YWB message output macro
#define DIAOS_DBG 1
#if defined(DIAOS_DBG)
# define GOSSIP(...) ALOG( LOG_VERBOSE, "YWB", __VA_ARGS__)
#else
# define GOSSIP(...) (void(0)) 
#endif

static bool traceFlag = false;
static bool unpackFlag = false;
static bool drflag = false;
void diaos_monitor_mov( const u2 * const pc, const u4 * const fp, const Thread * const self )
{
	//GOSSIP( "a" ); 
	/*
    const Method* method = self->interpSave.method;

	if ( util.apk_should_be_traced() )
	{
		GOSSIP( "%08x, %s\n", pc[0], method->clazz->descriptor ); 
	}
	*/
}

bool diaos_start( const Method * const method )
{

	static bool initFlag = false;
	if ( initFlag ) return true;

	if ( util.apk_should_be_traced() ) // check the existence of class.dlist file
	{
		initFlag = diaos_init();
		
		//if ( initFlag == true )
		//	GOSSIP( "InDroid starts for %s\n", method->clazz->descriptor ); 
		//else
		//	GOSSIP( "InDroid fails to start for %s\n", method->clazz->descriptor ); 
		
	}
	

	return initFlag;
}


bool diaos_init()
{
	
	bool status = true;

	filter.init( util.get_apk_dir() );
	status &= opcodeTracer.init( util.get_apk_dir() );
	status &= regTracer.init( util.get_apk_dir() );
	status &= funcTracer.init( util.get_apk_dir() );
	status &= objTracer.init( util.get_apk_dir() );
	status &= pareTracer.init();
	status &= unpackTracer.init( util.get_apk_dir() );

	return status;
	
}

void diaos_unpack( const Method * const method, const Method * const call)
{
	
	if ( (!unpackFlag) && filter.record_should_be_opened(UnpackFlag) && filter.file_should_be_unpack( call ) 
		&&  filter.class_should_be_traced( method->clazz->descriptor ))
	{
		unpackFlag = true;
	//	unpackTracer.odexOut(method);
		unpackTracer.anotherUnpack(method);
		/*
		if (filter.record_should_be_opened(LbdFlag))
		{
			unpackTracer.lbdUnpack(method);
		}
*/
		/*
		unpackTracer.simpleUnpack(method);
		unpackTracer.recoverDex(method);
		unpackTracer.odexOut(method);
		*/
	}
	
	if ((!drflag) && filter.record_should_be_opened(LbdFlag) && filter.file_should_be_unpack(call)
		&& filter.class_should_be_traced(method->clazz->descriptor))
	{
		GOSSIP("dex reassembly start");
		drflag = true;
	//	unpackTracer.odexOut(method);
		unpackTracer.lbdUnpack(method);
	}
	
}


void diaos_monitor_opcode ( const u2 * const pc, const u4 * const fp, const Thread * const self, const Method * method )
{
	
	if ( filter.class_should_be_traced( method->clazz->descriptor ) )   
	{
		// set traceFlag once for a single opcode, so that in monitor_reg() the filter should not be invoked.
		traceFlag = true;
		opcodeTracer.record_opcode( pc, self->threadId, method );
	}
	else
		traceFlag = false;
	
}

void diaos_monitor_reg( RegOpType type, const u4 * const fp, u2 index )
{
	
	if ( traceFlag && filter.record_should_be_opened(OpcodeFlag) ) 
		regTracer.record_reg( type, fp, index, opcodeTracer.get_instUid() );
	
}



void diaos_monitor_func_call( const Method * const method, const Method * const call )
{
	
	if ( filter.class_should_be_traced( method->clazz->descriptor ) 
		&& filter.record_should_be_opened(FuncFlag) )
	{
		
		//GOSSIP("xxxxxxxxxxxxxx");
		funcTracer.record_func( method, call, opcodeTracer.get_instUid() );
		//funcTracer.record_func( method, call, call->methodIndex );
		traceFlag = true;
	}
	else
		traceFlag = false;
	
		
}

void diaos_monitor_object( const Method * const m, Object *obj )
{
	
	if ( filter.class_should_be_traced( m->clazz->descriptor ) 
		&& filter.record_should_be_opened(ObjFlag) && filter.object_should_be_traced(obj) )
	{
		//objTracer.record_obj(obj);
		objTracer.record_all_obj(obj);

	}
	
}

void diaos_monitor_parameter(const Method * const m, u4* pr, const Method* const curMet)
{
	
	//if ( traceFlag && filter.record_should_be_opened(PaReFlag) && filter.method_should_be_traced(m) )
	if ( filter.record_should_be_opened(PaReFlag) && filter.method_should_be_traced(m) 
		&& filter.class_should_be_traced( curMet->clazz->descriptor ))
	{
		funcTracer.record_func( curMet, m, opcodeTracer.get_instUid() );
		pareTracer.record_para( m, pr );
	}
	
		
}

void diaos_monitor_temp_info(const Method * const m, s8& rj )
{
	
	if ( filter.record_should_be_opened(PaReFlag) && filter.method_should_be_traced(m) )
		pareTracer.record_temp_info( m, rj );
	
}

void diaos_monitor_retval(const Method * method)
{
	
	if ( filter.class_should_be_traced( method->clazz->descriptor ) && filter.record_should_be_opened(PaReFlag) 
		&& filter.method_should_be_traced( pareTracer.get_className(), pareTracer.get_methodName() ) )
		pareTracer.record_retval();
	
}
#if 0
#endif
