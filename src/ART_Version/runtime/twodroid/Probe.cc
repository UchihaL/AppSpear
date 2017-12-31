#include "twodroid/Probe.h"
#include "twodroid/tracer/FuncTracer.h"
#include "twodroid/tracer/PaReTracer.h"
#include "twodroid/tracer/UnpackTracer.h"
#include "twodroid/filter/Filter.h"
#include "twodroid/utils/Utilproc.h"
#include "interpreter/interpreter_common.h"

#include "twodroid/oatdump.h"




namespace gossip {


int testFlag = 0;

UtilProc* util = NULL;
Filter* filter = NULL;
FuncTracer* funcTracer = NULL;
PaReTracer* pareTracer = NULL;
UnpackTracer* unpackTracer = NULL;

static bool traceFlag = false;
static bool dumpFlag = false;

const void* ep = nullptr;


std::map<unsigned int, const void*> epMap;

//bool diaos_start( art::mirror::ArtMethod*  method ) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);

void diaos_start()//for test
{
	LOG(WARNING) << "UCHIHALART  test";
	const std::string s1("/data/local/tmp/test.oat");
	std::string* s2= new std::string;
    art::OatFile* oatfile = art::OatFile::Open(s1,s1,NULL,true,s2);
    

	
	art::Runtime* runtime = art::Runtime::Current();
	
    art::ClassLinker* class_linker = runtime->GetClassLinker();

    //const art::OatFile* oatfile = class_linker->FindOatFileFromOatLocation(s1,s2);

    
    class_linker->RegisterOatFile((const art::OatFile*)oatfile);



    

}

void diaos_prepare(){
	if(util == NULL){
		util = new UtilProc;
	}
	if(filter == NULL){
		filter = new Filter;
	}
	if(funcTracer == NULL){
		funcTracer = new FuncTracer;
	}
	if(pareTracer == NULL){
		pareTracer = new PaReTracer;
	}
	if(unpackTracer == NULL){
		unpackTracer = new UnpackTracer;
	}
}



bool diaos_check(){
	

	diaos_prepare();
	static bool initFlag = false;
	if ( initFlag ) return true;
	if ( util->apk_should_be_traced() ) // check the existence of trace.dlist file
	{
		initFlag = diaos_init();
		

		//diaos_start();

	}
	
	traceFlag = initFlag;

	if ( util->apk_should_log_oat() ){ // check the existence of oatlog.dlist file
		dumpFlag = true;
	}

	return initFlag;
}

bool diaos_init()
{
	
	bool status = true;

	filter->init( util->get_apk_dir() );
	//status &= opcodeTracer.init( util.get_apk_dir() );
	//status &= regTracer.init( util.get_apk_dir() );
	status &= funcTracer->init( util->get_apk_dir() );//create func.bin
	//status &= objTracer.init( util.get_apk_dir() );
	status &= pareTracer->init( util->get_apk_dir() );
	status &= unpackTracer->init( util->get_apk_dir() );

	return status;
	
}


void setEP(const char* flag, const void* ep1){
	epMap[ BKDRHash(flag) ] = ep1;
}

const void* getEP(const char* flag){
	return epMap[ BKDRHash(flag) ];
}

bool class_should_be_traced(const char * myclass){
	if(traceFlag && filter->class_should_be_traced(myclass)){
		return true;
	}
	return false;
}

void diaos_monitor_func_call( art::mirror::ArtMethod*  method, const char * currentclass)
{
    
	if(traceFlag && filter->class_should_be_traced(currentclass)){
	//if(traceFlag){
		const char * myclass = method->GetDeclaringClassDescriptor();
		const char* mymethod = method->GetName(); 
		const char* retype = method->GetReturnTypeDescriptor();
		uint32_t mid = method->GetDexMethodIndex();

		funcTracer->record_func( myclass, mymethod, retype, mid );
	}
}

void diaos_monitor_parameter_art( art::mirror::ArtMethod* method, art::ShadowFrame& shadow_frame, const art::Instruction* inst, uint16_t inst_data, bool is_range, const char * currentclass)
{
	const char * myclass = method->GetDeclaringClassDescriptor();
	const char* mymethod = method->GetName();
	if(traceFlag && filter->method_should_be_traced(myclass,mymethod) && filter->class_should_be_traced(currentclass)){
		LOG(WARNING) << "UCHIHALART  method trace art: "<<mymethod;
		pareTracer->record_para_art(method, shadow_frame, inst, inst_data,is_range);
	}
}

void diaos_unpack(art::mirror::ArtMethod*  method, art::mirror::ArtMethod*  sf_method){
	art::Thread * self=art::Thread::Current();
	art::Locks::mutator_lock_->SharedLock(self);
	const char * myclass = method->GetDeclaringClassDescriptor();
	const char* mymethod = method->GetName();
	const char * currentclass = sf_method->GetDeclaringClassDescriptor();
	art::Locks::mutator_lock_->SharedUnlock(self);
	if(traceFlag && dumpFlag && filter->dex_should_be_unpack(myclass,mymethod) && filter->class_should_be_traced(currentclass)){
		LOG(WARNING) << "UCHIHALART  unpack: "<<myclass<<" " <<mymethod;
		unpackTracer->unpack(sf_method);
		//log_insns(method->GetCodeItem());
	}
}


void diaos_log_oat(const std::string& filename, const std::string& location){
	LOG(WARNING) << "UCHIHALART  oat log: "<<filename.data();

	

	OatTracer(util->get_apk_dir(), filename);
}






















}//end  of namespace


