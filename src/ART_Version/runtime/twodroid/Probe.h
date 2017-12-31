#ifndef ART_RUNTIME_TWODROID_PROBE_H_
#define ART_RUNTIME_TWODROID_PROBE_H_

#include "twodroid/Constant.h"
#include "interpreter/interpreter_common.h"

namespace gossip{

//extern "C" {
	void diaos_start();
	bool diaos_check();
	bool diaos_init();
	void diaos_prepare();
	void diaos_monitor_func_call( art::mirror::ArtMethod*  method, const char * currentclass) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	void diaos_monitor_parameter_art( art::mirror::ArtMethod* method, art::ShadowFrame& shadow_frame, const art::Instruction* inst, uint16_t inst_data, bool is_range, const char * currentclass) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
    void diaos_unpack( art::mirror::ArtMethod*  method, art::mirror::ArtMethod*  sf_method); //SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);

	void diaos_log_oat(const std::string& filename, const std::string& location);


    void setEP(const char* flag, const void* ep1);

    const void* getEP(const char* flag);

    bool class_should_be_traced(const char * myclass);


//}//end of  extern "C"


}//end of namespace

#endif