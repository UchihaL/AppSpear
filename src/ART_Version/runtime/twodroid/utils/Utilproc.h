#ifndef ART_RUNTIME_TWODROID_UTILS_UTILPROC_H_
#define ART_RUNTIME_TWODROID_UTILS_UTILPROC_H_

#include "twodroid/Constant.h"
#include "interpreter/interpreter_common.h"

#include <map>
#include <string>


namespace gossip{

	class UtilProc
	{
	public:
		UtilProc();
		const std::string	get_apk_dir				();
		const std::string	get_proc_name			();
		bool 				init_uidmap				();
		bool				apk_should_be_traced	();
		bool				apk_should_log_oat	    ();
		void                prepare                 ();

	private:
		std::map<u4, std::string> uidMap_;
		u4 lastUid_;
	};


}//end of namespace





#endif