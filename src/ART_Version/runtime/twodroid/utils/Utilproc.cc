#include "twodroid/utils/Utilproc.h"
#include "twodroid/Constant.h"

#include "interpreter/interpreter_common.h"

#include <fstream>

using std::string;
using std::map;
using std::ifstream;



namespace gossip{

UtilProc::UtilProc()
	{	
		//LOG(WARNING) << "UCHIHALART UtilProc()!!!!!!!!"; 
		
		lastUid_ = 0;
		if ( !this->init_uidmap() )
		    LOG(WARNING) << "UCHIHALART uidmap init process failure "<<uidMap_.size(); 
		else 
			LOG(WARNING) << "UCHIHALART uidmap init process success "<<uidMap_.size(); 
	}


	bool UtilProc::init_uidmap()
	{
		
		ifstream f ("/data/system/packages.list");
		if ( !f ) {
			return false;	
		}
		
		// read a line and get path
		string s;
		string dir;
		u4 d;
		u4 e;
		string attr;
		string ids;

		while ( !f.eof() )
		{
			f >> s >> d >> e >> dir >> attr >> ids; // ugly... 
			uidMap_[d] = dir;
		}

		//LOG(WARNING) << "UCHIHALART Init map items "<<uidMap_.size(); 
		return true;	
	}

	const std::string UtilProc::get_proc_name ()
	{
		// query other process is forbidden
		u4 pid = getpid();
		string s;

		// Get procFile's name from pid
	    char name[ProcFileNameMaxLen];
	    snprintf( name,	ProcFileNameMaxLen, "/proc/%d/cmdline", pid );
		ifstream f( name );
		if ( !f )
		{
			return s;
		}
		
		std::getline(f, s);

		return s;
	}

	const std::string UtilProc::get_apk_dir ()
	{
		// don't allow to query other process' uid
		u4 uid = getuid();
		if (uid != lastUid_)
		{
			
			//LOG(WARNING) << "UCHIHALART CHANGE UID";
			this->init_uidmap();
			lastUid_ = uid;
		}


		map<u4, string>::const_iterator it = uidMap_.find(uid);

		if ( it != uidMap_.end() )
			return it->second; 


		//LOG(WARNING) << "UCHIHALART apk_dir "<<string(); 
		return string();
	}

	bool UtilProc::apk_should_be_traced ()
	{
		char classFilterFilename[MaxLineLen] = {0};
		snprintf ( classFilterFilename, MaxLineLen, "%s/class.dlist", this->get_apk_dir().c_str() );
		//snprintf ( classFilterFilename, MaxLineLen, "%s/trace.dlist", this->get_apk_dir().c_str() );
		return ( access( classFilterFilename, 0 ) == 0 );
	}


	bool UtilProc::apk_should_log_oat ()
	{
		char classFilterFilename[MaxLineLen] = {0};
		//snprintf ( classFilterFilename, MaxLineLen, "%s/class.dlist", this->get_apk_dir().c_str() );
		//snprintf ( classFilterFilename, MaxLineLen, "%s/oatlog.dlist", this->get_apk_dir().c_str() );
		snprintf ( classFilterFilename, MaxLineLen, "%s/unpack.dlist", this->get_apk_dir().c_str() );
		return ( access( classFilterFilename, 0 ) == 0 );
	}

	void UtilProc::prepare ()
	{
		//LOG(WARNING) << "UCHIHALART UtilProc::prepare";
	}










}//end of namespace