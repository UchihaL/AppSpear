#include <fstream>

#include "twodroid/filter/Filter.h"

using std::string;
using std::set;
using std::ifstream;

namespace gossip{
	void Filter::init( const std::string & apkDir )
	{
		apkDir_ = apkDir;

		string c_list("class.dlist");
		//string o_list("object.dlist"); 
		string m_list("method.dlist");
		//string u_list("oatlog.dlist");
		string u_list("unpack.dlist");
		//string f_list("flag.dlist");

		this->init_filter( c_list, classFilter_ );
		//this->init_filter( o_list, objectFilter_ );
		this->init_filter( m_list, methodFilter_ );
		this->init_filter( u_list, unpackFilter_ );
		//this->init_recordFlag(f_list);
	}

	void Filter::init_filter( const string & n, set<u4> & filter  )
	{
		// get class.dlist path
		char name[MaxLineLen] = {0};
		snprintf ( name, MaxLineLen, "%s/%s", apkDir_.c_str(), n.c_str() );
		// make class filter
		filter = list_to_hash_filter( name );

		//GOSSIP( "Init %s filter items: %d\n", n.c_str(), filter.size() );
	}

	bool Filter::class_should_be_traced ( const char* const className )
	{
		if ( className[0] == 0) 
			return false;

		return classFilter_.find( BKDRHash(className) ) != classFilter_.end();
	}

	bool Filter::method_should_be_traced( const char* const cn, const char* const mn )
	{
		char n[MaxLineLen] = {0};
		snprintf( n, MaxLineLen, "%s%s", cn, mn );
		if ( n[0] == 0 )
			return false;

		return methodFilter_.find( BKDRHash(n) ) != methodFilter_.end();
	}

	bool Filter::dex_should_be_unpack( const char* const cn, const char* const mn )
	{
		char n[MaxLineLen] = {0};
		snprintf( n, MaxLineLen, "%s%s", cn, mn );
		if ( n[0] == 0 )
			return false;

		return unpackFilter_.find( BKDRHash(n) ) != unpackFilter_.end();
	}

	set<u4> Filter::list_to_hash_filter( const char * const filename )
	{
		set<u4> filter;
		string s;
		ifstream f( filename );
		
		while ( std::getline(f, s) )
		{
			filter.insert( BKDRHash( s.c_str() ) );
		}
	
		return filter;
	}



}//end of namespace