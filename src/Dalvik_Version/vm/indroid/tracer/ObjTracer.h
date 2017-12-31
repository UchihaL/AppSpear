#ifndef _DIAOS_OBJ_TRACER_H_
#define _DIAOS_OBJ_TRACER_H_

#include <string>
#include <map>

#include "indroid/tracer/Tracer.h"
#include "indroid/Constant.h"
#include "indroid/tracer/OpcodeTracer.h"
	


namespace gossip_loccs
{	

class ObjTracer : public Tracer
{
public:
	~ObjTracer			();
	bool init			( const std::string & apkDir );
	bool check_obj ( const Object * const obj );

	void record_normal	( char t, u4* v/*, ObjWriteMode flag = OBJECT_TYPE*/);
	void record_str		( const Object * const obj, const u2 * const str, size_t len/*, ObjWriteMode flag */);
	void record_obj_new ( Object *o );
	void record_all_obj ( Object *o );
	void record_field_normal(char t, const InstField* pF, Object* obj);

	void extract_str				(const Object * const obj/*, ObjWriteMode flag = OBJECT_TYPE */);
	void extract_array          (Object * obj);

	void modify_intent( Object * obj);
	void dump_obj( const Object * const obj );

private:
	//bool init_traceFile	();
};


} // end of namespace loccs

#endif
