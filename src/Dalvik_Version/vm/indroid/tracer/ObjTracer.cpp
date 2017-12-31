#include "indroid/tracer/ObjTracer.h"

#include <cstdio>

// define YWB message output macro
#define DIAOS_DBG 1
#if defined(DIAOS_DBG)
# define GOSSIP(...) ALOG( LOG_VERBOSE, "YWB", __VA_ARGS__)
#else
# define GOSSIP(...) (void(0)) 
#endif

using std::string;
extern gossip_loccs::OpcodeTracer opcodeTracer;

namespace gossip_loccs
{
	const static char * ObjString = "Ljava/lang/String;";

	ObjTracer::~ObjTracer()
	{

	}

	bool ObjTracer::init( const string & apkDir ) 
	{
		apkDir_ = apkDir;
		char f[MaxLineLen] = {0};

		// generates opcodes.bin full name
		snprintf ( f, MaxLineLen, "%s/obj_%d.bin", apkDir_.c_str(), getpid() );
		traceFileName_ = string(f);
		return Tracer::init_traceFile();
	}

	bool ObjTracer::check_obj( const Object * const obj )
	{
		if ( obj == NULL || (u4)obj <= 65536)
			return false;
		if ( (u4)(obj->clazz) <= 65536 || obj->clazz == NULL )
			return false;
		if ( obj->clazz->descriptor == NULL )
			return false;
		return true;
	}

	void ObjTracer::record_normal( char t, u4* v/*, ObjWriteMode flag*/)
	{
		const unsigned char n = '\n';
		/*
		if ( flag == BASIC_TYPE )
		{
			//GOSSIP("normal  :::::::%p", traceFile_);
			//GOSSIP("normal  filename %s", traceFileName_.c_str());
			fprintf( traceFile_, "instUid %u", opcodeTracer.get_instUid());
			record_normal_type(t);
		}*/

		if ( t == 'I' )
			fprintf(traceFile_, " %d ", *v);

		if ( t == 'B' )
		{
			//s1 s = (s1)(*v);
			fprintf(traceFile_, " %02x ", (u1)(*v));
		}
		if ( t == 'X') //byte array
			fprintf(traceFile_, " %02x ", (u1)(*v));
			
		if ( t == 'S' )
			fprintf(traceFile_, " %d ", (s2)(*v));
		if ( t == 'Z' )
			fprintf(traceFile_, " %d ", (u1)(*v));
/*
		if ( t == 'F' )
		{
			float f = *v;
			fprintf(traceFile_, " %f ",f);
		}*/
			

		if ( t == 'C' )
			fprintf(traceFile_, " %c ", (u2)(*v));

		if ( t == 'D' )
		{
			union myunion m;
			m.u[0] = *v;
			m.u[1] = *(v+1);
			fprintf(traceFile_, " %lf ", m.d );
		}

		if ( t == 'J' )
		{
			union myunion m;
			m.u[0] = *v;
			m.u[1] = *(v+1);
			fprintf(traceFile_, " %ld ", (long)(m.s) );			
		}	

		if ( t!='X' )//byte array
			fwrite( &n, 1, 1, traceFile_ );
		fflush( traceFile_ );

	}

	void ObjTracer::record_str( const Object * const obj, const u2 * const str, size_t len/*, ObjWriteMode flag */)
	{
		const unsigned char n = '\n' ;
		const unsigned char space = ' ';

		//if ( flag == BASIC_TYPE )
		//{
			//fprintf( traceFile_, "#%s: %p\n", obj->clazz->descriptor, obj);
		//}

		if ( len >= StrMaxLen )
			len = StrMaxLen;
		fwrite( &space, 1, 1, traceFile_ );
		//fwrite( &len, sizeof(size_t), 1, f );
		fwrite( str, 1, len, traceFile_ );
		//if ( flag == OPC_STR || FUNC_STR )
		fwrite( &n, 1, 1, traceFile_ );
		fflush( traceFile_ );
	}

	void ObjTracer::record_all_obj(Object *obj)
	{
		if (!check_obj(obj))
		{
			fprintf(traceFile_, "\n");
			return;
		}

		fprintf( traceFile_, "instUid %u #%s %p\n",
			opcodeTracer.get_instUid(), obj->clazz->descriptor, obj);
		u4 hash = BKDRHash(obj->clazz->descriptor);

		if ( hash == BKDRHash(ObjString) )
		{
			this->extract_str( obj/*, BASIC_TYPE*/ );
		}			
		else
		{
			const char *objtype = obj->clazz->descriptor;
			if (objtype != NULL && objtype[0] == '[')
			{
				this->extract_array(obj);
			}
			else
			{
				this->record_obj_new(obj);
			}
			    
		}
	}

	void ObjTracer::record_obj_new(Object *obj)
	{
		if (!check_obj(obj))
		{
			fprintf(traceFile_, "--\n");
			return ;
		}
		//this->dump_obj(obj);
		ClassObject* clazz = obj->clazz;
		while (clazz != NULL)
		{
			//fprintf( traceFile_, "#%s:  %p\n", clazz->descriptor, obj);
			for (int i = 0; i < clazz->ifieldCount; i++)
			{
			    const InstField* pField = &clazz->ifields[i];
		        char type = pField->signature[0];
		        fprintf( traceFile_, "--%s #%s %p\n", pField->name, pField->signature, pField);
		        //endless recursion
		        // if (strcmp(pField->name, "this$0") == 0)
		        // {
		        // 	continue;
		        // }

		        if (type == '[')
		        {
		        	Object *o = dvmGetFieldObject( obj, pField->byteOffset );
		        	this->extract_array(o);
		        }
		        else if (BKDRHash(pField->signature) == BKDRHash(ObjString))
		        {
		        	Object *o = dvmGetFieldObject( obj, pField->byteOffset );
		        	this->extract_str(o);
		        }
		        else if (strlen(pField->signature) == 1)
		        {
		        	this->record_field_normal(type, pField, obj);
		        }
		        else
		        {
		        	//Object *o = dvmGetFieldObject( obj, pField->byteOffset );
		        	//fprintf();

		        }
		        //fprintf(traceFile_, "\n");

		    }
		    //clazz = clazz->super;
		    clazz = NULL;

		}
	}


	void ObjTracer::extract_array(Object * obj)
	{
		if ( !check_obj ( obj ) )
		{	
			//GOSSIP("ARRAY NULL");
			fprintf(traceFile_, "\n");
			return;
		}
		else
		{
			ArrayObject *arrayobj = (ArrayObject*) obj;
			const char *ot = arrayobj->clazz->descriptor;
			u4 arrayLen = arrayobj->length;
			fprintf(traceFile_, "#%s length:%d\n", ot, arrayLen);
			if (ot[1] != 'L')
			{
				//GOSSIP("array type %s", ot);
				//this->record_normal_type( ot[1] );
				
				//fprintf( traceFile_, " len:%d\n", arrayLen);
				//GOSSIP("array type %c:%d", ot[1], arrayLen);
				for (u4 i = 0; i < arrayLen; i++)
				{
					if (ot[1] == 'D' || ot[1] == 'J')
					{
						s8 *v = (s8*)(void*)(arrayobj->contents);
						this->record_normal(ot[1], (u4*)(v + i));
					}
					else if (ot[1] == 'Z')
					{
						u1 *v = (u1*)(void*)(arrayobj->contents);
						this->record_normal(ot[1], (u4*)(v + i));
					}
					else if (ot[1] == 'B')
					{
						s1 *v = (s1*)(void*)(arrayobj->contents);
						this->record_normal('X', (u4*)(v + i));//byte array
					}
					else if (ot[1] == 'C')
					{
						u2 *v = (u2*)(void*)(arrayobj->contents);
						this->record_normal(ot[1], (u4*)(v + i));
					}
					else if (ot[1] == 'S')
					{
						s2 *v = (s2*)(void*)(arrayobj->contents);
						this->record_normal(ot[1], (u4*)(v + i));
					}
					else
					{
						u4 *v = (u4*)(void*)(arrayobj->contents);
						this->record_normal(ot[1], v + i);
					}
					
				}
				if (ot[1] == 'B')
					fprintf( traceFile_, "\n");

			}
			else
			{
				//fprintf(traceFile_, "%s", obj->clazz->descriptor);
				//u4 arrayLen = arrayobj->length;
				//GOSSIP("array len %d", arrayLen);
				//fprintf( traceFile_, " len:%d\n", arrayLen);
				for (u4 i = 0; i < arrayLen; i++)
				{
					//GOSSIP("array obj: i %d", i);
					Object *o = ((Object **)(void *)(arrayobj)->contents)[i];
					if ( check_obj( o) )
					{
						//GOSSIP("array obj: type %s", o->clazz->descriptor);
						this->record_all_obj( o );
					}
					else
						fprintf( traceFile_, "\n");

				}

			}

		}

	}

	void ObjTracer::extract_str(const Object * const obj/*, ObjWriteMode flag*/)
	{
		if ( !check_obj ( obj ) )
		{	
			//ALOG(LOG_VERBOSE, "YWB", "OBJECT NULL");
			fprintf(traceFile_, "\n");
			return;
		}
		else
		{
			StringObject * so = (StringObject *) obj;
			const u2 *s = so->chars();
			if ( s == NULL )
        	{
        		ALOG(LOG_VERBOSE, "YWB","string is null");
        		return;
        	}
        	this->record_str( obj, s, sizeof(u2) * so->length()/*, flag */);		
		}

	}


	void ObjTracer::record_field_normal(char t, const InstField* pField, Object* obj)
	{
		if (pField == NULL || obj == NULL)
			return;
		if ( t == 'I')
		{
			u4 i = dvmGetFieldInt( obj, pField->byteOffset );
		    //this->record_normal('I', &i );
		    fprintf(traceFile_, "%d\n",i );
		}
		else if ( t == 'D' )
		{
			//union myunion m;
		    double d = dvmGetFieldDouble( obj, pField->byteOffset );
		    //this->record_normal('D', m.u );
		    fprintf(traceFile_, "%lf\n", d);
		}

		else if ( t == 'Z' )
		{
			//u1 *z = NULL ;
			bool z = dvmGetFieldBoolean( obj, pField->byteOffset );
			//this->record_normal('Z', (u4*)z);
			fprintf(traceFile_, "%d\n", z);
		}
		else if ( t == 'B' )
		{
			//u1*b = NULL;
			u1 b = dvmGetFieldByte( obj, pField->byteOffset );
			//this->record_normal('B', (u4*)b);
			fprintf(traceFile_, "%02x\n", b);
		}
		else if ( t == 'S' )
		{
			//u2 *s = NULL;
			u2 s = dvmGetFieldShort( obj, pField->byteOffset );
			//this->record_normal('S', (u4*)s);
			fprintf(traceFile_, "%d\n", s);
		}
		else if ( t == 'C' )
		{
			//u2 *c = NULL;
			u2 c = dvmGetFieldChar( obj, pField->byteOffset );
			//this->record_normal('C', (u4*)c);
			fprintf(traceFile_, "%c\n", c);
		}
		else if ( t == 'F' )
		{
			//float *f = NULL;
			float f = dvmGetFieldFloat( obj, pField->byteOffset );
			//this->record_normal('F', (u4*)f);
			fprintf(traceFile_, "%f\n", f);
		}
		else if ( t == 'J' )
		{
			//union myunion m;
			s8 j = dvmGetFieldLong( obj, pField->byteOffset );
			//this->record_normal('J', m.u);
			fprintf(traceFile_, "%lld\n", j);
		}
	}



	void ObjTracer::modify_intent( Object * obj)
	{
		//try to clear the action
		//action
		InstField *pF = &obj->clazz->ifields[0];
		//dvmDumpObject(obj);
		ALOG(LOG_VERBOSE,"YWB", "set action null");
		dvmSetFieldObject( obj, pF->byteOffset, NULL);
	}

	void ObjTracer::dump_obj( const Object * const obj )
	{
		if ( !check_obj ( obj ) )
		{
			ALOG( LOG_VERBOSE, "YWB", "NULL OBJECT" );
			return;
		}
		ClassObject* clazz = obj->clazz;
/*
		u4 hash = BKDRHash ( clazz->descriptor );
		if ( objectFilter_.find( hash ) == objectFilter_.end() )
			return;
*/
		ALOG( LOG_VERBOSE, "YWB", " class --%s ", clazz->descriptor );
		for ( int i = 0; i < clazz->ifieldCount; i++ )
		{
			const InstField* pField = &clazz->ifields[i];
			char type = pField->signature[0];
				
			if ( type == 'F' || type == 'D' )
			{
				double dval;
				if ( type == 'F' )
					dval = dvmGetFieldFloat( obj, pField->byteOffset );
				else
					dval = dvmGetFieldDouble( obj, pField->byteOffset );
				ALOG( LOG_VERBOSE, "YWB", " %2d: %s, %s, %lf ", i, pField->name, pField->signature, dval );
			}
			else
			{
				u8 lval;
				if ( type == 'J' )
					lval = dvmGetFieldLong( obj, pField->byteOffset );
				else if ( type == 'Z' )
					lval = dvmGetFieldBoolean( obj, pField->byteOffset );
				/*else if ( type == 'L' )
				{
					Object* o = dvmGetFieldObject ( obj, pField->byteOffset );
					dump_obj ( o );
				}*/
				else
					lval = dvmGetFieldInt( obj, pField->byteOffset );
				ALOG( LOG_VERBOSE, "YWB", " %2d: %s, %s, 0x%08llx ", i, pField->name, pField->signature, lval );
			}
		}
		
	}

}
