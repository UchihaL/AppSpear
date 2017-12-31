#include "indroid/tools/diaos_tools.h"
#include <fstream>
#include <string.h>
#include <vector>
#include <map>
#include <stdlib.h>

// define YWB message output macro
#define DIAOS_DBG 1
#if defined(DIAOS_DBG)
# define GOSSIP(...) ALOG( LOG_VERBOSE, "LBD", __VA_ARGS__)
#else
# define GOSSIP(...) (void(0)) 
#endif

namespace gossip_loccs
{
	void aaabc()
	{
		ALOG(LOG_VERBOSE,"LBD","abc");
	}

	void test(const DexFile* df, const char* filename)
	{
		ALOG(LOG_VERBOSE,"LBD","test");
		//ByteStream *bs = bsalloc(pDexFile->pHeader->headerSize);
		//size_t data_size = sizeof(DexHeader);
		//GOSSIP("header size %d", data_size);
		//u1* ptr = (uint8_t*) pDexFile->pHeader;
		//GOSSIP("header addr %p", ptr);
        
		//GOSSIP("StrID addr %p", pDexFile->pStringIds);
		/*
		const DexMapList* map_list = dexGetMap(df);
        int MyDexMapItem[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		for(unsigned int i=0;i<map_list->size;i++){
			DexMapItem dex_map_item = map_list->list[i];
			switch(dex_map_item.type){
				case 0x0000:
				MyDexMapItem[0]=1;
				break;
				case 0x0001:
				MyDexMapItem[1]=1;
				break;
				case 0x0002:
				MyDexMapItem[2]=1;
				break;
				case 0x0003:
				MyDexMapItem[3]=1;
				break;
				case 0x0004:
				MyDexMapItem[4]=1;
				break;
				case 0x0005:
				MyDexMapItem[5]=1;
				break;
				case 0x0006:
				MyDexMapItem[6]=1;
				break;
				case 0x1000:
				MyDexMapItem[7]=1;
				break;
				case 0x1001:
				MyDexMapItem[8]=1;
				break;
				case 0x1002:
				MyDexMapItem[9]=1;
				break;
				case 0x1003:
				MyDexMapItem[10]=1;
				break;
				case 0x2000:
				MyDexMapItem[11]=1;
				break;
				case 0x2001:
				MyDexMapItem[12]=1;
				break;
				case 0x2002:
				MyDexMapItem[13]=1;
				break;
				case 0x2003:
				MyDexMapItem[14]=1;
				break;
				case 0x2004:
				MyDexMapItem[15]=1;
				break;
				case 0x2005:
				MyDexMapItem[16]=1;
				break;
				case 0x2006:
				MyDexMapItem[17]=1;
				break;
      
			}
		}


		for(int i=0;i<18;i++){
			GOSSIP("MAP %d", MyDexMapItem[i]);
		}*/

        //bswrite(bs,ptr,data_size);
        //bssave(bs, FileName);
        //bsfree(bs);
	}

	void dxb_header(ByteStream *bs, const DexHeader *header,uint32_t offset)
	{
		if (bs == NULL || header == NULL)
		{
			return;
		}
		
		size_t data_size = sizeof(DexHeader);
		uint8_t* ptr = (uint8_t*) header;

		bsseek(bs,offset);
		bswrite(bs,ptr,data_size);

	}

	void dxb_oheader(ByteStream *bs, const DexOptHeader *header,uint32_t offset)
	{
		if (bs == NULL || header == NULL)
		{
			return;
		}
		
		size_t data_size = sizeof(DexOptHeader);
		uint8_t* ptr = (uint8_t*) header;

		bsseek(bs,offset);
		bswrite(bs,ptr,data_size);

	}



	void dxb_mapitem(ByteStream* bs, const DexMapItem *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexMapItem);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);

	}

	void dxb_maplist(ByteStream* bs, const DexFile* df)
	{
		const DexMapList* map_list = dexGetMap(df);
		unsigned int i;

  		if (bs == NULL || df == NULL || df->pHeader == NULL) return;

  		uint32_t offset = df->pHeader->mapOff;

  		bsseek(bs,offset);

  		bswrite(bs,(uint8_t*)&(map_list->size),sizeof(uint32_t));

  		offset = offset + sizeof(uint32_t);

  		for (i=0; i<map_list->size; i++)
  		{

  			dxb_mapitem(bs,&(map_list->list[i]), offset);
  			offset = offset + sizeof(DexMapItem);
  		}
    		

	}


	void dxb_stringid(ByteStream* bs, const DexStringId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexStringId);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_typeid(ByteStream* bs, const DexTypeId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexTypeId);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_protoid(ByteStream* bs, const DexProtoId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexProtoId);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_fieldid(ByteStream* bs, const DexFieldId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexFieldId);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_methodid(ByteStream* bs, const DexMethodId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexMethodId);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_classdef(ByteStream* bs, const DexClassDef *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexClassDef);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_stringdata(ByteStream* bs, const DexStringId *obj, const DexFile* df)
	{
		//mem mapping 
		const u1* ptr = df->baseAddr + obj->stringDataOff;
		bsseek(bs,obj->stringDataOff);
		
		size_t data_size = strlen((const char*)ptr);
		bswrite(bs,(uint8_t*)ptr,data_size);

	}

	void dxb_map_list_item(ByteStream *bs, const DexFile *df, int typeCode)
	{
		const DexMapList* map_list = dexGetMap(df);
		unsigned int i;
		for (i=0; i < map_list->size; i++)
  		{
  			DexMapItem dex_map_item = map_list->list[i];
  			if (dex_map_item.type == typeCode)
  			{
  				const u1* ptr = df->baseAddr + dex_map_item.offset;
  				bsseek(bs,dex_map_item.offset);
				/*
				size is tricky , not sure it's OK
				the type_list is memory mapping 
				*/
				size_t data_size = 0;
				if (i!= map_list->size -1 )
				{
					data_size = map_list->list[i+1].offset - dex_map_item.offset;
				}
  				else
  				{
  					data_size = df->pHeader->fileSize - dex_map_item.offset;
  				}

  				bswrite(bs,(uint8_t*)ptr,data_size);
  			}
  		}

	}


	int read_classdata_length(const u1* cd){
		const u1* start = cd;
		DexClassDataHeader *pHeader = new DexClassDataHeader;
		dexReadClassDataHeader(&cd, pHeader);
        //GOSSIP("staticFieldsSize: %d", pHeader->staticFieldsSize);  
        //GOSSIP("instanceFieldsSize: %d", pHeader->instanceFieldsSize); 
        //GOSSIP("directMethodsSize: %d", pHeader->directMethodsSize); 
        //GOSSIP("virtualMethodsSize: %d", pHeader->virtualMethodsSize);   


		int number = 2*(pHeader->staticFieldsSize+pHeader->instanceFieldsSize)+3*(pHeader->directMethodsSize+pHeader->virtualMethodsSize);
		for(int i=0;i<number;i++){
			readUnsignedLeb128(&cd);
			//GOSSIP("Leb128----: %d", a);
	    }
	    const u1* end = cd;
	    int length = (int)(end-start);
	    //GOSSIP("Leb128----addr: %d", length);
	    int methodNum = pHeader->directMethodsSize+pHeader->virtualMethodsSize;
	    return length+4*methodNum+4;  //!!!!!!!!!!!!  1 classdata may have more than 1 codeoff which will be changed.
	}


	int read_strdata_length(const u1* str){
		int length = 0;
  		while(true){
             if(str[length]==0x00){
             	return length+1;
             }
             length++;
  		}
	}

	int read_typelist_length(const u1* tyl){
		const DexTypeList* dtl = (const DexTypeList*)tyl;
		int length = 0;
    	if(dtl->size%2){//fill for 4 bytes
    		length = (dtl->size+1)*2+4;
    	}else{
    		length = dtl->size*2+4;
    	}
        return length;
	}


	int read_encodedarray_length(const u1* ea){
		
		int length = 0;
		const u1* start = ea;
		int number = readUnsignedLeb128(&ea);
		//GOSSIP("EncodedNumber: %d", number);
		const u1* end = ea;
		
		//int size = (((int)ea[0]) - ((int)ea[0])%32)/32 + 1;
		int i=0;
		
		while(true){
			if(i==number){
				break;
			}
			int value = (int)ea[length];  //1 byte for value type,first 3bits is type,last 5 bits is (size-1)
			int type = value%32;// the type is high 3 bits
			int size=0;

			if(type==31||type==30){//when the type is NULL or BOOLEAN , the value size is 0
				size = 0;
			}
			else if(type==29||type ==28){
				GOSSIP("EncodedArray:Static Value May Have ERROR!!!!!!!!!!!!!");
				size = 0;
			}
			else{
				size = (value - value%32)/32 +1;  // the value size is low 5 bits
			}

			//GOSSIP("EncodedSize: %d", size);
			//GOSSIP("EncodedType: %d", type);

			length = length + size + 1;
			i++;


		}
		length = length+end-start;

        return length;
	}

	int read_code_length(const u1* co){
		int length = (int)dexGetDexCodeSize((const DexCode*) co);
		//GOSSIP("codeSize: %d", length);
		return fill_4_byte(length);
	}

	int read_debuginfo_length(const u1* di){
		const u1* start = di;
		readUnsignedLeb128(&di);
		int number = (int)readUnsignedLeb128(&di);
		for(int i=0;i<number;i++){
			readUnsignedLeb128(&di);
		}
		//const u1* end = di;


		int length = 0;
		/*
  		while(true){
             if(di[length]==0x00){
             	break;
             }
             length++;
  		}*/

  		while(true){
            if(di[0]==0x00){
            	di=di+1;
            	break;
  			}
  			else if(di[0]==0x01){
  				di=di+1;
  				readUnsignedLeb128(&di);
  			}
  			else if(di[0]==0x02){
  				di=di+1;
  				readSignedLeb128(&di);
  			}
  			else if(di[0]==0x03){
  				di=di+1;
  				readUnsignedLeb128(&di);
  				readUnsignedLeb128(&di);
  				readUnsignedLeb128(&di);
  			}
  			else if(di[0]==0x04){
  				di=di+1;
  				readUnsignedLeb128(&di);
  				readUnsignedLeb128(&di);
  				readUnsignedLeb128(&di);
  				readUnsignedLeb128(&di);
  			}
  			else if(di[0]==0x05){
  				di=di+1;
  				readUnsignedLeb128(&di);
  			}
  			else if(di[0]==0x06){
  				di=di+1;
  				readUnsignedLeb128(&di);
  			}
  			else if(di[0]==0x07){
  				di=di+1;
  			}
  			else if(di[0]==0x08){
				di=di+1;
  			}
  			else if(di[0]==0x09){
  				di=di+1;
                readUnsignedLeb128(&di);
  			}
  			else{
  				di=di+1;
  			}

  		}


  		//GOSSIP("head: %d", (int)(end-start));
  		//GOSSIP("body: %d", length+1);
  		//length=length+1+(int)(end-start);
  		length = (int)(di-start);
  		//GOSSIP("debuginfo size: %d", length);
		return length;
	}



	void writeClassData(const u1* pClassData,int off,ByteStream* bs){
  			DexClassData* pCD = (DexClassData*)pClassData;
  			//GOSSIP("staticFieldsSize:%d",pCD->header.staticFieldsSize);
  			//GOSSIP("instanceFieldsSize:%d",pCD->header.instanceFieldsSize);
  			//GOSSIP("directMethodsSize:%d",pCD->header.directMethodsSize);
  			//GOSSIP("virtualMethodsSize:%d",pCD->header.virtualMethodsSize);
  			if(pCD!=NULL){
  				
  				u1 start[5] = {0};

  				
  				u1* temp;
  				temp = start;


  				temp = writeUnsignedLeb128(start, pCD->header.staticFieldsSize);
  			    int size = (int)temp-(int)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("sfs:--%d",pCD->header.staticFieldsSize);
		        //GOSSIP("sfs:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.instanceFieldsSize);
  			    size = (int)temp-(int)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("ifs:--%d",pCD->header.instanceFieldsSize);
		        //GOSSIP("ifs:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.directMethodsSize);
  			    size = (int)temp-(int)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("dms:--%d",pCD->header.directMethodsSize);
		        //GOSSIP("dms:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.virtualMethodsSize);
  			    size = (int)temp-(int)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("vms:--%d",pCD->header.virtualMethodsSize);
		        //GOSSIP("vms:--%x",*start);
		        
		        off = off +size;

		        for(unsigned int i=0;i<pCD->header.staticFieldsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->staticFields[i].fieldIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->staticFields[i].fieldIdx-pCD->staticFields[i-1].fieldIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->staticFields[i].fieldIdx);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("sf_fid:--%d",pCD->staticFields[i].fieldIdx);
		            //GOSSIP("sf_fid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->staticFields[i].accessFlags);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("sf_af:--%d",pCD->staticFields[i].accessFlags);
		            //GOSSIP("sf_af:--%x",*start);
			        
			        off = off +size;
		        }
		        for(unsigned int i=0;i<pCD->header.instanceFieldsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->instanceFields[i].fieldIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->instanceFields[i].fieldIdx-pCD->instanceFields[i-1].fieldIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->instanceFields[i].fieldIdx);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("if_fid:--%d",pCD->instanceFields[i].fieldIdx);
		            //GOSSIP("if_fid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->instanceFields[i].accessFlags);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("if_af:--%d",pCD->instanceFields[i].accessFlags);
		            //GOSSIP("if_af:--%x",*start);
			        
			        off = off +size;
		        }
		        for(unsigned int i=0;i<pCD->header.directMethodsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->directMethods[i].methodIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->directMethods[i].methodIdx-pCD->directMethods[i-1].methodIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->directMethods[i].methodIdx);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_mid:--%d",pCD->directMethods[i].methodIdx);
		            //GOSSIP("dm_mid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->directMethods[i].accessFlags);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_af:--%d",pCD->directMethods[i].accessFlags);
		            //GOSSIP("dm_af:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->directMethods[i].codeOff);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_cf:--%d",pCD->directMethods[i].codeOff);
		            //GOSSIP("dm_cf:--%x",*start);
			        
			        off = off +size;
		        }
		        for(unsigned int i=0;i<pCD->header.virtualMethodsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].methodIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].methodIdx-pCD->virtualMethods[i-1].methodIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].methodIdx);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_mid:--%d",pCD->virtualMethods[i].methodIdx);
		            //GOSSIP("vm_mid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].accessFlags);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_af:--%d",pCD->virtualMethods[i].accessFlags);
		            //GOSSIP("vm_af:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].codeOff);
	  			    size = (int)temp-(int)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_cf:--%d",pCD->virtualMethods[i].codeOff);
		            //GOSSIP("vm_cf:--%x",*start);
			        
			        off = off +size;
		        }

 
  			}

	}


	

	int fill_4_byte(int size){
		size = size + (4-size%4);
		return size;
	}





	void dexbuild(const DexFile* df,const char* filename, Object* loader){
		bool IsOdex = false;
		int OdexAddrOff = 0;

		GOSSIP("----------------------DEX BUILD START");
 		unsigned int i;
 		//uint32_t offset;
 		if (df == NULL) return;

 		const DexHeader *dh = df->pHeader;
 		const DexOptHeader* doh;

//----------------------------------------------------- 
 	    GOSSIP("----------------------Get Odex");
 	    if(IsOdex){
 	    	doh = df->pOptHeader;
 	    	OdexAddrOff = sizeof(DexOptHeader)+fill_4_byte(doh->depsLength)+fill_4_byte(doh->optLength);
 	    }
        


//-------------------------------------------------------------------------------intial Data 

        
        int baseAddr = 0+OdexAddrOff;
    	int StrIDAddr = sizeof(DexHeader)+OdexAddrOff;
    	int TypeIDAddr = StrIDAddr+dh->stringIdsSize*sizeof(DexStringId)+OdexAddrOff;
    	int ProtoIDAddr = TypeIDAddr+dh->typeIdsSize*sizeof(DexTypeId)+OdexAddrOff;
    	int FiledIDAddr = ProtoIDAddr+dh->protoIdsSize*sizeof(DexProtoId)+OdexAddrOff;
    	int MethodIDAddr = FiledIDAddr+dh->fieldIdsSize*sizeof(DexFieldId)+OdexAddrOff;
    	int ClassDefAddr = MethodIDAddr+dh->methodIdsSize*sizeof(DexMethodId)+OdexAddrOff;
    	int MapAddr = ClassDefAddr+dh->classDefsSize*sizeof(DexClassDef)+OdexAddrOff;

    	int TypeListAddr = MapAddr+4+18*sizeof(DexMapItem)+OdexAddrOff;
    	int ClassDataAddr = 0;
    	int CodeAddr = 0;
    	int StrDataAddr = 0;
    	int DebugAddr = 0;
    	int EncodedAddr = 0;
    	int EndAddr = 0;




 //----------------------------------------------------- 

    	GOSSIP("----------------------Get Map");
    	//const DexMapList* map_list = dexGetMap(df);
    	//int MyDexMapItem[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//same as the original dexmap

    	int TestDexMapItem[]={1,1,1,1,1,1,1,1,1,0,0,1,1,1,1,0,1,0};//test
    	u4 TestMapSize = 14;

		/*for(i=0;i<map_list->size;i++){
			DexMapItem dex_map_item = map_list->list[i];
			switch(dex_map_item.type){
				case 0x0000:
				MyDexMapItem[0]=1;
				break;
				case 0x0001:
				MyDexMapItem[1]=1;
				break;
				case 0x0002:
				MyDexMapItem[2]=1;
				break;
				case 0x0003:
				MyDexMapItem[3]=1;
				break;
				case 0x0004:
				MyDexMapItem[4]=1;
				break;
				case 0x0005:
				MyDexMapItem[5]=1;
				break;
				case 0x0006:
				MyDexMapItem[6]=1;
				break;
				case 0x1000:
				MyDexMapItem[7]=1;
				break;
				case 0x1001:
				MyDexMapItem[8]=1;
				break;
				case 0x1002:
				MyDexMapItem[9]=1;
				break;
				case 0x1003:
				MyDexMapItem[10]=1;
				break;
				case 0x2000:
				MyDexMapItem[11]=1;
				break;
				case 0x2001:
				MyDexMapItem[12]=1;
				break;
				case 0x2002:
				MyDexMapItem[13]=1;
				break;
				case 0x2003:
				MyDexMapItem[14]=1;
				break;
				case 0x2004:
				MyDexMapItem[15]=1;
				break;
				case 0x2005:
				MyDexMapItem[16]=1;
				break;
				case 0x2006:
				MyDexMapItem[17]=1;
				break;
      
			}
		}


		for(int i=0;i<18;i++){
			GOSSIP("MAP %d", MyDexMapItem[i]);
		}*/


 //----------------------------------------------------- 
		GOSSIP("----------------------Get StrData");

        std::vector<const u1*>* v_StrData = new std::vector<const u1*>;
        std::vector<int>* v_StrDataLength = new std::vector<int>;
        int StrDataSize = 0;
        

        
        for (i = 0; i < dh -> stringIdsSize; i++)
  		{
  			const DexStringId* dsi = dexGetStringId(df,i);
  			const u1* ptr = df->baseAddr + dsi->stringDataOff;
            v_StrData->push_back(ptr);
            //free(dsi);
  		}

  		for(i=0;i<v_StrData->size();i++){
  			int size = read_strdata_length(v_StrData->at(i));
  			v_StrDataLength->push_back(size);
  			StrDataSize = StrDataSize+size;
  		}

  		for (i = 0; i < dh -> stringIdsSize; i++)
  		{
  			//GOSSIP("STRsize %d", v_StrDataLength[i]);
  		}
  		GOSSIP("STR totalsize %d", StrDataSize);





 //----------------------------------------------------- 
  		GOSSIP("----------------------Get TypeList");
  		std::vector<const u1*>* v_TypelistData = new std::vector<const u1*>;
  		std::vector<int>* v_TypelistSize=new std::vector<int>;
  		int TypelistSize = 0;

  		for(i = 0;i<dh->protoIdsSize;i++){
  			const DexProtoId* dpi = dexGetProtoId(df, i);
  			const u1* addr = df->baseAddr+dpi->parametersOff;
            int lock = 1;
			for(unsigned int j=0;j<v_TypelistData->size();j++){
				if(v_TypelistData->at(j)==addr){
					lock = 0;
				}
			}
			if(dpi->parametersOff!=0){
				if(lock==1){
					v_TypelistData->push_back(addr);
					//GOSSIP("TypeListAddr %d", dpi->parametersOff);
			    }
			}
			//free(dpi);  			
			
  		}

  		for(i=0;i<dh->classDefsSize;i++){
  			const DexClassDef* dcd = dexGetClassDef(df, i);
  			const u1* addr = df->baseAddr+dcd->interfacesOff;
  			int lock = 1;
			for(unsigned int j=0;j<v_TypelistData->size();j++){
				if(v_TypelistData->at(j)==addr){
					lock = 0;
				}
			}
			if(dcd->interfacesOff!=0){
				if(lock==1){
					v_TypelistData->push_back(addr);
					//GOSSIP("TypeListAddr %d", dcd->interfacesOff);
			    }
			}
			//free(dcd);  			
			
  		}


        for(i=0;i<v_TypelistData->size();i++){
        	int size =  read_typelist_length(v_TypelistData->at(i));
        	v_TypelistSize->push_back(size);
        	TypelistSize=TypelistSize+size;
        }

        for(i=0;i<v_TypelistSize->size();i++){
        	//GOSSIP("TypeListSize %d", v_TypelistSize[i]);
        }
        GOSSIP("TypeListtotalSize %d", TypelistSize);

 //-----------------------------------------------------
        GOSSIP("----------------------Get Encoded");
        std::vector<const u1*>* v_EncodedData=new std::vector<const u1*>;
        std::vector<int>* v_EncodedSize=new std::vector<int>;
        int EncodeSize = 0;

		for(i=0;i<dh->classDefsSize;i++){
  			const DexClassDef* dcd = dexGetClassDef(df, i);
  			const u1* addr = df->baseAddr+dcd->staticValuesOff;
  			int lock = 1;
			for(unsigned int j=0;j<v_EncodedData->size();j++){
				if(v_EncodedData->at(j)==addr){
					lock = 0;
				}
			}
			if(dcd->staticValuesOff!=0){
				if(lock==1){
					v_EncodedData->push_back(addr);
					//GOSSIP("EncodedAddr %d", dcd->staticValuesOff);
			    }
			}
			//free(dcd);  			
			
  		}   

  		for(i=0;i<v_EncodedData->size();i++){
  			int size = read_encodedarray_length(v_EncodedData->at(i));
  			v_EncodedSize->push_back(size);
  			EncodeSize=EncodeSize+size;
  		}

  		for(i=0;i<v_EncodedSize->size();i++){
  			//GOSSIP("EncodedSize %d", v_EncodedSize[i]);
  		}

  		GOSSIP("EncodedtotalSize %d", EncodeSize);

 //-----------------------------------------------------
  		GOSSIP("----------------------Get ClassData");
  		std::vector<const u1*>* v_ClassData=new std::vector<const u1*>;
        	std::vector<int>* v_ClassDataSize=new std::vector<int>;
        	int ClassDtataSize=0;

        	for(i=0;i<dh->classDefsSize;i++){
  			const DexClassDef* dcd = dexGetClassDef(df, i);
			
  			const u1* addr = df->baseAddr+dcd->classDataOff;
			//YWB
			if (dcd->classIdx == 0x17c)
			{
				GOSSIP("0x17c %s", dexGetClassDescriptor(df, dcd));
				//const u1* viraddr = addr+0x19520-0x19497;
				/*
				for (int i = 0; i<37; i++)
				{
					GOSSIP("%x", *(viraddr+i));
				}
				*/	
				const u1* orderCodeOff = addr + 0x19541 - 0x19497;
				const u4 xx = readUnsignedLeb128(&orderCodeOff);
				GOSSIP("codeOff %d", xx);
				const u1* ordercode = df->baseAddr + xx; 
				for (int i = 18; i< 50; i++)
				{
					GOSSIP("%x", *(ordercode+i));
				}
				ClassObject * coreClazz = dvmFindClass("Lmm/purchasesdk/core/PurchaseCore;", loader);
				Method *orderMethod = dvmFindVirtualMethodByName(coreClazz, "order" );
				const u2* iii = orderMethod->insns;
				for (int i = 0; i<32; i++)
				{
					GOSSIP("%x",*(iii+i));
				}
			}
			//YWB	
  			int lock = 1;
			for(unsigned int j=0;j<v_ClassData->size();j++){
				if(v_ClassData->at(j)==addr){
					lock = 0;
				}
			}
			if(dcd->classDataOff!=0){
				if(lock==1){
					v_ClassData->push_back(addr);
					//GOSSIP("ClassDataAddr %d", dcd->classDataOff);
			    }
			}
			//free(dcd);  			
			
  		}

        
  		for(i=0;i<v_ClassData->size();i++){
  			/*int size;
  			if(i==347){
  				size = read_classdata_length2(v_ClassData[i]);
  			}else{
  				size = read_classdata_length(v_ClassData[i]);
  			}*/
  			int size = read_classdata_length(v_ClassData->at(i));
  			v_ClassDataSize->push_back(size);
  			ClassDtataSize =ClassDtataSize+size;
  		}

  		for(i=0;i<v_ClassDataSize->size();i++){
  			//GOSSIP("ClassDataSize %d", v_ClassDataSize[i]);
  		}

  		GOSSIP("ClassDatatotalSize %d", ClassDtataSize);


 //-----------------------------------------------------
  		GOSSIP("----------------------Get Code");
  		std::vector<const u1*>* v_CodeData=new std::vector<const u1*>;
  		std::vector<int>* v_CodeSize=new std::vector<int>;
  		int CodeSize=0;

  		for(i=0;i<v_ClassData->size();i++){
  			DexClassData* pClassData;
  			const u1* temp= new u1;
  			temp = v_ClassData->at(i);
  			//pClassData = dexReadAndVerifyClassData(&(v_ClassData[i]), NULL);
  			pClassData = dexReadAndVerifyClassData(&temp, NULL);//dexReadAndVerifyClassData will change the v_ClassData
  			if(pClassData!=NULL){
  				int number1 = pClassData->header.directMethodsSize;
  				int number2 = pClassData->header.virtualMethodsSize;
  				//GOSSIP("the %d classdata has %d d and %d v", i,number1,number2);
  				for(int j=0;j<number1;j++){
  					const u1* addr = pClassData->directMethods[j].codeOff+df->baseAddr;
  					if(pClassData->directMethods[j].codeOff!=0){
	  					int lock = 1;
	  					for(unsigned int k =0;k<v_CodeData->size();k++){
	  						if(addr==v_CodeData->at(k)){
	  							lock = 0;
	  						}
	  					}
	  					if(lock==1){
	  						v_CodeData->push_back(addr);
	  						//GOSSIP("CodeAddr %d", pClassData->directMethods[j].codeOff);
	  					}
  				    }
  				}
  				for(int j=0;j<number2;j++){
  					const u1* addr = pClassData->virtualMethods[j].codeOff+df->baseAddr;
  					if(pClassData->virtualMethods[j].codeOff!=0){
	  					int lock = 1;
	  					for(unsigned int k =0;k<v_CodeData->size();k++){
	  						if(addr==v_CodeData->at(k)){
	  							lock = 0;
	  						}
	  					}
	  					if(lock==1){
	  						v_CodeData->push_back(addr);
	  						//GOSSIP("CodeAddr %d", pClassData->virtualMethods[j].codeOff);
	  					}
  				    }
  				}
  			}
  			free(pClassData);
  		}

  		
  		//int read_code_length(const u1* co)
  		for(i=0;i<v_CodeData->size();i++){
  			int size = read_code_length(v_CodeData->at(i));
  			v_CodeSize->push_back(size);
  			CodeSize =CodeSize+size;
  		}

  		for(i=0;i<v_CodeSize->size();i++){
  			//GOSSIP("CodeSize %d", v_CodeSize[i]);
  		}

  		GOSSIP("CodetotalSize %d", CodeSize);

//-----------------------------------------------------
  		GOSSIP("----------------------Get Debug");
  		//std::vector<const u1*>* v_DebugData=new std::vector<const u1*>;
  		//std::vector<int>* v_DebugSize=new std::vector<int>;
  		int DebugSize=0;
  		/*

  		for(i=0;i<v_CodeData->size();i++){
  			const DexCode* dc = (const DexCode*)v_CodeData->at(i);
  			const u1* addr = df->baseAddr+dc->debugInfoOff;
  			int lock = 1;
			for(unsigned int j=0;j<v_DebugData->size();j++){
				if(v_DebugData->at(j)==addr){
					lock = 0;
				}
			}
			if(dc->debugInfoOff!=0){
				if(lock==1){
					v_DebugData->push_back(addr);
					//GOSSIP("DebugAddr %d", dc->debugInfoOff);
			    }
			}
			//free(dc);  		
  		}

  		for(i=0;i<v_DebugData->size();i++){
  			int size = read_debuginfo_length(v_DebugData->at(i));
  			v_DebugSize->push_back(size);
  			DebugSize = DebugSize+size;
  		}
  		for(i=0;i<v_DebugSize->size();i++){
  			//GOSSIP("DebugSize %d", v_DebugSize[i]);
  		}
  		GOSSIP("DebugtotalSize %d", DebugSize);
  		*/



//-------------------------------------------------------------------------------intial Obj 
  		GOSSIP("----------------------Make Addr");

		//std::map<const u1*,int> AddrMAP1;
  		std::map<const u1*,int>* AddrMAP = new std::map<const u1*,int>;
		std::map <const u1*,int>::iterator iter;

    	ClassDataAddr = TypeListAddr+fill_4_byte(TypelistSize)+OdexAddrOff;
    	CodeAddr = ClassDataAddr+fill_4_byte(ClassDtataSize)+OdexAddrOff;
    	StrDataAddr = CodeAddr+fill_4_byte(CodeSize)+OdexAddrOff;
    	DebugAddr = StrDataAddr+fill_4_byte(StrDataSize)+OdexAddrOff;
    	EncodedAddr = DebugAddr+fill_4_byte(DebugSize)+OdexAddrOff;
    	EndAddr = EncodedAddr+fill_4_byte(EncodeSize)+OdexAddrOff;

    	GOSSIP("baseAddr %d", baseAddr);
    	GOSSIP("StrIDAddr %d", StrIDAddr);
    	GOSSIP("TypeIDAddr %d", TypeIDAddr);
    	GOSSIP("ProtoIDAddr %d", ProtoIDAddr);
    	GOSSIP("FiledIDAddr %d", FiledIDAddr);
    	GOSSIP("MethodIDAddr %d", MethodIDAddr);
    	GOSSIP("ClassDefAddr %d", ClassDefAddr);
    	GOSSIP("MapAddr %d", MapAddr);
    	GOSSIP("TypeListAddr %d", TypeListAddr);
    	GOSSIP("ClassDataAddr %d", ClassDataAddr);
    	GOSSIP("CodeAddr %d", CodeAddr);
    	GOSSIP("StrDataAddr %d", StrDataAddr);
    	GOSSIP("DebugAddr %d", DebugAddr);
    	GOSSIP("EncodedAddr %d", EncodedAddr);
    	GOSSIP("EndAddr %d", EndAddr);


    	GOSSIP("----------------------Make AddrMap");
		if(v_TypelistData->size()!=0){
			for(i=0;i<v_TypelistData->size();i++){
					int off = 0;
					for(unsigned int j=0;j<i;j++){
						off = off+v_TypelistSize->at(j);
					}
					//AddrMAP1[v_TypelistData->at(i)] = TypeListAddr+off-baseAddr;
					AddrMAP->insert(std::map<const u1*,int>::value_type(v_TypelistData->at(i),TypeListAddr+off-baseAddr));
			}
		}

		if(v_StrData->size()!=0){
			for(i=0;i<v_StrData->size();i++){
					int off = 0;
					for(unsigned int j=0;j<i;j++){
						off = off+v_StrDataLength->at(j);
					}
					//AddrMAP1[v_StrData->at(i)] = StrDataAddr+off-baseAddr;
					AddrMAP->insert(std::map<const u1*,int>::value_type(v_StrData->at(i),StrDataAddr+off-baseAddr));
			}
		}


		if(v_EncodedData->size()!=0){
			for(i=0;i<v_EncodedData->size();i++){
					int off = 0;
					for(unsigned int j=0;j<i;j++){
						off = off+v_EncodedSize->at(j);
					}
					//AddrMAP1[v_EncodedData->at(i)] = EncodedAddr+off-baseAddr;
					AddrMAP->insert(std::map<const u1*,int>::value_type(v_EncodedData->at(i),EncodedAddr+off-baseAddr));
			}
		}

		if(v_ClassData->size()!=0){
			for(i=0;i<v_ClassData->size();i++){
					int off = 0;
					for(unsigned int j=0;j<i;j++){
						off = off+v_ClassDataSize->at(j);
					}
					//AddrMAP1[v_ClassData->at(i)] = ClassDataAddr+off-baseAddr;
					AddrMAP->insert(std::map<const u1*,int>::value_type(v_ClassData->at(i),ClassDataAddr+off-baseAddr));
					//GOSSIP("i: %d ----ori: %d-------new:%d",i, (int)v_ClassData[i]-(int)df->baseAddr,ClassDataAddr+off);

			}
		}

		if(v_CodeData->size()!=0){
			for(i=0;i<v_CodeData->size();i++){
					int off = 0;
					for(unsigned int j=0;j<i;j++){
						off = off+v_CodeSize->at(j);
					}
					//AddrMAP1[v_CodeData->at(i)] = CodeAddr+off-baseAddr;
					AddrMAP->insert(std::map<const u1*,int>::value_type(v_CodeData->at(i),CodeAddr+off-baseAddr));
			}
		}

		/*
		if(v_DebugData->size()!=0){
			for(i=0;i<v_DebugData->size();i++){
					int off = 0;
					for(unsigned int j=0;j<i;j++){
						off = off+v_DebugSize->at(j);
					}
					//AddrMAP[v_DebugData->at(i)] = DebugAddr+off-baseAddr;
					AddrMAP->insert(std::map<const u1*,int>::value_type(v_DebugData->at(i),DebugAddr+off-baseAddr));
			}
		}
		*/

		

    	//GOSSIP("AddrMAP %d", AddrMAP[v_TypelistData[0]]);
    	//GOSSIP("AddrMAP %d", AddrMAP[v_TypelistData[1]]);


//-------------------------------------------------------------------------------WriteFile

        
		ByteStream* bs = bsalloc(EndAddr);
		int offset = 0;

        if (bs == NULL) return;

        if(IsOdex){
        	GOSSIP("----------------------ODEX BUILD HEADER");
        	offset = 0;
        	DexOptHeader* myOptHeader = new DexOptHeader;
        	memset(myOptHeader, 0, sizeof(DexOptHeader));
		    memcpy(myOptHeader, doh, sizeof(DexOptHeader));

		    
		    myOptHeader->magic[0]=0x64;
		    myOptHeader->magic[1]=0x65;
		    myOptHeader->magic[2]=0x79;
		    myOptHeader->magic[3]=0x0a;
		    myOptHeader->magic[4]=0x30;
		    myOptHeader->magic[5]=0x33;
		    myOptHeader->magic[6]=0x36;
		    myOptHeader->magic[7]=0x00;

		    myOptHeader->dexOffset = baseAddr;
		    myOptHeader->dexLength = EndAddr-baseAddr;
		    myOptHeader->depsOffset = sizeof(DexOptHeader);
		    myOptHeader->optOffset = sizeof(DexOptHeader)+fill_4_byte(doh->depsLength);

		    dxb_oheader(bs,myOptHeader,offset);
		    free(myOptHeader);


		    GOSSIP("----------------------ODEX BUILD dependency");
		    GOSSIP("depsize:%d",fill_4_byte(doh->depsLength));

		    offset = sizeof(DexOptHeader);
    	    bsseek(bs,offset);
  		    bswrite(bs,(u1*)(df->baseAddr+fill_4_byte(doh->depsOffset)),fill_4_byte(doh->depsLength));

		    GOSSIP("----------------------ODEX BUILD optimized");
		    GOSSIP("optsize:%d",fill_4_byte(doh->optLength));

		    offset = sizeof(DexOptHeader)+fill_4_byte(doh->depsLength);
    	    bsseek(bs,offset);
  		    bswrite(bs,(u1*)(df->baseAddr+fill_4_byte(doh->optOffset)),fill_4_byte(doh->optLength));

        }



        GOSSIP("----------------------DEX BUILD HEADER");
        offset = baseAddr;
        DexHeader* myHeader = new DexHeader;
        //memset(myHeader, 0, dh->headerSize);
		//memcpy(myHeader, dh, dh->headerSize);
		memset(myHeader, 0, sizeof(DexHeader));
		memcpy(myHeader, dh, sizeof(DexHeader));

		//GOSSIP("TEST %d", myHeader->fileSize);
		//GOSSIP("TEST %d", myHeader->dataSize);

		/*
		myHeader->magic[0]=0x64;
		myHeader->magic[1]=0x65;
		myHeader->magic[2]=0x78;
		myHeader->magic[3]=0x0a;
		myHeader->magic[4]=0x30;
		myHeader->magic[5]=0x33;
		myHeader->magic[6]=0x35;
		myHeader->magic[7]=0x00;
		*/
			
		myHeader->magic[0]=0x00;
		myHeader->magic[1]=0x00;
		myHeader->magic[2]=0x00;
		myHeader->magic[3]=0x00;
		myHeader->magic[4]=0x00;
		myHeader->magic[5]=0x00;
		myHeader->magic[6]=0x00;
		myHeader->magic[7]=0x00;
		
		myHeader->headerSize=0x70;
		myHeader->fileSize = EndAddr-baseAddr;
		myHeader->mapOff = MapAddr-baseAddr;
		myHeader->stringIdsOff = StrIDAddr-baseAddr;
		myHeader->typeIdsOff = TypeIDAddr-baseAddr;
		myHeader->protoIdsOff = ProtoIDAddr-baseAddr;
		myHeader->fieldIdsOff = FiledIDAddr-baseAddr;
		myHeader->methodIdsOff = MethodIDAddr-baseAddr;
		myHeader->classDefsOff = ClassDefAddr-baseAddr;
		myHeader->dataSize = EndAddr-TypeListAddr;
		myHeader->dataOff = TypeListAddr-baseAddr;

		dxb_header(bs,myHeader,offset);
		free(myHeader);

		

		GOSSIP("----------------------DEX BUILD STRID");
		offset = StrIDAddr;
		
		for(i=0;i<dh -> stringIdsSize; i++){
			DexStringId* myStringId = new DexStringId;
			//memset(myStringId, 0, sizeof(u4));
			//memcpy(myStringId, df->pStringIds+i*(sizeof(u4)), sizeof(u4));
			
			const u1* ori = (const u1*)(df->pStringIds[i].stringDataOff+(int)df->baseAddr);
			//myStringId->stringDataOff = AddrMAP[ori];
			iter = AddrMAP->find(ori);
			if(iter!= AddrMAP->end()){
				myStringId->stringDataOff = iter->second;
			}else{
				myStringId->stringDataOff =0;
			}
			//myStringId->stringDataOff = AddrMAP->find(ori)->second;
			//GOSSIP("old %d, new %d", AddrMAP1[ori],myStringId->stringDataOff);
			dxb_stringid(bs,myStringId, offset);
			//GOSSIP("strdataoff %d", myStringId->stringDataOff);
  			offset = offset + sizeof(DexStringId);
  			free(myStringId);

		}

		GOSSIP("----------------------DEX BUILD TYPEID");
		offset = TypeIDAddr;
		for (i = 0; i < dh->typeIdsSize; i++)
  		{
  			dxb_typeid(bs, &(df->pTypeIds[i]), offset);
  			offset = offset + sizeof(DexTypeId);
  		}

  		offset = ProtoIDAddr;
  		for (i = 0; i< dh->protoIdsSize; i++)
    	{
    		DexProtoId* myProtoId = new DexProtoId;
    		memset(myProtoId, 0, sizeof(DexProtoId));
			memcpy(myProtoId, &(df->pProtoIds[i]), sizeof(DexProtoId));
			const u1* ori = (const u1*)(df->pProtoIds[i].parametersOff+(int)df->baseAddr);
			//myProtoId->parametersOff = AddrMAP[ori];
			iter = AddrMAP->find(ori);
			if(iter!= AddrMAP->end()){
				myProtoId->parametersOff = iter->second;
			}else{
				myProtoId->parametersOff =0;
			}
			//myProtoId->parametersOff = AddrMAP->find(ori)->second;
    		dxb_protoid(bs, myProtoId, offset);
    		//GOSSIP("dataoff %d", myProtoId->parametersOff);
    		offset = offset + sizeof(DexProtoId);
    		free(myProtoId);
    	}

    	GOSSIP("----------------------DEX BUILD FieldID");
    	offset = FiledIDAddr;
    	for (i = 0; i < dh->fieldIdsSize; i++)
    	{
    		dxb_fieldid(bs, &(df->pFieldIds[i]), offset);
    		offset = offset + sizeof(DexFieldId);
    	}

    	offset = MethodIDAddr;
  		for (i = 0; i < dh->methodIdsSize; i++)
  		{
  			dxb_methodid(bs, &(df->pMethodIds[i]), offset);
  			offset = offset + sizeof(DexMethodId);
  		}

  		GOSSIP("----------------------DEX BUILD ClassDef");

  		offset = ClassDefAddr;
  		for (i = 0; i < dh->classDefsSize; i++)
    	{
    		DexClassDef* myClassDef = (DexClassDef*)malloc(sizeof(DexClassDef));
    		memset(myClassDef, 0, sizeof(DexClassDef));
			memcpy(myClassDef, &(df->pClassDefs[i]), sizeof(DexClassDef));

			const u1* ori0 = (const u1*)(df->pClassDefs[i].interfacesOff+(int)df->baseAddr);//interfacesOff
			const u1* ori1 = (const u1*)(df->pClassDefs[i].classDataOff+(int)df->baseAddr);//classDataOff
			const u1* ori2 = (const u1*)(df->pClassDefs[i].staticValuesOff+(int)df->baseAddr);//staticValuesOff



			//myClassDef->interfacesOff = AddrMAP[ori0];
			iter = AddrMAP->find(ori0);
			if(iter!= AddrMAP->end()){
				myClassDef->interfacesOff = iter->second;
			}else{
				myClassDef->interfacesOff =0;
			}
			//myClassDef->interfacesOff = AddrMAP->find(ori0)->second;
			//myClassDef->classDataOff = AddrMAP[ori1];
			iter = AddrMAP->find(ori1);
			if(iter!= AddrMAP->end()){
				myClassDef->classDataOff =  iter->second;
			}else{
				myClassDef->classDataOff = 0;
			}
			//myClassDef->classDataOff = AddrMAP->find(ori1)->second;
			//myClassDef->staticValuesOff = AddrMAP[ori2];
			iter = AddrMAP->find(ori2);
			if(iter!= AddrMAP->end()){
				myClassDef->staticValuesOff =  iter->second;
			}else{
				myClassDef->staticValuesOff = 0;
			}
			//myClassDef->staticValuesOff = AddrMAP->find(ori2)->second;
			myClassDef->annotationsOff = 0;

			//for test
			myClassDef->accessFlags = myClassDef->accessFlags%0x30000;
            /*
            if(i==357){
            	GOSSIP("AAAAAAAA:%d",myClassDef->classDataOff);
            } */       

            //GOSSIP("offset:%d",offset);
            //GOSSIP("classid:%d",myClassDef->classIdx);
            //GOSSIP("acccess:%d",myClassDef->accessFlags);
    		dxb_classdef(bs, myClassDef, offset);
    		//GOSSIP("dataoff1 %d", myClassDef->interfacesOff);
    		//GOSSIP("dataoff2 %d ---- %d",df->pClassDefs[i].classDataOff, myClassDef->classDataOff);
    		//GOSSIP("dataoff3 %d", myClassDef->staticValuesOff);
    		offset = offset + sizeof(DexClassDef);
    		free(myClassDef);
    	}


    	GOSSIP("----------------------DEX BUILD Map");

    	offset = MapAddr;
    	bsseek(bs,offset);
  		bswrite(bs,(u1*)(&TestMapSize),sizeof(u4));
  		offset = offset + sizeof(u4);
    	for(i=0;i<18;i++){
    		if(TestDexMapItem[i]==1){
    			DexMapItem* myMapItem = new DexMapItem;
    			switch(i){
    				case 0:
    					myMapItem->type = 0x0000;
    					myMapItem->unused = 0;
    					myMapItem->size = 1;
    					myMapItem->offset = baseAddr-baseAddr;
    				break;
    				case 1:
    					myMapItem->type = 0x0001;
    					myMapItem->unused = 0;
    					myMapItem->size = dh -> stringIdsSize;
    					myMapItem->offset = StrIDAddr-baseAddr;
    				break;
    				case 2:
    					myMapItem->type = 0x0002;
    					myMapItem->unused = 0;
    					myMapItem->size = dh->typeIdsSize;
    					myMapItem->offset = TypeIDAddr-baseAddr;
    				break;
    				case 3:
    					myMapItem->type = 0x0003;
    					myMapItem->unused = 0;
    					myMapItem->size = dh->protoIdsSize;
    					myMapItem->offset = ProtoIDAddr-baseAddr;
    				break;
    				case 4:
    					myMapItem->type = 0x0004;
    					myMapItem->unused = 0;
    					myMapItem->size = dh->fieldIdsSize;
    					myMapItem->offset = FiledIDAddr-baseAddr;
    				break;
    				case 5:
    					myMapItem->type = 0x0005;
    					myMapItem->unused = 0;
    					myMapItem->size = dh->methodIdsSize;
    					myMapItem->offset = MethodIDAddr-baseAddr;
    				break;
    				case 6:
    					myMapItem->type = 0x0006;
    					myMapItem->unused = 0;
    					myMapItem->size = dh->classDefsSize;
    					myMapItem->offset = ClassDefAddr-baseAddr;
    				break;
    				case 7:
    					myMapItem->type = 0x1000;
    					myMapItem->unused = 0;
    					myMapItem->size = 1;
    					myMapItem->offset = MapAddr-baseAddr;
    				break;
    				case 8:
    					myMapItem->type = 0x1001;
    					myMapItem->unused = 0;
    					myMapItem->size = v_TypelistData->size();
    					myMapItem->offset = TypeListAddr-baseAddr;
    				break;
    				case 9:
    					myMapItem->type = 0x1002;
    					myMapItem->unused = 0;
    					myMapItem->size = 0;
    					myMapItem->offset = 0;
    				break;
    				case 10:
    					myMapItem->type = 0x1003;
    					myMapItem->unused = 0;
    					myMapItem->size = 0;
    					myMapItem->offset = 0;
    				break;
    				case 11:
    					myMapItem->type = 0x2000;
    					myMapItem->unused = 0;
    					myMapItem->size = v_ClassData->size();
    					myMapItem->offset = ClassDataAddr-baseAddr;
    				break;
    				case 12:
    					myMapItem->type = 0x2001;
    					myMapItem->unused = 0;
    					myMapItem->size = v_CodeData->size();
    					myMapItem->offset = CodeAddr-baseAddr;
    				break;
    				case 13:
    					myMapItem->type = 0x2002;
    					myMapItem->unused = 0;
    					myMapItem->size = v_StrData->size();
    					myMapItem->offset = StrDataAddr-baseAddr;
    				break;
    				case 14:
    					myMapItem->type = 0x2003;
    					myMapItem->unused = 0;
    					//myMapItem->size = v_DebugData->size();
						myMapItem->size =0;
    					myMapItem->offset = DebugAddr-baseAddr;
    				break;
    				case 15:
    					myMapItem->type = 0x2004;
    					myMapItem->unused = 0;
    					myMapItem->size = 0;
    					myMapItem->offset = 0;
    				break;
    				case 16:
    					myMapItem->type = 0x2005;
    					myMapItem->unused = 0;
    					myMapItem->size = v_EncodedData->size();
    					myMapItem->offset = EncodedAddr-baseAddr;
    				break;
    				case 17:
    					myMapItem->type = 0x2006;
    					myMapItem->unused = 0;
    					myMapItem->size = 0;
    					myMapItem->offset = 0;
    				break;
    			}
    			//GOSSIP("offset:%d",offset);
     			
     			bsseek(bs,offset);
  		        bswrite(bs,(u1*)&(myMapItem->type),sizeof(u2));
  		        offset = offset + sizeof(u2);
  		        //GOSSIP("type:%d",myMapItem->type);

  		        bsseek(bs,offset);
  		        bswrite(bs,(u1*)&(myMapItem->unused),sizeof(u2));
  		        offset = offset + sizeof(u2);
  		        //GOSSIP("unused:%d",myMapItem->unused);

  		        bsseek(bs,offset);
  		        bswrite(bs,(u1*)&(myMapItem->size),sizeof(u4));
  		        offset = offset + sizeof(u4);
  		        //GOSSIP("size:%d",myMapItem->size);

  		        bsseek(bs,offset);
  		        bswrite(bs,(u1*)&(myMapItem->offset),sizeof(u4));
  		        offset = offset + sizeof(u4);
  		        //GOSSIP("offset:%d",myMapItem->offset);



  		        free(myMapItem);
  		 
    		}
    	}
 

    	GOSSIP("----------------------DEX BUILD TypeList");
    	offset = TypeListAddr;
    	for(i=0;i<v_TypelistData->size();i++){
    		bsseek(bs,offset);
    		bswrite(bs,(u1*)v_TypelistData->at(i),v_TypelistSize->at(i));
    		offset = offset+v_TypelistSize->at(i);
    	}
    	free(v_TypelistData);
    	free(v_TypelistSize);

    
    	GOSSIP("----------------------DEX BUILD ClassData");
    	offset = ClassDataAddr;
    	for(i=0;i<v_ClassData->size();i++){
    		DexClassData* pClassData;
  			const u1* temp= new u1;
  			temp = v_ClassData->at(i);
  			//GOSSIP("v_ClassData:%d",(int)v_ClassData[i]-(int)df->baseAddr);
  			//pClassData = dexReadAndVerifyClassData(&(v_ClassData[i]), NULL);
  			pClassData = dexReadAndVerifyClassData(&temp, NULL);//dexReadAndVerifyClassData will change the v_ClassData
  			if(pClassData!=NULL){
  				int num1 = pClassData->header.directMethodsSize;
  				int num2 = pClassData->header.virtualMethodsSize;
  				for(int j=0;j<num1;j++){
  					const u1* ori = (const u1*)(pClassData->directMethods[j].codeOff+(int)df->baseAddr);
  					//pClassData->directMethods[j].codeOff = AddrMAP[ori];
                    iter = AddrMAP->find(ori);
					if(iter!= AddrMAP->end()){
						pClassData->directMethods[j].codeOff = iter->second;
					}else{
						pClassData->directMethods[j].codeOff =0;
					}

					//pClassData->directMethods[j].codeOff = AddrMAP->find(ori)->second;
					
  					//GOSSIP("old:%d new: %d",AddrMAP1[ori],pClassData->directMethods[j].codeOff);
  				}
  				for(int j=0;j<num2;j++){
  					const u1* ori = (const u1*)(pClassData->virtualMethods[j].codeOff+(int)df->baseAddr);
  					//pClassData->virtualMethods[j].codeOff = AddrMAP[ori];
					iter = AddrMAP->find(ori);
					if(iter!= AddrMAP->end()){
						pClassData->virtualMethods[j].codeOff = iter->second;
					}else{
						pClassData->virtualMethods[j].codeOff = 0;
					}
					//pClassData->virtualMethods[j].codeOff = AddrMAP->find(ori)->second;
  					//GOSSIP("dataoff %d ----new: %d",pClassData->virtualMethods[j].codeOff, AddrMAP[ori]);
  				}
  				
  		        /*if(offset==267521){
					GOSSIP("classdatasizeQQQQQQQ:%d",v_ClassDataSize[i]);
					GOSSIP("indexQQQQQQQ:%d",i);
  		        }*/
  				writeClassData((const u1*) pClassData,offset,bs);
  				offset = offset+v_ClassDataSize->at(i);
  				free(pClassData);
  			}


    	}
    	free(v_ClassData);
    	free(v_ClassDataSize);

    	
    	GOSSIP("----------------------DEX BUILD Code");
    	offset = CodeAddr;
    	for(i=0;i<v_CodeData->size();i++){
    		//GOSSIP("1");
    		DexCode* myCode = (DexCode*)malloc(v_CodeSize->at(i));
    		//GOSSIP("2");
    		memset(myCode, 0, v_CodeSize->at(i));
    		//GOSSIP("3");
			memcpy(myCode, v_CodeData->at(i), v_CodeSize->at(i));
			//GOSSIP("4");
			/*
			const u1* ori = (const u1*)(myCode->debugInfoOff+(int)df->baseAddr);
			myCode->debugInfoOff = AddrMAP[ori];
			if(myCode->debugInfoOff== 0xffffffff){
				GOSSIP("debugInfo!!!");
				myCode->debugInfoOff=0x00000000;
			}
			*/
			myCode->debugInfoOff =0x00000000;
			//GOSSIP("5");
			bsseek(bs,offset);
			//GOSSIP("6");
    		bswrite(bs,(u1*)(myCode),v_CodeSize->at(i));
    		//GOSSIP("7");
    		offset = offset+v_CodeSize->at(i);
    		free(myCode);
    	}
    	free(v_CodeData);
    	free(v_CodeSize);

    	GOSSIP("----------------------DEX BUILD StrData");
    	offset = StrDataAddr;
    	for(i=0;i<v_StrData->size();i++){
    		bsseek(bs,offset);
    		bswrite(bs,(u1*)v_StrData->at(i),v_StrDataLength->at(i));
    		offset = offset+v_StrDataLength->at(i);
    	}
    	free(v_StrData);
    	free(v_StrDataLength);

    	/*GOSSIP("----------------------DEX BUILD DebugInfo");
    	offset = DebugAddr;
    	for(i=0;i<v_DebugData->size();i++){
    		bsseek(bs,offset);
    		bswrite(bs,(u1*)v_DebugData->at(i),v_DebugSize->at(i));
    		offset = offset+v_DebugSize->at(i);
    	}
    	free(v_DebugData);
    	free(v_DebugSize);*/

    	GOSSIP("----------------------DEX BUILD Encoded");
    	offset = EncodedAddr;
    	for(i=0;i<v_EncodedData->size();i++){
    		bsseek(bs,offset);
    		bswrite(bs,(u1*)v_EncodedData->at(i),v_EncodedSize->at(i));
    		offset = offset+v_EncodedSize->at(i);
    	}
    	free(v_EncodedData);
    	free(v_EncodedSize);

    	
    	//AddrMAP.clear();
		free(AddrMAP);
    	GOSSIP("----------------------DEX BUILD Finish 0518");



/*
        dxb_header(bs,dh);
  		dxb_maplist(bs,df);

  		offset = dh->stringIdsOff;
  		for (i = 0; i < dh -> stringIdsSize; i++)
  		{
  			dxb_stringid(bs,&(df->pStringIds[i]), offset);
  			offset = offset + sizeof(DexStringId);
  		}

  		offset = dh->typeIdsOff;
  		for (i = 0; i < dh->typeIdsSize; i++)
  		{
  			dxb_typeid(bs, &(df->pTypeIds[i]), offset);
  			offset = offset + sizeof(DexTypeId);
  		}
    	
    	offset = dh->protoIdsOff;	
  		for (i = 0; i< dh->protoIdsSize; i++)
    	{
    		dxb_protoid(bs, &(df->pProtoIds[i]), offset);
    		offset = offset + sizeof(DexProtoId);
    	}	

    	offset = dh->fieldIdsOff;
  		for (i = 0; i < dh->fieldIdsSize; i++)
    	{
    		dxb_fieldid(bs, &(df->pFieldIds[i]), offset);
    		offset = offset + sizeof(DexFieldId);
    	}	

    	offset = dh->methodIdsOff;
  		for (i = 0; i < dh->methodIdsSize; i++)
  		{
  			dxb_methodid(bs, &(df->pMethodIds[i]), offset);
  		for (i = 0; i < dh->classDefsSize; i++)
    	{
    		dxb_classdef(bs, &(df->pClassDefs[i]), offset);
    		offset = offset + sizeof(DexClassDef);
    	}

    	
		//all of the following section is memory mapping
		//which means the offset may be incorrect 
		//because it can be modified by the app itself in native code
    	
    	//mem maping
    	for (i = 0; i < dh -> stringIdsSize; i++)
    	{
    		dxb_stringdata(bs, &(df->pStringIds[i]), df);
    	}

    	//mem mapping
    	dxb_map_list_item(bs, df, kDexTypeTypeList);
    	dxb_map_list_item(bs, df, kDexTypeAnnotationsDirectoryItem);
    	dxb_map_list_item(bs, df, kDexTypeClassDataItem);
    	dxb_map_list_item(bs, df, kDexTypeEncodedArrayItem);
    	dxb_map_list_item(bs, df, kDexTypeCodeItem);
    	dxb_map_list_item(bs, df, kDexTypeDebugInfoItem);
    	dxb_map_list_item(bs, df, kDexTypeAnnotationSetItem);
    	dxb_map_list_item(bs, df, kDexTypeAnnotationSetRefList);
    	dxb_map_list_item(bs, df, kDexTypeAnnotationItem);

    	
 */   		


  		bssave(bs,filename);

  		bsfree(bs);



	}

	void printOdex(const DexFile *df)
	{
		const DexOptHeader* h = df->pOptHeader;
		GOSSIP("====odex header======");
		GOSSIP("odex header addr: %p", h);
		GOSSIP("dex offset: 0x%x, dex length: 0x%x", h->dexOffset, h->dexLength);
		GOSSIP("depsOffset 0x%x, depsLength 0x%x", h->depsOffset, h->depsLength);
		GOSSIP("optOffset 0x%x, optLength 0x%x", h->optOffset, h->optLength);
		GOSSIP("flags 0x%x, checksum 0x%x", h->flags, h->checksum);


	}

	


}
