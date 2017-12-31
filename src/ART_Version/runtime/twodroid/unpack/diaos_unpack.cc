#include "twodroid/unpack/diaos_unpack.h"
#include <fstream>
#include <string.h>
#include <vector>
#include <map>
#include <stdlib.h>
#include <iostream>
#include "bytestream.h"
#include "dex_file.h"
#include "leb128.h"
#include "twodroid/Constant.h"
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "twodroid/unpack/dalvik_tool.h"

using ::art::DexFile;


namespace gossip {

	static bool Flag_Mode = true;
	static bool Flag_logmap = true;
	static bool Flag_logcm = true;
	static bool Flag_logins = true;

	//void dexbuild_lbd(art::mirror::ArtMethod*  method, const char* filename) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	void* dexbuild_lbd(void *arg);// SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	
	//int GetStrData(const art::DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_StrData, std::vector<int>* v_StrDataLength);
	int GetStrData(const DexFile::Header& dh);
	//int GetTypeList(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize);
	int GetTypeList(const DexFile::Header& dh);
	//int GetEncoded(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize);
	int GetEncoded(const DexFile::Header& dh);
	//int GetClassData(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize);
	int GetClassData(const DexFile::Header& dh);
	//int GetCode(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<u4>* v_mid,std::vector<u4>* v_DorV,std::vector<const u1*>* v_ClassData);
	int GetCode(const DexFile::Header& dh);

	void MakeAddrMap(std::map<const u1*,int>* AddrMAP,std::vector<const u1*>* v_Data,std::vector<int>* v_Size,int baseAddr,int Addr);
	//void MakeAddrMap();
	
	//int  BuildHeader(ByteStream* bs, int offset,const DexFile::Header& dh,int baseAddr,int EndAddr,int MapAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int TypeListAddr);
	int  BuildHeader(const DexFile::Header& dh);
	//int  BuildStrID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,std::map<const u1*,int>* AddrMAP,int StrIDAddr);
	int  BuildStrID(const DexFile::Header& dh);
	//int  BuildTypeID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,int TypeIDAddr);
	int  BuildTypeID(const DexFile::Header& dh);
	//int  BuildProtoID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,std::map<const u1*,int>* AddrMAP,int ProtoIDAddr);
	int  BuildProtoID(const DexFile::Header& dh);
	//int  BuildFieldID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,int FiledIDAddr);
	int  BuildFieldID(const DexFile::Header& dh);
	//int  BuildMethodID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,int MethodIDAddr);
	int  BuildMethodID(const DexFile::Header& dh);
	//int  BuildClassDef(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,std::map<const u1*,int>* AddrMAP,int ClassDefAddr);
	int  BuildClassDef(const DexFile::Header& dh);

	//int  BuildMap(ByteStream* bs, int offset,const DexFile::Header& dh,
	//	 int baseAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int MapAddr,int TypeListAddr,int ClassDataAddr,int CodeAddr,int StrDataAddr,int DebugAddr,int EncodedAddr,int EndAddr,
	//	 std::vector<const u1*>* v_TypelistData,std::vector<const u1*>* v_ClassData,std::vector<const u1*>* v_CodeData,std::vector<const u1*>* v_StrData,std::vector<const u1*>* v_EncodedData
	//	 );

	int  BuildMap(const DexFile::Header& dh);

	//int BuildTypeList(ByteStream* bs, int offset,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize,int TypeListAddr);
	//int BuildClassData(ByteStream* bs, int offset,const DexFile* df,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize,std::map<const u1*,int>* AddrMAP,int ClassDataAddr);
	//int BuildCode(ByteStream* bs, int offset,const DexFile* df,art::mirror::ClassLoader* classloader,art::mirror::DexCache* dexcache,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<u4>* v_mid,std::vector<u4>* v_DorV,int CodeAddr) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	//int BuildStrData(ByteStream* bs, int offset,std::vector<const u1*>* v_StrData,std::vector<int>* v_StrDataLength,int StrDataAddr);
	//int BuildEncoded(ByteStream* bs, int offset,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize,int EncodedAddr);

	int BuildTypeList();
	int BuildClassData();
	int BuildCode();// SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	int BuildStrData();
	int BuildEncoded();


	void dxb_header(ByteStream *bs, const DexHeader *header,uint32_t offset);
	void dxb_stringid(ByteStream* bs, const DexStringId *obj, uint32_t offset);
	void dxb_typeid(ByteStream* bs, const DexFile::TypeId *obj, uint32_t offset);
	void dxb_protoid(ByteStream* bs, const DexProtoId *obj, uint32_t offset);
	void dxb_fieldid(ByteStream* bs, const DexFile::FieldId *obj, uint32_t offset);
	void dxb_methodid(ByteStream* bs, const DexFile::MethodId *obj, uint32_t offset);
	void dxb_classdef(ByteStream* bs, const DexClassDef *obj, uint32_t offset);

	int read_strdata_length(const u1* str);
	int read_typelist_length(const u1* tyl);
	int read_encodedarray_length(const u1* ea);
	int read_classdata_length(const u1* cd);
	int read_code_length(const u1* co);
	void writeClassData(const u1* pClassData,int off,ByteStream* bs);
	int fill_4_byte(int size);
	void initflag();
	bool CheckStr(const char* s1, const char* s2);
	bool CheckStr2(const char* s1, const char* s2);
	void test_debug();

	art::mirror::ArtMethod*  U_method;
	const char* U_filename;
	const char* U_dirname;
	int U_filenamelength;

	const art::DexFile*  df;
	art::mirror::DexCache* dexcache;
	art::mirror::ClassLoader* classloader;
	//const DexFile::Header& dh;

	int baseAddr;
	int StrIDAddr;
	int TypeIDAddr;
	int ProtoIDAddr;
	int FiledIDAddr;
	int MethodIDAddr;
	int ClassDefAddr;
	int MapAddr;

	int TypeListAddr;
	int ClassDataAddr;
	int CodeAddr;
	int StrDataAddr;
	int DebugAddr;
	int EncodedAddr;
	int EndAddr;

	std::vector<const u1*>* v_StrData;
	std::vector<int>* v_StrDataLength;
	int StrDataSize;

	std::vector<const u1*>* v_TypelistData;
	std::vector<int>* v_TypelistSize;
    int TypelistSize;

    std::vector<const u1*>* v_EncodedData;
    std::vector<int>* v_EncodedSize;
    int EncodeSize;

    std::vector<const u1*>* v_ClassData;
    std::vector<int>* v_ClassDataSize;
    int ClassDtataSize;


    std::vector<const u1*>* v_CodeData;
	std::vector<int>* v_CodeSize;
	std::vector<u4>* v_mid;
    std::vector<u4>* v_DorV;
    int CodeSize;

    int DebugSize;

    std::map<const u1*,int>* AddrMAP;
	std::map <const u1*,int>::iterator iter;

	ByteStream* bs;
	int offset;


	art::ClassLinker* class_linker;
	art::Thread *self;
	art::Runtime* runtime;
	









	
/*	
	class lbdThread
	{
	    private:
	        pthread_t pid;
	    private:
	        static void * start_thread(void *arg);
	    public:
	        int start();
	        virtual void run() = 0;
	};


	int lbdThread::start() 
	{
	        if(pthread_create(&pid,NULL,start_thread,(void *)this) != 0)
	        {      
	            return -1;
	        }      
	        return 0;
	}

	void* lbdThread::start_thread(void *arg)
	{
	    lbdThread *ptr = (lbdThread *)arg;
	    ptr->run();      
		return NULL;
	}


	class MyThread:public lbdThread
	{
	    public:
			art::mirror::ArtMethod*  method;
			const char* filename;
			MyThread(art::mirror::ArtMethod*  method,const char* filename);
	        void run() SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	};

	MyThread::MyThread(art::mirror::ArtMethod*  method,const char* filename)
	{
	    MyThread::method = method;
		MyThread::filename=filename;
	}

	void MyThread::run()
	{
	    dexbuild_lbd(method, filename);
	}
*/
/*
	class UThread
	{
	    private:
	        pthread_t pid;
	        //art::mirror::ArtMethod*  method;
			//const char* filename;
	        static void * start_thread(void *arg) SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	    public:
	    	//UThread(art::mirror::ArtMethod*  method,const char* filename);
	    	UThread();
	        int start() SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	        void run() SHARED_LOCKS_REQUIRED(art::Locks::mutator_lock_);
	};

	//UThread::UThread(art::mirror::ArtMethod*  method,const char* filename){
	UThread::UThread(){
		//UThread::method = method;
		//UThread::filename=filename;
		//LOG(WARNING) << "UCHIHALART  filename2 "<< UThread::filename;
	}

	int UThread::start() 
	{
        if(pthread_create(&pid,NULL,start_thread,(void *)this) != 0)
        {      
            return -1;
        }      
        return 0;
	}

	void* UThread::start_thread(void *arg)
	{
	    UThread *ptr = (UThread *)arg;
	    ptr->run();      
		return NULL;
	}

	void UThread::run()
	{
	    //LOG(WARNING) << "UCHIHALART  filename3 "<< filename;
	    //dexbuild_lbd(method, filename);
	    dexbuild_lbd();
	}

*/

	void dexbuild(art::mirror::ArtMethod*  method, const char* filename, const char* dirname){
		LOG(WARNING) << "UCHIHALART dexbuild  ";

	    U_method = method;
	    U_filename = filename;
	    U_filenamelength = strlen(U_filename);
	    U_dirname = dirname;
	    //self=art::Thread::Current();

        

	    
		//self=art::Thread::Current();
		//UThread unpackthread(method,filename);
        pthread_t pid;
	    pthread_create(&pid,NULL,dexbuild_lbd,NULL);


		//UThread unpackthread();
    	//unpackthread.start();
	}



	//void dexbuild_lbd(art::mirror::ArtMethod*  method, const char* filename){
	void * dexbuild_lbd(void *arg){
		LOG(WARNING) << "UCHIHALART dexbuild_lbd  ";

		sleep(5);
		LOG(WARNING) << "UCHIHALART sleep ok  ";
		//const DexFile::Header& dh = df->GetHeader();
		//ByteStream* bs = bsalloc(dh.file_size_);
		//bsseek(bs,0);
		//bswrite(bs,(u1*)df->Begin(),dh.file_size_);
		//bssave(bs,filename);
        //bsfree(bs);
        /*
		char * filename = new char[U_filenamelength+1];
        strcpy(filename,U_filename);
        LOG(WARNING) << "UCHIHALART  filename3 "<< filename;

        art::mirror::ArtMethod&  method = *U_method;

		df = method.GetDexFile();
		dexcache = method.GetDexCache();
		classloader = method.GetClassLoader();
		*/
		runtime = art::Runtime::Current();
		if(runtime->AttachCurrentThread("buildcode", false, NULL, false)){
			self=art::Thread::Current();
			art::Locks::mutator_lock_->SharedLock(self);
			class_linker = art::Runtime::Current()->GetClassLinker();
			

			

			const char * filename = U_filename;
			art::mirror::ArtMethod*  method = U_method;
			//art::Locks::mutator_lock_->SharedLock(self);
			df = method->GetDexFile();
			dexcache = method->GetDexCache();
			classloader = method->GetClassLoader();
			//art::Locks::mutator_lock_->SharedUnlock(self);
			

			LOG(WARNING) << "UCHIHALART folder  "<<U_dirname;
			initflag();

			if(Flag_Mode){
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   MODE ON";
			}else{
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   MODE OFF";
			}
			if(Flag_logmap){
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   LOG MAP ON";
			}else{
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   LOG MAP OFF";
			}
			if(Flag_logcm){
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   LOG CM ON";
			}else{
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   LOG CM OFF";
			}
			if(Flag_logins){
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   LOG INS ON";
			}else{
				LOG(WARNING) << "UCHIHALART----------------------DEX BUILD START   LOG INS OFF";
			}

	    
			const DexFile::Header& dh = df->GetHeader();
			//-------------------------------------------------------------------------------declare Objects
			
			baseAddr = 0;
		
			StrIDAddr = sizeof(DexFile::Header);
			TypeIDAddr = StrIDAddr + dh.string_ids_size_ * sizeof(DexFile::StringId);
			ProtoIDAddr = TypeIDAddr + dh.type_ids_size_ * sizeof(DexFile::TypeId);
			FiledIDAddr = ProtoIDAddr + dh.proto_ids_size_ * sizeof(DexFile::ProtoId);
			MethodIDAddr = FiledIDAddr + dh.field_ids_size_ * sizeof(DexFile::FieldId);
			ClassDefAddr = MethodIDAddr + dh.method_ids_size_ * sizeof(DexFile::MethodId);
			MapAddr = ClassDefAddr + dh.class_defs_size_ * sizeof(DexFile::ClassDef);

			TypeListAddr = MapAddr+4+18*sizeof(DexFile::MapItem);
			ClassDataAddr = 0;
			CodeAddr = 0; 
			StrDataAddr = 0;
			DebugAddr = 0;
			EncodedAddr = 0;
			EndAddr = 0;
	    
			//-----------------------------------------------------------------------------get Data
			v_StrData = new std::vector<const u1*>;
	    	v_StrDataLength = new std::vector<int>;
	    	//StrDataSize = GetStrData(df,dh,v_StrData,v_StrDataLength);
	    	StrDataSize = GetStrData(dh);

	    	//std::vector<const u1*>* 
	    	v_TypelistData = new std::vector<const u1*>;
	  	    //std::vector<int>* 
	  	    v_TypelistSize=new std::vector<int>;
	        //int 
	        //TypelistSize = GetTypeList(df,dh,v_TypelistData,v_TypelistSize);
	        TypelistSize = GetTypeList(dh);

	        //std::vector<const u1*>* 
	        v_EncodedData=new std::vector<const u1*>;
	        //std::vector<int>* 
	        v_EncodedSize=new std::vector<int>;
	        //int 
	        //EncodeSize = GetEncoded(df,dh,v_EncodedData,v_EncodedSize);
	        EncodeSize = GetEncoded(dh);

	        //std::vector<const u1*>* 
	        v_ClassData=new std::vector<const u1*>;
	        //std::vector<int>* 
	        v_ClassDataSize=new std::vector<int>;
	        //int 
	        //ClassDtataSize= GetClassData(df,dh,v_ClassData,v_ClassDataSize);
	        ClassDtataSize= GetClassData(dh);


	        //std::vector<const u1*>* 
	        v_CodeData=new std::vector<const u1*>;
	  	    //std::vector<int>* 
	  	    v_CodeSize=new std::vector<int>;
	  	    //std::vector<u4>* 
	  	    v_mid = new std::vector<u4>;
		    //std::vector<u4>* 
		    v_DorV = new std::vector<u4>;
		    //int 
		    //CodeSize= GetCode(df,dh,v_CodeData,v_CodeSize,v_mid,v_DorV,v_ClassData);
		    CodeSize= GetCode(dh);

		    //int 
		    DebugSize=0;
		    //-------------------------------------------------------------------------------intial Objects
		    //std::map<const u1*,int>* 
		    AddrMAP = new std::map<const u1*,int>;
			//std::map <const u1*,int>::iterator iter;

		    ClassDataAddr = TypeListAddr+fill_4_byte(TypelistSize);
			CodeAddr = ClassDataAddr+fill_4_byte(ClassDtataSize);
			StrDataAddr = CodeAddr+fill_4_byte(CodeSize);
			DebugAddr = StrDataAddr+fill_4_byte(StrDataSize);
			EncodedAddr = DebugAddr+fill_4_byte(DebugSize);
			EndAddr = EncodedAddr+fill_4_byte(EncodeSize);

			
			LOG(WARNING) << "UCHIHALART  baseAddr: "<<baseAddr;
			LOG(WARNING) << "UCHIHALART  StrIDAddr: "<<StrIDAddr;
			LOG(WARNING) << "UCHIHALART  TypeIDAddr: "<<TypeIDAddr;
			LOG(WARNING) << "UCHIHALART  ProtoIDAddr: "<<ProtoIDAddr;
			LOG(WARNING) << "UCHIHALART  FiledIDAddr: "<<FiledIDAddr;
			LOG(WARNING) << "UCHIHALART  MethodIDAddr: "<<MethodIDAddr;
			LOG(WARNING) << "UCHIHALART  ClassDefAddr: "<<ClassDefAddr;
			LOG(WARNING) << "UCHIHALART  MapAddr: "<<MapAddr;
			LOG(WARNING) << "UCHIHALART  TypeListAddr: "<<TypeListAddr;
			LOG(WARNING) << "UCHIHALART  ClassDataAddr: "<<ClassDataAddr;
			LOG(WARNING) << "UCHIHALART  CodeAddr: "<<CodeAddr;
			LOG(WARNING) << "UCHIHALART  StrDataAddr: "<<StrDataAddr;
			LOG(WARNING) << "UCHIHALART  DebugAddr: "<<DebugAddr;
			LOG(WARNING) << "UCHIHALART  EncodedAddr: "<<EncodedAddr;
			LOG(WARNING) << "UCHIHALART  EndAddr: "<<EndAddr;


		    LOG(WARNING) << "UCHIHALART----------------------Make AddrMap";
		    //art::Locks::mutator_lock_->SharedLock(self);
			MakeAddrMap(AddrMAP,v_TypelistData,v_TypelistSize,baseAddr,TypeListAddr);
			MakeAddrMap(AddrMAP,v_StrData,v_StrDataLength,baseAddr,StrDataAddr);
			MakeAddrMap(AddrMAP,v_EncodedData,v_EncodedSize,baseAddr,EncodedAddr);
			MakeAddrMap(AddrMAP,v_ClassData,v_ClassDataSize,baseAddr,ClassDataAddr);
		    MakeAddrMap(AddrMAP,v_CodeData,v_CodeSize,baseAddr,CodeAddr);
		    //art::Locks::mutator_lock_->SharedUnlock(self);


			//-------------------------------------------------------------------------------WriteFile
			//ByteStream* 
			bs = bsalloc(EndAddr);
		    //int 
		    offset = 0;
	        //if (bs == NULL) return NULL;

	        //offset = BuildHeader(bs,offset,dh,baseAddr,EndAddr,MapAddr,StrIDAddr,TypeIDAddr,ProtoIDAddr,FiledIDAddr,MethodIDAddr,ClassDefAddr,TypeListAddr);
	        //offset = BuildStrID(bs,offset,df,dh,AddrMAP,StrIDAddr);
	        //offset = BuildTypeID(bs,offset,df,dh,TypeIDAddr);
			//offset = BuildProtoID(bs,offset,df,dh,AddrMAP,ProtoIDAddr);
			//offset = BuildFieldID(bs,offset,df,dh,FiledIDAddr);
			//offset = BuildMethodID(bs,offset,df,dh,MethodIDAddr);
			//offset = BuildClassDef(bs,offset,df,dh,AddrMAP,ClassDefAddr);
			offset = BuildHeader(dh);
	        offset = BuildStrID(dh);
	        offset = BuildTypeID(dh);
			offset = BuildProtoID(dh);
			offset = BuildFieldID(dh);
			offset = BuildMethodID(dh);
			offset = BuildClassDef(dh);

	        //offset = BuildMap(bs,offset,dh,baseAddr,StrIDAddr,TypeIDAddr,ProtoIDAddr,FiledIDAddr,MethodIDAddr,ClassDefAddr,MapAddr,TypeListAddr,ClassDataAddr,CodeAddr,StrDataAddr,DebugAddr,EncodedAddr,EndAddr,v_TypelistData,v_ClassData,v_CodeData,v_StrData,v_EncodedData);
	        
	        //offset = BuildTypeList(bs,offset,v_TypelistData,v_TypelistSize,TypeListAddr);
	        //offset = BuildClassData(bs,offset,df,v_ClassData,v_ClassDataSize,AddrMAP,ClassDataAddr);
	        //offset = BuildCode(bs,offset,df,classloader,dexcache,v_CodeData,v_CodeSize,v_mid,v_DorV,CodeAddr);
		    //offset = BuildStrData(bs,offset,v_StrData,v_StrDataLength,StrDataAddr);
		    //offset = BuildEncoded(bs,offset,v_EncodedData,v_EncodedSize,EncodedAddr);


		    offset = BuildMap(dh);
	        
	        offset = BuildTypeList();
	        offset = BuildClassData();
	        art::Locks::mutator_lock_->SharedUnlock(self);
	        offset = BuildCode();
	        art::Locks::mutator_lock_->SharedLock(self);
		    offset = BuildStrData();
		    offset = BuildEncoded();


	        free(AddrMAP);
			bssave(bs,filename);
	  		bsfree(bs);

	        LOG(WARNING) << "UCHIHALART  DEX BUILD Finish 170213 "<< filename;
	        //test_debug();
	        art::Locks::mutator_lock_->SharedUnlock(self);
	        self->SetState(art::kSleeping);
		    runtime->DetachCurrentThread();
	    }//end if(runtime->AttachCurrentThread("buildcode", false, NULL, false))
        return NULL;
     
	}




	//int GetStrData(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_StrData, std::vector<int>* v_StrDataLength){
	int GetStrData(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----------------------Get StrData";
		int StrDataSize = 0;
		unsigned int i = 0;
	    for (i = 0; i < dh.string_ids_size_; i++)
		{
			const DexFile::StringId& dsi = df->GetStringId(i);
			const u1* ptr = (const u1*)df->Begin() + dsi.string_data_off_;
			v_StrData->push_back(ptr);
		}

		for(i=0;i<v_StrData->size();i++){
			int size = read_strdata_length(v_StrData->at(i));
			v_StrDataLength->push_back(size);
			StrDataSize = StrDataSize+size;
		}

		LOG(WARNING) << "UCHIHALART----STR totalsize: "<<StrDataSize;
		return StrDataSize;

    }



	//int GetTypeList(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize){
    int GetTypeList(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----------------------Get TypeList";
	    int TypelistSize = 0;
		unsigned int i = 0;

		for(i = 0;i<dh.proto_ids_size_;i++){
			const DexFile::ProtoId& dpi = df->GetProtoId(i);
			const u1* addr = (const u1*)df->Begin() + dpi.parameters_off_;
			int lock = 1;
			for(unsigned int j=0;j<v_TypelistData->size();j++){
				if(v_TypelistData->at(j)==addr){
					lock = 0;
				}
			}
			if(dpi.parameters_off_!=0){
				if(lock==1){
					v_TypelistData->push_back(addr);
				}
			} 			
			
		}

		for(i=0;i<dh.class_defs_size_;i++){
			const DexFile::ClassDef& dcd = df->GetClassDef(i);
			const u1* addr = (const u1*)df->Begin()+dcd.interfaces_off_;
			int lock = 1;
			for(unsigned int j=0;j<v_TypelistData->size();j++){
				if(v_TypelistData->at(j)==addr){
					lock = 0;
				}
			}
			if(dcd.interfaces_off_!=0){
				if(lock==1){
					v_TypelistData->push_back(addr);
				}
			}  			
			
		}


		for(i=0;i<v_TypelistData->size();i++){
			int size =  read_typelist_length(v_TypelistData->at(i));
			v_TypelistSize->push_back(size);
			TypelistSize=TypelistSize+size;
		}

		LOG(WARNING) << "UCHIHALART----TypeListtotalSize: "<<TypelistSize;
		return TypelistSize;

	}

	//int GetEncoded(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize){
	int GetEncoded(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----------------------Get Encoded";
		int EncodeSize = 0;
	    unsigned int i = 0;
		for(i=0;i<dh.class_defs_size_;i++){
			const DexFile::ClassDef& dcd = df->GetClassDef(i);
			const u1* addr = (const u1*)df->Begin() + dcd.static_values_off_;
			int lock = 1;
			for(unsigned int j=0;j<v_EncodedData->size();j++){
				if(v_EncodedData->at(j)==addr){
					lock = 0;
				}
			}
			if(dcd.static_values_off_!=0){
				if(lock==1){
					v_EncodedData->push_back(addr);
				}
			}			
			
		}   

		for(i=0;i<v_EncodedData->size();i++){
			int size = read_encodedarray_length(v_EncodedData->at(i));
			v_EncodedSize->push_back(size);
			EncodeSize=EncodeSize+size;
		}


		LOG(WARNING) << "UCHIHALART----EncodedtotalSize: "<<EncodeSize;
		return EncodeSize;
	}

	int GetClassData(const DexFile::Header& dh){
	//int GetClassData(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize){
		LOG(WARNING) << "UCHIHALART----------------------Get ClassData";
	    int ClassDtataSize=0;
	    unsigned int i = 0;
		for(i=0;i<dh.class_defs_size_;i++){
			const DexFile::ClassDef& dcd = df->GetClassDef(i);

			const u1* addr = (const u1*)df->Begin() + dcd.class_data_off_;
			int lock = 1;
			for(unsigned int j=0;j<v_ClassData->size();j++){
				if(v_ClassData->at(j)==addr){
					lock = 0;
				}
			}
			if(dcd.class_data_off_!=0){
				if(lock==1){
					v_ClassData->push_back(addr);
				}
			}else{
				//classDataOff=0
			} 			
			
		}

		
		for(i=0;i<v_ClassData->size();i++){
			int size = read_classdata_length(v_ClassData->at(i));
			v_ClassDataSize->push_back(size);
			ClassDtataSize =ClassDtataSize+size;
		}

        LOG(WARNING) << "UCHIHALART----ClassDatatotalSize: "<<ClassDtataSize;
		return ClassDtataSize;
	}


	//int GetCode(const DexFile* df,const DexFile::Header& dh,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<u4>* v_mid,std::vector<u4>* v_DorV,std::vector<const u1*>* v_ClassData){
	int GetCode(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----------------------Get Code";
		int CodeSize=0;
	    unsigned int i = 0;

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
					const u1* addr = pClassData->directMethods[j].codeOff+df->Begin();
					if(pClassData->directMethods[j].codeOff!=0){
						v_CodeData->push_back(addr);
						if(Flag_Mode){
							u4 dmidx = pClassData->directMethods[j].methodIdx;
							v_DorV->push_back(1);
							v_mid->push_back(dmidx);
						}
					}else{
						//directMethod codeOff = 0
					}
				}
				for(int j=0;j<number2;j++){
					const u1* addr = pClassData->virtualMethods[j].codeOff+df->Begin();
					if(pClassData->virtualMethods[j].codeOff!=0){	
						v_CodeData->push_back(addr);
						if(Flag_Mode){
							u4 dmidx = pClassData->virtualMethods[j].methodIdx;
							v_DorV->push_back(2);
							v_mid->push_back(dmidx);
						}
					}else{
						//virtualMethod codeOff = 0
					}
				}
			}
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
		LOG(WARNING) << "UCHIHALART----CodetotalSize: "<<CodeSize;
		return CodeSize;
	}

	void MakeAddrMap(std::map<const u1*,int>* AddrMAP,std::vector<const u1*>* v_Data,std::vector<int>* v_Size,int baseAddr,int Addr){
		unsigned int i = 0;
		u4 size = (u4)v_Data->size();
		if(size!=0){
			for(i=0;i<size;i++){
				int off = 0;
				for(unsigned int j=0;j<i;j++){
					off = off+v_Size->at(j);
				}
				//AddrMAP1[v_TypelistData->at(i)] = TypeListAddr+off-baseAddr;
				AddrMAP->insert(std::map<const u1*,int>::value_type(v_Data->at(i),Addr+off-baseAddr));

				if(Flag_logmap){
					LOG(WARNING) << "UCHIHALART---- "<<i<<"/"<<size;
				}
			}
		}
	}

	//int  BuildHeader(ByteStream* bs, int offset,const DexFile::Header& dh,int baseAddr,int EndAddr,int MapAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int TypeListAddr){
    int  BuildHeader(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----DEX BUILD HEADER ";
	    offset = baseAddr;

		DexHeader* myHeader = new DexHeader;
		memset(myHeader, 0, sizeof(DexHeader));
		memcpy(myHeader, &dh, sizeof(DexHeader));

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

		return offset;
	}

	//int BuildStrID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,std::map<const u1*,int>* AddrMAP,int StrIDAddr){
	int BuildStrID(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----DEX BUILD STRID ";
		offset = StrIDAddr;
		unsigned int i;
		std::map <const u1*,int>::iterator iter;
		
		for(i=0;i<dh.string_ids_size_; i++){
			DexStringId* myStringId = new DexStringId;
			//memset(myStringId, 0, sizeof(u4));
			//memcpy(myStringId, df->pStringIds+i*(sizeof(u4)), sizeof(u4));
			
			const u1* ori = (const u1*)(df->GetStringId(i).string_data_off_+(const u1*)df->Begin());
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

		return offset;
	}


	//int BuildTypeID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,int TypeIDAddr){
	int BuildTypeID(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----DEX BUILD TYPEID ";
		unsigned int i;
		offset = TypeIDAddr;

		for (i = 0; i < dh.type_ids_size_; i++)
		{
			dxb_typeid(bs, &(df->GetTypeId(i)), offset);
			offset = offset + sizeof(DexTypeId);
		}
		return offset;
	}

	//int BuildProtoID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,std::map<const u1*,int>* AddrMAP,int ProtoIDAddr){
	int BuildProtoID(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----DEX BUILD ProtoID ";
		unsigned int i;
		offset = ProtoIDAddr;
		std::map <const u1*,int>::iterator iter;

		for (i = 0; i< dh.proto_ids_size_; i++)
		{
			DexProtoId* myProtoId = new DexProtoId;
			memset(myProtoId, 0, sizeof(DexProtoId));
			memcpy(myProtoId, &(df->GetProtoId(i)), sizeof(DexProtoId));
			const u1* ori = (const u1*)(df->GetProtoId(i).parameters_off_+(const u1*)df->Begin());
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
		return offset;
	}

	//int BuildFieldID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,int FiledIDAddr){
	int BuildFieldID(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----DEX BUILD FieldID ";
		unsigned int i;
	    offset = FiledIDAddr;

	    for (i = 0; i < dh.field_ids_size_; i++)
		{
			dxb_fieldid(bs, &(df->GetFieldId(i)), offset);
			offset = offset + sizeof(DexFieldId);
		}
	    return offset;

	}

	//int BuildMethodID(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,int MethodIDAddr){
	int BuildMethodID(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----DEX BUILD MethodID ";
		unsigned int i;
		offset = MethodIDAddr;
		for (i = 0; i < dh.method_ids_size_; i++)
		{
			dxb_methodid(bs, &(df->GetMethodId(i)), offset);
			offset = offset + sizeof(DexMethodId);
		}
		return offset;

	}
	//int BuildClassDef(ByteStream* bs, int offset,const DexFile* df,const DexFile::Header& dh,std::map<const u1*,int>* AddrMAP,int ClassDefAddr){
	int BuildClassDef(const DexFile::Header& dh){
		LOG(WARNING) << "UCHIHALART----DEX BUILD ClassDef ";

		offset = ClassDefAddr;
		unsigned int i;
	    std::map <const u1*,int>::iterator iter;

		for (i = 0; i < dh.class_defs_size_; i++)
		{
			DexClassDef* myClassDef = (DexClassDef*)malloc(sizeof(DexClassDef));
			memset(myClassDef, 0, sizeof(DexClassDef));
			memcpy(myClassDef, &(df->GetClassDef(i)), sizeof(DexClassDef));

			const u1* ori0 = (const u1*)(df->GetClassDef(i).interfaces_off_+(const u1*)df->Begin());//interfacesOff
			const u1* ori1 = (const u1*)(df->GetClassDef(i).class_data_off_+(const u1*)df->Begin());//classDataOff
			const u1* ori2 = (const u1*)(df->GetClassDef(i).static_values_off_+(const u1*)df->Begin());//staticValuesOff

			iter = AddrMAP->find(ori0);
			if(iter!= AddrMAP->end()){
				myClassDef->interfacesOff = iter->second;
			}else{
				myClassDef->interfacesOff =0;
			}

			iter = AddrMAP->find(ori1);
			if(iter!= AddrMAP->end()){
				myClassDef->classDataOff =  iter->second;
			}else{
				myClassDef->classDataOff = 0;
			}
			iter = AddrMAP->find(ori2);
			if(iter!= AddrMAP->end()){
				myClassDef->staticValuesOff =  iter->second;
			}else{
				myClassDef->staticValuesOff = 0;
			}

			myClassDef->annotationsOff = 0;

			//for test
			myClassDef->accessFlags = myClassDef->accessFlags%0x30000;
			dxb_classdef(bs, myClassDef, offset);
			offset = offset + sizeof(DexClassDef);
			free(myClassDef);
		}
		return offset;
	}


	//int BuildMap(ByteStream* bs, int offset,const DexFile::Header& dh,
	//	int baseAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int MapAddr,int TypeListAddr,int ClassDataAddr,int CodeAddr,int StrDataAddr,int DebugAddr,int EncodedAddr,int EndAddr,
	//	std::vector<const u1*>* v_TypelistData,std::vector<const u1*>* v_ClassData,std::vector<const u1*>* v_CodeData,std::vector<const u1*>* v_StrData,std::vector<const u1*>* v_EncodedData
	//	){
	int BuildMap(const DexFile::Header& dh){
	    int TestDexMapItem[]={1,1,1,1,1,1,1,1,1,0,0,1,1,1,1,0,1,0};//test
	    u4 TestMapSize = 14;
		LOG(WARNING) << "UCHIHALART----DEX BUILD Map ";
	    unsigned int i;
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
						myMapItem->size = dh.string_ids_size_;
						myMapItem->offset = StrIDAddr-baseAddr;
					break;
					case 2:
						myMapItem->type = 0x0002;
						myMapItem->unused = 0;
						myMapItem->size = dh.type_ids_size_;
						myMapItem->offset = TypeIDAddr-baseAddr;
					break;
					case 3:
						myMapItem->type = 0x0003;
						myMapItem->unused = 0;
						myMapItem->size = dh.proto_ids_size_;
						myMapItem->offset = ProtoIDAddr-baseAddr;
					break;
					case 4:
						myMapItem->type = 0x0004;
						myMapItem->unused = 0;
						myMapItem->size = dh.field_ids_size_;
						myMapItem->offset = FiledIDAddr-baseAddr;
					break;
					case 5:
						myMapItem->type = 0x0005;
						myMapItem->unused = 0;
						myMapItem->size = dh.method_ids_size_;
						myMapItem->offset = MethodIDAddr-baseAddr;
					break;
					case 6:
						myMapItem->type = 0x0006;
						myMapItem->unused = 0;
						myMapItem->size = dh.class_defs_size_;
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
		return offset;
	}

	//int BuildTypeList(ByteStream* bs, int offset,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize,int TypeListAddr){
	int BuildTypeList(){
		LOG(WARNING) << "UCHIHALART----DEX BUILD TypeList ";
		unsigned int i;
		offset = TypeListAddr;
		for(i=0;i<v_TypelistData->size();i++){
			bsseek(bs,offset);
			bswrite(bs,(u1*)v_TypelistData->at(i),v_TypelistSize->at(i));
			offset = offset+v_TypelistSize->at(i);
		}
		free(v_TypelistData);
		free(v_TypelistSize);
		return offset;
	}

	//int BuildClassData(ByteStream* bs, int offset,const DexFile* df,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize,std::map<const u1*,int>* AddrMAP,int ClassDataAddr){
	int BuildClassData(){
		LOG(WARNING) << "UCHIHALART----DEX BUILD ClassData ";
		unsigned int i;
		offset = ClassDataAddr;
		std::map <const u1*,int>::iterator iter;

		for(i=0;i<v_ClassData->size();i++){
			DexClassData* pClassData;
			const u1* temp= new u1;
			temp = v_ClassData->at(i);
			pClassData = dexReadAndVerifyClassData(&temp, NULL);//dexReadAndVerifyClassData will change the v_ClassData
			if(pClassData!=NULL){
				int num1 = pClassData->header.directMethodsSize;
				int num2 = pClassData->header.virtualMethodsSize;
				for(int j=0;j<num1;j++){
					const u1* ori = (const u1*)(pClassData->directMethods[j].codeOff+(const u1*)df->Begin());
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
					const u1* ori = (const u1*)(pClassData->virtualMethods[j].codeOff+(const u1*)df->Begin());
					//pClassData->virtualMethods[j].codeOff = AddrMAP[ori];
					iter = AddrMAP->find(ori);
					if(iter!= AddrMAP->end()){
						pClassData->virtualMethods[j].codeOff = iter->second;
					}else{
						pClassData->virtualMethods[j].codeOff = 0;
					}
				}

				writeClassData((const u1*) pClassData,offset,bs);
				offset = offset+v_ClassDataSize->at(i);
				free(pClassData);
			}

			//delete temp;
		}
		free(v_ClassData);
		free(v_ClassDataSize);
		return offset;
	}

	//int BuildCode(ByteStream* bs, int offset,const DexFile* df,art::mirror::ClassLoader* classloader,art::mirror::DexCache* dexcache,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<u4>* v_mid,std::vector<u4>* v_DorV,int CodeAddr){
	int BuildCode(){
		LOG(WARNING) << "UCHIHALART----DEX BUILD Code ";
		art::Locks::mutator_lock_->SharedLock(self);
		unsigned int i;
		offset = CodeAddr;
		for(i=0;i<v_CodeData->size();i++){
			DexCode* myCode = (DexCode*)malloc(v_CodeSize->at(i));
			memset(myCode, 0, v_CodeSize->at(i));
			memcpy(myCode, v_CodeData->at(i), v_CodeSize->at(i));
			myCode->debugInfoOff =0x00000000;

			if(Flag_Mode){
				//class_linker = art::Runtime::Current()->GetClassLinker();
	            //self=art::Thread::Current();
		        //art::StackHandleScope<2> hs(self);
                //art::Handle<art::mirror::ClassLoader> loader(hs.NewHandle(classloader));
				
                //art::Handle<art::mirror::DexCache> cache(hs.NewHandle(dexcache));
                //art::Handle<art::mirror::ArtMethod> nullhandle(hs.NewHandle(NULL));
				u4 dmidx = v_mid->at(i);
				if(dmidx!=0){
					//if(myCode->insnsSize > 1 && myCode->insns[0]==0){
						const art::DexFile::MethodId& dmi = df->GetMethodId(dmidx);
						const char* cname = df->StringByTypeIdx(dmi.class_idx_);
						const char* mname = df->StringDataByIdx(dmi.name_idx_);
						if(CheckStr(cname,mname)){
				  			//if(runtime->AttachCurrentThread("buildcode", false, NULL, false)){
								
								bool debug = false;
								if(CheckStr2(cname,mname)){
									debug = true;
								}
								if(Flag_logcm){
									LOG(WARNING) << "UCHIHALART----buildcode "<< cname << mname;
							    }
							    if(debug){
									LOG(WARNING) << "UCHIHALART----debug "<< cname << mname;
									LOG(WARNING) << "UCHIHALART----debug dmidx "<< dmidx;
							    }
							    //art::Locks::mutator_lock_->SharedLock(self);
		                        art::StackHandleScope<2> hs(self);
                                art::Handle<art::mirror::ClassLoader> loader(hs.NewHandle(classloader));

								art::mirror::Class* klass=NULL;
								klass=class_linker->FindClass(self,cname,loader);
								//const art::DexFile::ClassDef* dex_class_def= df->FindClassDef(cname);
								//klass=class_linker->DefineClass(cname,loader,*df,*dex_class_def);
								if(klass!=NULL){
									art::Handle<art::mirror::Class> oclass(hs.NewHandle(klass));
									if(class_linker->EnsureInitialized(oclass, true, true)){
										if(debug){
						            		LOG(WARNING) << "UCHIHALART----init clazz "<< cname;
						            	}	
						          	}else{
						              self->ClearException();
						          	}
						        	art::mirror::ArtMethod* o_method = NULL;
						        	//art::InvokeType invoketype = art::ClassDataItemIterator::GetMethodInvokeType(*dex_class_def);
						        	//o_method = class_linker->ResolveMethod(*df,dmidx,cache,loader,nullhandle,art::kDirect);
						        	
						        	if(v_mid->at(i)==1){
										o_method = klass->FindDirectMethod(dexcache, dmidx);
										//o_method = class_linker->ResolveMethod(*df,dmidx,cache,loader,art::NullHandle<art::mirror::ArtMethod>(),art::kDirect);
										//o_method = class_linker->ResolveMethod(self,dmidx,NULL,art::kDirect);
									}else{
										o_method = klass->FindVirtualMethod(dexcache, dmidx);
										//o_method = class_linker->ResolveMethod(*df,dmidx,cache,loader,art::NullHandle<art::mirror::ArtMethod>(),art::kVirtual);
										//o_method = class_linker->ResolveMethod(self,dmidx,NULL,art::kVirtual);
									}
									if(o_method!=NULL){
										if(debug){
											LOG(WARNING) << "UCHIHALART----test "<< o_method->GetName();
										}
										const art::DexFile::CodeItem* codeitem = o_method->GetCodeItem();
										if(debug){
											LOG(WARNING) << "UCHIHALART  insnsSize:  " << myCode->insnsSize<<"  "<<codeitem->insns_size_in_code_units_;
										}
										if(codeitem->insns_size_in_code_units_!=0&&myCode->insnsSize!=0){
											for(unsigned int j =0;j<myCode->insnsSize;j++){
												myCode->insns[j] = codeitem->insns_[j];
												if(Flag_logins||debug){
													LOG(WARNING) << "UCHIHALART  insns:  " << myCode->insns[j]<<"  "<<codeitem->insns_[j];
												}	
											}
										}else{
											if(debug){
												LOG(WARNING) << "UCHIHALART----insnsSize=0 "<< cname << mname;
											}
										}
									}else{//end if(o_method!=NULL)
										if(debug){
											LOG(WARNING) << "UCHIHALART----method null "<< cname << mname;
										}
									}
								}else{//end if(klass!=NULL)
									if(debug){
										LOG(WARNING) << "UCHIHALART----clazz null "<< cname;
									}
								}
								//art::Locks::mutator_lock_->SharedUnlock(self);
								//self->SetState(art::kSleeping);
					            //runtime->DetachCurrentThread();
						    //}else{
						    //	LOG(WARNING) << "UCHIHALART----attach failed";
						    //}//end if(runtime->AttachCurrentThread("buildcode", false, NULL, false))	
						}//end if(CheckStr(cname))
					//}//end if(myCode->insnsSize > 1 && myCode->insns[0]==0)
				}//end if(dmidx!=0)
			}//end if(Flag_Mode)

			bsseek(bs,offset);
			bswrite(bs,(u1*)(myCode),v_CodeSize->at(i));
			offset = offset+v_CodeSize->at(i);
			free(myCode);
		}
		free(v_CodeData);
		free(v_CodeSize);
		art::Locks::mutator_lock_->SharedUnlock(self);
		return offset;
	}

	//int BuildStrData(ByteStream* bs, int offset,std::vector<const u1*>* v_StrData,std::vector<int>* v_StrDataLength,int StrDataAddr){
	int BuildStrData(){
		LOG(WARNING) << "UCHIHALART----DEX BUILD StrData ";
		unsigned int i;
		offset = StrDataAddr;
		for(i=0;i<v_StrData->size();i++){
			bsseek(bs,offset);
			bswrite(bs,(u1*)v_StrData->at(i),v_StrDataLength->at(i));
			offset = offset+v_StrDataLength->at(i);
		}
		free(v_StrData);
		free(v_StrDataLength);

		return offset;
	}

	//int BuildEncoded(ByteStream* bs, int offset,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize,int EncodedAddr){
	int BuildEncoded(){
		LOG(WARNING) << "UCHIHALART----DEX BUILD Encoded ";
		unsigned int i;
		offset = EncodedAddr;
		for(i=0;i<v_EncodedData->size();i++){
			bsseek(bs,offset);
			bswrite(bs,(u1*)v_EncodedData->at(i),v_EncodedSize->at(i));
			offset = offset+v_EncodedSize->at(i);
		}
		free(v_EncodedData);
		free(v_EncodedSize);

		return offset;
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

	void dxb_stringid(ByteStream* bs, const DexStringId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexStringId);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_typeid(ByteStream* bs, const DexFile::TypeId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexFile::TypeId);
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

	void dxb_fieldid(ByteStream* bs, const DexFile::FieldId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexFile::FieldId);
		uint8_t* ptr = (uint8_t*) obj;
		bswrite(bs,ptr,data_size);
	}

	void dxb_methodid(ByteStream* bs, const DexFile::MethodId *obj, uint32_t offset)
	{
		if (bs == NULL || obj == NULL) return;

		bsseek(bs,offset);
		size_t data_size = sizeof(DexFile::MethodId);
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
		const DexFile::TypeList* dtl = (const DexFile::TypeList*)tyl;
		int length = 0;
    	if(dtl->Size()%2){//fill for 4 bytes
    		length = (dtl->Size()+1)*2+4;
    	}else{
    		length = dtl->Size()*2+4;
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
				LOG(WARNING) << "UCHIHALART----EncodedArray:Static Value May Have ERROR!!!!!!!!!!!!!";
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

	int read_classdata_length(const u1* cd){
		const u1* start = cd;
		DexClassDataHeader *pHeader = new DexClassDataHeader;
		dexReadClassDataHeader(&cd, pHeader); 


		int number = 2*(pHeader->staticFieldsSize+pHeader->instanceFieldsSize)+3*(pHeader->directMethodsSize+pHeader->virtualMethodsSize);
		for(int i=0;i<number;i++){
			readUnsignedLeb128(&cd);
			//GOSSIP("Leb128----: %d", a);
	    }
	    const u1* end = cd;
	    int length = (int)(end-start);
	    //GOSSIP("Leb128----addr: %d", length);
	    int methodNum = pHeader->directMethodsSize+pHeader->virtualMethodsSize;
		//delete pHeader;
	    return length+4*methodNum+4;  //!!!!!!!!!!!!  1 classdata may have more than 1 codeoff which will be changed.
	}

	int read_code_length(const u1* co){
		int length = (int)dexGetDexCodeSize((const DexCode*) co);
		//GOSSIP("codeSize: %d", length);
		return fill_4_byte(length);
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
  			    long size = (long)temp-(long)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("sfs:--%d",pCD->header.staticFieldsSize);
		        //GOSSIP("sfs:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.instanceFieldsSize);
  			    size = (long)temp-(long)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("ifs:--%d",pCD->header.instanceFieldsSize);
		        //GOSSIP("ifs:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.directMethodsSize);
  			    size = (long)temp-(long)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("dms:--%d",pCD->header.directMethodsSize);
		        //GOSSIP("dms:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.virtualMethodsSize);
  			    size = (long)temp-(long)start;
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
	  			    size = (long)temp-(long)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("sf_fid:--%d",pCD->staticFields[i].fieldIdx);
		            //GOSSIP("sf_fid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->staticFields[i].accessFlags);
	  			    size = (long)temp-(long)start;
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
	  			    size = (long)temp-(long)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("if_fid:--%d",pCD->instanceFields[i].fieldIdx);
		            //GOSSIP("if_fid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->instanceFields[i].accessFlags);
	  			    size = (long)temp-(long)start;
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
	  			    size = (long)temp-(long)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_mid:--%d",pCD->directMethods[i].methodIdx);
		            //GOSSIP("dm_mid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->directMethods[i].accessFlags);
	  			    size = (long)temp-(long)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_af:--%d",pCD->directMethods[i].accessFlags);
		            //GOSSIP("dm_af:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->directMethods[i].codeOff);
	  			    size = (long)temp-(long)start;
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
	  			    size = (const u1*)temp-(const u1*)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_mid:--%d",pCD->virtualMethods[i].methodIdx);
		            //GOSSIP("vm_mid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].accessFlags);
	  			    size = (const u1*)temp-(const u1*)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_af:--%d",pCD->virtualMethods[i].accessFlags);
		            //GOSSIP("vm_af:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].codeOff);
	  			    size = (const u1*)temp-(const u1*)start;
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


	void initflag(){
		std::string ss;
		char filename[256] = {0};
		snprintf ( filename, 256, "%s/%s", U_dirname, "unpackflag" );
		std::ifstream f( filename );	
		if (!f){
			return;
		}
		LOG(WARNING) << "UCHIHALART initflag";
		char t = 0;
		if(!f.eof()){
			f >> t;
			if(t=='0'){
				Flag_Mode = false;
			}
		}

		if(!f.eof()){
			f >> t;
			if(t=='0'){
				Flag_logmap = false;
			}
		}

		if(!f.eof()){
			f >> t;
			if(t=='0'){
				Flag_logcm = false;
			}
		}

		if(!f.eof()){
			f >> t;
			if(t=='0'){
				Flag_logins = false;
			}
		}
		
	}

	bool CheckStr(const char* s1, const char* s2){
		
		if(strstr(s1,"Landroid")){
			return false;
		}
		if(strstr(s1,"Lcn/sharesdk")){
			return false;
		}
		if(strstr(s1,"Lcom/baidu")){
			return false;
		}
		if(strstr(s1,"Lcom/google")){
			return false;
		}
		if(strstr(s1,"Lcom/tencent")){
			return false;
		}
		if(strstr(s1,"Lorg/apache")){
			return false;
		}

		std::string ss;
	    char filename[256] = {0};
	    snprintf ( filename, 256, "%s/%s", U_dirname, "unpacklist1" );
	    std::ifstream f( filename );	
	    while ( std::getline(f, ss) )
	    {
		//GOSSIP("filter1 %s",ss.c_str());
			if(strstr(s1,ss.c_str())){
				f.close();
				return false;
			}
		}
		f.close();

		return true;
		
		
		//if(strstr(s,"Lcom/paem")){
		//	return true;
		//}
		//if(strstr(s,"Lcom/payidaixian")){
		//	return true;
		//}
		//if(strstr(s,"Lcom/pingan/a")){
		//	return true;
		//}
		

		//if(strstr(s,"L0")){
		//	return true;
		//}

		//return false;
	}

	bool CheckStr2(const char* s1, const char* s2){

		std::string ss;
		char filename[256] = {0};
		snprintf ( filename, 256, "%s/%s", U_dirname, "unpacklist2" );
		char cm[256] = {0};
		snprintf ( cm, 256, "%s%s", s1, s2 );
		std::ifstream f( filename );	
		while ( std::getline(f, ss) )
		{
		//GOSSIP("filter2 %s",ss.c_str());
			if(strstr(cm,ss.c_str())){
				f.close();
				return true;
			}
		}
		f.close();

		return false;
	}

	void test_debug(){
		art::Locks::mutator_lock_->SharedLock(self);
		const char* cname = "Lcom/example/goodluck/Act_Main;";
		const char* mname = "init";
		u4 dmidx = 4658;

		art::StackHandleScope<2> hs(self);
		art::Handle<art::mirror::ClassLoader> loader(hs.NewHandle(classloader));
		art::mirror::Class* klass=NULL;
		klass=class_linker->FindClass(self,cname,loader);
		if(klass!=NULL){
			art::Handle<art::mirror::Class> oclass(hs.NewHandle(klass));
			if(class_linker->EnsureInitialized(oclass, true, true)){
            	LOG(WARNING) << "UCHIHALART----debug_test----init clazz "<< cname;
          	}else{
              self->ClearException();
          	}
          	art::mirror::ArtMethod* o_method = NULL;
          	o_method = klass->FindDirectMethod(dexcache, dmidx);
          	if(o_method!=NULL){
          		LOG(WARNING) << "UCHIHALART----debug_test----test "<< o_method->GetName();
          		const art::DexFile::CodeItem* codeitem = o_method->GetCodeItem();
				LOG(WARNING) << "UCHIHALART  insnsSize:  " <<codeitem->insns_size_in_code_units_;
				if(codeitem->insns_size_in_code_units_!=0){
					for(unsigned int j =0;j<codeitem->insns_size_in_code_units_;j++){
							LOG(WARNING) << "UCHIHALART  insns:  "<<codeitem->insns_[j];
					}
				}else{
					LOG(WARNING) << "UCHIHALART----debug_test----insnsSize=0 "<< cname << mname;
				}
          	}else{
          		LOG(WARNING) << "UCHIHALART----debug_test----method null "<< cname << mname;
          	}
        }else{
        	LOG(WARNING) << "UCHIHALART----debug_test----class null "<< cname;
        }
        art::Locks::mutator_lock_->SharedUnlock(self);

	}


}