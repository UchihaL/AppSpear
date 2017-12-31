#include "indroid/tools/diaos_tools.h"
#include "indroid/Constant.h"
#include <fstream>
#include <string.h>
#include <vector>
#include <map>
#include <stdlib.h>
#include <iostream>  
#include <exception> 
#include "Thread.h"

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>

// define YWB message output macro
#define DIAOS_DBG 1
#if defined(DIAOS_DBG)
# define GOSSIP(...) ALOG( LOG_VERBOSE, "LBD", __VA_ARGS__)
#else
# define GOSSIP(...) (void(0)) 
#endif

//normal

namespace gossip_loccs
{
	static bool Flag_Mode = true;
	static bool Flag_logmap = true;
	static bool Flag_logcm = true;
	static bool Flag_logins = true;
	



//void dexbuild(DvmDex* pDvmDex,const char* filename, Object* loader);
void* dexbuild_lbd(void *arg);
u4 GetStrData();
u4 GetTypeList();
u4 GetEncoded();
u4 GetClassData();
u4 GetCode();
void MakeAddrMap(std::map<const u1*,u4>* AddrMAP,std::vector<const u1*>* v_Data,std::vector<u4>* v_Size,u4 baseAddr,u4 Addr);
void MakeAddrMap(std::vector<const u1*>* v_Data,std::vector<u4>* v_Size,u4 baseAddr,u4 Addr);

u4 BuildOdexHeader();
u4 BuildHeader();
u4 BuildStrID();
u4 BuildTypeID();
u4 BuildProtoID();
u4 BuildFieldID();
u4 BuildMethodID();
u4 BuildClassDef();
u4 BuildMap();
u4 BuildTypeList();
u4 BuildClassData();
u4 BuildCode(DvmDex* pDvmDex,Object* loader);
u4 BuildStrData();
u4 BuildEncoded();
void dxb_header(ByteStream *bs, const DexHeader *header,uint32_t offset);
void dxb_oheader(ByteStream *bs, const DexOptHeader *header,uint32_t offset);
void dxb_stringid(ByteStream* bs, const DexStringId *obj, uint32_t offset);
void dxb_typeid(ByteStream* bs, const DexTypeId *obj, uint32_t offset);
void dxb_protoid(ByteStream* bs, const DexProtoId *obj, uint32_t offset);
void dxb_fieldid(ByteStream* bs, const DexFieldId *obj, uint32_t offset);
void dxb_methodid(ByteStream* bs, const DexMethodId *obj, uint32_t offset);
void dxb_classdef(ByteStream* bs, const DexClassDef *obj, uint32_t offset);
u4 read_classdata_length(const u1* cd);
u4 read_strdata_length(const u1* str);
u4 read_typelist_length(const u1* tyl);
u4 read_encodedarray_length(const u1* ea);
u4 read_code_length(const u1* co);
u4 read_debuginfo_length(const u1* di);
void writeClassData(const u1* pClassData,u4 off,ByteStream* bs);
u4 fill_4_byte(u4 size);
void initflag();
bool CheckStr(const char* s);
bool CheckStr2(const char* s1, const char* s2);
void test_debug(DvmDex* pDvmDex,Object* loader);
void putmap(const u1* data1, u4 data2);
void getmap(const u1* data1, u1* data2);

void logClass(DvmDex* pDvmDex,Object* loader,const DexFile* df,const DexClassDef* dcd);
void logMethod(DvmDex* pDvmDex,Object* loader,const DexFile* df,DexMethod dm,u4 dorv);


DvmDex* L_pDvmDex;
const char* L_filename;
const char* L_folder; 
Object* L_loader;


bool IsOdex;
u4 OdexAddrOff;

const DexFile* df;
const DexHeader *dh;
const DexOptHeader* doh;

u4 baseAddr;
u4 StrIDAddr;
u4 TypeIDAddr;
u4 ProtoIDAddr;
u4 FiledIDAddr;
u4 MethodIDAddr;
u4 ClassDefAddr;
u4 MapAddr;

u4 TypeListAddr;
u4 ClassDataAddr;
u4 CodeAddr;
u4 StrDataAddr;
u4 DebugAddr;
u4 EncodedAddr;
u4 EndAddr;

std::vector<const u1*>* v_StrData;
std::vector<u4>* v_StrDataLength;
u4 StrDataSize;

std::vector<const u1*>* v_TypelistData;
std::vector<u4>* v_TypelistSize;
u4 TypelistSize;

std::vector<const u1*>* v_EncodedData;
std::vector<u4>* v_EncodedSize;
u4 EncodeSize;

std::vector<const u1*>* v_ClassData;
std::vector<u4>* v_ClassDataSize;
u4 ClassDtataSize;

std::vector<const u1*>* v_CodeData;
std::vector<u4>* v_CodeSize;
//std::vector<CMname*>* v_name=new std::vector<CMname*>;
std::vector<u4>* v_mid;
std::vector<u4>* v_DorV;

u4 CodeSize;

u4 DebugSize;

std::map<const u1*,u4>* AddrMAP;
std::map <const u1*,u4>::iterator iter;

ByteStream* bs;
//ByteStream* bs_pm;
//ByteStream* bs_gm;
u4 offset;

JavaVMAttachArgs jniArgs;
Object* systemGroup;




void dexbuild(DvmDex* pDvmDex,const char* filename,const char* dirname, Object* loader){

	L_pDvmDex = pDvmDex;
	L_filename = filename;
	L_folder = dirname;
	L_loader = loader;

	systemGroup = dvmGetSystemThreadGroup();
    jniArgs.version = JNI_VERSION_1_2;
    jniArgs.name = "dexbuild_lbd";
    jniArgs.group = reinterpret_cast<jobject>(systemGroup);

	

	pthread_t pid;
	//dvmCreateInternalThread_lbd(&pid,"ClassDumper",dexbuild_lbd,NULL);  
	pthread_create(&pid,NULL,dexbuild_lbd,NULL);

    

	GOSSIP("----------------------Thread!!!--------");

}

void* dexbuild_lbd(void *arg){
	
	sleep(10);
	
    DvmDex* pDvmDex = L_pDvmDex;
    const char* filename = L_filename;
    Object* loader = L_loader;

    //int len = strlen(L_filename);
	//char folder[len-3];
    //strncpy(folder, L_filename, len-3);
	//folder[len-4] = '\0';
	//L_folder = folder;
	//mkdir(L_folder,0777);
    GOSSIP("folder %s",L_folder);
	
	initflag();
	


	IsOdex = false;
	OdexAddrOff = 0;

	if(Flag_Mode){
		GOSSIP("----------------------DEX BUILD START   MODE ON");
	}else{
		GOSSIP("----------------------DEX BUILD START   MODE OFF");
	}
	if(Flag_logmap){
		GOSSIP("LOG MAP ON");
	}else{
		GOSSIP("LOG MAP OFF");
	}
	if(Flag_logcm){
		GOSSIP("LOG CM ON");
	}else{
		GOSSIP("LOG CM OFF");
	}
	if(Flag_logins){
		GOSSIP("LOG INS ON");
	}else{
		GOSSIP("LOG INS OFF");
	}
	df = pDvmDex->pDexFile;
	if (df == NULL) return NULL;
	dh = df->pHeader;
 	

	if(IsOdex){
		GOSSIP("----------------------Get Odex");
		doh = df->pOptHeader;
		OdexAddrOff = sizeof(DexOptHeader)+fill_4_byte(doh->depsLength)+fill_4_byte(doh->optLength);
 	}

	//-------------------------------------------------------------------------------declare Objects
    baseAddr = 0+OdexAddrOff;
	StrIDAddr = sizeof(DexHeader)+OdexAddrOff;
	TypeIDAddr = StrIDAddr+dh->stringIdsSize*sizeof(DexStringId)+OdexAddrOff;
	ProtoIDAddr = TypeIDAddr+dh->typeIdsSize*sizeof(DexTypeId)+OdexAddrOff;
	FiledIDAddr = ProtoIDAddr+dh->protoIdsSize*sizeof(DexProtoId)+OdexAddrOff;
	MethodIDAddr = FiledIDAddr+dh->fieldIdsSize*sizeof(DexFieldId)+OdexAddrOff;
	ClassDefAddr = MethodIDAddr+dh->methodIdsSize*sizeof(DexMethodId)+OdexAddrOff;
	MapAddr = ClassDefAddr+dh->classDefsSize*sizeof(DexClassDef)+OdexAddrOff;

	TypeListAddr = MapAddr+4+18*sizeof(DexMapItem)+OdexAddrOff;
	ClassDataAddr = 0;
	CodeAddr = 0;
	StrDataAddr = 0;
	DebugAddr = 0;
	EncodedAddr = 0;
	EndAddr = 0;

    
    //-----------------------------------------------------------------------------get Datas
    v_StrData = new std::vector<const u1*>;
    v_StrDataLength = new std::vector<u4>;
    StrDataSize = GetStrData();

    v_TypelistData = new std::vector<const u1*>;
  	v_TypelistSize=new std::vector<u4>;
	TypelistSize = GetTypeList();

    v_EncodedData=new std::vector<const u1*>;
    v_EncodedSize=new std::vector<u4>;
	EncodeSize = GetEncoded();

	v_ClassData=new std::vector<const u1*>;
    v_ClassDataSize=new std::vector<u4>;
	ClassDtataSize= GetClassData();

    v_CodeData=new std::vector<const u1*>;
  	v_CodeSize=new std::vector<u4>;
    v_mid = new std::vector<u4>;
	v_DorV = new std::vector<u4>;
	
	CodeSize= GetCode();

	DebugSize=0;

    //-------------------------------------------------------------------------------intial Objects
    AddrMAP = new std::map<const u1*,u4>;
	//std::map <const u1*,int>::iterator iter;

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
	MakeAddrMap(AddrMAP,v_TypelistData,v_TypelistSize,baseAddr,TypeListAddr);
	MakeAddrMap(AddrMAP,v_StrData,v_StrDataLength,baseAddr,StrDataAddr);
	MakeAddrMap(AddrMAP,v_EncodedData,v_EncodedSize,baseAddr,EncodedAddr);
	MakeAddrMap(AddrMAP,v_ClassData,v_ClassDataSize,baseAddr,ClassDataAddr);
    MakeAddrMap(AddrMAP,v_CodeData,v_CodeSize,baseAddr,CodeAddr);
	
	//MakeAddrMap(v_TypelistData,v_TypelistSize,baseAddr,TypeListAddr);
	//MakeAddrMap(v_StrData,v_StrDataLength,baseAddr,StrDataAddr);
	//MakeAddrMap(v_EncodedData,v_EncodedSize,baseAddr,EncodedAddr);
	//MakeAddrMap(v_ClassData,v_ClassDataSize,baseAddr,ClassDataAddr);
    //MakeAddrMap(v_CodeData,v_CodeSize,baseAddr,CodeAddr);
    
    //-------------------------------------------------------------------------------WriteFile
    //bs_gm = bsalloc(4);
	
	bs = bsalloc(EndAddr);
	offset = 0;
    if (bs == NULL) return NULL;

	if(IsOdex){
		offset = BuildOdexHeader();
	}

	
	offset = BuildHeader();
	offset = BuildStrID();
	offset = BuildTypeID();
    offset = BuildProtoID();
	offset = BuildFieldID();
	offset = BuildMethodID();
    offset = BuildClassDef();
	offset = BuildMap();
	offset = BuildTypeList();
	offset = BuildClassData();
	//if (dvmAttachCurrentThread(&jniArgs, true)) {
		offset = BuildCode(pDvmDex,loader);
	//	dvmDetachCurrentThread();
	//}
	offset = BuildStrData();
    offset = BuildEncoded();

    free(AddrMAP);

	bssave(bs,filename);

  	//bsfree(bs_gm);
	bsfree(bs);
    GOSSIP("----------------------DEX BUILD Finish 170718 %s",filename);

	//test_debug(pDvmDex,loader);
	
	//}//end if (dvmAttachCurrentThread(&jniArgs, true))
	return NULL;

}

u4 GetStrData(){
	GOSSIP("----------------------Get StrData");
	u4 StrDataSize = 0;
	unsigned int i = 0;
    for (i = 0; i < dh -> stringIdsSize; i++)
	{
		const DexStringId* dsi = dexGetStringId(df,i);
		const u1* ptr = df->baseAddr + dsi->stringDataOff;
		v_StrData->push_back(ptr);
		//free(dsi);
	}

	for(i=0;i<v_StrData->size();i++){
		u4 size = read_strdata_length(v_StrData->at(i));
		v_StrDataLength->push_back(size);
		StrDataSize = StrDataSize+size;
	}

	for (i = 0; i < dh -> stringIdsSize; i++)
	{
		//GOSSIP("STRsize %d", v_StrDataLength[i]);
	}
	GOSSIP("STR totalsize %d", StrDataSize);
	return StrDataSize;

}

u4 GetTypeList(){
	GOSSIP("----------------------Get TypeList");
    u4 TypelistSize = 0;
	u4 i = 0;

	for(i = 0;i<dh->protoIdsSize;i++){
		const DexProtoId* dpi = dexGetProtoId(df, i);
		const u1* addr = df->baseAddr+dpi->parametersOff;
		int lock = 1;
		for(u4 j=0;j<v_TypelistData->size();j++){
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
		for(u4 j=0;j<v_TypelistData->size();j++){
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
		u4 size =  read_typelist_length(v_TypelistData->at(i));
		v_TypelistSize->push_back(size);
		TypelistSize=TypelistSize+size;
	}

	for(i=0;i<v_TypelistSize->size();i++){
		//GOSSIP("TypeListSize %d", v_TypelistSize[i]);
	}
	GOSSIP("TypeListtotalSize %d", TypelistSize);
	return TypelistSize;

}

u4 GetEncoded(){
	GOSSIP("----------------------Get Encoded");
	u4 EncodeSize = 0;
    u4 i = 0;
	for(i=0;i<dh->classDefsSize;i++){
		const DexClassDef* dcd = dexGetClassDef(df, i);
		const u1* addr = df->baseAddr+dcd->staticValuesOff;
		int lock = 1;
		for(u4 j=0;j<v_EncodedData->size();j++){
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
		u4 size = read_encodedarray_length(v_EncodedData->at(i));
		v_EncodedSize->push_back(size);
		EncodeSize=EncodeSize+size;
	}

	for(i=0;i<v_EncodedSize->size();i++){
		//GOSSIP("EncodedSize %d", v_EncodedSize[i]);
	}

	GOSSIP("EncodedtotalSize %d", EncodeSize);
	return EncodeSize;
}

u4 GetClassData(){
	GOSSIP("----------------------Get ClassData");
    u4 ClassDtataSize=0;
    u4 i = 0;
	for(i=0;i<dh->classDefsSize;i++){


		const DexClassDef* dcd = dexGetClassDef(df, i);

		const u1* addr = df->baseAddr+dcd->classDataOff;
		int lock = 1;
		for(u4 j=0;j<v_ClassData->size();j++){
			if(v_ClassData->at(j)==addr){
				lock = 0;
			}
		}
		if(dcd->classDataOff!=0){
			if(lock==1){
				v_ClassData->push_back(addr);
				//GOSSIP("ClassDataAddr %d", dcd->classDataOff);
			}
		}else{
			//classDataOff=0
			
            //logClass(pDvmDex,loader,df,dcd);
			//GOSSIP("Miss Class!");
		}
		//free(dcd);  			
		
	}

	
	for(i=0;i<v_ClassData->size();i++){
		u4 size = read_classdata_length(v_ClassData->at(i));
		v_ClassDataSize->push_back(size);
		ClassDtataSize =ClassDtataSize+size;
	}

	for(i=0;i<v_ClassDataSize->size();i++){
		//GOSSIP("ClassDataSize %d", v_ClassDataSize[i]);
	}

	GOSSIP("ClassDatatotalSize %d", ClassDtataSize);
	return ClassDtataSize;
}

u4 GetCode(){
	GOSSIP("----------------------Get Code");
	u4 CodeSize=0;
    u4 i = 0;
	for(i=0;i<v_ClassData->size();i++){
		DexClassData* pClassData;
		const u1* temp= new u1;
		temp = v_ClassData->at(i);
		//pClassData = dexReadAndVerifyClassData(&(v_ClassData[i]), NULL);
		pClassData = dexReadAndVerifyClassData(&temp, NULL);//dexReadAndVerifyClassData will change the v_ClassData
		if(pClassData!=NULL){
			u4 number1 = pClassData->header.directMethodsSize;
			u4 number2 = pClassData->header.virtualMethodsSize;
			//GOSSIP("the %d classdata has %d d and %d v", i,number1,number2);

			for(u4 j=0;j<number1;j++){
				const u1* addr = pClassData->directMethods[j].codeOff+df->baseAddr;
				if(pClassData->directMethods[j].codeOff!=0){
					v_CodeData->push_back(addr);

                    if(Flag_Mode){
						u4 dmidx = pClassData->directMethods[j].methodIdx;
						v_DorV->push_back(1);
						v_mid->push_back(dmidx);
					}
				}else{
					//if(Flag_Mode){
					//	GOSSIP("Miss directMethod");
					//}
					//directMethod codeOff = 0
				}
			}
			for(u4 j=0;j<number2;j++){
				const u1* addr = pClassData->virtualMethods[j].codeOff+df->baseAddr;
				if(pClassData->virtualMethods[j].codeOff!=0){
					
					v_CodeData->push_back(addr);
					if(Flag_Mode){
						u4 dmidx = pClassData->virtualMethods[j].methodIdx;
						v_DorV->push_back(2);
						v_mid->push_back(dmidx);
					}
				}else{
					//if(Flag_Mode){
					//	GOSSIP("Miss virtualMethod");
					//}
					//virtualMethod codeOff = 0
				}
			}
		}
		//delete temp;
		//free(pClassData);
	}

	
	//int read_code_length(const u1* co)
	for(i=0;i<v_CodeData->size();i++){
		u4 size = read_code_length(v_CodeData->at(i));
		v_CodeSize->push_back(size);
		CodeSize =CodeSize+size;
	}

	for(i=0;i<v_CodeSize->size();i++){
		//GOSSIP("CodeSize %d", v_CodeSize[i]);
	}

	GOSSIP("CodetotalSize %d", CodeSize);
	return CodeSize;
}
void MakeAddrMap(std::vector<const u1*>* v_Data,std::vector<u4>* v_Size,u4 baseAddr,u4 Addr){
	u4 i = 0;
	if(v_Data->size()!=0){
		for(i=0;i<v_Data->size();i++){
			u4 off = 0;
			for(u4 j=0;j<i;j++){
				off = off+v_Size->at(j);
			}
			
			//AddrMAP->insert(std::map<const u1*,int>::value_type(v_Data->at(i),Addr+off-baseAddr));
			putmap(v_Data->at(i),Addr+off-baseAddr);
		}
	}
}

void MakeAddrMap(std::map<const u1*,u4>* AddrMAP,std::vector<const u1*>* v_Data,std::vector<u4>* v_Size,u4 baseAddr,u4 Addr){
	u4 i = 0;
	u4 size = (u4)v_Data->size();
	if(size!=0){
		for(i=0;i<size;i++){
			u4 off = 0;
			for(u4 j=0;j<i;j++){
				off = off+v_Size->at(j);
			}
			
			AddrMAP->insert(std::map<const u1*,u4>::value_type(v_Data->at(i),Addr+off-baseAddr));
			
			if(Flag_logmap){
				GOSSIP("%d/%d",i,size);
			}
			//putmap(v_Data->at(i),Addr+off-baseAddr);
		}
	}
}

void putmap(const u1* data1, u4 data2){
	char mapfile[256] = {0};
    snprintf ( mapfile, 256, "%s/%d.data", L_folder, (u4)data1 );
	GOSSIP("mapfile %s",mapfile);
	FILE *fp = fopen(mapfile,"w+t"); 
	if(fp!=NULL){
		fwrite( (u1*)(&data2), sizeof( u1 ), 4, fp );
	    fclose(fp);
	}
	
}


void getmap(const u1* data1, u1* data2){
	char mapfile[256] = {0};
    snprintf ( mapfile, 256, "%s/%d.data", L_folder, (u4)data1 );
	FILE *fp = fopen(mapfile,"r+t"); 
	if(fp!=NULL){
		fread( data2, sizeof( u1 ), 4, fp );
	    fclose(fp);
	}
}


u4 BuildOdexHeader(){
	GOSSIP("----------------------ODEX BUILD HEADER");
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

	return offset;
}


u4  BuildHeader(){
	GOSSIP("----------------------DEX BUILD HEADER");
    offset = baseAddr;

	DexHeader* myHeader = new DexHeader;
	memset(myHeader, 0, sizeof(DexHeader));
	memcpy(myHeader, dh, sizeof(DexHeader));

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


u4 BuildStrID(){
	GOSSIP("----------------------DEX BUILD STRID");
	offset = StrIDAddr;
	u4 i;
	for(i=0;i<dh -> stringIdsSize; i++){
		DexStringId* myStringId = new DexStringId;
		//memset(myStringId, 0, sizeof(u4));
		//memcpy(myStringId, df->pStringIds+i*(sizeof(u4)), sizeof(u4));
		
		const u1* ori = (const u1*)(df->pStringIds[i].stringDataOff+(u4)df->baseAddr);

		iter = AddrMAP->find(ori);
		if(iter!= AddrMAP->end()){
			myStringId->stringDataOff = iter->second;
		}else{
			myStringId->stringDataOff =0;
		}
		//u4 addr=0;
	    //getmap(ori,(u1*)(&addr));
		//myStringId->stringDataOff = addr;
		//GOSSIP("new %d", addr);
		dxb_stringid(bs,myStringId, offset);
		//GOSSIP("strdataoff %d", myStringId->stringDataOff);
		offset = offset + sizeof(DexStringId);
		free(myStringId);
	}

	return offset;
}


u4 BuildTypeID(){
	GOSSIP("----------------------DEX BUILD TYPEID");
	u4 i;
	offset = TypeIDAddr;

	for (i = 0; i < dh->typeIdsSize; i++)
	{
		dxb_typeid(bs, &(df->pTypeIds[i]), offset);
		offset = offset + sizeof(DexTypeId);
	}
	return offset;
}

u4 BuildProtoID(){
	GOSSIP("----------------------DEX BUILD ProtoID");
	u4 i;
	offset = ProtoIDAddr;
    
	for (i = 0; i< dh->protoIdsSize; i++)
	{
		DexProtoId* myProtoId = new DexProtoId;
		memset(myProtoId, 0, sizeof(DexProtoId));
		memcpy(myProtoId, &(df->pProtoIds[i]), sizeof(DexProtoId));
		const u1* ori = (const u1*)(df->pProtoIds[i].parametersOff+(u4)df->baseAddr);
		//u4 addr=0;
		//getmap(ori,(u1*)(&addr));
		//myProtoId->parametersOff = addr;
		//GOSSIP("new %d", addr);
		iter = AddrMAP->find(ori);
		if(iter!= AddrMAP->end()){
			myProtoId->parametersOff = iter->second;
		}else{
			myProtoId->parametersOff =0;
		}

		dxb_protoid(bs, myProtoId, offset);
		//GOSSIP("dataoff %d", myProtoId->parametersOff);
		offset = offset + sizeof(DexProtoId);
		free(myProtoId);
	}
	return offset;
}


u4 BuildFieldID(){
	GOSSIP("----------------------DEX BUILD FieldID");
	u4 i;
    offset = FiledIDAddr;

    for (i = 0; i < dh->fieldIdsSize; i++)
	{
		dxb_fieldid(bs, &(df->pFieldIds[i]), offset);
		offset = offset + sizeof(DexFieldId);
	}
    return offset;

}


u4 BuildMethodID(){
	GOSSIP("----------------------DEX BUILD MethodID");
	u4 i;
	offset = MethodIDAddr;
	for (i = 0; i < dh->methodIdsSize; i++)
	{
		dxb_methodid(bs, &(df->pMethodIds[i]), offset);
		offset = offset + sizeof(DexMethodId);
	}
	return offset;

}

u4 BuildClassDef(){
	GOSSIP("----------------------DEX BUILD ClassDef");

	offset = ClassDefAddr;
	u4 i;
	

	for (i = 0; i < dh->classDefsSize; i++)
	{
		DexClassDef* myClassDef = (DexClassDef*)malloc(sizeof(DexClassDef));
		memset(myClassDef, 0, sizeof(DexClassDef));
		memcpy(myClassDef, &(df->pClassDefs[i]), sizeof(DexClassDef));

		const u1* ori0 = (const u1*)(df->pClassDefs[i].interfacesOff+(u4)df->baseAddr);//interfacesOff
		const u1* ori1 = (const u1*)(df->pClassDefs[i].classDataOff+(u4)df->baseAddr);//classDataOff
		const u1* ori2 = (const u1*)(df->pClassDefs[i].staticValuesOff+(u4)df->baseAddr);//staticValuesOff

		//u4 addr0 = 0;
	    //u4 addr1 = 0;
	    //u4 addr2 = 0;
		
		//getmap(ori0,(u1*)(&addr0));
		//myClassDef->interfacesOff = addr0;
		//GOSSIP("new %d", addr0);
		iter = AddrMAP->find(ori0);
		if(iter!= AddrMAP->end()){
			myClassDef->interfacesOff = iter->second;
		}else{
			myClassDef->interfacesOff =0;
		}
		//getmap(ori1,(u1*)(&addr1));
		//myClassDef->classDataOff = addr1;
		//GOSSIP("new %d", addr1);
		iter = AddrMAP->find(ori1);
		if(iter!= AddrMAP->end()){
			myClassDef->classDataOff =  iter->second;
		}else{
			myClassDef->classDataOff = 0;
		}
		//getmap(ori2,(u1*)(&addr2));
		//myClassDef->staticValuesOff = addr2;
		//GOSSIP("new %d", addr2);
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


u4 BuildMap(){
	int TestDexMapItem[]={1,1,1,1,1,1,1,1,1,0,0,1,1,1,1,0,1,0};//test
    u4 TestMapSize = 14;
	GOSSIP("----------------------DEX BUILD Map");
    u4 i;
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
	return offset;
}


u4 BuildTypeList(){
	GOSSIP("----------------------DEX BUILD TypeList");
	u4 i;
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

u4 BuildClassData(){
	GOSSIP("----------------------DEX BUILD ClassData");
	u4 i;
	offset = ClassDataAddr;
    

	for(i=0;i<v_ClassData->size();i++){
		DexClassData* pClassData;
		const u1* temp= new u1;
		temp = v_ClassData->at(i);
		pClassData = dexReadAndVerifyClassData(&temp, NULL);//dexReadAndVerifyClassData will change the v_ClassData
		if(pClassData!=NULL){
			u4 num1 = pClassData->header.directMethodsSize;
			u4 num2 = pClassData->header.virtualMethodsSize;
			for(u4 j=0;j<num1;j++){
				const u1* ori = (const u1*)(pClassData->directMethods[j].codeOff+(u4)df->baseAddr);
				//u4 addr = 0;
				//getmap(ori,(u1*)(&addr));
				//pClassData->directMethods[j].codeOff = addr;
				//GOSSIP("new %d", addr);
				iter = AddrMAP->find(ori);
				if(iter!= AddrMAP->end()){
					pClassData->directMethods[j].codeOff = iter->second;
				}else{
					pClassData->directMethods[j].codeOff =0;
				}
				
				//GOSSIP("old:%d new: %d",AddrMAP1[ori],pClassData->directMethods[j].codeOff);
			}
			for(u4 j=0;j<num2;j++){
				const u1* ori = (const u1*)(pClassData->virtualMethods[j].codeOff+(u4)df->baseAddr);
				//u4 addr = 0;
				//getmap(ori,(u1*)(&addr));
				//pClassData->virtualMethods[j].codeOff = addr;
				//GOSSIP("new %d", addr);
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


u4 BuildCode(DvmDex* pDvmDex,Object* loader){
	GOSSIP("----------------------DEX BUILD Code");
	u4 i;
	offset = CodeAddr;
	for(i=0;i<v_CodeData->size();i++){
		DexCode* myCode = (DexCode*)malloc(v_CodeSize->at(i));
		memset(myCode, 0, v_CodeSize->at(i));
		memcpy(myCode, v_CodeData->at(i), v_CodeSize->at(i));
		myCode->debugInfoOff =0x00000000;


		if(Flag_Mode){
				u4 dmidx = v_mid->at(i);
				if(dmidx!=0){
					//if(myCode->insnsSize > 1 && myCode->insns[0]==0){
						
						const DexMethodId* dmi = dexGetMethodId(df,dmidx);
						const char* cname = dexStringByTypeIdx(df,dmi->classIdx);
						const char* mname = dexStringById(df,dmi->nameIdx);
						if(CheckStr(cname)){
							bool debug = false;
							if(CheckStr2(cname,mname)){
								debug = true;
							}
							if(Flag_logcm){
								GOSSIP("buildcode %s%s",cname,mname);
							}
							if (dvmAttachCurrentThread(&jniArgs, true)) {
								if(debug){
									GOSSIP("debug %s%s",cname,mname);
								}
								ClassObject * coreClazz=NULL;							
								coreClazz= dvmDefineClass(pDvmDex, cname,loader);
                                //Thread* self = dvmThreadSelf();
								//if(dvmCheckException(self)){
                                //   dvmClearException(self);
								//   coreClazz = NULL;
								//}

								if(coreClazz!=NULL){
									//dvmInitClass(coreClazz);
									if (!dvmIsClassInitialized(coreClazz)){
										if(dvmInitClass(coreClazz)){
											if(debug){
												GOSSIP("init clazz %s",cname);
											}
										}else{
											if(debug){
												GOSSIP("init clazz failed %s",cname);
											}
										}
									}
									DexProto proto;
									proto.dexFile = df;
									proto.protoIdx = dmi->protoIdx;
									Method *orderMethod=0;
									if(v_mid->at(i)==1){
										orderMethod = dvmFindDirectMethod(coreClazz, mname, &proto );
									}else{
										orderMethod = dvmFindVirtualMethod(coreClazz, mname, &proto );
									}
									if(orderMethod!=NULL){
										if(orderMethod->insns!=0&&myCode->insnsSize!=0){
											for(u4 j =0;j<myCode->insnsSize;j++){
												if(Flag_logins||debug){
													GOSSIP("%02x ---------- %02x", myCode->insns[j], *((orderMethod->insns)+j));
												}
												
												myCode->insns[j] = *(orderMethod->insns+j);
											}
										}else{
											if(debug){
												GOSSIP("ins size 0 %s",mname);
											}
										}
									}else{
										if(debug){
											GOSSIP("method null %s",mname);
										}
									}//end if(orderMethod!=NULL)
								}else{
									if(debug){
										GOSSIP("clazz null %s",cname);
									}
								}//end if(coreClazz!=NULL)
								dvmDetachCurrentThread();
							}//end if (dvmAttachCurrentThread(&jniArgs, true)) 
						}//end if(CheckStr(cname))
					//}//end if(myCode->insnsSize > 1 && myCode->insns[0]==0)
				}//end if(dmidx!=0)
		}//end if(Flag_Mode)

		bsseek(bs,offset);
		bswrite(bs,(u1*)(myCode),v_CodeSize->at(i));
		offset = offset+v_CodeSize->at(i);
		free(myCode);
	}//end for
	free(v_CodeData);
	free(v_CodeSize);
	free(v_mid);

	return offset;
}

u4 BuildStrData(){
	GOSSIP("----------------------DEX BUILD StrData");
	u4 i;
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

u4 BuildEncoded(){
	GOSSIP("----------------------DEX BUILD Encoded");
	u4 i;
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
u4 read_classdata_length(const u1* cd){
		const u1* start = cd;
		DexClassDataHeader *pHeader = new DexClassDataHeader;
		dexReadClassDataHeader(&cd, pHeader); 


		u4 number = 2*(pHeader->staticFieldsSize+pHeader->instanceFieldsSize)+3*(pHeader->directMethodsSize+pHeader->virtualMethodsSize);
		for(u4 i=0;i<number;i++){
			readUnsignedLeb128(&cd);
			//GOSSIP("Leb128----: %d", a);
	    }
	    const u1* end = cd;
	    u4 length = (u4)(end-start);
	    //GOSSIP("Leb128----addr: %d", length);
	    u4 methodNum = pHeader->directMethodsSize+pHeader->virtualMethodsSize;
		//delete pHeader;
	    return length+4*methodNum+4;  //!!!!!!!!!!!!  1 classdata may have more than 1 codeoff which will be changed.
	}
u4 read_strdata_length(const u1* str){
		u4 length = 0;
  		while(true){
             if(str[length]==0x00){
             	return length+1;
             }
             length++;
  		}
	}
u4 read_typelist_length(const u1* tyl){
		const DexTypeList* dtl = (const DexTypeList*)tyl;
		u4 length = 0;
    	if(dtl->size%2){//fill for 4 bytes
    		length = (dtl->size+1)*2+4;
    	}else{
    		length = dtl->size*2+4;
    	}
        return length;
	}
u4 read_encodedarray_length(const u1* ea){
		
		u4 length = 0;
		const u1* start = ea;
		u4 number = readUnsignedLeb128(&ea);
		//GOSSIP("EncodedNumber: %d", number);
		const u1* end = ea;
		
		//int size = (((int)ea[0]) - ((int)ea[0])%32)/32 + 1;
		u4 i=0;
		
		while(true){
			if(i==number){
				break;
			}
			u4 value = (u4)ea[length];  //1 byte for value type,first 3bits is type,last 5 bits is (size-1)
			u4 type = value%32;// the type is high 3 bits
			u4 size=0;

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

u4 read_code_length(const u1* co){
		u4 length = (u4)dexGetDexCodeSize((const DexCode*) co);
		//GOSSIP("codeSize: %d", length);
		return fill_4_byte(length);
	}

u4 read_debuginfo_length(const u1* di){
		const u1* start = di;
		readUnsignedLeb128(&di);
		u4 number = (u4)readUnsignedLeb128(&di);
		for(u4 i=0;i<number;i++){
			readUnsignedLeb128(&di);
		}
		//const u1* end = di;


		u4 length = 0;
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
  		length = (u4)(di-start);
  		//GOSSIP("debuginfo size: %d", length);
		return length;
	}


void writeClassData(const u1* pClassData,u4 off,ByteStream* bs){
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
  			    u4 size = (u4)temp-(u4)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("sfs:--%d",pCD->header.staticFieldsSize);
		        //GOSSIP("sfs:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.instanceFieldsSize);
  			    size = (u4)temp-(u4)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("ifs:--%d",pCD->header.instanceFieldsSize);
		        //GOSSIP("ifs:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.directMethodsSize);
  			    size = (u4)temp-(u4)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("dms:--%d",pCD->header.directMethodsSize);
		        //GOSSIP("dms:--%x",*start);
		        
		        off = off +size;

		        temp = start;
		        temp=writeUnsignedLeb128(start, pCD->header.virtualMethodsSize);
  			    size = (u4)temp-(u4)start;
  				bsseek(bs,off);
		        bswrite(bs,start,size);
		        //GOSSIP("vms:--%d",pCD->header.virtualMethodsSize);
		        //GOSSIP("vms:--%x",*start);
		        
		        off = off +size;

		        for(u4 i=0;i<pCD->header.staticFieldsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->staticFields[i].fieldIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->staticFields[i].fieldIdx-pCD->staticFields[i-1].fieldIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->staticFields[i].fieldIdx);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("sf_fid:--%d",pCD->staticFields[i].fieldIdx);
		            //GOSSIP("sf_fid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->staticFields[i].accessFlags);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("sf_af:--%d",pCD->staticFields[i].accessFlags);
		            //GOSSIP("sf_af:--%x",*start);
			        
			        off = off +size;
		        }
		        for(u4 i=0;i<pCD->header.instanceFieldsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->instanceFields[i].fieldIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->instanceFields[i].fieldIdx-pCD->instanceFields[i-1].fieldIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->instanceFields[i].fieldIdx);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("if_fid:--%d",pCD->instanceFields[i].fieldIdx);
		            //GOSSIP("if_fid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->instanceFields[i].accessFlags);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("if_af:--%d",pCD->instanceFields[i].accessFlags);
		            //GOSSIP("if_af:--%x",*start);
			        
			        off = off +size;
		        }
		        for(u4 i=0;i<pCD->header.directMethodsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->directMethods[i].methodIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->directMethods[i].methodIdx-pCD->directMethods[i-1].methodIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->directMethods[i].methodIdx);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_mid:--%d",pCD->directMethods[i].methodIdx);
		            //GOSSIP("dm_mid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->directMethods[i].accessFlags);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_af:--%d",pCD->directMethods[i].accessFlags);
		            //GOSSIP("dm_af:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->directMethods[i].codeOff);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("dm_cf:--%d",pCD->directMethods[i].codeOff);
		            //GOSSIP("dm_cf:--%x",*start);
			        
			        off = off +size;
		        }
		        for(u4 i=0;i<pCD->header.virtualMethodsSize;i++){
		        	temp = start;
		        	if(i==0){
						temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].methodIdx);
			        }else{
						temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].methodIdx-pCD->virtualMethods[i-1].methodIdx);
			        }
		        	//temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].methodIdx);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_mid:--%d",pCD->virtualMethods[i].methodIdx);
		            //GOSSIP("vm_mid:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].accessFlags);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_af:--%d",pCD->virtualMethods[i].accessFlags);
		            //GOSSIP("vm_af:--%x",*start);
			        
			        off = off +size;

			        temp = start;
			        temp=writeUnsignedLeb128(start, pCD->virtualMethods[i].codeOff);
	  			    size = (u4)temp-(u4)start;
	  				bsseek(bs,off);
			        bswrite(bs,start,size);
			        //GOSSIP("vm_cf:--%d",pCD->virtualMethods[i].codeOff);
		            //GOSSIP("vm_cf:--%x",*start);
			        
			        off = off +size;
		        }

 
  			}

	}

u4 fill_4_byte(u4 size){
		size = size + (4-size%4);
		return size;
	}
void initflag(){
	GOSSIP("initflag");
	std::string ss;
	char filename[256] = {0};
	snprintf ( filename, 256, "%s/%s", L_folder, "unpackflag" );
	std::ifstream f( filename );	
	if (!f){
		return;
	}
	GOSSIP("initflag");
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

bool CheckStr(const char* s){
	if(strstr(s,"Landroid")){
		return false;
	}
	if(strstr(s,"Lcn/sharesdk")){
		return false;
	}
	if(strstr(s,"Lcom/baidu")){
		return false;
	}
	if(strstr(s,"Lcom/google")){
		return false;
	}
	if(strstr(s,"Lcom/tencent")){
		return false;
	}
	if(strstr(s,"Lorg/apache")){
		return false;
	}
	//if(strstr(s,"Lcom/amap")){
	//	return false;
	//}

	//if(strstr(s,"Lbonree")){
	//	return false;
	//}
	//if(strstr(s,"Lcn/org/bjca")){
	//	return false;
	//}
	//if(strstr(s,"Lcom/fjs/util/CommonUtil")){
	//	return false;
	//}
	//if(strstr(s,"Lcom/paem/bussiness/home/utils/ZHHBLoginUtil")){
	//	return false;
	//}
	std::string ss;
	char filename[256] = {0};
	snprintf ( filename, 256, "%s/%s", L_folder, "unpacklist1" );
	std::ifstream f( filename );	
	while ( std::getline(f, ss) )
	{
		//GOSSIP("filter1 %s",ss.c_str());
		if(strstr(s,ss.c_str())){
			f.close();
			return false;
		}
	}
	f.close();
	return true;

}


bool CheckStr2(const char* s1, const char* s2){
	std::string ss;
	char filename[256] = {0};
	snprintf ( filename, 256, "%s/%s", L_folder, "unpacklist2" );
	char cm[256] = {0};
	snprintf ( cm, 256, "%s%s", s1, s2 );
	std::ifstream f( filename );	
	while ( std::getline(f, ss) )
	{
		//GOSSIP("filter2 %s %s",cm,ss.c_str());
		if(strstr(cm,ss.c_str())){
			f.close();
			return true;
		}
	}
	f.close();

	return false;

}


void test_debug(DvmDex* pDvmDex,Object* loader){
	const char* cname = "Lcom/example/goodluck/Act_Main;";
	const char* mname = "init";
	u4 dmidx = 4658;
	const DexMethodId* dmi = dexGetMethodId(df,dmidx);
	//int type = 1;//direct
	if (dvmAttachCurrentThread(&jniArgs, true)) {
		ClassObject * coreClazz=NULL;
		coreClazz= dvmDefineClass(pDvmDex, cname,loader);
		if(coreClazz!=NULL){
			if (!dvmIsClassInitialized(coreClazz)){
				if(dvmInitClass(coreClazz)){
					GOSSIP("debug_test init clazz %s",cname);
				}else{
					GOSSIP("debug_test init clazz failed %s",cname);
				}
			}
			DexProto proto;
			proto.dexFile = df;
			proto.protoIdx = dmi->protoIdx;

			Method *orderMethod=NULL;
			//orderMethod = dvmFindVirtualMethodByName(coreClazz, mname);
			orderMethod = dvmFindDirectMethod(coreClazz, mname, &proto );
			if(orderMethod!=NULL){
				GOSSIP("debug_test ins size  %d",orderMethod->insSize);
				if(orderMethod->insSize!=0 && orderMethod->insns!=NULL){
					for(u4 j =0;j<orderMethod->insSize;j++){
						GOSSIP("debug_test ins---------- %02x", *((orderMethod->insns)+j));
					}
				}else{
					GOSSIP("debug_test ins size 0 %s",mname);
					
				}
			}else{
				GOSSIP("debug_test method null %s",mname);
			}
		}else{
			GOSSIP("debug_test class null %s",cname);
		}
		dvmDetachCurrentThread();
	}
}



void logClass(DvmDex* pDvmDex,Object* loader,const DexFile* df,const DexClassDef* dcd){
	
	const char* cname = dexStringByTypeIdx(df,dcd->classIdx);
    GOSSIP("fucklog: try to get class: %s",cname);
	ClassObject * coreClazz=0;
	
	coreClazz= dvmDefineClass(pDvmDex, cname,loader);
	Thread* self = dvmThreadSelf();
	if (dvmCheckException(self)) {
		Object* excep = dvmGetException(self);
		if (strcmp(excep->clazz->descriptor,
				   "Ljava/lang/ClassNotFoundException;") == 0 ||
			strcmp(excep->clazz->descriptor,
				   "Ljava/lang/NoClassDefFoundError;") == 0)
		{
			dvmClearException(self);
		}
		GOSSIP("exception");
		coreClazz = NULL;
	}
	if(coreClazz == NULL){
		GOSSIP("fucklog: get class: %s failed",cname);
	}else{
		GOSSIP("fucklog: get class: %s successfully",cname);
		GOSSIP("fucklog: class: %s directMethodCount %d virtualMethodCount %d ifieldCount %d sfieldCount %d",cname,coreClazz->directMethodCount,coreClazz->virtualMethodCount,coreClazz->ifieldCount,coreClazz->sfieldCount);
	}

}

void logMethod(DvmDex* pDvmDex,Object* loader,const DexFile* df,DexMethod dm,u4 dorv){

	
	u4 dmidx = dm.methodIdx;
	const DexMethodId* dmi = dexGetMethodId(df,dmidx);
	const char* cname = dexStringByTypeIdx(df,dmi->classIdx);
	const char* mname = dexStringById(df,dmi->nameIdx);
	
	if(CheckStr(cname)){
		GOSSIP("fucklog2: logMethod: %s %s",cname,mname);
		//GOSSIP("fucklog2: try to get class: %s method: %s",cname,mname);
		ClassObject * coreClazz=0;
		
		coreClazz= dvmDefineClass(pDvmDex, cname,loader);
		Thread* self = dvmThreadSelf();
		if (dvmCheckException(self)) {
			Object* excep = dvmGetException(self);
			if (strcmp(excep->clazz->descriptor,
					   "Ljava/lang/ClassNotFoundException;") == 0 ||
				strcmp(excep->clazz->descriptor,
					   "Ljava/lang/NoClassDefFoundError;") == 0)
			{
				dvmClearException(self);
			}
			GOSSIP("exception");
			coreClazz = NULL;
		}
		if(coreClazz == NULL){
			GOSSIP("fucklog2: get class: %s %s failed",cname,mname);
		}else{
			//GOSSIP("fucklog2: get class: %s successfully",cname);
			DexProto proto;
			proto.dexFile = df;
			proto.protoIdx = dmi->protoIdx;
			Method *orderMethod=0;
			if(dorv == 1){
				orderMethod = dvmFindVirtualMethod(coreClazz, mname, &proto );
			}else{
				orderMethod = dvmFindDirectMethod(coreClazz, mname, &proto );
			}
			if(orderMethod == NULL){
				GOSSIP("fucklog2: get method: %s %s failed",cname,mname);
			}else{
				//GOSSIP("fucklog2: get method: %s successfully",mname);
				//GOSSIP("fucklog2: base: %p",df->baseAddr);
				if(orderMethod->insns!=NULL){
					GOSSIP("fucklog2: class : %s method: %s insnsSize %d",cname,mname,*((orderMethod->insns)-2));
					if((unsigned int)*((orderMethod->insns)-2)>1000){
						GOSSIP("insnsSize %d",*((orderMethod->insns)-2));
					}
				}else{
					GOSSIP("fucklog2: class : %s method: %s null",cname,mname);
				}
				/*Thread* self = dvmThreadSelf();
				if (dvmCheckException(self)) {
					Object* excep = dvmGetException(self);
					if(excep != NULL){
						dvmClearException(self);
					}
				}*/
			}
		}
	}
				
}















}