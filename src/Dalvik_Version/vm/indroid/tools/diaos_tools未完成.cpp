#include "indroid/tools/diaos_tools.h"
#include <fstream>
#include <string.h>
#include <vector>
#include <map>
#include <stdlib.h>
#include <iostream>  
#include <exception> 

// define YWB message output macro
#define DIAOS_DBG 1
#if defined(DIAOS_DBG)
# define GOSSIP(...) ALOG( LOG_VERBOSE, "LBD", __VA_ARGS__)
#else
# define GOSSIP(...) (void(0)) 
#endif


namespace gossip_loccs
{
	struct CMname {// class name and method name for code insns
        const char*   classname;
		const char*   methodname;
		int dorv;  //direct or virtual
		u2 protoIdx;  
    };



void dexbuild(DvmDex* pDvmDex,const char* filename, Object* loader);
int GetStrData(const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_StrData, std::vector<int>* v_StrDataLength);
int GetTypeList(const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize);
int GetEncoded(const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize);
int GetClassData(DvmDex* pDvmDex,Object* loader,const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize);
int GetCode(DvmDex* pDvmDex,Object* loader,const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<CMname*>* v_name,std::vector<const u1*>* v_ClassData);
void MakeAddrMap(std::map<const u1*,int>* AddrMAP,std::vector<const u1*>* v_Data,std::vector<int>* v_Size,int baseAddr,int Addr);
int BuildOdexHeader(ByteStream* bs, int offset, const DexFile* df,const DexOptHeader* doh, int EndAddr,int baseAddr);
int BuildHeader(ByteStream* bs, int offset,const DexHeader *dh,int baseAddr,int EndAddr,int MapAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int TypeListAddr);
int BuildStrID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,std::map<const u1*,int>* AddrMAP,int StrIDAddr);
int BuildTypeID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,int TypeIDAddr);
int BuildProtoID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,std::map<const u1*,int>* AddrMAP,int ProtoIDAddr);
int BuildFieldID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,int FiledIDAddr);
int BuildMethodID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,int MethodIDAddr);
int BuildClassDef(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,std::map<const u1*,int>* AddrMAP,int ClassDefAddr);
int BuildMap(ByteStream* bs, int offset,const DexHeader *dh,
	int baseAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int MapAddr,int TypeListAddr,int ClassDataAddr,int CodeAddr,int StrDataAddr,int DebugAddr,int EncodedAddr,int EndAddr,
    std::vector<const u1*>* v_TypelistData,std::vector<const u1*>* v_ClassData,std::vector<const u1*>* v_CodeData,std::vector<const u1*>* v_StrData,std::vector<const u1*>* v_EncodedData	
    );
int BuildTypeList(ByteStream* bs, int offset,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize,int TypeListAddr);
int BuildClassData(ByteStream* bs, int offset,const DexFile* df,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize,std::map<const u1*,int>* AddrMAP,int ClassDataAddr);
int BuildCode(ByteStream* bs, int offset,DvmDex* pDvmDex,Object* loader,const DexFile* df,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<CMname*>* v_name,int CodeAddr);
int BuildStrData(ByteStream* bs, int offset,std::vector<const u1*>* v_StrData,std::vector<int>* v_StrDataLength,int StrDataAddr);
int BuildEncoded(ByteStream* bs, int offset,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize,int EncodedAddr);
void dxb_header(ByteStream *bs, const DexHeader *header,uint32_t offset);
void dxb_oheader(ByteStream *bs, const DexOptHeader *header,uint32_t offset);
void dxb_stringid(ByteStream* bs, const DexStringId *obj, uint32_t offset);
void dxb_typeid(ByteStream* bs, const DexTypeId *obj, uint32_t offset);
void dxb_protoid(ByteStream* bs, const DexProtoId *obj, uint32_t offset);
void dxb_fieldid(ByteStream* bs, const DexFieldId *obj, uint32_t offset);
void dxb_methodid(ByteStream* bs, const DexMethodId *obj, uint32_t offset);
void dxb_classdef(ByteStream* bs, const DexClassDef *obj, uint32_t offset);
int read_classdata_length(const u1* cd);
int read_strdata_length(const u1* str);
int read_typelist_length(const u1* tyl);
int read_encodedarray_length(const u1* ea);
int read_code_length(const u1* co);
int read_debuginfo_length(const u1* di);
void writeClassData(const u1* pClassData,int off,ByteStream* bs);
int fill_4_byte(int size);
bool CheckStr(const char* s);

void logClass(DvmDex* pDvmDex,Object* loader,const DexFile* df,const DexClassDef* dcd);
void logMethod(DvmDex* pDvmDex,Object* loader,const DexFile* df,DexMethod dm,int dorv);
int lbdGetCodeSizeFromLoader(DvmDex* pDvmDex,Object* loader,const DexFile* df,DexMethod dm,int dorv);
void lbdInitCodeFromLoader(DvmDex* pDvmDex,Object* loader,const DexFile* df,CMname* cm,DexCode* myCode);








void dexbuild(DvmDex* pDvmDex,const char* filename, Object* loader){
	bool IsOdex = false;
	int OdexAddrOff = 0;

	GOSSIP("----------------------DEX BUILD START");
	const DexFile* df = pDvmDex->pDexFile;
	if (df == NULL) return;
	const DexHeader *dh = df->pHeader;
 	const DexOptHeader* doh;

	if(IsOdex){
		GOSSIP("----------------------Get Odex");
		doh = df->pOptHeader;
		OdexAddrOff = sizeof(DexOptHeader)+fill_4_byte(doh->depsLength)+fill_4_byte(doh->optLength);
 	}

	//-------------------------------------------------------------------------------declare Objects
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

    
    //-----------------------------------------------------------------------------get Datas
    std::vector<const u1*>* v_StrData = new std::vector<const u1*>;
    std::vector<int>* v_StrDataLength = new std::vector<int>;
    int StrDataSize = GetStrData(df,dh,v_StrData,v_StrDataLength);

    std::vector<const u1*>* v_TypelistData = new std::vector<const u1*>;
  	std::vector<int>* v_TypelistSize=new std::vector<int>;
    int TypelistSize = GetTypeList(df,dh,v_TypelistData,v_TypelistSize);

    std::vector<const u1*>* v_EncodedData=new std::vector<const u1*>;
    std::vector<int>* v_EncodedSize=new std::vector<int>;
    int EncodeSize = GetEncoded(df,dh,v_EncodedData,v_EncodedSize);

	std::vector<const u1*>* v_ClassData=new std::vector<const u1*>;
    std::vector<int>* v_ClassDataSize=new std::vector<int>;
    int ClassDtataSize= GetClassData(pDvmDex,loader,df,dh,v_ClassData,v_ClassDataSize);

    std::vector<const u1*>* v_CodeData=new std::vector<const u1*>;
  	std::vector<int>* v_CodeSize=new std::vector<int>;
    std::vector<CMname*>* v_name=new std::vector<CMname*>;
    int CodeSize= GetCode(pDvmDex,loader,df,dh,v_CodeData,v_CodeSize,v_name,v_ClassData);

	int DebugSize=0;

    //-------------------------------------------------------------------------------intial Objects
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
	MakeAddrMap(AddrMAP,v_TypelistData,v_TypelistSize,baseAddr,TypeListAddr);
	MakeAddrMap(AddrMAP,v_StrData,v_StrDataLength,baseAddr,StrDataAddr);
	MakeAddrMap(AddrMAP,v_EncodedData,v_EncodedSize,baseAddr,EncodedAddr);
	MakeAddrMap(AddrMAP,v_ClassData,v_ClassDataSize,baseAddr,ClassDataAddr);
    MakeAddrMap(AddrMAP,v_CodeData,v_CodeSize,baseAddr,CodeAddr);
    
    //-------------------------------------------------------------------------------WriteFile
    ByteStream* bs = bsalloc(EndAddr);
	int offset = 0;
    if (bs == NULL) return;

	if(IsOdex){
		offset = BuildOdexHeader(bs,offset,df,doh,EndAddr,baseAddr);
	}

	offset = BuildHeader(bs,offset,dh,baseAddr,EndAddr,MapAddr,StrIDAddr,TypeIDAddr,ProtoIDAddr,FiledIDAddr,MethodIDAddr,ClassDefAddr,TypeListAddr);
	offset = BuildStrID(bs,offset,df,dh,AddrMAP,StrIDAddr);
	offset = BuildTypeID(bs,offset,df,dh,TypeIDAddr);
	offset = BuildProtoID(bs,offset,df,dh,AddrMAP,ProtoIDAddr);
	offset = BuildFieldID(bs,offset,df,dh,FiledIDAddr);
	offset = BuildMethodID(bs,offset,df,dh,MethodIDAddr);
	offset = BuildClassDef(bs,offset,df,dh,AddrMAP,ClassDefAddr);
    offset = BuildMap(bs,offset,dh,baseAddr,StrIDAddr,TypeIDAddr,ProtoIDAddr,FiledIDAddr,MethodIDAddr,ClassDefAddr,MapAddr,TypeListAddr,ClassDataAddr,CodeAddr,StrDataAddr,DebugAddr,EncodedAddr,EndAddr,v_TypelistData,v_ClassData,v_CodeData,v_StrData,v_EncodedData);
	offset = BuildTypeList(bs,offset,v_TypelistData,v_TypelistSize,TypeListAddr);
	offset = BuildClassData(bs,offset,df,v_ClassData,v_ClassDataSize,AddrMAP,ClassDataAddr);
	offset = BuildCode(bs,offset,pDvmDex,loader,df,v_CodeData,v_CodeSize,v_name,CodeAddr);
	offset = BuildStrData(bs,offset,v_StrData,v_StrDataLength,StrDataAddr);
	offset = BuildEncoded(bs,offset,v_EncodedData,v_EncodedSize,EncodedAddr);

    free(AddrMAP);

	bssave(bs,filename);

  	bsfree(bs);
    GOSSIP("----------------------DEX BUILD Finish 1207 new");

}

int GetStrData(const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_StrData, std::vector<int>* v_StrDataLength){
	GOSSIP("----------------------Get StrData");
	int StrDataSize = 0;
	unsigned int i = 0;
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
	return StrDataSize;

}

int GetTypeList(const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize){
	GOSSIP("----------------------Get TypeList");
    int TypelistSize = 0;
	unsigned int i = 0;

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
	return TypelistSize;

}
int GetEncoded(const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize){
	GOSSIP("----------------------Get Encoded");
	int EncodeSize = 0;
    unsigned int i = 0;
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
	return EncodeSize;
}
int GetClassData(DvmDex* pDvmDex,Object* loader,const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize){
	GOSSIP("----------------------Get ClassData");
    int ClassDtataSize=0;
    unsigned int i = 0;
	for(i=0;i<dh->classDefsSize;i++){
		const DexClassDef* dcd = dexGetClassDef(df, i);

		const u1* addr = df->baseAddr+dcd->classDataOff;
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
		}else{
			//classDataOff=0
			
            //logClass(pDvmDex,loader,df,dcd);
		}
		//free(dcd);  			
		
	}

	
	for(i=0;i<v_ClassData->size();i++){
		int size = read_classdata_length(v_ClassData->at(i));
		v_ClassDataSize->push_back(size);
		ClassDtataSize =ClassDtataSize+size;
	}

	for(i=0;i<v_ClassDataSize->size();i++){
		//GOSSIP("ClassDataSize %d", v_ClassDataSize[i]);
	}

	GOSSIP("ClassDatatotalSize %d", ClassDtataSize);
	return ClassDtataSize;
}
int GetCode(DvmDex* pDvmDex,Object* loader,const DexFile* df,const DexHeader *dh,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<CMname*>* v_name,std::vector<const u1*>* v_ClassData){
	GOSSIP("----------------------Get Code");
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
				const u1* addr = pClassData->directMethods[j].codeOff+df->baseAddr;
                int lockforpush = 0;

				if(pClassData->directMethods[j].codeOff!=0){
					int lock = 1;
					for(unsigned int k =0;k<v_CodeData->size();k++){
						if(addr==v_CodeData->at(k)){
							lock = 0;
						}
					}
					if(lock==1){
						v_CodeData->push_back(addr);
						int size = read_code_length(addr);
						v_CodeSize->push_back(size);
		                CodeSize =CodeSize+size;
						lockforpush = 1;
					}
				}else{
					//directMethod codeOff = 0
					int codesize = 
						lbdGetCodeSizeFromLoader(pDvmDex,loader,df,pClassData->directMethods[j],0);
					if(codesize!=0){
						v_CodeData->push_back(0);
						v_CodeSize->push_back(codesize);
		                CodeSize =CodeSize+codesize;
						lockforpush = 1;
					}
				}

				if(lockforpush == 1){
					u4 dmidx = pClassData->directMethods[j].methodIdx;
					const DexMethodId* dmi = dexGetMethodId(df,dmidx);
					const char* cname = dexStringByTypeIdx(df,dmi->classIdx);
					const char* mname = dexStringById(df,dmi->nameIdx);

					//GOSSIP("directMethod %s %s", cname, mname);

					CMname* cm = new  CMname;
					cm->classname = cname;
					cm->methodname = mname;
					cm->dorv = 0;
					cm->protoIdx=dmi->protoIdx;
					v_name->push_back(cm);
				}
			}
			for(int j=0;j<number2;j++){
				const u1* addr = pClassData->virtualMethods[j].codeOff+df->baseAddr;
				int lockforpush = 0;
				if(pClassData->virtualMethods[j].codeOff!=0){
					int lock = 1;
					for(unsigned int k =0;k<v_CodeData->size();k++){
						if(addr==v_CodeData->at(k)){
							lock = 0;
						}
					}
					if(lock==1){
						v_CodeData->push_back(addr);
						int size = read_code_length(addr);
						v_CodeSize->push_back(size);
		                CodeSize =CodeSize+size;
						lockforpush = 1;
					}
				}else{
					//virtualMethod codeOff = 0
					int codesize = 
						lbdGetCodeSizeFromLoader(pDvmDex,loader,df,pClassData->virtualMethods[j],1);
					if(codesize!=0){
						v_CodeData->push_back(0);
						v_CodeSize->push_back(codesize);
		                CodeSize =CodeSize+codesize;
						lockforpush = 1;
					}
				}

				if(lockforpush == 1){
					u4 dmidx = pClassData->virtualMethods[j].methodIdx;
					const DexMethodId* dmi = dexGetMethodId(df,dmidx);
					const char* cname = dexStringByTypeIdx(df,dmi->classIdx);
					const char* mname = dexStringById(df,dmi->nameIdx);

					//GOSSIP("virtualMethod %s %s", cname, mname);

					CMname* cm = new  CMname;
					cm->classname = cname;
					cm->methodname = mname;
					cm->dorv = 1;
					cm->protoIdx=dmi->protoIdx;
					v_name->push_back(cm);
				}

			}
		}
		//delete temp;
		//free(pClassData);
	}

	
	//int read_code_length(const u1* co)
	/*
	for(i=0;i<v_CodeData->size();i++){
		int size = read_code_length(v_CodeData->at(i));
		v_CodeSize->push_back(size);
		CodeSize =CodeSize+size;
	}

	for(i=0;i<v_CodeSize->size();i++){
		//GOSSIP("CodeSize %d", v_CodeSize[i]);
	}*/

	GOSSIP("CodetotalSize %d", CodeSize);
	return CodeSize;
}
void MakeAddrMap(std::map<const u1*,int>* AddrMAP,std::vector<const u1*>* v_Data,std::vector<int>* v_Size,int baseAddr,int Addr){
	unsigned int i = 0;
	if(v_Data->size()!=0){
		for(i=0;i<v_Data->size();i++){
			int off = 0;
			for(unsigned int j=0;j<i;j++){
				off = off+v_Size->at(j);
			}
			//AddrMAP1[v_TypelistData->at(i)] = TypeListAddr+off-baseAddr;
			AddrMAP->insert(std::map<const u1*,int>::value_type(v_Data->at(i),Addr+off-baseAddr));
		}
	}
}

int BuildOdexHeader(ByteStream* bs, int offset, const DexFile* df,const DexOptHeader* doh, int EndAddr,int baseAddr){
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

int  BuildHeader(ByteStream* bs, int offset,const DexHeader *dh,int baseAddr,int EndAddr,int MapAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int TypeListAddr){
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

int BuildStrID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,std::map<const u1*,int>* AddrMAP,int StrIDAddr){
	GOSSIP("----------------------DEX BUILD STRID");
	offset = StrIDAddr;
	unsigned int i;
	std::map <const u1*,int>::iterator iter;
	
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

	return offset;
}

int BuildTypeID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,int TypeIDAddr){
	GOSSIP("----------------------DEX BUILD TYPEID");
	unsigned int i;
	offset = TypeIDAddr;

	for (i = 0; i < dh->typeIdsSize; i++)
	{
		dxb_typeid(bs, &(df->pTypeIds[i]), offset);
		offset = offset + sizeof(DexTypeId);
	}
	return offset;
}
int BuildProtoID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,std::map<const u1*,int>* AddrMAP,int ProtoIDAddr){
	GOSSIP("----------------------DEX BUILD ProtoID");
	unsigned int i;
	offset = ProtoIDAddr;
	std::map <const u1*,int>::iterator iter;

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
	return offset;
}

int BuildFieldID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,int FiledIDAddr){
	GOSSIP("----------------------DEX BUILD FieldID");
	unsigned int i;
    offset = FiledIDAddr;

    for (i = 0; i < dh->fieldIdsSize; i++)
	{
		dxb_fieldid(bs, &(df->pFieldIds[i]), offset);
		offset = offset + sizeof(DexFieldId);
	}
    return offset;

}

int BuildMethodID(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,int MethodIDAddr){
	GOSSIP("----------------------DEX BUILD MethodID");
	unsigned int i;
	offset = MethodIDAddr;
	for (i = 0; i < dh->methodIdsSize; i++)
	{
		dxb_methodid(bs, &(df->pMethodIds[i]), offset);
		offset = offset + sizeof(DexMethodId);
	}
	return offset;

}
int BuildClassDef(ByteStream* bs, int offset,const DexFile* df,const DexHeader *dh,std::map<const u1*,int>* AddrMAP,int ClassDefAddr){
	GOSSIP("----------------------DEX BUILD ClassDef");

	offset = ClassDefAddr;
	unsigned int i;
    std::map <const u1*,int>::iterator iter;

	for (i = 0; i < dh->classDefsSize; i++)
	{
		DexClassDef* myClassDef = (DexClassDef*)malloc(sizeof(DexClassDef));
		memset(myClassDef, 0, sizeof(DexClassDef));
		memcpy(myClassDef, &(df->pClassDefs[i]), sizeof(DexClassDef));

		const u1* ori0 = (const u1*)(df->pClassDefs[i].interfacesOff+(int)df->baseAddr);//interfacesOff
		const u1* ori1 = (const u1*)(df->pClassDefs[i].classDataOff+(int)df->baseAddr);//classDataOff
		const u1* ori2 = (const u1*)(df->pClassDefs[i].staticValuesOff+(int)df->baseAddr);//staticValuesOff

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

int BuildMap(ByteStream* bs, int offset,const DexHeader *dh,
		int baseAddr,int StrIDAddr,int TypeIDAddr,int ProtoIDAddr,int FiledIDAddr,int MethodIDAddr,int ClassDefAddr,int MapAddr,int TypeListAddr,int ClassDataAddr,int CodeAddr,int StrDataAddr,int DebugAddr,int EncodedAddr,int EndAddr,
		std::vector<const u1*>* v_TypelistData,std::vector<const u1*>* v_ClassData,std::vector<const u1*>* v_CodeData,std::vector<const u1*>* v_StrData,std::vector<const u1*>* v_EncodedData
		){
    int TestDexMapItem[]={1,1,1,1,1,1,1,1,1,0,0,1,1,1,1,0,1,0};//test
    u4 TestMapSize = 14;
	GOSSIP("----------------------DEX BUILD Map");
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

int BuildTypeList(ByteStream* bs, int offset,std::vector<const u1*>* v_TypelistData,std::vector<int>* v_TypelistSize,int TypeListAddr){
	GOSSIP("----------------------DEX BUILD TypeList");
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

int BuildClassData(ByteStream* bs, int offset,const DexFile* df,std::vector<const u1*>* v_ClassData,std::vector<int>* v_ClassDataSize,std::map<const u1*,int>* AddrMAP,int ClassDataAddr){
	GOSSIP("----------------------DEX BUILD ClassData");
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

int BuildCode(ByteStream* bs, int offset,DvmDex* pDvmDex,Object* loader,const DexFile* df,std::vector<const u1*>* v_CodeData,std::vector<int>* v_CodeSize,std::vector<CMname*>* v_name,int CodeAddr){
	GOSSIP("----------------------DEX BUILD Code");
	unsigned int i;
	offset = CodeAddr;
	for(i=0;i<v_CodeData->size();i++){
		
		DexCode* myCode;
		if(v_CodeData->at(i) == 0){
			myCode = new DexCode;
			CMname* cm = v_name->at(i);
			GOSSIP("name: %s%s size: %d",cm->classname,cm->methodname,v_CodeSize->at(i));
			lbdInitCodeFromLoader(pDvmDex,loader,df,cm,myCode);
			GOSSIP("OK");
			
		}else{
			myCode = (DexCode*)malloc(v_CodeSize->at(i));
		    memset(myCode, 0, v_CodeSize->at(i));
			memcpy(myCode, v_CodeData->at(i), v_CodeSize->at(i));
			myCode->debugInfoOff =0x00000000;
			
			CMname* cm = v_name->at(i);
			if(CheckStr(cm->classname)){
				//GOSSIP("method: %s   %s",cm->classname,cm->methodname);
				ClassObject * coreClazz=0;
				//try  {
				coreClazz= dvmDefineClass(pDvmDex, cm->classname,loader);
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
				//coreClazz = dvmFindClass(cm->classname, loader);
				//coreClazz = dvmFindClassNoInit(cm->classname, loader);
				//if(coreClazz==0){
				  // GOSSIP("system loader");
				   //coreClazz = dvmFindClassNoInit(cm->classname, dvmGetSystemClassLoader());
				   //GOSSIP("system loader111");
				//}
				//GOSSIP("1");
				//}catch (std::exception& e) {coreClazz = 0;}
				if(coreClazz!=0){
					DexProto proto;
					proto.dexFile = df;
					proto.protoIdx = cm->protoIdx;
					Method *orderMethod=0;
					//GOSSIP("2");
					if(cm->dorv == 1){
						//GOSSIP("virtual method");
						orderMethod = dvmFindVirtualMethod(coreClazz, cm->methodname, &proto );
						//GOSSIP("3");
					}else{
						//GOSSIP("direct method");
						orderMethod = dvmFindDirectMethod(coreClazz, cm->methodname, &proto );
						//GOSSIP("4");
					}
					if(orderMethod!=0&&orderMethod->insns!=0){
						//GOSSIP("5");
						if(myCode->insnsSize!=0){
							//GOSSIP("6");
							for(unsigned int j =0;j<myCode->insnsSize;j++){
								//GOSSIP("7");
									//GOSSIP("%02x ---------- %02x", myCode->insns[j], *((orderMethod->insns)+j));
									//GOSSIP("8");
									myCode->insns[j] = *(orderMethod->insns+j);
							}
						}
					}
				}
				 
			}
	    }	
		GOSSIP("OK111111");
		bsseek(bs,offset);
		GOSSIP("OK22222");
		bswrite(bs,(u1*)(myCode),v_CodeSize->at(i));
		GOSSIP("OK3333");
		offset = offset+v_CodeSize->at(i);
		GOSSIP("OK4444");
		free(myCode);
		GOSSIP("OK5555");
		
	}
	free(v_CodeData);
	free(v_CodeSize);
	free(v_name);

	return offset;
}

int BuildStrData(ByteStream* bs, int offset,std::vector<const u1*>* v_StrData,std::vector<int>* v_StrDataLength,int StrDataAddr){
	GOSSIP("----------------------DEX BUILD StrData");
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

int BuildEncoded(ByteStream* bs, int offset,std::vector<const u1*>* v_EncodedData,std::vector<int>* v_EncodedSize,int EncodedAddr){
	GOSSIP("----------------------DEX BUILD Encoded");
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

bool CheckStr(const char* s){
	
	if(strlen(s)<19){
		return true;
	}
	const char* s2 = "Landroid/support/v4";
	bool y = false;
	for(int i=0;i<19;i++){
		if(s[i]!=s2[i]){
			y=true;
		}
	}
	return y;
	
/*
	if(strlen(s)<45){
		return false;
	}

	const char* s2 = "Lcom/zjrc/meeting_hlwdh/activity/loginActivity;";
	bool y = true;
	for(int i=0;i<45;i++){
		if(s[i]!=s2[i]){
			y=false;
		}
	}
	return y;
*/
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

void logMethod(DvmDex* pDvmDex,Object* loader,const DexFile* df,DexMethod dm,int dorv){

	
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
					GOSSIP("fucklog2: class : %s method: %s accessFlags %02x insns %p insnsSize %02x %02x",cname,mname,orderMethod->accessFlags,orderMethod->insns, *((orderMethod->insns)-2),*((orderMethod->insns)-1));
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


int lbdGetCodeSizeFromLoader(DvmDex* pDvmDex,Object* loader,const DexFile* df,DexMethod dm,int dorv){
	int totalSize = 0;
	int insnsSize = 0;

	u4 dmidx = dm.methodIdx;
	const DexMethodId* dmi = dexGetMethodId(df,dmidx);
	const char* cname = dexStringByTypeIdx(df,dmi->classIdx);
	const char* mname = dexStringById(df,dmi->nameIdx);
	
	if(CheckStr(cname)){
		//GOSSIP("lbdGetCodeSizeFromLoader: %s %s",cname,mname);
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
			//GOSSIP("fucklog2: get class: %s %s failed",cname,mname);
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
				//GOSSIP("fucklog2: get method: %s %s failed",cname,mname);
			}else{
				//GOSSIP("fucklog2: get method: %s successfully",mname);
				//GOSSIP("fucklog2: base: %p",df->baseAddr);
				if(orderMethod->insns!=NULL){
					//GOSSIP("fucklog2: class : %s method: %s accessFlags %02x insns %p insnsSize %02x %02x",cname,mname,orderMethod->accessFlags,orderMethod->insns, *((orderMethod->insns)-2),*((orderMethod->insns)-1));
				
					insnsSize = (int) *((orderMethod->insns)-2);
					//GOSSIP("lbdGetCodeSizeFromLoader:%s %s insnsSize: %d",cname,mname,insnsSize);
				}else{
					//GOSSIP("fucklog2: class : %s method: %s null",cname,mname);
				}
			}
		}
	}
	if(insnsSize!=0&& insnsSize<100){
		totalSize = insnsSize + 16;
	}
	//GOSSIP("lbdGetCodeSizeFromLoader:%s %s totalSize: %d",cname,mname,totalSize);
    
	return totalSize;

}

void lbdInitCodeFromLoader(DvmDex* pDvmDex,Object* loader,const DexFile* df,CMname* cm,DexCode* myCode){
	
	if(CheckStr(cm->classname)){
		GOSSIP("lbdInitCodeFromLoader: %s %s",cm->classname,cm->methodname);
		ClassObject * coreClazz=0;
		coreClazz= dvmDefineClass(pDvmDex, cm->classname,loader);
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
		if(coreClazz!=NULL){
			//GOSSIP("11111111111111111");
			DexProto proto;
			proto.dexFile = df;
			proto.protoIdx = cm->protoIdx;
			Method *orderMethod=0;
			if(cm->dorv == 1){
				orderMethod = dvmFindVirtualMethod(coreClazz, cm->methodname, &proto );
			}else{
				orderMethod = dvmFindDirectMethod(coreClazz, cm->methodname, &proto );
			}
			if(orderMethod!=0&&orderMethod->insns!=0){
				//GOSSIP("22222222222222222");
				
				if(orderMethod->registersSize!=0){
					myCode->registersSize = orderMethod->registersSize;
				}else{
					myCode->registersSize = 0;
				}
				//GOSSIP("1");
				if(orderMethod->insSize!=0){
					myCode->insSize = orderMethod->insSize;
				}else{
					myCode->insSize = 0;
				}
				//GOSSIP("2");
				if(orderMethod->outsSize!=0){
					myCode->outsSize = orderMethod->outsSize;
				}else{
					myCode->outsSize = 0;
				}
				//GOSSIP("3");
				myCode->triesSize = 0;
				//GOSSIP("4");
				myCode->debugInfoOff = 0x00000000;
				//GOSSIP("5");
				unsigned int insnsSize = (unsigned int) *((orderMethod->insns)-2);
				myCode->insnsSize = insnsSize;
				GOSSIP("6");
				myCode->insns = (u2*)orderMethod->insns;
				/*for(unsigned int j =0;j<myCode->insnsSize;j++){
					if(orderMethod->insns+j){
						myCode->insns[j] = *(orderMethod->insns+j);
					}else{
						myCode->insns[j] = 0;
					}
					//GOSSIP("lbdInitCodeFromLoader: %02x", myCode->insns[j]);
					GOSSIP("%d %d %02x",j,insnsSize,*(orderMethod->insns+j));
				}*/
				GOSSIP("7");

			}
		}
	}

}















}