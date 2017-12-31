#include "oatdump.h"

#include <sstream>
#include <list>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "../utils.h"
#include "interpreter/interpreter_common.h"
#include "twodroid/Constant.h"
#include "dex_file.h"

using ::art::DexFile;




namespace gossip {

	void copyfile(const std::string& readname,const std::string& writename);
	const std::string get_apk_dir();
	void getdex(const std::string& filename);
	void write_to_file (unsigned char *data, int size, int file_count, const std::string& filename);



	void OatTracer(const std::string & apkDir_, const std::string & filename){
		char f[MaxLineLen] = {0};
		std::string		traceFileName_;
		snprintf ( f, MaxLineLen, "%s/oat_%d.bin", apkDir_.c_str(), std::rand() );
		traceFileName_ = std::string(f);
		FILE *	traceFile_ = fopen ( traceFileName_.c_str(), "wb" );
		FILE *	oatFile_ = fopen ( filename.c_str(), "rb" );

		if(traceFile_==NULL){
			LOG(WARNING) << "UCHIHALART  traceFile_ error ";
			return;
		}
		if(oatFile_==NULL){
			LOG(WARNING) << "UCHIHALART  oatFile_ error ";
			return;
		}

		//std::string content = "";
		//if(!art::ReadFileToString(filename, &content)){
		//	LOG(WARNING) << "UCHIHALART  oatFile_ error ";
		//    return;
		//}
		int c;
		while((c=fgetc(oatFile_))!=EOF){
        	fputc(c, traceFile_);
    	}

		fclose(traceFile_);
		fclose(oatFile_);

	}


	void log_insns(const art::DexFile::CodeItem* code){
		LOG(WARNING) << "UCHIHAL  insns: "<<code->insns_size_in_code_units_;
			if(code->insns_size_in_code_units_!=0){
						for(unsigned int j =0;j<code->insns_size_in_code_units_;j++){
							//GOSSIP("%02x ---------- %02x", myCode->insns[j], *((orderMethod->insns)+j));
							LOG(WARNING) << "UCHIHAL  insns:  " << j<<"  "<<code->insns_[j];

						}
		    }
	}


	void ClassDump(art::mirror::Class* myclass,const char * cn){
		LOG(WARNING) << "UCHIHALART  ClassDump "<< cn;
		myclass->DumpClass(LOG(ERROR), 1);
	}


	void test(){
		LOG(WARNING) << "UCHIHAL" << "testtesttest";
	}

	void openOat(const std::string& filename, const std::string& location){
		LOG(WARNING) << "UCHIHAL " << filename; // << " "<<location;
                std::string filter = "";
		if(art::ReadFileToString("/data/local/tmp/oat.dlist", &filter)){
		        //LOG(WARNING) << "UCHIHAL "<<"read oat.dlist ok!";
			//LOG(WARNING) << "UCHIHAL "<< filter;
			
			std::string::size_type idx = filename.find( filter );
			if ( idx != std::string::npos ){
				
				    //std::string cmd = "dd if="+filename+" of=/data/local/tmp/lbd_"+art::GetIsoDate()+".dex";
                                    //system(cmd.data());
				//const std::string apkdir = get_apk_dir();
				//if(apkdir.length()!=0){
					LOG(WARNING) << "UCHIHAL "<< "start cp";
					//const std::string outfile = filename+"_bak";
					//copyfile(filename,outfile);

				        std::string content = "";
					art::ReadFileToString(filename, &content);
                                        LOG(WARNING) << "UCHIHAL file size "<< content.length();
				        LOG(WARNING) << content.data();
                                        //getdex(filename);

					//LOG(WARNING) << "UCHIHAL ************"<< content;
					LOG(WARNING) << "UCHIHAL "<< "stop cp";
				//}

			}
			
		}else{
			//LOG(WARNING) << "UCHIHAL "<<"read oat.dlist error!";
		}
		
	}

	void getdex(const std::string& filename){
		FILE *infp = fopen(filename.data(), "rb");
		if (infp == NULL) {
			LOG(WARNING) << "UCHIHAL "<< "open file failed";
			return;
		}
		fseek(infp, 0, SEEK_END);
		unsigned int insize = ftell(infp);
		LOG(WARNING) << "UCHIHAL "<< "file size is "<< insize;
		fseek(infp, 0, SEEK_SET);
		unsigned char *indata = (unsigned char *)malloc(insize);
		fread(indata, 1, insize, infp);
		fclose(infp);

		

	        unsigned int file_count = 0;
		write_to_file(indata, insize, ++file_count, filename);
		/*
		unsigned int ptr;
		for (ptr = 0; ptr < insize; ptr ++) {
			if (memcmp(indata+ptr, "dex\n035", 8) != 0)
				continue;
			unsigned int dexsize = *(unsigned int *)(indata+ptr+32); // the 'file_size_' field in the header
			if (ptr + dexsize > insize)
				continue;
			write_to_file(indata+ptr, dexsize, ++file_count, filename);
		}
		*/


	}

	void write_to_file (unsigned char *data, int size, int file_count, const std::string& filepath)
	{
		LOG(WARNING) << "UCHIHAL "<< "get dex";
		char filename[16];
		sprintf(filename, (filepath+"_bak%02d").data(), file_count);
		//printf("Writing %d bytes to %s\n", size, filename);
		FILE *fp = fopen(filename, "wb");
		fwrite(data, 1, size, fp);
		fclose(fp);
	}


	void copyfile(const std::string& readname,const std::string& writename){
		std::ifstream in(readname.data());
		std::ofstream out(writename.data()); 
		char buffer[256]; 
		if (in.is_open()&&out.is_open()){ 
			while (!in.eof() ){  
				in.getline (buffer,100);  
				out << buffer;
			}
			in.close();
			out.close();
		}  
	}


	const std::string get_apk_dir(){
		std::map<unsigned int, std::string> uidMap_;
		std::ifstream f ("/data/system/packages.list");
		if ( !f ) {
			return std::string();	
		}
		std::string s;
		std::string dir;
		unsigned int d;
		unsigned int e;
		std::string attr;
		std::string ids;


		while ( !f.eof() )
		{
			f >> s >> d >> e >> dir >> attr >> ids; // ugly... 
			uidMap_[d] = dir;
		}

		unsigned int uid = getuid();
		std::map<unsigned int, std::string>::const_iterator it = uidMap_.find(uid);

		if ( it != uidMap_.end() ){
			return it->second; 
		}
		return std::string();
	}
}