#include "twodroid/tracer/PaReTracer.h"

#include <cstdio>




using std::string;

namespace gossip
{
	PaReTracer::~PaReTracer()
	{
	}

	bool PaReTracer::init(const string & apkDir) 
	{
		apkDir_ = apkDir;
		char f[MaxLineLen] = {0};

		// generates opcodes.bin full name
		snprintf ( f, MaxLineLen, "%s/mthd_%d.bin", apkDir_.c_str(), getpid() );
		traceFileName_ = string(f);
		return Tracer::init_traceFile();
	}

	
	void PaReTracer::record_para_art(art::mirror::ArtMethod* method, art::ShadowFrame& shadow_frame, const art::Instruction* inst, uint16_t inst_data, bool is_range){

		fprintf ( traceFile_, "%s%s\n", method->GetDeclaringClassDescriptor(),method->GetName());

		const art::DexFile::CodeItem* code_item = method->GetCodeItem();
		const uint16_t num_ins = (is_range) ? inst->VRegA_3rc(inst_data) : inst->VRegA_35c(inst_data);
		uint16_t num_regs;
		if (LIKELY(code_item != NULL)) {
    		num_regs = code_item->registers_size_;
    		DCHECK_EQ(num_ins, code_item->ins_size_);
  		} else {
    		DCHECK(method->IsNative() || method->IsProxyMethod());
    		num_regs = num_ins;
  		}

  		const size_t first_dest_reg = num_regs - num_ins;
  		//const DexFile::TypeList* params = method->GetParameterTypeList();
  		uint32_t shorty_len = 0;
  		const char* shorty = method->GetShorty(&shorty_len);
  		fprintf ( traceFile_, "%s\n", shorty );

  		uint32_t arg[5];  // only used in invoke-XXX.
    	uint32_t vregC; 
    	if (is_range) {
      		vregC = inst->VRegC_3rc();
    	} else {
      		inst->GetVarArgs(arg, inst_data);
    	}
    	size_t dest_reg = first_dest_reg;
    	size_t arg_offset = 0;
    	if (!method->IsStatic()) {
      		//size_t receiver_reg = is_range ? vregC : arg[0];
      		++dest_reg;
      		++arg_offset;
    	}



    	for (uint32_t shorty_pos = 0; dest_reg < num_regs; ++shorty_pos, ++dest_reg, ++arg_offset) {
    		const size_t src_reg = (is_range) ? vregC + arg_offset : arg[arg_offset];
    		
    		if(shadow_frame.GetVRegReference(src_reg) == NULL){
    			fprintf ( traceFile_, "parameter%d L: null\n", shorty_pos+1);
    		}else{

	    		switch (shorty[shorty_pos + 1]) {
	    			case 'L': {
	    				Object* o = shadow_frame.GetVRegReference(src_reg);
	    				if(o == NULL){
	    					fprintf ( traceFile_, "parameter%d L: null\n", shorty_pos+1);
	    				}else{
	    					std::string temp1, temp2;
							if(strstr(o->GetClass()->GetDescriptor(&temp1),"Ljava/lang/String;")){             //when this Object is a system object such as Bundle, it will crash
								art::mirror::String * so = (art::mirror::String *) o;
								fprintf ( traceFile_, "parameter%d String: %s\n", shorty_pos+1,so->ToModifiedUtf8().data());
							}
	    				}

	    				
	    				break;
	    			}
	    			case 'I':{
	    				fprintf ( traceFile_, "parameter%d  int: %d\n", shorty_pos+1,shadow_frame.GetVReg(src_reg));
	    				break;
	    			}
	    			case 'Z':{
	    				fprintf ( traceFile_, "parameter%d  bool:  %d\n",shorty_pos+1, (u1)shadow_frame.GetVReg(src_reg));
	    				break;
	    			}
	    			case 'S':{
	    				fprintf ( traceFile_, "parameter%d  short:  %d\n",shorty_pos+1, shadow_frame.GetVReg(src_reg));
	    				break;
	    			}
	    			case 'C':{
	    				fprintf ( traceFile_, "parameter%d  char:  %c\n",shorty_pos+1, (u2)shadow_frame.GetVReg(src_reg));
	    				break;
	    			}
	    			case 'J':{
	    				uint64_t wide_value = (static_cast<uint64_t>(shadow_frame.GetVReg(src_reg + 1)) << 32) |
	                                static_cast<uint32_t>(shadow_frame.GetVReg(src_reg));
						fprintf ( traceFile_, "parameter%d  long:  %ld\n",shorty_pos+1, (long)wide_value);
						++dest_reg;
	          			++arg_offset;
	    				break;
	    			}
	    			case 'D':{

	    				union myunion m;
				        m.u[0] = shadow_frame.GetVReg(src_reg);
				        m.u[1] = shadow_frame.GetVReg(src_reg + 1);
	    				//uint64_t wide_value = (static_cast<uint64_t>(shadow_frame.GetVReg(src_reg + 1)) << 32) |
	                      //          static_cast<uint32_t>(shadow_frame.GetVReg(src_reg));
	    				fprintf ( traceFile_, "parameter%d  double:  %lf\n",shorty_pos+1, m.d);
	    				++dest_reg;
	          			++arg_offset;
	    				break;
	    			}

	    		}
    		}
    	}

    	fflush ( traceFile_);
	}


	void PaReTracer::record_para( art::mirror::ArtMethod*  method, u4* pr)
	{

		fprintf ( traceFile_, "%s%s\n", method->GetDeclaringClassDescriptor(),method->GetName());
		 
		uint32_t shortyLen = 0;
        const char* s = method->GetShorty(&shortyLen);
        fprintf ( traceFile_, "%s\n", s );

        uint32_t argNum = method->GetCodeItem()->ins_size_;
        uint32_t outIndex = 0;
		shortyLen = strlen( s ) - 1;

		uint32_t DJcount = 0;

		for (uint32_t t = 1; t <= shortyLen; t++)
		{
			if (s[t] == 'J' || s[t] == 'D')
				DJcount ++;
		}

		if (argNum != shortyLen + DJcount)
		{
			outIndex = 1;
		}

		LOG(WARNING) << "UCHIHALART  "<<"parameter number: "<<argNum<<"shortyLen: "<<shortyLen<<"DJcount: "<<DJcount<<"outIndex"<<outIndex;

		for ( uint32_t i = 1, j = outIndex ; i <= shortyLen; i++, j++ )
		{
			if ( s[i] == 'L' )
			{	
				art::mirror::Object* o = (art::mirror::Object*)(intptr_t) pr[j];
				std::string temp1, temp2;
				if(strstr(o->GetClass()->GetDescriptor(&temp1),"Ljava/lang/String;")){
					art::mirror::String * so = (art::mirror::String *) o;
					fprintf ( traceFile_, "parameter%d String: %s\n", i,so->ToModifiedUtf8().data());
				}
			}
			else
			{
				if(s[i] == 'I'){
					fprintf ( traceFile_, "parameter%d  int: %d\n", i,pr[j]);
				}
				if(s[i]== 'Z'){
					fprintf ( traceFile_, "parameter%d  bool:  %d\n",i, (u1)pr[j]);
				}
				if(s[i]== 'S'){
					fprintf ( traceFile_, "parameter%d  short:  %d\n",i, pr[j]);
				}
				if(s[i]== 'C'){
					fprintf ( traceFile_, "parameter%d  char:  %c\n",i, (u2)pr[j]);
				}
				if(s[i]== 'J'){
					union myunion m;
			        m.u[0] = pr[j];
			        m.u[1] = pr[j+1];
					fprintf ( traceFile_, "parameter%d  long:  %ld\n",i, (long)(m.s));
				}
				if(s[i]== 'D'){
					union myunion m;
			        m.u[0] = pr[j];
			        m.u[1] = pr[j+1];
					fprintf ( traceFile_, "parameter%d  double:  %lf\n",i, m.d);
				}




				if (s[i] == 'D' || s[i] == 'J')
					j++;
			}
		}



		fflush ( traceFile_);
	}

	FILE* PaReTracer::get_traceFile()
	{
		return traceFile_;
	}

	string PaReTracer::get_traceFileName()
	{
		return traceFileName_;
	}
}