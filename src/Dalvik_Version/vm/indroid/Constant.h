#ifndef _DIAOS_CONSTANT_H_
#define _DIAOS_CONSTANT_H_
#include <stdint.h>


static unsigned int inline BKDRHash( const char * const str )
{
	const static unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned int hash = 0;
 	unsigned int i = 0;
	while ( str[i] != 0 )
		hash = hash * seed + str[i++];
 
	return hash;
}

namespace gossip_loccs
{
	typedef unsigned int 	u4;
	typedef unsigned short	u2;
	typedef unsigned char	u1;
	typedef long long		s8;

	//directory's permission must be system!! if we create a directory, it's root. so we should use existed directory
	//const static std::string SystemServerDir = "/data/system"; 
	//const static u4 SystemServerUid = 1000;

	//const static uint8_t RecordFlag = 0x05;

	const static u4 InstNum				= 5;	// shujunliang
	const static u4 RegMaxNum				= 256;
	const static u4 FileNameMaxLen		= 64;
	const static u4 ClassNameMaxLen		= 128;
	const static u4 MethodNameMaxLen		= 64;
	const static u4 ShortyNameMaxLen		= 16;

	const static u4 ProcNameMaxLen		= 128;
	const static u4 ProcFileNameMaxLen	= 64;

	const static u4	OpcodeBufSize		= 512;
	const static u4	MaxLineLen			= 256;

	const static u4	ClassFilterSize		= 256;
	const static u4	StrMaxLen			= 1024;
	const static u4	RegBufMaxLen		= 1024;

	const static uint8_t DefaultRecordFlag = 0x0;
	const static uint8_t ObjFlag = 0x01;
	const static uint8_t PaReFlag = 0x02;
	const static uint8_t FuncFlag = 0x04;
	const static uint8_t OpcodeFlag = 0x8;
	const static uint8_t UnpackFlag = 0x10;
	const static uint8_t LbdFlag = 0x20;

enum RegOpType
{
	REG_READ,
	REG_WRITE,
	REG_READ_INT,
	REG_WRITE_INT,
	REG_READ_OBJ,
	REG_WRITE_OBJ,
	REG_READ_WIDE,
	REG_WRITE_WIDE,
	REG_READ_FLOAT,
	REG_WRITE_FLOAT,
	REG_READ_DOUBLE,
	REG_WRITE_DOUBLE
};

enum ObjWriteMode 
{
	BASIC_TYPE,
	OBJECT_TYPE
};

enum ObjType {
	OTHER_OBJ, 
	INTEGER, 
	BYTE,
	BOOLEAN,
	SHORT,
	CHAR,
	LONG,
	FLOAT,
	DOUBLE, 
	ARRAY,
	STR_OBJ, 
	INTENT_OBJ, 
	CMPNM_OBJ, 
	ACTINFO_OBJ, 
	PROREC_OBJ, 
	ACTREC_OBJ,
	LOCAT_OBJ,
	STRURI_OBJ,
	TEST_OBJ
};

union myunion{
	double d;
	u4 u[2];
	s8 s;
};

struct RegRecord
{
	u1 index[8];
	u4 buf[6];
};

struct OpcodeRecord
{
	u2 inst[6];
};

struct LoCCS_opcode
{
	u4 threadId;
	u4 pc;
	u2 inst[InstNum];
    u4 reg[RegMaxNum];
	char methodDescriptor[ClassNameMaxLen];
	char methodName[MethodNameMaxLen];
};
	struct InstRecord_
	{
		u4 threadId;
		u4 pc;
		u4 classHash;
		u4 methodHash;
		u4 instId;
		u2 inst[6];
	};
} // end of namespace gossip_loccs

#endif
