#ifndef __DALVIK_TOOL__
#define __DALVIK_TOOL__

namespace gossip{


	typedef int32_t             s4;


	int readSignedLeb128(const u1** pStream) {
	    const u1* ptr = *pStream;
	    int result = *(ptr++);

	    if (result <= 0x7f) {
	        result = (result << 25) >> 25;
	    } else {
	        int cur = *(ptr++);
	        result = (result & 0x7f) | ((cur & 0x7f) << 7);
	        if (cur <= 0x7f) {
	            result = (result << 18) >> 18;
	        } else {
	            cur = *(ptr++);
	            result |= (cur & 0x7f) << 14;
	            if (cur <= 0x7f) {
	                result = (result << 11) >> 11;
	            } else {
	                cur = *(ptr++);
	                result |= (cur & 0x7f) << 21;
	                if (cur <= 0x7f) {
	                    result = (result << 4) >> 4;
	                } else {
	                    /*
	                     * Note: We don't check to see if cur is out of
	                     * range here, meaning we tolerate garbage in the
	                     * high four-order bits.
	                     */
	                    cur = *(ptr++);
	                    result |= cur << 28;
	                }
	            }
	        }
	    }

	    *pStream = ptr;
	    return result;
	}

	int readUnsignedLeb128(const u1** pStream) {
	    const u1* ptr = *pStream;
	    int result = *(ptr++);

	    if (result > 0x7f) {
	        int cur = *(ptr++);
	        result = (result & 0x7f) | ((cur & 0x7f) << 7);
	        if (cur > 0x7f) {
	            cur = *(ptr++);
	            result |= (cur & 0x7f) << 14;
	            if (cur > 0x7f) {
	                cur = *(ptr++);
	                result |= (cur & 0x7f) << 21;
	                if (cur > 0x7f) {
	                    /*
	                     * Note: We don't check to see if cur is out of
	                     * range here, meaning we tolerate garbage in the
	                     * high four-order bits.
	                     */
	                    cur = *(ptr++);
	                    result |= cur << 28;
	                }
	            }
	        }
	    }

	    *pStream = ptr;
	    return result;
	}


	u1* writeUnsignedLeb128(u1* ptr, u4 data)
	{
	    while (true) {
	        u1 out = data & 0x7f;
	        if (out != data) {
	            *ptr++ = out | 0x80;
	            data >>= 7;
	        } else {
	            *ptr++ = out;
	            break;
	        }
	    }

	    return ptr;
	}

	int readAndVerifyUnsignedLeb128(const u1** pStream, const u1* limit,
        bool* okay) {
	    const u1* ptr = *pStream;
	    int result = readUnsignedLeb128(pStream);

	    if (((limit != NULL) && (*pStream > limit))
	            || (((*pStream - ptr) == 5) && (ptr[4] > 0x0f))) {
	        *okay = false;
	    }

	    return result;
	}

	static bool verifyUlebs(const u1* pData, const u1* pLimit, u4 count) {
	    bool okay = true;
	    //u4 i;

	    while (okay && (count-- != 0)) {
	        readAndVerifyUnsignedLeb128(&pData, pLimit, &okay);
	    }

	    return okay;
	}

	struct DexHeader {
	    u1  magic[8];           /* includes version number */
	    u4  checksum;           /* adler32 checksum */
	    u1  signature[20]; /* SHA-1 hash */
	    u4  fileSize;           /* length of entire file */
	    u4  headerSize;         /* offset to start of next section */
	    u4  endianTag;
	    u4  linkSize;
	    u4  linkOff;
	    u4  mapOff;
	    u4  stringIdsSize;
	    u4  stringIdsOff;
	    u4  typeIdsSize;
	    u4  typeIdsOff;
	    u4  protoIdsSize;
	    u4  protoIdsOff;
	    u4  fieldIdsSize;
	    u4  fieldIdsOff;
	    u4  methodIdsSize;
	    u4  methodIdsOff;
	    u4  classDefsSize;
	    u4  classDefsOff;
	    u4  dataSize;
	    u4  dataOff;
	};

	struct DexStringId {
    	u4 stringDataOff;      /* file offset to string_data_item */
    };

    struct DexTypeId {
	    u4  descriptorIdx;      /* index into stringIds list for type descriptor */
	};

    struct DexProtoId {
	    u4  shortyIdx;          /* index into stringIds for shorty descriptor */
	    u4  returnTypeIdx;      /* index into typeIds list for return type */
	    u4  parametersOff;      /* file offset to type_list for parameter types */
	};

	struct DexFieldId {
	    u2  classIdx;           /* index into typeIds list for defining class */
	    u2  typeIdx;            /* index into typeIds for field type */
	    u4  nameIdx;            /* index into stringIds for field name */
	};

	struct DexMethodId {
	    u2  classIdx;           /* index into typeIds list for defining class */
	    u2  protoIdx;           /* index into protoIds for method prototype */
	    u4  nameIdx;            /* index into stringIds for method name */
	};

	struct DexClassDef {
	    u4  classIdx;           /* index into typeIds for this class */
	    u4  accessFlags;
	    u4  superclassIdx;      /* index into typeIds for superclass */
	    u4  interfacesOff;      /* file offset to DexTypeList */
	    u4  sourceFileIdx;      /* index into stringIds for source file name */
	    u4  annotationsOff;     /* file offset to annotations_directory_item */
	    u4  classDataOff;       /* file offset to class_data_item */
	    u4  staticValuesOff;    /* file offset to DexEncodedArray */
	};



	struct DexClassDataHeader {
    	u4 staticFieldsSize;
    	u4 instanceFieldsSize;
    	u4 directMethodsSize;
    	u4 virtualMethodsSize;
	};

	struct DexField {
	    u4 fieldIdx;    /* index to a field_id_item */
	    u4 accessFlags;
	};

	struct DexMethod {
	    u4 methodIdx;    /* index to a method_id_item */
	    u4 accessFlags;
	    u4 codeOff;      /* file offset to a code_item */
	};

	struct DexClassData {
	    DexClassDataHeader header;
	    DexField*          staticFields;
	    DexField*          instanceFields;
	    DexMethod*         directMethods;
	    DexMethod*         virtualMethods;
	};

	struct DexMapItem {
	    u2 type;              /* type code (see kDexType* above) */
	    u2 unused;
	    u4 size;              /* count of items of the indicated type */
	    u4 offset;            /* file offset to the start of data */
	};

	void dexReadClassDataHeader(const u1** pData,
        DexClassDataHeader *pHeader) {
    	pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    	pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    	pHeader->directMethodsSize = readUnsignedLeb128(pData);
    	pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
	}

	void dexReadClassDataMethod(const u1** pData, DexMethod* pMethod,
        u4* lastIndex) {
	    u4 index = *lastIndex + readUnsignedLeb128(pData);

	    pMethod->accessFlags = readUnsignedLeb128(pData);
	    pMethod->codeOff = readUnsignedLeb128(pData);
	    pMethod->methodIdx = index;
	    *lastIndex = index;
	}

	void dexReadClassDataField(const u1** pData, DexField* pField,
        u4* lastIndex) {
	    u4 index = *lastIndex + readUnsignedLeb128(pData);

	    pField->accessFlags = readUnsignedLeb128(pData);
	    pField->fieldIdx = index;
	    *lastIndex = index;
	}


	bool dexReadAndVerifyClassDataField(const u1** pData, const u1* pLimit,
	        DexField* pField, u4* lastIndex) {
	    if (! verifyUlebs(*pData, pLimit, 2)) {
	        return false;
	    }

	    dexReadClassDataField(pData, pField, lastIndex);
	    return true;
	}

	bool dexReadAndVerifyClassDataMethod(const u1** pData, const u1* pLimit,
	    DexMethod* pMethod, u4* lastIndex) {
	    //if (! verifyUlebs(*pData, pLimit, 3)) {
	    //    return false;
	    //}

	    dexReadClassDataMethod(pData, pMethod, lastIndex);
	    return true;
	}

	bool dexReadAndVerifyClassDataHeader(const u1** pData, const u1* pLimit,
        DexClassDataHeader *pHeader) {
	    if (! verifyUlebs(*pData, pLimit, 4)) {
	        return false;
	    }

	    dexReadClassDataHeader(pData, pHeader);
	    return true;
	}

	DexClassData* dexReadAndVerifyClassData(const u1** pData, const u1* pLimit) {
	    DexClassDataHeader header;
	    u4 lastIndex;

	    if (*pData == NULL) {
	        DexClassData* result = (DexClassData*) malloc(sizeof(DexClassData));
	        memset(result, 0, sizeof(*result));
	        return result;
	    }

	    if (! dexReadAndVerifyClassDataHeader(pData, pLimit, &header)) {
	        return NULL;
	    }

	    size_t resultSize = sizeof(DexClassData) +
	        (header.staticFieldsSize * sizeof(DexField)) +
	        (header.instanceFieldsSize * sizeof(DexField)) +
	        (header.directMethodsSize * sizeof(DexMethod)) +
	        (header.virtualMethodsSize * sizeof(DexMethod));

	    DexClassData* result = (DexClassData*) malloc(resultSize);
	    u1* ptr = ((u1*) result) + sizeof(DexClassData);
	    bool okay = true;
	    u4 i;

	    if (result == NULL) {
	        return NULL;
	    }

	    result->header = header;

	    if (header.staticFieldsSize != 0) {
	        result->staticFields = (DexField*) ptr;
	        ptr += header.staticFieldsSize * sizeof(DexField);
	    } else {
	        result->staticFields = NULL;
	    }

	    if (header.instanceFieldsSize != 0) {
	        result->instanceFields = (DexField*) ptr;
	        ptr += header.instanceFieldsSize * sizeof(DexField);
	    } else {
	        result->instanceFields = NULL;
	    }

	    if (header.directMethodsSize != 0) {
	        result->directMethods = (DexMethod*) ptr;
	        ptr += header.directMethodsSize * sizeof(DexMethod);
	    } else {
	        result->directMethods = NULL;
	    }

	    if (header.virtualMethodsSize != 0) {
	        result->virtualMethods = (DexMethod*) ptr;
	    } else {
	        result->virtualMethods = NULL;
	    }

	    lastIndex = 0;
	    for (i = 0; okay && (i < header.staticFieldsSize); i++) {
	        okay = dexReadAndVerifyClassDataField(pData, pLimit,
	                &result->staticFields[i], &lastIndex);
	    }

	    lastIndex = 0;
	    for (i = 0; okay && (i < header.instanceFieldsSize); i++) {
	        okay = dexReadAndVerifyClassDataField(pData, pLimit,
	                &result->instanceFields[i], &lastIndex);
	    }

	    lastIndex = 0;
	    for (i = 0; okay && (i < header.directMethodsSize); i++) {
	        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
	                &result->directMethods[i], &lastIndex);
	    }

	    lastIndex = 0;
	    for (i = 0; okay && (i < header.virtualMethodsSize); i++) {
	        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
	                &result->virtualMethods[i], &lastIndex);
	    }

	    if (! okay) {
	        free(result);
	        return NULL;
	    }

	    return result;
	}

	struct DexCode {
	    u2  registersSize;
	    u2  insSize;
	    u2  outsSize;
	    u2  triesSize;
	    u4  debugInfoOff;       /* file offset to debug info stream */
	    u4  insnsSize;          /* size of the insns array, in u2 units */
	    u2  insns[1];
	    /* followed by optional u2 padding */
	    /* followed by try_item[triesSize] */
	    /* followed by uleb128 handlersSize */
	    /* followed by catch_handler_item[handlersSize] */
	};

	struct DexTry {
	    u4  startAddr;          /* start address, in 16-bit code units */
	    u2  insnCount;          /* instruction count, in 16-bit code units */
	    u2  handlerOff;         /* offset in encoded handler data to handlers */
	};

	struct DexCatchHandler {
	    u4          typeIdx;    /* type index of the caught exception type */
	    u4          address;    /* handler address */
	};

	struct DexCatchIterator {
	    const u1* pEncodedData;
	    bool catchesAll;
	    u4 countRemaining;
	    DexCatchHandler handler;
	};


	const DexTry* dexGetTries(const DexCode* pCode) {
	    const u2* insnsEnd = &pCode->insns[pCode->insnsSize];

	    // Round to four bytes.
	    if ((((uintptr_t) insnsEnd) & 3) != 0) {
	        insnsEnd++;
	    }

	    return (const DexTry*) insnsEnd;
	}

	const u1* dexGetCatchHandlerData(const DexCode* pCode) {
	    const DexTry* pTries = dexGetTries(pCode);
	    return (const u1*) &pTries[pCode->triesSize];
	}

	u4 dexGetHandlersSize(const DexCode* pCode) {
	    if (pCode->triesSize == 0) {
	        return 0;
	    }

	    const u1* data = dexGetCatchHandlerData(pCode);

	    return readUnsignedLeb128(&data);
	}

	u4 dexGetFirstHandlerOffset(const DexCode* pCode) {
	    if (pCode->triesSize == 0) {
	        return 0;
	    }

	    const u1* baseData = dexGetCatchHandlerData(pCode);
	    const u1* data = baseData;

	    readUnsignedLeb128(&data);

	    return data - baseData;
	}

	void dexCatchIteratorInitToPointer(DexCatchIterator* pIterator,
    const u1* pEncodedData)
	{
	    s4 count = readSignedLeb128(&pEncodedData);

	    if (count <= 0) {
	        pIterator->catchesAll = true;
	        count = -count;
	    } else {
	        pIterator->catchesAll = false;
	    }

	    pIterator->pEncodedData = pEncodedData;
	    pIterator->countRemaining = count;
	}

	void dexCatchIteratorInit(DexCatchIterator* pIterator,
    const DexCode* pCode, u4 offset)
	{
	    dexCatchIteratorInitToPointer(pIterator,
	            dexGetCatchHandlerData(pCode) + offset);
	}

	DexCatchHandler* dexCatchIteratorNext(DexCatchIterator* pIterator) {
	    if (pIterator->countRemaining == 0) {
	        if (! pIterator->catchesAll) {
	            return NULL;
	        }

	        pIterator->catchesAll = false;
	        pIterator->handler.typeIdx = art::DexFile::kDexNoIndex;
	    } else {
	        u4 typeIdx = readUnsignedLeb128(&pIterator->pEncodedData);
	        pIterator->handler.typeIdx = typeIdx;
	        pIterator->countRemaining--;
	    }

	    pIterator->handler.address = readUnsignedLeb128(&pIterator->pEncodedData);
	    return &pIterator->handler;
	}

	u4 dexCatchIteratorGetEndOffset(DexCatchIterator* pIterator,
        const DexCode* pCode) {
	    while (dexCatchIteratorNext(pIterator) != NULL) /* empty */ ;

	    return (u4) (pIterator->pEncodedData - dexGetCatchHandlerData(pCode));
	}

	size_t dexGetDexCodeSize(const DexCode* pCode)
	{
	    /*
	     * The catch handler data is the last entry.  It has a variable number
	     * of variable-size pieces, so we need to create an iterator.
	     */
	    u4 handlersSize;
	    u4 offset;
	    u4 ui;

	    if (pCode->triesSize != 0) {
	        handlersSize = dexGetHandlersSize(pCode);
	        offset = dexGetFirstHandlerOffset(pCode);
	    } else {
	        handlersSize = 0;
	        offset = 0;
	    }

	    for (ui = 0; ui < handlersSize; ui++) {
	        DexCatchIterator iterator;
	        dexCatchIteratorInit(&iterator, pCode, offset);
	        offset = dexCatchIteratorGetEndOffset(&iterator, pCode);
	    }

	    const u1* handlerData = dexGetCatchHandlerData(pCode);

	    //ALOGD("+++ pCode=%p handlerData=%p last offset=%d",
	    //    pCode, handlerData, offset);

	    /* return the size of the catch handler + everything before it */
	    return (handlerData - (u1*) pCode) + offset;
	}


}	

#endif