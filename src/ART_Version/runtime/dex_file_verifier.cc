/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dex_file_verifier.h"

#include <zlib.h>
#include <memory>

#include "base/stringprintf.h"
#include "dex_file-inl.h"
#include "leb128.h"
#include "safe_map.h"
#include "utf-inl.h"
#include "utils.h"

namespace art {

static uint32_t MapTypeToBitMask(uint32_t map_type) {
  switch (map_type) {
    case DexFile::kDexTypeHeaderItem:               return 1 << 0;
    case DexFile::kDexTypeStringIdItem:             return 1 << 1;
    case DexFile::kDexTypeTypeIdItem:               return 1 << 2;
    case DexFile::kDexTypeProtoIdItem:              return 1 << 3;
    case DexFile::kDexTypeFieldIdItem:              return 1 << 4;
    case DexFile::kDexTypeMethodIdItem:             return 1 << 5;
    case DexFile::kDexTypeClassDefItem:             return 1 << 6;
    case DexFile::kDexTypeMapList:                  return 1 << 7;
    case DexFile::kDexTypeTypeList:                 return 1 << 8;
    case DexFile::kDexTypeAnnotationSetRefList:     return 1 << 9;
    case DexFile::kDexTypeAnnotationSetItem:        return 1 << 10;
    case DexFile::kDexTypeClassDataItem:            return 1 << 11;
    case DexFile::kDexTypeCodeItem:                 return 1 << 12;
    case DexFile::kDexTypeStringDataItem:           return 1 << 13;
    case DexFile::kDexTypeDebugInfoItem:            return 1 << 14;
    case DexFile::kDexTypeAnnotationItem:           return 1 << 15;
    case DexFile::kDexTypeEncodedArrayItem:         return 1 << 16;
    case DexFile::kDexTypeAnnotationsDirectoryItem: return 1 << 17;
  }
  return 0;
}

static bool IsDataSectionType(uint32_t map_type) {
  switch (map_type) {
    case DexFile::kDexTypeHeaderItem:
    case DexFile::kDexTypeStringIdItem:
    case DexFile::kDexTypeTypeIdItem:
    case DexFile::kDexTypeProtoIdItem:
    case DexFile::kDexTypeFieldIdItem:
    case DexFile::kDexTypeMethodIdItem:
    case DexFile::kDexTypeClassDefItem:
      return false;
  }
  return true;
}

const char* DexFileVerifier::CheckLoadStringByIdx(uint32_t idx, const char* error_string) {
  if (UNLIKELY(!CheckIndex(idx, dex_file_->NumStringIds(), error_string))) {
    return nullptr;
  }
  return dex_file_->StringDataByIdx(idx);
}

const char* DexFileVerifier::CheckLoadStringByTypeIdx(uint32_t type_idx, const char* error_string) {
  if (UNLIKELY(!CheckIndex(type_idx, dex_file_->NumTypeIds(), error_string))) {
    return nullptr;
  }
  const DexFile::TypeId& type_id = dex_file_->GetTypeId(type_idx);
  uint32_t idx = type_id.descriptor_idx_;
  return CheckLoadStringByIdx(idx, error_string);
}

const DexFile::FieldId* DexFileVerifier::CheckLoadFieldId(uint32_t idx, const char* error_string) {
  if (UNLIKELY(!CheckIndex(idx, dex_file_->NumFieldIds(), error_string))) {
    return nullptr;
  }
  return &dex_file_->GetFieldId(idx);
}

const DexFile::MethodId* DexFileVerifier::CheckLoadMethodId(uint32_t idx, const char* err_string) {
  if (UNLIKELY(!CheckIndex(idx, dex_file_->NumMethodIds(), err_string))) {
    return nullptr;
  }
  return &dex_file_->GetMethodId(idx);
}

// Helper macro to load string and return false on error.
#define LOAD_STRING(var, idx, error)                  \
  const char* var = CheckLoadStringByIdx(idx, error); \
  if (UNLIKELY(var == nullptr)) {                     \
    return false;                                     \
  }

// Helper macro to load string by type idx and return false on error.
#define LOAD_STRING_BY_TYPE(var, type_idx, error)              \
  const char* var = CheckLoadStringByTypeIdx(type_idx, error); \
  if (UNLIKELY(var == nullptr)) {                              \
    return false;                                              \
  }

// Helper macro to load method id. Return last parameter on error.
#define LOAD_METHOD(var, idx, error_string, error_stmt)                 \
  const DexFile::MethodId* var  = CheckLoadMethodId(idx, error_string); \
  if (UNLIKELY(var == nullptr)) {                                       \
    error_stmt;                                                         \
  }

// Helper macro to load method id. Return last parameter on error.
#define LOAD_FIELD(var, idx, fmt, error_stmt)               \
  const DexFile::FieldId* var = CheckLoadFieldId(idx, fmt); \
  if (UNLIKELY(var == nullptr)) {                           \
    error_stmt;                                             \
  }

bool DexFileVerifier::Verify(const DexFile* dex_file, const byte* begin, size_t size,
                             const char* location, std::string* error_msg) {
  std::unique_ptr<DexFileVerifier> verifier(new DexFileVerifier(dex_file, begin, size, location));
  if (!verifier->Verify()) {
    *error_msg = verifier->FailureReason();
    return false;
  }
  return true;
}

bool DexFileVerifier::CheckShortyDescriptorMatch(char shorty_char, const char* descriptor,
                                                bool is_return_type) {
  switch (shorty_char) {
    case 'V':
      if (UNLIKELY(!is_return_type)) {
        ErrorStringPrintf("Invalid use of void");
        return false;
      }
      // Intentional fallthrough.
    case 'B':
    case 'C':
    case 'D':
    case 'F':
    case 'I':
    case 'J':
    case 'S':
    case 'Z':
      if (UNLIKELY((descriptor[0] != shorty_char) || (descriptor[1] != '\0'))) {
        ErrorStringPrintf("Shorty vs. primitive type mismatch: '%c', '%s'",
                          shorty_char, descriptor);
        return false;
      }
      break;
    case 'L':
      if (UNLIKELY((descriptor[0] != 'L') && (descriptor[0] != '['))) {
        ErrorStringPrintf("Shorty vs. type mismatch: '%c', '%s'", shorty_char, descriptor);
        return false;
      }
      break;
    default:
      ErrorStringPrintf("Bad shorty character: '%c'", shorty_char);
      return false;
  }
  return true;
}

bool DexFileVerifier::CheckListSize(const void* start, size_t count, size_t elem_size,
                                    const char* label) {
  // Check that size is not 0.
  CHECK_NE(elem_size, 0U);

  const byte* range_start = reinterpret_cast<const byte*>(start);
  const byte* file_start = reinterpret_cast<const byte*>(begin_);

  // Check for overflow.
  uintptr_t max = 0 - 1;
  size_t available_bytes_till_end_of_mem = max - reinterpret_cast<uintptr_t>(start);
  size_t max_count = available_bytes_till_end_of_mem / elem_size;
  if (max_count < count) {
    ErrorStringPrintf("Overflow in range for %s: %zx for %zu@%zu", label,
                      static_cast<size_t>(range_start - file_start),
                      count, elem_size);
    return false;
  }

  const byte* range_end = range_start + count * elem_size;
  const byte* file_end = file_start + size_;
  if (UNLIKELY((range_start < file_start) || (range_end > file_end))) {
    // Note: these two tests are enough as we make sure above that there's no overflow.
    ErrorStringPrintf("Bad range for %s: %zx to %zx", label,
                      static_cast<size_t>(range_start - file_start),
                      static_cast<size_t>(range_end - file_start));
    return false;
  }
  return true;
}

bool DexFileVerifier::CheckList(size_t element_size, const char* label, const byte* *ptr) {
  // Check that the list is available. The first 4B are the count.
  if (!CheckListSize(*ptr, 1, 4U, label)) {
    return false;
  }

  uint32_t count = *reinterpret_cast<const uint32_t*>(*ptr);
  if (count > 0) {
    if (!CheckListSize(*ptr + 4, count, element_size, label)) {
      return false;
    }
  }

  *ptr += 4 + count * element_size;
  return true;
}

bool DexFileVerifier::CheckIndex(uint32_t field, uint32_t limit, const char* label) {
  if (UNLIKELY(field >= limit)) {
    ErrorStringPrintf("Bad index for %s: %x >= %x", label, field, limit);
    return false;
  }
  return true;
}

bool DexFileVerifier::CheckValidOffsetAndSize(uint32_t offset, uint32_t size, const char* label) {
  if (size == 0) {
    if (offset != 0) {
      ErrorStringPrintf("Offset(%d) should be zero when size is zero for %s.", offset, label);
      return false;
    }
  }
  if (size_ <= offset) {
    ErrorStringPrintf("Offset(%d) should be within file size(%zu) for %s.", offset, size_, label);
    return false;
  }
  return true;
}

bool DexFileVerifier::CheckHeader() {
  // Check file size from the header.
  uint32_t expected_size = header_->file_size_;
  if (size_ != expected_size) {
    ErrorStringPrintf("Bad file size (%zd, expected %ud)", size_, expected_size);
    return false;
  }

  // Compute and verify the checksum in the header.
  uint32_t adler_checksum = adler32(0L, Z_NULL, 0);
  const uint32_t non_sum = sizeof(header_->magic_) + sizeof(header_->checksum_);
  const byte* non_sum_ptr = reinterpret_cast<const byte*>(header_) + non_sum;
  adler_checksum = adler32(adler_checksum, non_sum_ptr, expected_size - non_sum);
  if (adler_checksum != header_->checksum_) {
    ErrorStringPrintf("Bad checksum (%08x, expected %08x)", adler_checksum, header_->checksum_);
    return false;
  }

  // Check the contents of the header.
  if (header_->endian_tag_ != DexFile::kDexEndianConstant) {
    ErrorStringPrintf("Unexpected endian_tag: %x", header_->endian_tag_);
    return false;
  }

  if (header_->header_size_ != sizeof(DexFile::Header)) {
    ErrorStringPrintf("Bad header size: %ud", header_->header_size_);
    return false;
  }

  // Check that all offsets are inside the file.
  bool result =
      CheckValidOffsetAndSize(header_->link_off_, header_->link_size_, "link") &&
      CheckValidOffsetAndSize(header_->map_off_, header_->map_off_, "map") &&
      CheckValidOffsetAndSize(header_->string_ids_off_, header_->string_ids_size_, "string-ids") &&
      CheckValidOffsetAndSize(header_->type_ids_off_, header_->type_ids_size_, "type-ids") &&
      CheckValidOffsetAndSize(header_->proto_ids_off_, header_->proto_ids_size_, "proto-ids") &&
      CheckValidOffsetAndSize(header_->field_ids_off_, header_->field_ids_size_, "field-ids") &&
      CheckValidOffsetAndSize(header_->method_ids_off_, header_->method_ids_size_, "method-ids") &&
      CheckValidOffsetAndSize(header_->class_defs_off_, header_->class_defs_size_, "class-defs") &&
      CheckValidOffsetAndSize(header_->data_off_, header_->data_size_, "data");

  return result;
}

bool DexFileVerifier::CheckMap() {
  const DexFile::MapList* map = reinterpret_cast<const DexFile::MapList*>(begin_ +
                                                                          header_->map_off_);
  // Check that map list content is available.
  if (!CheckListSize(map, 1, sizeof(DexFile::MapList), "maplist content")) {
    return false;
  }

  const DexFile::MapItem* item = map->list_;

  uint32_t count = map->size_;
  uint32_t last_offset = 0;
  uint32_t data_item_count = 0;
  uint32_t data_items_left = header_->data_size_;
  uint32_t used_bits = 0;

  // Sanity check the size of the map list.
  if (!CheckListSize(item, count, sizeof(DexFile::MapItem), "map size")) {
    return false;
  }

  // Check the items listed in the map.
  for (uint32_t i = 0; i < count; i++) {
    if (UNLIKELY(last_offset >= item->offset_ && i != 0)) {
      ErrorStringPrintf("Out of order map item: %x then %x", last_offset, item->offset_);
      return false;
    }
    if (UNLIKELY(item->offset_ >= header_->file_size_)) {
      ErrorStringPrintf("Map item after end of file: %x, size %x",
                        item->offset_, header_->file_size_);
      return false;
    }

    if (IsDataSectionType(item->type_)) {
      uint32_t icount = item->size_;
      if (UNLIKELY(icount > data_items_left)) {
        ErrorStringPrintf("Too many items in data section: %ud", data_item_count + icount);
        return false;
      }
      data_items_left -= icount;
      data_item_count += icount;
    }

    uint32_t bit = MapTypeToBitMask(item->type_);

    if (UNLIKELY(bit == 0)) {
      ErrorStringPrintf("Unknown map section type %x", item->type_);
      return false;
    }

    if (UNLIKELY((used_bits & bit) != 0)) {
      ErrorStringPrintf("Duplicate map section of type %x", item->type_);
      return false;
    }

    used_bits |= bit;
    last_offset = item->offset_;
    item++;
  }

  // Check for missing sections in the map.
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeHeaderItem)) == 0)) {
    ErrorStringPrintf("Map is missing header entry");
    return false;
  }
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeMapList)) == 0)) {
    ErrorStringPrintf("Map is missing map_list entry");
    return false;
  }
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeStringIdItem)) == 0 &&
               ((header_->string_ids_off_ != 0) || (header_->string_ids_size_ != 0)))) {
    ErrorStringPrintf("Map is missing string_ids entry");
    return false;
  }
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeTypeIdItem)) == 0 &&
               ((header_->type_ids_off_ != 0) || (header_->type_ids_size_ != 0)))) {
    ErrorStringPrintf("Map is missing type_ids entry");
    return false;
  }
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeProtoIdItem)) == 0 &&
               ((header_->proto_ids_off_ != 0) || (header_->proto_ids_size_ != 0)))) {
    ErrorStringPrintf("Map is missing proto_ids entry");
    return false;
  }
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeFieldIdItem)) == 0 &&
               ((header_->field_ids_off_ != 0) || (header_->field_ids_size_ != 0)))) {
    ErrorStringPrintf("Map is missing field_ids entry");
    return false;
  }
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeMethodIdItem)) == 0 &&
               ((header_->method_ids_off_ != 0) || (header_->method_ids_size_ != 0)))) {
    ErrorStringPrintf("Map is missing method_ids entry");
    return false;
  }
  if (UNLIKELY((used_bits & MapTypeToBitMask(DexFile::kDexTypeClassDefItem)) == 0 &&
               ((header_->class_defs_off_ != 0) || (header_->class_defs_size_ != 0)))) {
    ErrorStringPrintf("Map is missing class_defs entry");
    return false;
  }
  return true;
}

uint32_t DexFileVerifier::ReadUnsignedLittleEndian(uint32_t size) {
  uint32_t result = 0;
  if (LIKELY(CheckListSize(ptr_, size, sizeof(byte), "encoded_value"))) {
    for (uint32_t i = 0; i < size; i++) {
      result |= ((uint32_t) *(ptr_++)) << (i * 8);
    }
  }
  return result;
}

bool DexFileVerifier::CheckAndGetHandlerOffsets(const DexFile::CodeItem* code_item,
                                                uint32_t* handler_offsets, uint32_t handlers_size) {
  const byte* handlers_base = DexFile::GetCatchHandlerData(*code_item, 0);

  for (uint32_t i = 0; i < handlers_size; i++) {
    bool catch_all;
    size_t offset = ptr_ - handlers_base;
    int32_t size = DecodeSignedLeb128(&ptr_);

    if (UNLIKELY((size < -65536) || (size > 65536))) {
      ErrorStringPrintf("Invalid exception handler size: %d", size);
      return false;
    }

    if (size <= 0) {
      catch_all = true;
      size = -size;
    } else {
      catch_all = false;
    }

    handler_offsets[i] = static_cast<uint32_t>(offset);

    while (size-- > 0) {
      uint32_t type_idx = DecodeUnsignedLeb128(&ptr_);
      if (!CheckIndex(type_idx, header_->type_ids_size_, "handler type_idx")) {
        return false;
      }

      uint32_t addr = DecodeUnsignedLeb128(&ptr_);
      if (UNLIKELY(addr >= code_item->insns_size_in_code_units_)) {
        ErrorStringPrintf("Invalid handler addr: %x", addr);
        return false;
      }
    }

    if (catch_all) {
      uint32_t addr = DecodeUnsignedLeb128(&ptr_);
      if (UNLIKELY(addr >= code_item->insns_size_in_code_units_)) {
        ErrorStringPrintf("Invalid handler catch_all_addr: %x", addr);
        return false;
      }
    }
  }

  return true;
}

bool DexFileVerifier::CheckClassDataItemField(uint32_t idx, uint32_t access_flags,
                                              bool expect_static) {
  if (!CheckIndex(idx, header_->field_ids_size_, "class_data_item field_idx")) {
    return false;
  }

  bool is_static = (access_flags & kAccStatic) != 0;
  if (UNLIKELY(is_static != expect_static)) {
    ErrorStringPrintf("Static/instance field not in expected list");
    return false;
  }

  if (UNLIKELY((access_flags & ~kAccJavaFlagsMask) != 0)) {
    ErrorStringPrintf("Bad class_data_item field access_flags %x", access_flags);
    return false;
  }

  return true;
}

bool DexFileVerifier::CheckClassDataItemMethod(uint32_t idx, uint32_t access_flags,
                                               uint32_t code_offset, bool expect_direct) {
  if (!CheckIndex(idx, header_->method_ids_size_, "class_data_item method_idx")) {
    return false;
  }

  bool is_direct = (access_flags & (kAccStatic | kAccPrivate | kAccConstructor)) != 0;
  bool expect_code = (access_flags & (kAccNative | kAccAbstract)) == 0;
  bool is_synchronized = (access_flags & kAccSynchronized) != 0;
  bool allow_synchronized = (access_flags & kAccNative) != 0;

  if (UNLIKELY(is_direct != expect_direct)) {
    ErrorStringPrintf("Direct/virtual method not in expected list");
    return false;
  }

  constexpr uint32_t access_method_mask = kAccJavaFlagsMask | kAccConstructor |
      kAccDeclaredSynchronized;
  if (UNLIKELY(((access_flags & ~access_method_mask) != 0) ||
               (is_synchronized && !allow_synchronized))) {
    ErrorStringPrintf("Bad class_data_item method access_flags %x", access_flags);
    return false;
  }

  if (UNLIKELY(expect_code && (code_offset == 0))) {
    ErrorStringPrintf("Unexpected zero value for class_data_item method code_off with access "
                      "flags %x", access_flags);
    return false;
  } else if (UNLIKELY(!expect_code && (code_offset != 0))) {
    ErrorStringPrintf("Unexpected non-zero value %x for class_data_item method code_off"
                      " with access flags %x", code_offset, access_flags);
    return false;
  }

  return true;
}

bool DexFileVerifier::CheckPadding(size_t offset, uint32_t aligned_offset) {
  if (offset < aligned_offset) {
    if (!CheckListSize(begin_ + offset, aligned_offset - offset, sizeof(byte), "section")) {
      return false;
    }
    while (offset < aligned_offset) {
      if (UNLIKELY(*ptr_ != '\0')) {
        ErrorStringPrintf("Non-zero padding %x before section start at %zx", *ptr_, offset);
        return false;
      }
      ptr_++;
      offset++;
    }
  }
  return true;
}

bool DexFileVerifier::CheckEncodedValue() {
  if (!CheckListSize(ptr_, 1, sizeof(byte), "encoded_value header")) {
    return false;
  }

  uint8_t header_byte = *(ptr_++);
  uint32_t value_type = header_byte & DexFile::kDexAnnotationValueTypeMask;
  uint32_t value_arg = header_byte >> DexFile::kDexAnnotationValueArgShift;

  switch (value_type) {
    case DexFile::kDexAnnotationByte:
      if (UNLIKELY(value_arg != 0)) {
        ErrorStringPrintf("Bad encoded_value byte size %x", value_arg);
        return false;
      }
      ptr_++;
      break;
    case DexFile::kDexAnnotationShort:
    case DexFile::kDexAnnotationChar:
      if (UNLIKELY(value_arg > 1)) {
        ErrorStringPrintf("Bad encoded_value char/short size %x", value_arg);
        return false;
      }
      ptr_ += value_arg + 1;
      break;
    case DexFile::kDexAnnotationInt:
    case DexFile::kDexAnnotationFloat:
      if (UNLIKELY(value_arg > 3)) {
        ErrorStringPrintf("Bad encoded_value int/float size %x", value_arg);
        return false;
      }
      ptr_ += value_arg + 1;
      break;
    case DexFile::kDexAnnotationLong:
    case DexFile::kDexAnnotationDouble:
      ptr_ += value_arg + 1;
      break;
    case DexFile::kDexAnnotationString: {
      if (UNLIKELY(value_arg > 3)) {
        ErrorStringPrintf("Bad encoded_value string size %x", value_arg);
        return false;
      }
      uint32_t idx = ReadUnsignedLittleEndian(value_arg + 1);
      if (!CheckIndex(idx, header_->string_ids_size_, "encoded_value string")) {
        return false;
      }
      break;
    }
    case DexFile::kDexAnnotationType: {
      if (UNLIKELY(value_arg > 3)) {
        ErrorStringPrintf("Bad encoded_value type size %x", value_arg);
        return false;
      }
      uint32_t idx = ReadUnsignedLittleEndian(value_arg + 1);
      if (!CheckIndex(idx, header_->type_ids_size_, "encoded_value type")) {
        return false;
      }
      break;
    }
    case DexFile::kDexAnnotationField:
    case DexFile::kDexAnnotationEnum: {
      if (UNLIKELY(value_arg > 3)) {
        ErrorStringPrintf("Bad encoded_value field/enum size %x", value_arg);
        return false;
      }
      uint32_t idx = ReadUnsignedLittleEndian(value_arg + 1);
      if (!CheckIndex(idx, header_->field_ids_size_, "encoded_value field")) {
        return false;
      }
      break;
    }
    case DexFile::kDexAnnotationMethod: {
      if (UNLIKELY(value_arg > 3)) {
        ErrorStringPrintf("Bad encoded_value method size %x", value_arg);
        return false;
      }
      uint32_t idx = ReadUnsignedLittleEndian(value_arg + 1);
      if (!CheckIndex(idx, header_->method_ids_size_, "encoded_value method")) {
        return false;
      }
      break;
    }
    case DexFile::kDexAnnotationArray:
      if (UNLIKELY(value_arg != 0)) {
        ErrorStringPrintf("Bad encoded_value array value_arg %x", value_arg);
        return false;
      }
      if (!CheckEncodedArray()) {
        return false;
      }
      break;
    case DexFile::kDexAnnotationAnnotation:
      if (UNLIKELY(value_arg != 0)) {
        ErrorStringPrintf("Bad encoded_value annotation value_arg %x", value_arg);
        return false;
      }
      if (!CheckEncodedAnnotation()) {
        return false;
      }
      break;
    case DexFile::kDexAnnotationNull:
      if (UNLIKELY(value_arg != 0)) {
        ErrorStringPrintf("Bad encoded_value null value_arg %x", value_arg);
        return false;
      }
      break;
    case DexFile::kDexAnnotationBoolean:
      if (UNLIKELY(value_arg > 1)) {
        ErrorStringPrintf("Bad encoded_value boolean size %x", value_arg);
        return false;
      }
      break;
    default:
      ErrorStringPrintf("Bogus encoded_value value_type %x", value_type);
      return false;
  }

  return true;
}

bool DexFileVerifier::CheckEncodedArray() {
  uint32_t size = DecodeUnsignedLeb128(&ptr_);

  while (size--) {
    if (!CheckEncodedValue()) {
      failure_reason_ = StringPrintf("Bad encoded_array value: %s", failure_reason_.c_str());
      return false;
    }
  }
  return true;
}

bool DexFileVerifier::CheckEncodedAnnotation() {
  uint32_t idx = DecodeUnsignedLeb128(&ptr_);
  if (!CheckIndex(idx, header_->type_ids_size_, "encoded_annotation type_idx")) {
    return false;
  }

  uint32_t size = DecodeUnsignedLeb128(&ptr_);
  uint32_t last_idx = 0;

  for (uint32_t i = 0; i < size; i++) {
    idx = DecodeUnsignedLeb128(&ptr_);
    if (!CheckIndex(idx, header_->string_ids_size_, "annotation_element name_idx")) {
      return false;
    }

    if (UNLIKELY(last_idx >= idx && i != 0)) {
      ErrorStringPrintf("Out-of-order annotation_element name_idx: %x then %x",
                        last_idx, idx);
      return false;
    }

    if (!CheckEncodedValue()) {
      return false;
    }

    last_idx = idx;
  }
  return true;
}

bool DexFileVerifier::CheckIntraClassDataItem() {
  ClassDataItemIterator it(*dex_file_, ptr_);

  // These calls use the raw access flags to check whether the whole dex field is valid.

  for (; it.HasNextStaticField(); it.Next()) {
    if (!CheckClassDataItemField(it.GetMemberIndex(), it.GetRawMemberAccessFlags(), true)) {
      return false;
    }
  }
  for (; it.HasNextInstanceField(); it.Next()) {
    if (!CheckClassDataItemField(it.GetMemberIndex(), it.GetRawMemberAccessFlags(), false)) {
      return false;
    }
  }
  for (; it.HasNextDirectMethod(); it.Next()) {
    if (!CheckClassDataItemMethod(it.GetMemberIndex(), it.GetRawMemberAccessFlags(),
        it.GetMethodCodeItemOffset(), true)) {
      return false;
    }
  }
  for (; it.HasNextVirtualMethod(); it.Next()) {
    if (!CheckClassDataItemMethod(it.GetMemberIndex(), it.GetRawMemberAccessFlags(),
        it.GetMethodCodeItemOffset(), false)) {
      return false;
    }
  }

  ptr_ = it.EndDataPointer();
  return true;
}

bool DexFileVerifier::CheckIntraCodeItem() {
  const DexFile::CodeItem* code_item = reinterpret_cast<const DexFile::CodeItem*>(ptr_);
  if (!CheckListSize(code_item, 1, sizeof(DexFile::CodeItem), "code")) {
    return false;
  }

  if (UNLIKELY(code_item->ins_size_ > code_item->registers_size_)) {
    ErrorStringPrintf("ins_size (%ud) > registers_size (%ud)",
                      code_item->ins_size_, code_item->registers_size_);
    return false;
  }

  if (UNLIKELY((code_item->outs_size_ > 5) &&
               (code_item->outs_size_ > code_item->registers_size_))) {
    /*
     * outs_size can be up to 5, even if registers_size is smaller, since the
     * short forms of method invocation allow repetitions of a register multiple
     * times within a single parameter list. However, longer parameter lists
     * need to be represented in-order in the register file.
     */
    ErrorStringPrintf("outs_size (%ud) > registers_size (%ud)",
                      code_item->outs_size_, code_item->registers_size_);
    return false;
  }

  const uint16_t* insns = code_item->insns_;
  uint32_t insns_size = code_item->insns_size_in_code_units_;
  if (!CheckListSize(insns, insns_size, sizeof(uint16_t), "insns size")) {
    return false;
  }

  // Grab the end of the insns if there are no try_items.
  uint32_t try_items_size = code_item->tries_size_;
  if (try_items_size == 0) {
    ptr_ = reinterpret_cast<const byte*>(&insns[insns_size]);
    return true;
  }

  // try_items are 4-byte aligned. Verify the spacer is 0.
  if (((reinterpret_cast<uintptr_t>(&insns[insns_size]) & 3) != 0) && (insns[insns_size] != 0)) {
    ErrorStringPrintf("Non-zero padding: %x", insns[insns_size]);
    return false;
  }

  const DexFile::TryItem* try_items = DexFile::GetTryItems(*code_item, 0);
  ptr_ = DexFile::GetCatchHandlerData(*code_item, 0);
  uint32_t handlers_size = DecodeUnsignedLeb128(&ptr_);

  if (!CheckListSize(try_items, try_items_size, sizeof(DexFile::TryItem), "try_items size")) {
    return false;
  }

  if (UNLIKELY((handlers_size == 0) || (handlers_size >= 65536))) {
    ErrorStringPrintf("Invalid handlers_size: %ud", handlers_size);
    return false;
  }

  std::unique_ptr<uint32_t[]> handler_offsets(new uint32_t[handlers_size]);
  if (!CheckAndGetHandlerOffsets(code_item, &handler_offsets[0], handlers_size)) {
    return false;
  }

  uint32_t last_addr = 0;
  while (try_items_size--) {
    if (UNLIKELY(try_items->start_addr_ < last_addr)) {
      ErrorStringPrintf("Out-of_order try_item with start_addr: %x", try_items->start_addr_);
      return false;
    }

    if (UNLIKELY(try_items->start_addr_ >= insns_size)) {
      ErrorStringPrintf("Invalid try_item start_addr: %x", try_items->start_addr_);
      return false;
    }

    uint32_t i;
    for (i = 0; i < handlers_size; i++) {
      if (try_items->handler_off_ == handler_offsets[i]) {
        break;
      }
    }

    if (UNLIKELY(i == handlers_size)) {
      ErrorStringPrintf("Bogus handler offset: %x", try_items->handler_off_);
      return false;
    }

    last_addr = try_items->start_addr_ + try_items->insn_count_;
    if (UNLIKELY(last_addr > insns_size)) {
      ErrorStringPrintf("Invalid try_item insn_count: %x", try_items->insn_count_);
      return false;
    }

    try_items++;
  }

  return true;
}

bool DexFileVerifier::CheckIntraStringDataItem() {
  uint32_t size = DecodeUnsignedLeb128(&ptr_);
  const byte* file_end = begin_ + size_;

  for (uint32_t i = 0; i < size; i++) {
    CHECK_LT(i, size);  // b/15014252 Prevents hitting the impossible case below
    if (UNLIKELY(ptr_ >= file_end)) {
      ErrorStringPrintf("String data would go beyond end-of-file");
      return false;
    }

    uint8_t byte = *(ptr_++);

    // Switch on the high 4 bits.
    switch (byte >> 4) {
      case 0x00:
        // Special case of bit pattern 0xxx.
        if (UNLIKELY(byte == 0)) {
          CHECK_LT(i, size);  // b/15014252 Actually hit this impossible case with clang
          ErrorStringPrintf("String data shorter than indicated utf16_size %x", size);
          return false;
        }
        break;
      case 0x01:
      case 0x02:
      case 0x03:
      case 0x04:
      case 0x05:
      case 0x06:
      case 0x07:
        // No extra checks necessary for bit pattern 0xxx.
        break;
      case 0x08:
      case 0x09:
      case 0x0a:
      case 0x0b:
      case 0x0f:
        // Illegal bit patterns 10xx or 1111.
        // Note: 1111 is valid for normal UTF-8, but not here.
        ErrorStringPrintf("Illegal start byte %x in string data", byte);
        return false;
      case 0x0c:
      case 0x0d: {
        // Bit pattern 110x has an additional byte.
        uint8_t byte2 = *(ptr_++);
        if (UNLIKELY((byte2 & 0xc0) != 0x80)) {
          ErrorStringPrintf("Illegal continuation byte %x in string data", byte2);
          return false;
        }
        uint16_t value = ((byte & 0x1f) << 6) | (byte2 & 0x3f);
        if (UNLIKELY((value != 0) && (value < 0x80))) {
          ErrorStringPrintf("Illegal representation for value %x in string data", value);
          return false;
        }
        break;
      }
      case 0x0e: {
        // Bit pattern 1110 has 2 additional bytes.
        uint8_t byte2 = *(ptr_++);
        if (UNLIKELY((byte2 & 0xc0) != 0x80)) {
          ErrorStringPrintf("Illegal continuation byte %x in string data", byte2);
          return false;
        }
        uint8_t byte3 = *(ptr_++);
        if (UNLIKELY((byte3 & 0xc0) != 0x80)) {
          ErrorStringPrintf("Illegal continuation byte %x in string data", byte3);
          return false;
        }
        uint16_t value = ((byte & 0x0f) << 12) | ((byte2 & 0x3f) << 6) | (byte3 & 0x3f);
        if (UNLIKELY(value < 0x800)) {
          ErrorStringPrintf("Illegal representation for value %x in string data", value);
          return false;
        }
        break;
      }
    }
  }

  if (UNLIKELY(*(ptr_++) != '\0')) {
    ErrorStringPrintf("String longer than indicated size %x", size);
    return false;
  }

  return true;
}

bool DexFileVerifier::CheckIntraDebugInfoItem() {
  DecodeUnsignedLeb128(&ptr_);
  uint32_t parameters_size = DecodeUnsignedLeb128(&ptr_);
  if (UNLIKELY(parameters_size > 65536)) {
    ErrorStringPrintf("Invalid parameters_size: %x", parameters_size);
    return false;
  }

  for (uint32_t j = 0; j < parameters_size; j++) {
    uint32_t parameter_name = DecodeUnsignedLeb128(&ptr_);
    if (parameter_name != 0) {
      parameter_name--;
      if (!CheckIndex(parameter_name, header_->string_ids_size_, "debug_info_item parameter_name")) {
        return false;
      }
    }
  }

  while (true) {
    uint8_t opcode = *(ptr_++);
    switch (opcode) {
      case DexFile::DBG_END_SEQUENCE: {
        return true;
      }
      case DexFile::DBG_ADVANCE_PC: {
        DecodeUnsignedLeb128(&ptr_);
        break;
      }
      case DexFile::DBG_ADVANCE_LINE: {
        DecodeSignedLeb128(&ptr_);
        break;
      }
      case DexFile::DBG_START_LOCAL: {
        uint32_t reg_num = DecodeUnsignedLeb128(&ptr_);
        if (UNLIKELY(reg_num >= 65536)) {
          ErrorStringPrintf("Bad reg_num for opcode %x", opcode);
          return false;
        }
        uint32_t name_idx = DecodeUnsignedLeb128(&ptr_);
        if (name_idx != 0) {
          name_idx--;
          if (!CheckIndex(name_idx, header_->string_ids_size_, "DBG_START_LOCAL name_idx")) {
            return false;
          }
        }
        uint32_t type_idx = DecodeUnsignedLeb128(&ptr_);
        if (type_idx != 0) {
          type_idx--;
          if (!CheckIndex(type_idx, header_->string_ids_size_, "DBG_START_LOCAL type_idx")) {
            return false;
          }
        }
        break;
      }
      case DexFile::DBG_END_LOCAL:
      case DexFile::DBG_RESTART_LOCAL: {
        uint32_t reg_num = DecodeUnsignedLeb128(&ptr_);
        if (UNLIKELY(reg_num >= 65536)) {
          ErrorStringPrintf("Bad reg_num for opcode %x", opcode);
          return false;
        }
        break;
      }
      case DexFile::DBG_START_LOCAL_EXTENDED: {
        uint32_t reg_num = DecodeUnsignedLeb128(&ptr_);
        if (UNLIKELY(reg_num >= 65536)) {
          ErrorStringPrintf("Bad reg_num for opcode %x", opcode);
          return false;
        }
        uint32_t name_idx = DecodeUnsignedLeb128(&ptr_);
        if (name_idx != 0) {
          name_idx--;
          if (!CheckIndex(name_idx, header_->string_ids_size_, "DBG_START_LOCAL_EXTENDED name_idx")) {
            return false;
          }
        }
        uint32_t type_idx = DecodeUnsignedLeb128(&ptr_);
        if (type_idx != 0) {
          type_idx--;
          if (!CheckIndex(type_idx, header_->string_ids_size_, "DBG_START_LOCAL_EXTENDED type_idx")) {
            return false;
          }
        }
        uint32_t sig_idx = DecodeUnsignedLeb128(&ptr_);
        if (sig_idx != 0) {
          sig_idx--;
          if (!CheckIndex(sig_idx, header_->string_ids_size_, "DBG_START_LOCAL_EXTENDED sig_idx")) {
            return false;
          }
        }
        break;
      }
      case DexFile::DBG_SET_FILE: {
        uint32_t name_idx = DecodeUnsignedLeb128(&ptr_);
        if (name_idx != 0) {
          name_idx--;
          if (!CheckIndex(name_idx, header_->string_ids_size_, "DBG_SET_FILE name_idx")) {
            return false;
          }
        }
        break;
      }
    }
  }
}

bool DexFileVerifier::CheckIntraAnnotationItem() {
  if (!CheckListSize(ptr_, 1, sizeof(byte), "annotation visibility")) {
    return false;
  }

  // Check visibility
  switch (*(ptr_++)) {
    case DexFile::kDexVisibilityBuild:
    case DexFile::kDexVisibilityRuntime:
    case DexFile::kDexVisibilitySystem:
      break;
    default:
      ErrorStringPrintf("Bad annotation visibility: %x", *ptr_);
      return false;
  }

  if (!CheckEncodedAnnotation()) {
    return false;
  }

  return true;
}

bool DexFileVerifier::CheckIntraAnnotationsDirectoryItem() {
  const DexFile::AnnotationsDirectoryItem* item =
      reinterpret_cast<const DexFile::AnnotationsDirectoryItem*>(ptr_);
  if (!CheckListSize(item, 1, sizeof(DexFile::AnnotationsDirectoryItem), "annotations_directory")) {
    return false;
  }

  // Field annotations follow immediately after the annotations directory.
  const DexFile::FieldAnnotationsItem* field_item =
      reinterpret_cast<const DexFile::FieldAnnotationsItem*>(item + 1);
  uint32_t field_count = item->fields_size_;
  if (!CheckListSize(field_item, field_count, sizeof(DexFile::FieldAnnotationsItem), "field_annotations list")) {
    return false;
  }

  uint32_t last_idx = 0;
  for (uint32_t i = 0; i < field_count; i++) {
    if (UNLIKELY(last_idx >= field_item->field_idx_ && i != 0)) {
      ErrorStringPrintf("Out-of-order field_idx for annotation: %x then %x", last_idx, field_item->field_idx_);
      return false;
    }
    last_idx = field_item->field_idx_;
    field_item++;
  }

  // Method annotations follow immediately after field annotations.
  const DexFile::MethodAnnotationsItem* method_item =
      reinterpret_cast<const DexFile::MethodAnnotationsItem*>(field_item);
  uint32_t method_count = item->methods_size_;
  if (!CheckListSize(method_item, method_count, sizeof(DexFile::MethodAnnotationsItem), "method_annotations list")) {
    return false;
  }

  last_idx = 0;
  for (uint32_t i = 0; i < method_count; i++) {
    if (UNLIKELY(last_idx >= method_item->method_idx_ && i != 0)) {
      ErrorStringPrintf("Out-of-order method_idx for annotation: %x then %x",
                       last_idx, method_item->method_idx_);
      return false;
    }
    last_idx = method_item->method_idx_;
    method_item++;
  }

  // Parameter annotations follow immediately after method annotations.
  const DexFile::ParameterAnnotationsItem* parameter_item =
      reinterpret_cast<const DexFile::ParameterAnnotationsItem*>(method_item);
  uint32_t parameter_count = item->parameters_size_;
  if (!CheckListSize(parameter_item, parameter_count, sizeof(DexFile::ParameterAnnotationsItem),
                     "parameter_annotations list")) {
    return false;
  }

  last_idx = 0;
  for (uint32_t i = 0; i < parameter_count; i++) {
    if (UNLIKELY(last_idx >= parameter_item->method_idx_ && i != 0)) {
      ErrorStringPrintf("Out-of-order method_idx for annotation: %x then %x",
                        last_idx, parameter_item->method_idx_);
      return false;
    }
    last_idx = parameter_item->method_idx_;
    parameter_item++;
  }

  // Return a pointer to the end of the annotations.
  ptr_ = reinterpret_cast<const byte*>(parameter_item);
  return true;
}

bool DexFileVerifier::CheckIntraSectionIterate(size_t offset, uint32_t section_count,
                                               uint16_t type) {
  // Get the right alignment mask for the type of section.
  size_t alignment_mask;
  switch (type) {
    case DexFile::kDexTypeClassDataItem:
    case DexFile::kDexTypeStringDataItem:
    case DexFile::kDexTypeDebugInfoItem:
    case DexFile::kDexTypeAnnotationItem:
    case DexFile::kDexTypeEncodedArrayItem:
      alignment_mask = sizeof(uint8_t) - 1;
      break;
    default:
      alignment_mask = sizeof(uint32_t) - 1;
      break;
  }

  // Iterate through the items in the section.
  for (uint32_t i = 0; i < section_count; i++) {
    size_t aligned_offset = (offset + alignment_mask) & ~alignment_mask;

    // Check the padding between items.
    if (!CheckPadding(offset, aligned_offset)) {
      return false;
    }

    // Check depending on the section type.
    switch (type) {
      case DexFile::kDexTypeStringIdItem: {
        if (!CheckListSize(ptr_, 1, sizeof(DexFile::StringId), "string_ids")) {
          return false;
        }
        ptr_ += sizeof(DexFile::StringId);
        break;
      }
      case DexFile::kDexTypeTypeIdItem: {
        if (!CheckListSize(ptr_, 1, sizeof(DexFile::TypeId), "type_ids")) {
          return false;
        }
        ptr_ += sizeof(DexFile::TypeId);
        break;
      }
      case DexFile::kDexTypeProtoIdItem: {
        if (!CheckListSize(ptr_, 1, sizeof(DexFile::ProtoId), "proto_ids")) {
          return false;
        }
        ptr_ += sizeof(DexFile::ProtoId);
        break;
      }
      case DexFile::kDexTypeFieldIdItem: {
        if (!CheckListSize(ptr_, 1, sizeof(DexFile::FieldId), "field_ids")) {
          return false;
        }
        ptr_ += sizeof(DexFile::FieldId);
        break;
      }
      case DexFile::kDexTypeMethodIdItem: {
        if (!CheckListSize(ptr_, 1, sizeof(DexFile::MethodId), "method_ids")) {
          return false;
        }
        ptr_ += sizeof(DexFile::MethodId);
        break;
      }
      case DexFile::kDexTypeClassDefItem: {
        if (!CheckListSize(ptr_, 1, sizeof(DexFile::ClassDef), "class_defs")) {
          return false;
        }
        ptr_ += sizeof(DexFile::ClassDef);
        break;
      }
      case DexFile::kDexTypeTypeList: {
        if (!CheckList(sizeof(DexFile::TypeItem), "type_list", &ptr_)) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeAnnotationSetRefList: {
        if (!CheckList(sizeof(DexFile::AnnotationSetRefItem), "annotation_set_ref_list", &ptr_)) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeAnnotationSetItem: {
        if (!CheckList(sizeof(uint32_t), "annotation_set_item", &ptr_)) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeClassDataItem: {
        if (!CheckIntraClassDataItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeCodeItem: {
        if (!CheckIntraCodeItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeStringDataItem: {
        if (!CheckIntraStringDataItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeDebugInfoItem: {
        if (!CheckIntraDebugInfoItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeAnnotationItem: {
        if (!CheckIntraAnnotationItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeEncodedArrayItem: {
        if (!CheckEncodedArray()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeAnnotationsDirectoryItem: {
        if (!CheckIntraAnnotationsDirectoryItem()) {
          return false;
        }
        break;
      }
      default:
        ErrorStringPrintf("Unknown map item type %x", type);
        return false;
    }

    if (IsDataSectionType(type)) {
      offset_to_type_map_.Put(aligned_offset, type);
    }

    aligned_offset = ptr_ - begin_;
    if (UNLIKELY(aligned_offset > size_)) {
      ErrorStringPrintf("Item %d at ends out of bounds", i);
      return false;
    }

    offset = aligned_offset;
  }

  return true;
}

bool DexFileVerifier::CheckIntraIdSection(size_t offset, uint32_t count, uint16_t type) {
  uint32_t expected_offset;
  uint32_t expected_size;

  // Get the expected offset and size from the header.
  switch (type) {
    case DexFile::kDexTypeStringIdItem:
      expected_offset = header_->string_ids_off_;
      expected_size = header_->string_ids_size_;
      break;
    case DexFile::kDexTypeTypeIdItem:
      expected_offset = header_->type_ids_off_;
      expected_size = header_->type_ids_size_;
      break;
    case DexFile::kDexTypeProtoIdItem:
      expected_offset = header_->proto_ids_off_;
      expected_size = header_->proto_ids_size_;
      break;
    case DexFile::kDexTypeFieldIdItem:
      expected_offset = header_->field_ids_off_;
      expected_size = header_->field_ids_size_;
      break;
    case DexFile::kDexTypeMethodIdItem:
      expected_offset = header_->method_ids_off_;
      expected_size = header_->method_ids_size_;
      break;
    case DexFile::kDexTypeClassDefItem:
      expected_offset = header_->class_defs_off_;
      expected_size = header_->class_defs_size_;
      break;
    default:
      ErrorStringPrintf("Bad type for id section: %x", type);
      return false;
  }

  // Check that the offset and size are what were expected from the header.
  if (UNLIKELY(offset != expected_offset)) {
    ErrorStringPrintf("Bad offset for section: got %zx, expected %x", offset, expected_offset);
    return false;
  }
  if (UNLIKELY(count != expected_size)) {
    ErrorStringPrintf("Bad size for section: got %x, expected %x", count, expected_size);
    return false;
  }

  return CheckIntraSectionIterate(offset, count, type);
}

bool DexFileVerifier::CheckIntraDataSection(size_t offset, uint32_t count, uint16_t type) {
  size_t data_start = header_->data_off_;
  size_t data_end = data_start + header_->data_size_;

  // Sanity check the offset of the section.
  if (UNLIKELY((offset < data_start) || (offset > data_end))) {
    ErrorStringPrintf("Bad offset for data subsection: %zx", offset);
    return false;
  }

  if (!CheckIntraSectionIterate(offset, count, type)) {
    return false;
  }

  size_t next_offset = ptr_ - begin_;
  if (next_offset > data_end) {
    ErrorStringPrintf("Out-of-bounds end of data subsection: %zx", next_offset);
    return false;
  }

  return true;
}

bool DexFileVerifier::CheckIntraSection() {
  const DexFile::MapList* map = reinterpret_cast<const DexFile::MapList*>(begin_ + header_->map_off_);
  const DexFile::MapItem* item = map->list_;

  uint32_t count = map->size_;
  size_t offset = 0;
  ptr_ = begin_;

  // Check the items listed in the map.
  while (count--) {
    uint32_t section_offset = item->offset_;
    uint32_t section_count = item->size_;
    uint16_t type = item->type_;

    // Check for padding and overlap between items.
    if (!CheckPadding(offset, section_offset)) {
      return false;
    } else if (UNLIKELY(offset > section_offset)) {
      ErrorStringPrintf("Section overlap or out-of-order map: %zx, %x", offset, section_offset);
      return false;
    }

    // Check each item based on its type.
    switch (type) {
      case DexFile::kDexTypeHeaderItem:
        if (UNLIKELY(section_count != 1)) {
          ErrorStringPrintf("Multiple header items");
          return false;
        }
        if (UNLIKELY(section_offset != 0)) {
          ErrorStringPrintf("Header at %x, not at start of file", section_offset);
          return false;
        }
        ptr_ = begin_ + header_->header_size_;
        offset = header_->header_size_;
        break;
      case DexFile::kDexTypeStringIdItem:
      case DexFile::kDexTypeTypeIdItem:
      case DexFile::kDexTypeProtoIdItem:
      case DexFile::kDexTypeFieldIdItem:
      case DexFile::kDexTypeMethodIdItem:
      case DexFile::kDexTypeClassDefItem:
        if (!CheckIntraIdSection(section_offset, section_count, type)) {
          return false;
        }
        offset = ptr_ - begin_;
        break;
      case DexFile::kDexTypeMapList:
        if (UNLIKELY(section_count != 1)) {
          ErrorStringPrintf("Multiple map list items");
          return false;
        }
        if (UNLIKELY(section_offset != header_->map_off_)) {
          ErrorStringPrintf("Map not at header-defined offset: %x, expected %x",
                            section_offset, header_->map_off_);
          return false;
        }
        ptr_ += sizeof(uint32_t) + (map->size_ * sizeof(DexFile::MapItem));
        offset = section_offset + sizeof(uint32_t) + (map->size_ * sizeof(DexFile::MapItem));
        break;
      case DexFile::kDexTypeTypeList:
      case DexFile::kDexTypeAnnotationSetRefList:
      case DexFile::kDexTypeAnnotationSetItem:
      case DexFile::kDexTypeClassDataItem:
      case DexFile::kDexTypeCodeItem:
      case DexFile::kDexTypeStringDataItem:
      case DexFile::kDexTypeDebugInfoItem:
      case DexFile::kDexTypeAnnotationItem:
      case DexFile::kDexTypeEncodedArrayItem:
      case DexFile::kDexTypeAnnotationsDirectoryItem:
        if (!CheckIntraDataSection(section_offset, section_count, type)) {
          return false;
        }
        offset = ptr_ - begin_;
        break;
      default:
        ErrorStringPrintf("Unknown map item type %x", type);
        return false;
    }

    item++;
  }

  return true;
}

bool DexFileVerifier::CheckOffsetToTypeMap(size_t offset, uint16_t type) {
  auto it = offset_to_type_map_.find(offset);
  if (UNLIKELY(it == offset_to_type_map_.end())) {
    ErrorStringPrintf("No data map entry found @ %zx; expected %x", offset, type);
    return false;
  }
  if (UNLIKELY(it->second != type)) {
    ErrorStringPrintf("Unexpected data map entry @ %zx; expected %x, found %x",
                      offset, type, it->second);
    return false;
  }
  return true;
}

uint16_t DexFileVerifier::FindFirstClassDataDefiner(const byte* ptr, bool* success) {
  ClassDataItemIterator it(*dex_file_, ptr);
  *success = true;

  if (it.HasNextStaticField() || it.HasNextInstanceField()) {
    LOAD_FIELD(field, it.GetMemberIndex(), "first_class_data_definer field_id",
               *success = false; return DexFile::kDexNoIndex16)
    return field->class_idx_;
  }

  if (it.HasNextDirectMethod() || it.HasNextVirtualMethod()) {
    LOAD_METHOD(method, it.GetMemberIndex(), "first_class_data_definer method_id",
                *success = false; return DexFile::kDexNoIndex16)
    return method->class_idx_;
  }

  return DexFile::kDexNoIndex16;
}

uint16_t DexFileVerifier::FindFirstAnnotationsDirectoryDefiner(const byte* ptr, bool* success) {
  const DexFile::AnnotationsDirectoryItem* item =
      reinterpret_cast<const DexFile::AnnotationsDirectoryItem*>(ptr);
  *success = true;

  if (item->fields_size_ != 0) {
    DexFile::FieldAnnotationsItem* field_items = (DexFile::FieldAnnotationsItem*) (item + 1);
    LOAD_FIELD(field, field_items[0].field_idx_, "first_annotations_dir_definer field_id",
               *success = false; return DexFile::kDexNoIndex16)
    return field->class_idx_;
  }

  if (item->methods_size_ != 0) {
    DexFile::MethodAnnotationsItem* method_items = (DexFile::MethodAnnotationsItem*) (item + 1);
    LOAD_METHOD(method, method_items[0].method_idx_, "first_annotations_dir_definer method id",
                *success = false; return DexFile::kDexNoIndex16)
    return method->class_idx_;
  }

  if (item->parameters_size_ != 0) {
    DexFile::ParameterAnnotationsItem* parameter_items = (DexFile::ParameterAnnotationsItem*) (item + 1);
    LOAD_METHOD(method, parameter_items[0].method_idx_, "first_annotations_dir_definer method id",
                *success = false; return DexFile::kDexNoIndex16)
    return method->class_idx_;
  }

  return DexFile::kDexNoIndex16;
}

bool DexFileVerifier::CheckInterStringIdItem() {
  const DexFile::StringId* item = reinterpret_cast<const DexFile::StringId*>(ptr_);

  // Check the map to make sure it has the right offset->type.
  if (!CheckOffsetToTypeMap(item->string_data_off_, DexFile::kDexTypeStringDataItem)) {
    return false;
  }

  // Check ordering between items.
  if (previous_item_ != NULL) {
    const DexFile::StringId* prev_item = reinterpret_cast<const DexFile::StringId*>(previous_item_);
    const char* prev_str = dex_file_->GetStringData(*prev_item);
    const char* str = dex_file_->GetStringData(*item);
    if (UNLIKELY(CompareModifiedUtf8ToModifiedUtf8AsUtf16CodePointValues(prev_str, str) >= 0)) {
      ErrorStringPrintf("Out-of-order string_ids: '%s' then '%s'", prev_str, str);
      return false;
    }
  }

  ptr_ += sizeof(DexFile::StringId);
  return true;
}

bool DexFileVerifier::CheckInterTypeIdItem() {
  const DexFile::TypeId* item = reinterpret_cast<const DexFile::TypeId*>(ptr_);

  LOAD_STRING(descriptor, item->descriptor_idx_, "inter_type_id_item descriptor_idx")

  // Check that the descriptor is a valid type.
  if (UNLIKELY(!IsValidDescriptor(descriptor))) {
    ErrorStringPrintf("Invalid type descriptor: '%s'", descriptor);
    return false;
  }

  // Check ordering between items.
  if (previous_item_ != NULL) {
    const DexFile::TypeId* prev_item = reinterpret_cast<const DexFile::TypeId*>(previous_item_);
    if (UNLIKELY(prev_item->descriptor_idx_ >= item->descriptor_idx_)) {
      ErrorStringPrintf("Out-of-order type_ids: %x then %x",
                        prev_item->descriptor_idx_, item->descriptor_idx_);
      return false;
    }
  }

  ptr_ += sizeof(DexFile::TypeId);
  return true;
}

bool DexFileVerifier::CheckInterProtoIdItem() {
  const DexFile::ProtoId* item = reinterpret_cast<const DexFile::ProtoId*>(ptr_);

  LOAD_STRING(shorty, item->shorty_idx_, "inter_proto_id_item shorty_idx")

  if (item->parameters_off_ != 0 &&
      !CheckOffsetToTypeMap(item->parameters_off_, DexFile::kDexTypeTypeList)) {
    return false;
  }

  // Check the return type and advance the shorty.
  LOAD_STRING_BY_TYPE(return_type, item->return_type_idx_, "inter_proto_id_item return_type_idx")
  if (!CheckShortyDescriptorMatch(*shorty, return_type, true)) {
    return false;
  }
  shorty++;

  DexFileParameterIterator it(*dex_file_, *item);
  while (it.HasNext() && *shorty != '\0') {
    if (!CheckIndex(it.GetTypeIdx(), dex_file_->NumTypeIds(),
                    "inter_proto_id_item shorty type_idx")) {
      return false;
    }
    const char* descriptor = it.GetDescriptor();
    if (!CheckShortyDescriptorMatch(*shorty, descriptor, false)) {
      return false;
    }
    it.Next();
    shorty++;
  }
  if (UNLIKELY(it.HasNext() || *shorty != '\0')) {
    ErrorStringPrintf("Mismatched length for parameters and shorty");
    return false;
  }

  // Check ordering between items. This relies on type_ids being in order.
  if (previous_item_ != NULL) {
    const DexFile::ProtoId* prev = reinterpret_cast<const DexFile::ProtoId*>(previous_item_);
    if (UNLIKELY(prev->return_type_idx_ > item->return_type_idx_)) {
      ErrorStringPrintf("Out-of-order proto_id return types");
      return false;
    } else if (prev->return_type_idx_ == item->return_type_idx_) {
      DexFileParameterIterator curr_it(*dex_file_, *item);
      DexFileParameterIterator prev_it(*dex_file_, *prev);

      while (curr_it.HasNext() && prev_it.HasNext()) {
        uint16_t prev_idx = prev_it.GetTypeIdx();
        uint16_t curr_idx = curr_it.GetTypeIdx();
        if (prev_idx == DexFile::kDexNoIndex16) {
          break;
        }
        if (UNLIKELY(curr_idx == DexFile::kDexNoIndex16)) {
          ErrorStringPrintf("Out-of-order proto_id arguments");
          return false;
        }

        if (prev_idx < curr_idx) {
          break;
        } else if (UNLIKELY(prev_idx > curr_idx)) {
          ErrorStringPrintf("Out-of-order proto_id arguments");
          return false;
        }

        prev_it.Next();
        curr_it.Next();
      }
    }
  }

  ptr_ += sizeof(DexFile::ProtoId);
  return true;
}

bool DexFileVerifier::CheckInterFieldIdItem() {
  const DexFile::FieldId* item = reinterpret_cast<const DexFile::FieldId*>(ptr_);

  // Check that the class descriptor is valid.
  LOAD_STRING_BY_TYPE(class_descriptor, item->class_idx_, "inter_field_id_item class_idx")
  if (UNLIKELY(!IsValidDescriptor(class_descriptor) || class_descriptor[0] != 'L')) {
    ErrorStringPrintf("Invalid descriptor for class_idx: '%s'", class_descriptor);
    return false;
  }

  // Check that the type descriptor is a valid field name.
  LOAD_STRING_BY_TYPE(type_descriptor, item->type_idx_, "inter_field_id_item type_idx")
  if (UNLIKELY(!IsValidDescriptor(type_descriptor) || type_descriptor[0] == 'V')) {
    ErrorStringPrintf("Invalid descriptor for type_idx: '%s'", type_descriptor);
    return false;
  }

  // Check that the name is valid.
  LOAD_STRING(descriptor, item->name_idx_, "inter_field_id_item name_idx")
  if (UNLIKELY(!IsValidMemberName(descriptor))) {
    ErrorStringPrintf("Invalid field name: '%s'", descriptor);
    return false;
  }

  // Check ordering between items. This relies on the other sections being in order.
  if (previous_item_ != NULL) {
    const DexFile::FieldId* prev_item = reinterpret_cast<const DexFile::FieldId*>(previous_item_);
    if (UNLIKELY(prev_item->class_idx_ > item->class_idx_)) {
      ErrorStringPrintf("Out-of-order field_ids");
      return false;
    } else if (prev_item->class_idx_ == item->class_idx_) {
      if (UNLIKELY(prev_item->name_idx_ > item->name_idx_)) {
        ErrorStringPrintf("Out-of-order field_ids");
        return false;
      } else if (prev_item->name_idx_ == item->name_idx_) {
        if (UNLIKELY(prev_item->type_idx_ >= item->type_idx_)) {
          ErrorStringPrintf("Out-of-order field_ids");
          return false;
        }
      }
    }
  }

  ptr_ += sizeof(DexFile::FieldId);
  return true;
}

bool DexFileVerifier::CheckInterMethodIdItem() {
  const DexFile::MethodId* item = reinterpret_cast<const DexFile::MethodId*>(ptr_);

  // Check that the class descriptor is a valid reference name.
  LOAD_STRING_BY_TYPE(class_descriptor, item->class_idx_, "inter_method_id_item class_idx")
  if (UNLIKELY(!IsValidDescriptor(class_descriptor) || (class_descriptor[0] != 'L' &&
                                                        class_descriptor[0] != '['))) {
    ErrorStringPrintf("Invalid descriptor for class_idx: '%s'", class_descriptor);
    return false;
  }

  // Check that the name is valid.
  LOAD_STRING(descriptor, item->name_idx_, "inter_method_id_item name_idx")
  if (UNLIKELY(!IsValidMemberName(descriptor))) {
    ErrorStringPrintf("Invalid method name: '%s'", descriptor);
    return false;
  }

  // Check that the proto id is valid.
  if (UNLIKELY(!CheckIndex(item->proto_idx_, dex_file_->NumProtoIds(),
                           "inter_method_id_item proto_idx"))) {
    return false;
  }

  // Check ordering between items. This relies on the other sections being in order.
  if (previous_item_ != NULL) {
    const DexFile::MethodId* prev_item = reinterpret_cast<const DexFile::MethodId*>(previous_item_);
    if (UNLIKELY(prev_item->class_idx_ > item->class_idx_)) {
      ErrorStringPrintf("Out-of-order method_ids");
      return false;
    } else if (prev_item->class_idx_ == item->class_idx_) {
      if (UNLIKELY(prev_item->name_idx_ > item->name_idx_)) {
        ErrorStringPrintf("Out-of-order method_ids");
        return false;
      } else if (prev_item->name_idx_ == item->name_idx_) {
        if (UNLIKELY(prev_item->proto_idx_ >= item->proto_idx_)) {
          ErrorStringPrintf("Out-of-order method_ids");
          return false;
        }
      }
    }
  }

  ptr_ += sizeof(DexFile::MethodId);
  return true;
}

bool DexFileVerifier::CheckInterClassDefItem() {
  const DexFile::ClassDef* item = reinterpret_cast<const DexFile::ClassDef*>(ptr_);

  // Check for duplicate class def.
  if (defined_classes_.find(item->class_idx_) != defined_classes_.end()) {
    ErrorStringPrintf("Redefinition of class with type idx: '%d'", item->class_idx_);
    return false;
  }
  defined_classes_.insert(item->class_idx_);

  LOAD_STRING_BY_TYPE(class_descriptor, item->class_idx_, "inter_class_def_item class_idx")
  if (UNLIKELY(!IsValidDescriptor(class_descriptor) || class_descriptor[0] != 'L')) {
    ErrorStringPrintf("Invalid class descriptor: '%s'", class_descriptor);
    return false;
  }

  // Only allow non-runtime modifiers.
  if ((item->access_flags_ & ~kAccJavaFlagsMask) != 0) {
    ErrorStringPrintf("Invalid class flags: '%d'", item->access_flags_);
    return false;
  }

  if (item->interfaces_off_ != 0 &&
      !CheckOffsetToTypeMap(item->interfaces_off_, DexFile::kDexTypeTypeList)) {
    return false;
  }
  if (item->annotations_off_ != 0 &&
      !CheckOffsetToTypeMap(item->annotations_off_, DexFile::kDexTypeAnnotationsDirectoryItem)) {
    return false;
  }
  if (item->class_data_off_ != 0 &&
      !CheckOffsetToTypeMap(item->class_data_off_, DexFile::kDexTypeClassDataItem)) {
    return false;
  }
  if (item->static_values_off_ != 0 &&
      !CheckOffsetToTypeMap(item->static_values_off_, DexFile::kDexTypeEncodedArrayItem)) {
    return false;
  }

  if (item->superclass_idx_ != DexFile::kDexNoIndex16) {
    LOAD_STRING_BY_TYPE(superclass_descriptor, item->superclass_idx_,
                        "inter_class_def_item superclass_idx")
    if (UNLIKELY(!IsValidDescriptor(superclass_descriptor) || superclass_descriptor[0] != 'L')) {
      ErrorStringPrintf("Invalid superclass: '%s'", superclass_descriptor);
      return false;
    }
  }

  const DexFile::TypeList* interfaces = dex_file_->GetInterfacesList(*item);
  if (interfaces != NULL) {
    uint32_t size = interfaces->Size();

    // Ensure that all interfaces refer to classes (not arrays or primitives).
    for (uint32_t i = 0; i < size; i++) {
      LOAD_STRING_BY_TYPE(inf_descriptor, interfaces->GetTypeItem(i).type_idx_,
                          "inter_class_def_item interface type_idx")
      if (UNLIKELY(!IsValidDescriptor(inf_descriptor) || inf_descriptor[0] != 'L')) {
        ErrorStringPrintf("Invalid interface: '%s'", inf_descriptor);
        return false;
      }
    }

    /*
     * Ensure that there are no duplicates. This is an O(N^2) test, but in
     * practice the number of interfaces implemented by any given class is low.
     */
    for (uint32_t i = 1; i < size; i++) {
      uint32_t idx1 = interfaces->GetTypeItem(i).type_idx_;
      for (uint32_t j =0; j < i; j++) {
        uint32_t idx2 = interfaces->GetTypeItem(j).type_idx_;
        if (UNLIKELY(idx1 == idx2)) {
          ErrorStringPrintf("Duplicate interface: '%s'", dex_file_->StringByTypeIdx(idx1));
          return false;
        }
      }
    }
  }

  // Check that references in class_data_item are to the right class.
  if (item->class_data_off_ != 0) {
    const byte* data = begin_ + item->class_data_off_;
    bool success;
    uint16_t data_definer = FindFirstClassDataDefiner(data, &success);
    if (!success) {
      return false;
    }
    if (UNLIKELY((data_definer != item->class_idx_) && (data_definer != DexFile::kDexNoIndex16))) {
      ErrorStringPrintf("Invalid class_data_item");
      return false;
    }
  }

  // Check that references in annotations_directory_item are to right class.
  if (item->annotations_off_ != 0) {
    const byte* data = begin_ + item->annotations_off_;
    bool success;
    uint16_t annotations_definer = FindFirstAnnotationsDirectoryDefiner(data, &success);
    if (!success) {
      return false;
    }
    if (UNLIKELY((annotations_definer != item->class_idx_) &&
                 (annotations_definer != DexFile::kDexNoIndex16))) {
      ErrorStringPrintf("Invalid annotations_directory_item");
      return false;
    }
  }

  ptr_ += sizeof(DexFile::ClassDef);
  return true;
}

bool DexFileVerifier::CheckInterAnnotationSetRefList() {
  const DexFile::AnnotationSetRefList* list =
      reinterpret_cast<const DexFile::AnnotationSetRefList*>(ptr_);
  const DexFile::AnnotationSetRefItem* item = list->list_;
  uint32_t count = list->size_;

  while (count--) {
    if (item->annotations_off_ != 0 &&
        !CheckOffsetToTypeMap(item->annotations_off_, DexFile::kDexTypeAnnotationSetItem)) {
      return false;
    }
    item++;
  }

  ptr_ = reinterpret_cast<const byte*>(item);
  return true;
}

bool DexFileVerifier::CheckInterAnnotationSetItem() {
  const DexFile::AnnotationSetItem* set = reinterpret_cast<const DexFile::AnnotationSetItem*>(ptr_);
  const uint32_t* offsets = set->entries_;
  uint32_t count = set->size_;
  uint32_t last_idx = 0;

  for (uint32_t i = 0; i < count; i++) {
    if (*offsets != 0 && !CheckOffsetToTypeMap(*offsets, DexFile::kDexTypeAnnotationItem)) {
      return false;
    }

    // Get the annotation from the offset and the type index for the annotation.
    const DexFile::AnnotationItem* annotation =
        reinterpret_cast<const DexFile::AnnotationItem*>(begin_ + *offsets);
    const uint8_t* data = annotation->annotation_;
    uint32_t idx = DecodeUnsignedLeb128(&data);

    if (UNLIKELY(last_idx >= idx && i != 0)) {
      ErrorStringPrintf("Out-of-order entry types: %x then %x", last_idx, idx);
      return false;
    }

    last_idx = idx;
    offsets++;
  }

  ptr_ = reinterpret_cast<const byte*>(offsets);
  return true;
}

bool DexFileVerifier::CheckInterClassDataItem() {
  ClassDataItemIterator it(*dex_file_, ptr_);
  bool success;
  uint16_t defining_class = FindFirstClassDataDefiner(ptr_, &success);
  if (!success) {
    return false;
  }

  for (; it.HasNextStaticField() || it.HasNextInstanceField(); it.Next()) {
    LOAD_FIELD(field, it.GetMemberIndex(), "inter_class_data_item field_id", return false)
    if (UNLIKELY(field->class_idx_ != defining_class)) {
      ErrorStringPrintf("Mismatched defining class for class_data_item field");
      return false;
    }
  }
  for (; it.HasNextDirectMethod() || it.HasNextVirtualMethod(); it.Next()) {
    uint32_t code_off = it.GetMethodCodeItemOffset();
    if (code_off != 0 && !CheckOffsetToTypeMap(code_off, DexFile::kDexTypeCodeItem)) {
      return false;
    }
    LOAD_METHOD(method, it.GetMemberIndex(), "inter_class_data_item method_id", return false)
    if (UNLIKELY(method->class_idx_ != defining_class)) {
      ErrorStringPrintf("Mismatched defining class for class_data_item method");
      return false;
    }
  }

  ptr_ = it.EndDataPointer();
  return true;
}

bool DexFileVerifier::CheckInterAnnotationsDirectoryItem() {
  const DexFile::AnnotationsDirectoryItem* item =
      reinterpret_cast<const DexFile::AnnotationsDirectoryItem*>(ptr_);
  bool success;
  uint16_t defining_class = FindFirstAnnotationsDirectoryDefiner(ptr_, &success);
  if (!success) {
    return false;
  }

  if (item->class_annotations_off_ != 0 &&
      !CheckOffsetToTypeMap(item->class_annotations_off_, DexFile::kDexTypeAnnotationSetItem)) {
    return false;
  }

  // Field annotations follow immediately after the annotations directory.
  const DexFile::FieldAnnotationsItem* field_item =
      reinterpret_cast<const DexFile::FieldAnnotationsItem*>(item + 1);
  uint32_t field_count = item->fields_size_;
  for (uint32_t i = 0; i < field_count; i++) {
    LOAD_FIELD(field, field_item->field_idx_, "inter_annotations_directory_item field_id",
               return false)
    if (UNLIKELY(field->class_idx_ != defining_class)) {
      ErrorStringPrintf("Mismatched defining class for field_annotation");
      return false;
    }
    if (!CheckOffsetToTypeMap(field_item->annotations_off_, DexFile::kDexTypeAnnotationSetItem)) {
      return false;
    }
    field_item++;
  }

  // Method annotations follow immediately after field annotations.
  const DexFile::MethodAnnotationsItem* method_item =
      reinterpret_cast<const DexFile::MethodAnnotationsItem*>(field_item);
  uint32_t method_count = item->methods_size_;
  for (uint32_t i = 0; i < method_count; i++) {
    LOAD_METHOD(method, method_item->method_idx_, "inter_annotations_directory_item method_id",
                return false)
    if (UNLIKELY(method->class_idx_ != defining_class)) {
      ErrorStringPrintf("Mismatched defining class for method_annotation");
      return false;
    }
    if (!CheckOffsetToTypeMap(method_item->annotations_off_, DexFile::kDexTypeAnnotationSetItem)) {
      return false;
    }
    method_item++;
  }

  // Parameter annotations follow immediately after method annotations.
  const DexFile::ParameterAnnotationsItem* parameter_item =
      reinterpret_cast<const DexFile::ParameterAnnotationsItem*>(method_item);
  uint32_t parameter_count = item->parameters_size_;
  for (uint32_t i = 0; i < parameter_count; i++) {
    LOAD_METHOD(parameter_method, parameter_item->method_idx_,
                "inter_annotations_directory_item parameter method_id", return false)
    if (UNLIKELY(parameter_method->class_idx_ != defining_class)) {
      ErrorStringPrintf("Mismatched defining class for parameter_annotation");
      return false;
    }
    if (!CheckOffsetToTypeMap(parameter_item->annotations_off_,
        DexFile::kDexTypeAnnotationSetRefList)) {
      return false;
    }
    parameter_item++;
  }

  ptr_ = reinterpret_cast<const byte*>(parameter_item);
  return true;
}

bool DexFileVerifier::CheckInterSectionIterate(size_t offset, uint32_t count, uint16_t type) {
  // Get the right alignment mask for the type of section.
  size_t alignment_mask;
  switch (type) {
    case DexFile::kDexTypeClassDataItem:
      alignment_mask = sizeof(uint8_t) - 1;
      break;
    default:
      alignment_mask = sizeof(uint32_t) - 1;
      break;
  }

  // Iterate through the items in the section.
  previous_item_ = NULL;
  for (uint32_t i = 0; i < count; i++) {
    uint32_t new_offset = (offset + alignment_mask) & ~alignment_mask;
    ptr_ = begin_ + new_offset;
    const byte* prev_ptr = ptr_;

    // Check depending on the section type.
    switch (type) {
      case DexFile::kDexTypeStringIdItem: {
        if (!CheckInterStringIdItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeTypeIdItem: {
        if (!CheckInterTypeIdItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeProtoIdItem: {
        if (!CheckInterProtoIdItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeFieldIdItem: {
        if (!CheckInterFieldIdItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeMethodIdItem: {
        if (!CheckInterMethodIdItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeClassDefItem: {
        if (!CheckInterClassDefItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeAnnotationSetRefList: {
        if (!CheckInterAnnotationSetRefList()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeAnnotationSetItem: {
        if (!CheckInterAnnotationSetItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeClassDataItem: {
        if (!CheckInterClassDataItem()) {
          return false;
        }
        break;
      }
      case DexFile::kDexTypeAnnotationsDirectoryItem: {
        if (!CheckInterAnnotationsDirectoryItem()) {
          return false;
        }
        break;
      }
      default:
        ErrorStringPrintf("Unknown map item type %x", type);
        return false;
    }

    previous_item_ = prev_ptr;
    offset = ptr_ - begin_;
  }

  return true;
}

bool DexFileVerifier::CheckInterSection() {
  const DexFile::MapList* map = reinterpret_cast<const DexFile::MapList*>(begin_ + header_->map_off_);
  const DexFile::MapItem* item = map->list_;
  uint32_t count = map->size_;

  // Cross check the items listed in the map.
  while (count--) {
    uint32_t section_offset = item->offset_;
    uint32_t section_count = item->size_;
    uint16_t type = item->type_;

    switch (type) {
      case DexFile::kDexTypeHeaderItem:
      case DexFile::kDexTypeMapList:
      case DexFile::kDexTypeTypeList:
      case DexFile::kDexTypeCodeItem:
      case DexFile::kDexTypeStringDataItem:
      case DexFile::kDexTypeDebugInfoItem:
      case DexFile::kDexTypeAnnotationItem:
      case DexFile::kDexTypeEncodedArrayItem:
        break;
      case DexFile::kDexTypeStringIdItem:
      case DexFile::kDexTypeTypeIdItem:
      case DexFile::kDexTypeProtoIdItem:
      case DexFile::kDexTypeFieldIdItem:
      case DexFile::kDexTypeMethodIdItem:
      case DexFile::kDexTypeClassDefItem:
      case DexFile::kDexTypeAnnotationSetRefList:
      case DexFile::kDexTypeAnnotationSetItem:
      case DexFile::kDexTypeClassDataItem:
      case DexFile::kDexTypeAnnotationsDirectoryItem: {
        if (!CheckInterSectionIterate(section_offset, section_count, type)) {
          return false;
        }
        break;
      }
      default:
        ErrorStringPrintf("Unknown map item type %x", type);
        return false;
    }

    item++;
  }

  return true;
}

bool DexFileVerifier::Verify() {
  // Check the header.
  if (!CheckHeader()) {
    return false;
  }

  // Check the map section.
  if (!CheckMap()) {
    return false;
  }

  // Check structure within remaining sections.
  if (!CheckIntraSection()) {
    return false;
  }

  // Check references from one section to another.
  if (!CheckInterSection()) {
    return false;
  }

  return true;
}

void DexFileVerifier::ErrorStringPrintf(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  DCHECK(failure_reason_.empty()) << failure_reason_;
  failure_reason_ = StringPrintf("Failure to verify dex file '%s': ", location_);
  StringAppendV(&failure_reason_, fmt, ap);
  va_end(ap);
}

}  // namespace art
