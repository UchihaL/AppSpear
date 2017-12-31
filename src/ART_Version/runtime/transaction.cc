/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "transaction.h"

#include "base/stl_util.h"
#include "base/logging.h"
#include "gc/accounting/card_table-inl.h"
#include "intern_table.h"
#include "mirror/object-inl.h"
#include "mirror/object_array-inl.h"

#include <list>

namespace art {

// TODO: remove (only used for debugging purpose).
static constexpr bool kEnableTransactionStats = false;

Transaction::Transaction() : log_lock_("transaction log lock", kTransactionLogLock) {
  CHECK(Runtime::Current()->IsCompiler());
}

Transaction::~Transaction() {
  if (kEnableTransactionStats) {
    MutexLock mu(Thread::Current(), log_lock_);
    size_t objects_count = object_logs_.size();
    size_t field_values_count = 0;
    for (auto it : object_logs_) {
      field_values_count += it.second.Size();
    }
    size_t array_count = array_logs_.size();
    size_t array_values_count = 0;
    for (auto it : array_logs_) {
      array_values_count += it.second.Size();
    }
    size_t string_count = intern_string_logs_.size();
    LOG(INFO) << "Transaction::~Transaction"
              << ": objects_count=" << objects_count
              << ", field_values_count=" << field_values_count
              << ", array_count=" << array_count
              << ", array_values_count=" << array_values_count
              << ", string_count=" << string_count;
  }
}

void Transaction::RecordWriteField32(mirror::Object* obj, MemberOffset field_offset, uint32_t value,
                                     bool is_volatile) {
  DCHECK(obj != nullptr);
  MutexLock mu(Thread::Current(), log_lock_);
  ObjectLog& object_log = object_logs_[obj];
  object_log.Log32BitsValue(field_offset, value, is_volatile);
}

void Transaction::RecordWriteField64(mirror::Object* obj, MemberOffset field_offset, uint64_t value,
                                     bool is_volatile) {
  DCHECK(obj != nullptr);
  MutexLock mu(Thread::Current(), log_lock_);
  ObjectLog& object_log = object_logs_[obj];
  object_log.Log64BitsValue(field_offset, value, is_volatile);
}

void Transaction::RecordWriteFieldReference(mirror::Object* obj, MemberOffset field_offset,
                                            mirror::Object* value, bool is_volatile) {
  DCHECK(obj != nullptr);
  MutexLock mu(Thread::Current(), log_lock_);
  ObjectLog& object_log = object_logs_[obj];
  object_log.LogReferenceValue(field_offset, value, is_volatile);
}

void Transaction::RecordWriteArray(mirror::Array* array, size_t index, uint64_t value) {
  DCHECK(array != nullptr);
  DCHECK(array->IsArrayInstance());
  DCHECK(!array->IsObjectArray());
  MutexLock mu(Thread::Current(), log_lock_);
  ArrayLog& array_log = array_logs_[array];
  array_log.LogValue(index, value);
}

void Transaction::RecordStrongStringInsertion(mirror::String* s) {
  InternStringLog log(s, InternStringLog::kStrongString, InternStringLog::kInsert);
  LogInternedString(log);
}

void Transaction::RecordWeakStringInsertion(mirror::String* s) {
  InternStringLog log(s, InternStringLog::kWeakString, InternStringLog::kInsert);
  LogInternedString(log);
}

void Transaction::RecordStrongStringRemoval(mirror::String* s) {
  InternStringLog log(s, InternStringLog::kStrongString, InternStringLog::kRemove);
  LogInternedString(log);
}

void Transaction::RecordWeakStringRemoval(mirror::String* s) {
  InternStringLog log(s, InternStringLog::kWeakString, InternStringLog::kRemove);
  LogInternedString(log);
}

void Transaction::LogInternedString(InternStringLog& log) {
  Locks::intern_table_lock_->AssertExclusiveHeld(Thread::Current());
  MutexLock mu(Thread::Current(), log_lock_);
  intern_string_logs_.push_front(log);
}

void Transaction::Abort() {
  CHECK(!Runtime::Current()->IsActiveTransaction());
  Thread* self = Thread::Current();
  self->AssertNoPendingException();
  MutexLock mu1(self, *Locks::intern_table_lock_);
  MutexLock mu2(self, log_lock_);
  UndoObjectModifications();
  UndoArrayModifications();
  UndoInternStringTableModifications();
}

void Transaction::UndoObjectModifications() {
  // TODO we may not need to restore objects allocated during this transaction. Or we could directly
  // remove them from the heap.
  for (auto it : object_logs_) {
    it.second.Undo(it.first);
  }
  object_logs_.clear();
}

void Transaction::UndoArrayModifications() {
  // TODO we may not need to restore array allocated during this transaction. Or we could directly
  // remove them from the heap.
  for (auto it : array_logs_) {
    it.second.Undo(it.first);
  }
  array_logs_.clear();
}

void Transaction::UndoInternStringTableModifications() {
  InternTable* const intern_table = Runtime::Current()->GetInternTable();
  // We want to undo each operation from the most recent to the oldest. List has been filled so the
  // most recent operation is at list begin so just have to iterate over it.
  for (InternStringLog& string_log : intern_string_logs_) {
    string_log.Undo(intern_table);
  }
  intern_string_logs_.clear();
}

void Transaction::VisitRoots(RootCallback* callback, void* arg) {
  MutexLock mu(Thread::Current(), log_lock_);
  VisitObjectLogs(callback, arg);
  VisitArrayLogs(callback, arg);
  VisitStringLogs(callback, arg);
}

void Transaction::VisitObjectLogs(RootCallback* callback, void* arg) {
  // List of moving roots.
  typedef std::pair<mirror::Object*, mirror::Object*> ObjectPair;
  std::list<ObjectPair> moving_roots;

  // Visit roots.
  for (auto it : object_logs_) {
    it.second.VisitRoots(callback, arg);
    mirror::Object* old_root = it.first;
    mirror::Object* new_root = old_root;
    callback(&new_root, arg, 0, kRootUnknown);
    if (new_root != old_root) {
      moving_roots.push_back(std::make_pair(old_root, new_root));
    }
  }

  // Update object logs with moving roots.
  for (const ObjectPair& pair : moving_roots) {
    mirror::Object* old_root = pair.first;
    mirror::Object* new_root = pair.second;
    auto old_root_it = object_logs_.find(old_root);
    CHECK(old_root_it != object_logs_.end());
    CHECK(object_logs_.find(new_root) == object_logs_.end());
    object_logs_.insert(std::make_pair(new_root, old_root_it->second));
    object_logs_.erase(old_root_it);
  }
}

void Transaction::VisitArrayLogs(RootCallback* callback, void* arg) {
  // List of moving roots.
  typedef std::pair<mirror::Array*, mirror::Array*> ArrayPair;
  std::list<ArrayPair> moving_roots;

  for (auto it : array_logs_) {
    mirror::Array* old_root = it.first;
    CHECK(!old_root->IsObjectArray());
    mirror::Array* new_root = old_root;
    callback(reinterpret_cast<mirror::Object**>(&new_root), arg, 0, kRootUnknown);
    if (new_root != old_root) {
      moving_roots.push_back(std::make_pair(old_root, new_root));
    }
  }

  // Update array logs with moving roots.
  for (const ArrayPair& pair : moving_roots) {
    mirror::Array* old_root = pair.first;
    mirror::Array* new_root = pair.second;
    auto old_root_it = array_logs_.find(old_root);
    CHECK(old_root_it != array_logs_.end());
    CHECK(array_logs_.find(new_root) == array_logs_.end());
    array_logs_.insert(std::make_pair(new_root, old_root_it->second));
    array_logs_.erase(old_root_it);
  }
}

void Transaction::VisitStringLogs(RootCallback* callback, void* arg) {
  for (InternStringLog& log : intern_string_logs_) {
    log.VisitRoots(callback, arg);
  }
}

void Transaction::ObjectLog::Log32BitsValue(MemberOffset offset, uint32_t value, bool is_volatile) {
  auto it = field_values_.find(offset.Uint32Value());
  if (it == field_values_.end()) {
    ObjectLog::FieldValue field_value;
    field_value.value = value;
    field_value.is_volatile = is_volatile;
    field_value.kind = ObjectLog::k32Bits;
    field_values_.insert(std::make_pair(offset.Uint32Value(), field_value));
  }
}

void Transaction::ObjectLog::Log64BitsValue(MemberOffset offset, uint64_t value, bool is_volatile) {
  auto it = field_values_.find(offset.Uint32Value());
  if (it == field_values_.end()) {
    ObjectLog::FieldValue field_value;
    field_value.value = value;
    field_value.is_volatile = is_volatile;
    field_value.kind = ObjectLog::k64Bits;
    field_values_.insert(std::make_pair(offset.Uint32Value(), field_value));
  }
}

void Transaction::ObjectLog::LogReferenceValue(MemberOffset offset, mirror::Object* obj, bool is_volatile) {
  auto it = field_values_.find(offset.Uint32Value());
  if (it == field_values_.end()) {
    ObjectLog::FieldValue field_value;
    field_value.value = reinterpret_cast<uintptr_t>(obj);
    field_value.is_volatile = is_volatile;
    field_value.kind = ObjectLog::kReference;
    field_values_.insert(std::make_pair(offset.Uint32Value(), field_value));
  }
}

void Transaction::ObjectLog::Undo(mirror::Object* obj) {
  for (auto& it : field_values_) {
    // Garbage collector needs to access object's class and array's length. So we don't rollback
    // these values.
    MemberOffset field_offset(it.first);
    if (field_offset.Uint32Value() == mirror::Class::ClassOffset().Uint32Value()) {
      // Skip Object::class field.
      continue;
    }
    if (obj->IsArrayInstance() &&
        field_offset.Uint32Value() == mirror::Array::LengthOffset().Uint32Value()) {
      // Skip Array::length field.
      continue;
    }
    FieldValue& field_value = it.second;
    UndoFieldWrite(obj, field_offset, field_value);
  }
}

void Transaction::ObjectLog::UndoFieldWrite(mirror::Object* obj, MemberOffset field_offset,
                                            const FieldValue& field_value) {
  // TODO We may want to abort a transaction while still being in transaction mode. In this case,
  // we'd need to disable the check.
  constexpr bool kCheckTransaction = true;
  switch (field_value.kind) {
    case k32Bits:
      if (UNLIKELY(field_value.is_volatile)) {
        obj->SetField32Volatile<false, kCheckTransaction>(field_offset,
                                                          static_cast<uint32_t>(field_value.value));
      } else {
        obj->SetField32<false, kCheckTransaction>(field_offset,
                                                  static_cast<uint32_t>(field_value.value));
      }
      break;
    case k64Bits:
      if (UNLIKELY(field_value.is_volatile)) {
        obj->SetField64Volatile<false, kCheckTransaction>(field_offset, field_value.value);
      } else {
        obj->SetField64<false, kCheckTransaction>(field_offset, field_value.value);
      }
      break;
    case kReference:
      if (UNLIKELY(field_value.is_volatile)) {
        obj->SetFieldObjectVolatile<false, kCheckTransaction>(field_offset,
                                                              reinterpret_cast<mirror::Object*>(field_value.value));
      } else {
        obj->SetFieldObject<false, kCheckTransaction>(field_offset,
                                                      reinterpret_cast<mirror::Object*>(field_value.value));
      }
      break;
    default:
      LOG(FATAL) << "Unknown value kind " << field_value.kind;
      break;
  }
}

void Transaction::ObjectLog::VisitRoots(RootCallback* callback, void* arg) {
  for (auto it : field_values_) {
    FieldValue& field_value = it.second;
    if (field_value.kind == ObjectLog::kReference) {
      mirror::Object* obj =
          reinterpret_cast<mirror::Object*>(static_cast<uintptr_t>(field_value.value));
      if (obj != nullptr) {
        callback(&obj, arg, 0, kRootUnknown);
        field_value.value = reinterpret_cast<uintptr_t>(obj);
      }
    }
  }
}

void Transaction::InternStringLog::Undo(InternTable* intern_table) {
  DCHECK(intern_table != nullptr);
  switch (string_op_) {
      case InternStringLog::kInsert: {
        switch (string_kind_) {
          case InternStringLog::kStrongString:
            intern_table->RemoveStrongFromTransaction(str_);
            break;
          case InternStringLog::kWeakString:
            intern_table->RemoveWeakFromTransaction(str_);
            break;
          default:
            LOG(FATAL) << "Unknown interned string kind";
            break;
        }
        break;
      }
      case InternStringLog::kRemove: {
        switch (string_kind_) {
          case InternStringLog::kStrongString:
            intern_table->InsertStrongFromTransaction(str_);
            break;
          case InternStringLog::kWeakString:
            intern_table->InsertWeakFromTransaction(str_);
            break;
          default:
            LOG(FATAL) << "Unknown interned string kind";
            break;
        }
        break;
      }
      default:
        LOG(FATAL) << "Unknown interned string op";
        break;
    }
}

void Transaction::InternStringLog::VisitRoots(RootCallback* callback, void* arg) {
  callback(reinterpret_cast<mirror::Object**>(&str_), arg, 0, kRootInternedString);
}

void Transaction::ArrayLog::LogValue(size_t index, uint64_t value) {
  auto it = array_values_.find(index);
  if (it == array_values_.end()) {
    array_values_.insert(std::make_pair(index, value));
  }
}

void Transaction::ArrayLog::Undo(mirror::Array* array) {
  DCHECK(array != nullptr);
  DCHECK(array->IsArrayInstance());
  Primitive::Type type = array->GetClass()->GetComponentType()->GetPrimitiveType();
  for (auto it : array_values_) {
    UndoArrayWrite(array, type, it.first, it.second);
  }
}

void Transaction::ArrayLog::UndoArrayWrite(mirror::Array* array, Primitive::Type array_type,
                                           size_t index, uint64_t value) {
  // TODO We may want to abort a transaction while still being in transaction mode. In this case,
  // we'd need to disable the check.
  switch (array_type) {
    case Primitive::kPrimBoolean:
      array->AsBooleanArray()->SetWithoutChecks<false>(index, static_cast<uint8_t>(value));
      break;
    case Primitive::kPrimByte:
      array->AsByteArray()->SetWithoutChecks<false>(index, static_cast<int8_t>(value));
      break;
    case Primitive::kPrimChar:
      array->AsCharArray()->SetWithoutChecks<false>(index, static_cast<uint16_t>(value));
      break;
    case Primitive::kPrimShort:
      array->AsShortArray()->SetWithoutChecks<false>(index, static_cast<int16_t>(value));
      break;
    case Primitive::kPrimInt:
      array->AsIntArray()->SetWithoutChecks<false>(index, static_cast<int32_t>(value));
      break;
    case Primitive::kPrimFloat:
      array->AsFloatArray()->SetWithoutChecks<false>(index, static_cast<float>(value));
      break;
    case Primitive::kPrimLong:
      array->AsLongArray()->SetWithoutChecks<false>(index, static_cast<int64_t>(value));
      break;
    case Primitive::kPrimDouble:
      array->AsDoubleArray()->SetWithoutChecks<false>(index, static_cast<double>(value));
      break;
    case Primitive::kPrimNot:
      LOG(FATAL) << "ObjectArray should be treated as Object";
      break;
    default:
      LOG(FATAL) << "Unsupported type " << array_type;
  }
}

}  // namespace art
