/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "large_object_space.h"

#include <memory>

#include "gc/accounting/space_bitmap-inl.h"
#include "base/logging.h"
#include "base/mutex-inl.h"
#include "base/stl_util.h"
#include "image.h"
#include "os.h"
#include "space-inl.h"
#include "thread-inl.h"
#include "utils.h"

namespace art {
namespace gc {
namespace space {

class ValgrindLargeObjectMapSpace FINAL : public LargeObjectMapSpace {
 public:
  explicit ValgrindLargeObjectMapSpace(const std::string& name) : LargeObjectMapSpace(name) {
  }

  virtual mirror::Object* Alloc(Thread* self, size_t num_bytes, size_t* bytes_allocated,
                                size_t* usable_size) OVERRIDE {
    mirror::Object* obj =
        LargeObjectMapSpace::Alloc(self, num_bytes + kValgrindRedZoneBytes * 2, bytes_allocated,
                                   usable_size);
    mirror::Object* object_without_rdz = reinterpret_cast<mirror::Object*>(
        reinterpret_cast<uintptr_t>(obj) + kValgrindRedZoneBytes);
    VALGRIND_MAKE_MEM_NOACCESS(reinterpret_cast<void*>(obj), kValgrindRedZoneBytes);
    VALGRIND_MAKE_MEM_NOACCESS(reinterpret_cast<byte*>(object_without_rdz) + num_bytes,
                               kValgrindRedZoneBytes);
    if (usable_size != nullptr) {
      *usable_size = num_bytes;  // Since we have redzones, shrink the usable size.
    }
    return object_without_rdz;
  }

  virtual size_t AllocationSize(mirror::Object* obj, size_t* usable_size) OVERRIDE {
    mirror::Object* object_with_rdz = reinterpret_cast<mirror::Object*>(
        reinterpret_cast<uintptr_t>(obj) - kValgrindRedZoneBytes);
    return LargeObjectMapSpace::AllocationSize(object_with_rdz, usable_size);
  }

  virtual size_t Free(Thread* self, mirror::Object* obj) OVERRIDE {
    mirror::Object* object_with_rdz = reinterpret_cast<mirror::Object*>(
        reinterpret_cast<uintptr_t>(obj) - kValgrindRedZoneBytes);
    VALGRIND_MAKE_MEM_UNDEFINED(object_with_rdz, AllocationSize(obj, nullptr));
    return LargeObjectMapSpace::Free(self, object_with_rdz);
  }

  bool Contains(const mirror::Object* obj) const OVERRIDE {
    mirror::Object* object_with_rdz = reinterpret_cast<mirror::Object*>(
        reinterpret_cast<uintptr_t>(obj) - kValgrindRedZoneBytes);
    return LargeObjectMapSpace::Contains(object_with_rdz);
  }

 private:
  static constexpr size_t kValgrindRedZoneBytes = kPageSize;
};

void LargeObjectSpace::SwapBitmaps() {
  live_bitmap_.swap(mark_bitmap_);
  // Swap names to get more descriptive diagnostics.
  std::string temp_name = live_bitmap_->GetName();
  live_bitmap_->SetName(mark_bitmap_->GetName());
  mark_bitmap_->SetName(temp_name);
}

LargeObjectSpace::LargeObjectSpace(const std::string& name, byte* begin, byte* end)
    : DiscontinuousSpace(name, kGcRetentionPolicyAlwaysCollect),
      num_bytes_allocated_(0), num_objects_allocated_(0), total_bytes_allocated_(0),
      total_objects_allocated_(0), begin_(begin), end_(end) {
}


void LargeObjectSpace::CopyLiveToMarked() {
  mark_bitmap_->CopyFrom(live_bitmap_.get());
}

LargeObjectMapSpace::LargeObjectMapSpace(const std::string& name)
    : LargeObjectSpace(name, nullptr, nullptr),
      lock_("large object map space lock", kAllocSpaceLock) {}

LargeObjectMapSpace* LargeObjectMapSpace::Create(const std::string& name) {
  if (Runtime::Current()->RunningOnValgrind()) {
    return new ValgrindLargeObjectMapSpace(name);
  } else {
    return new LargeObjectMapSpace(name);
  }
}

mirror::Object* LargeObjectMapSpace::Alloc(Thread* self, size_t num_bytes,
                                           size_t* bytes_allocated, size_t* usable_size) {
  std::string error_msg;
  MemMap* mem_map = MemMap::MapAnonymous("large object space allocation", NULL, num_bytes,
                                         PROT_READ | PROT_WRITE, true, &error_msg);
  if (UNLIKELY(mem_map == NULL)) {
    LOG(WARNING) << "Large object allocation failed: " << error_msg;
    return NULL;
  }
  MutexLock mu(self, lock_);
  mirror::Object* obj = reinterpret_cast<mirror::Object*>(mem_map->Begin());
  large_objects_.push_back(obj);
  mem_maps_.Put(obj, mem_map);
  size_t allocation_size = mem_map->Size();
  DCHECK(bytes_allocated != nullptr);
  begin_ = std::min(begin_, reinterpret_cast<byte*>(obj));
  byte* obj_end = reinterpret_cast<byte*>(obj) + allocation_size;
  if (end_ == nullptr || obj_end > end_) {
    end_ = obj_end;
  }
  *bytes_allocated = allocation_size;
  if (usable_size != nullptr) {
    *usable_size = allocation_size;
  }
  num_bytes_allocated_ += allocation_size;
  total_bytes_allocated_ += allocation_size;
  ++num_objects_allocated_;
  ++total_objects_allocated_;
  return obj;
}

size_t LargeObjectMapSpace::Free(Thread* self, mirror::Object* ptr) {
  MutexLock mu(self, lock_);
  MemMaps::iterator found = mem_maps_.find(ptr);
  if (UNLIKELY(found == mem_maps_.end())) {
    Runtime::Current()->GetHeap()->DumpSpaces(LOG(ERROR));
    LOG(FATAL) << "Attempted to free large object " << ptr << " which was not live";
  }
  DCHECK_GE(num_bytes_allocated_, found->second->Size());
  size_t allocation_size = found->second->Size();
  num_bytes_allocated_ -= allocation_size;
  --num_objects_allocated_;
  delete found->second;
  mem_maps_.erase(found);
  return allocation_size;
}

size_t LargeObjectMapSpace::AllocationSize(mirror::Object* obj, size_t* usable_size) {
  MutexLock mu(Thread::Current(), lock_);
  auto found = mem_maps_.find(obj);
  CHECK(found != mem_maps_.end()) << "Attempted to get size of a large object which is not live";
  return found->second->Size();
}

size_t LargeObjectSpace::FreeList(Thread* self, size_t num_ptrs, mirror::Object** ptrs) {
  size_t total = 0;
  for (size_t i = 0; i < num_ptrs; ++i) {
    if (kDebugSpaces) {
      CHECK(Contains(ptrs[i]));
    }
    total += Free(self, ptrs[i]);
  }
  return total;
}

void LargeObjectMapSpace::Walk(DlMallocSpace::WalkCallback callback, void* arg) {
  MutexLock mu(Thread::Current(), lock_);
  for (auto it = mem_maps_.begin(); it != mem_maps_.end(); ++it) {
    MemMap* mem_map = it->second;
    callback(mem_map->Begin(), mem_map->End(), mem_map->Size(), arg);
    callback(NULL, NULL, 0, arg);
  }
}

bool LargeObjectMapSpace::Contains(const mirror::Object* obj) const {
  Thread* self = Thread::Current();
  if (lock_.IsExclusiveHeld(self)) {
    // We hold lock_ so do the check.
    return mem_maps_.find(const_cast<mirror::Object*>(obj)) != mem_maps_.end();
  } else {
    MutexLock mu(self, lock_);
    return mem_maps_.find(const_cast<mirror::Object*>(obj)) != mem_maps_.end();
  }
}

// Keeps track of allocation sizes + whether or not the previous allocation is free.
// Used to coalesce free blocks and find the best fit block for an allocation.
class AllocationInfo {
 public:
  AllocationInfo() : prev_free_(0), alloc_size_(0) {
  }
  // Return the number of pages that the allocation info covers.
  size_t AlignSize() const {
    return alloc_size_ & ~kFlagFree;
  }
  // Returns the allocation size in bytes.
  size_t ByteSize() const {
    return AlignSize() * FreeListSpace::kAlignment;
  }
  // Updates the allocation size and whether or not it is free.
  void SetByteSize(size_t size, bool free) {
    DCHECK_ALIGNED(size, FreeListSpace::kAlignment);
    alloc_size_ = (size / FreeListSpace::kAlignment) | (free ? kFlagFree : 0U);
  }
  bool IsFree() const {
    return (alloc_size_ & kFlagFree) != 0;
  }
  // Finds and returns the next non free allocation info after ourself.
  AllocationInfo* GetNextInfo() {
    return this + AlignSize();
  }
  const AllocationInfo* GetNextInfo() const {
    return this + AlignSize();
  }
  // Returns the previous free allocation info by using the prev_free_ member to figure out
  // where it is. This is only used for coalescing so we only need to be able to do it if the
  // previous allocation info is free.
  AllocationInfo* GetPrevFreeInfo() {
    DCHECK_NE(prev_free_, 0U);
    return this - prev_free_;
  }
  // Returns the address of the object associated with this allocation info.
  mirror::Object* GetObjectAddress() {
    return reinterpret_cast<mirror::Object*>(reinterpret_cast<uintptr_t>(this) + sizeof(*this));
  }
  // Return how many kAlignment units there are before the free block.
  size_t GetPrevFree() const {
    return prev_free_;
  }
  // Returns how many free bytes there is before the block.
  size_t GetPrevFreeBytes() const {
    return GetPrevFree() * FreeListSpace::kAlignment;
  }
  // Update the size of the free block prior to the allocation.
  void SetPrevFreeBytes(size_t bytes) {
    DCHECK_ALIGNED(bytes, FreeListSpace::kAlignment);
    prev_free_ = bytes / FreeListSpace::kAlignment;
  }

 private:
  // Used to implement best fit object allocation. Each allocation has an AllocationInfo which
  // contains the size of the previous free block preceding it. Implemented in such a way that we
  // can also find the iterator for any allocation info pointer.
  static constexpr uint32_t kFlagFree = 0x8000000;
  // Contains the size of the previous free block with kAlignment as the unit. If 0 then the
  // allocation before us is not free.
  // These variables are undefined in the middle of allocations / free blocks.
  uint32_t prev_free_;
  // Allocation size of this object in kAlignment as the unit.
  uint32_t alloc_size_;
};

size_t FreeListSpace::GetSlotIndexForAllocationInfo(const AllocationInfo* info) const {
  DCHECK_GE(info, allocation_info_);
  DCHECK_LT(info, reinterpret_cast<AllocationInfo*>(allocation_info_map_->End()));
  return info - allocation_info_;
}

AllocationInfo* FreeListSpace::GetAllocationInfoForAddress(uintptr_t address) {
  return &allocation_info_[GetSlotIndexForAddress(address)];
}

const AllocationInfo* FreeListSpace::GetAllocationInfoForAddress(uintptr_t address) const {
  return &allocation_info_[GetSlotIndexForAddress(address)];
}

inline bool FreeListSpace::SortByPrevFree::operator()(const AllocationInfo* a,
                                                      const AllocationInfo* b) const {
  if (a->GetPrevFree() < b->GetPrevFree()) return true;
  if (a->GetPrevFree() > b->GetPrevFree()) return false;
  if (a->AlignSize() < b->AlignSize()) return true;
  if (a->AlignSize() > b->AlignSize()) return false;
  return reinterpret_cast<uintptr_t>(a) < reinterpret_cast<uintptr_t>(b);
}

FreeListSpace* FreeListSpace::Create(const std::string& name, byte* requested_begin, size_t size) {
  CHECK_EQ(size % kAlignment, 0U);
  std::string error_msg;
  MemMap* mem_map = MemMap::MapAnonymous(name.c_str(), requested_begin, size,
                                         PROT_READ | PROT_WRITE, true, &error_msg);
  CHECK(mem_map != NULL) << "Failed to allocate large object space mem map: " << error_msg;
  return new FreeListSpace(name, mem_map, mem_map->Begin(), mem_map->End());
}

FreeListSpace::FreeListSpace(const std::string& name, MemMap* mem_map, byte* begin, byte* end)
    : LargeObjectSpace(name, begin, end),
      mem_map_(mem_map),
      lock_("free list space lock", kAllocSpaceLock) {
  const size_t space_capacity = end - begin;
  free_end_ = space_capacity;
  CHECK_ALIGNED(space_capacity, kAlignment);
  const size_t alloc_info_size = sizeof(AllocationInfo) * (space_capacity / kAlignment);
  std::string error_msg;
  allocation_info_map_.reset(MemMap::MapAnonymous("large object free list space allocation info map",
                                                  nullptr, alloc_info_size, PROT_READ | PROT_WRITE,
                                                  false, &error_msg));
  CHECK(allocation_info_map_.get() != nullptr) << "Failed to allocate allocation info map"
      << error_msg;
  allocation_info_ = reinterpret_cast<AllocationInfo*>(allocation_info_map_->Begin());
}

FreeListSpace::~FreeListSpace() {}

void FreeListSpace::Walk(DlMallocSpace::WalkCallback callback, void* arg) {
  MutexLock mu(Thread::Current(), lock_);
  const uintptr_t free_end_start = reinterpret_cast<uintptr_t>(end_) - free_end_;
  AllocationInfo* cur_info = &allocation_info_[0];
  const AllocationInfo* end_info = GetAllocationInfoForAddress(free_end_start);
  while (cur_info < end_info) {
    if (!cur_info->IsFree()) {
      size_t alloc_size = cur_info->ByteSize();
      byte* byte_start = reinterpret_cast<byte*>(GetAddressForAllocationInfo(cur_info));
      byte* byte_end = byte_start + alloc_size;
      callback(byte_start, byte_end, alloc_size, arg);
      callback(nullptr, nullptr, 0, arg);
    }
    cur_info = cur_info->GetNextInfo();
  }
  CHECK_EQ(cur_info, end_info);
}

void FreeListSpace::RemoveFreePrev(AllocationInfo* info) {
  CHECK_GT(info->GetPrevFree(), 0U);
  auto it = free_blocks_.lower_bound(info);
  CHECK(it != free_blocks_.end());
  CHECK_EQ(*it, info);
  free_blocks_.erase(it);
}

size_t FreeListSpace::Free(Thread* self, mirror::Object* obj) {
  MutexLock mu(self, lock_);
  DCHECK(Contains(obj)) << reinterpret_cast<void*>(Begin()) << " " << obj << " "
                        << reinterpret_cast<void*>(End());
  DCHECK_ALIGNED(obj, kAlignment);
  AllocationInfo* info = GetAllocationInfoForAddress(reinterpret_cast<uintptr_t>(obj));
  DCHECK(!info->IsFree());
  const size_t allocation_size = info->ByteSize();
  DCHECK_GT(allocation_size, 0U);
  DCHECK_ALIGNED(allocation_size, kAlignment);
  info->SetByteSize(allocation_size, true);  // Mark as free.
  // Look at the next chunk.
  AllocationInfo* next_info = info->GetNextInfo();
  // Calculate the start of the end free block.
  uintptr_t free_end_start = reinterpret_cast<uintptr_t>(end_) - free_end_;
  size_t prev_free_bytes = info->GetPrevFreeBytes();
  size_t new_free_size = allocation_size;
  if (prev_free_bytes != 0) {
    // Coalesce with previous free chunk.
    new_free_size += prev_free_bytes;
    RemoveFreePrev(info);
    info = info->GetPrevFreeInfo();
    // The previous allocation info must not be free since we are supposed to always coalesce.
    DCHECK_EQ(info->GetPrevFreeBytes(), 0U) << "Previous allocation was free";
  }
  uintptr_t next_addr = GetAddressForAllocationInfo(next_info);
  if (next_addr >= free_end_start) {
    // Easy case, the next chunk is the end free region.
    CHECK_EQ(next_addr, free_end_start);
    free_end_ += new_free_size;
  } else {
    AllocationInfo* new_free_info;
    if (next_info->IsFree()) {
      AllocationInfo* next_next_info = next_info->GetNextInfo();
      // Next next info can't be free since we always coalesce.
      DCHECK(!next_next_info->IsFree());
      DCHECK(IsAligned<kAlignment>(next_next_info->ByteSize()));
      new_free_info = next_next_info;
      new_free_size += next_next_info->GetPrevFreeBytes();
      RemoveFreePrev(next_next_info);
    } else {
      new_free_info = next_info;
    }
    new_free_info->SetPrevFreeBytes(new_free_size);
    free_blocks_.insert(new_free_info);
    info->SetByteSize(new_free_size, true);
    DCHECK_EQ(info->GetNextInfo(), new_free_info);
  }
  --num_objects_allocated_;
  DCHECK_LE(allocation_size, num_bytes_allocated_);
  num_bytes_allocated_ -= allocation_size;
  madvise(obj, allocation_size, MADV_DONTNEED);
  if (kIsDebugBuild) {
    // Can't disallow reads since we use them to find next chunks during coalescing.
    mprotect(obj, allocation_size, PROT_READ);
  }
  return allocation_size;
}

size_t FreeListSpace::AllocationSize(mirror::Object* obj, size_t* usable_size) {
  DCHECK(Contains(obj));
  AllocationInfo* info = GetAllocationInfoForAddress(reinterpret_cast<uintptr_t>(obj));
  DCHECK(!info->IsFree());
  size_t alloc_size = info->ByteSize();
  if (usable_size != nullptr) {
    *usable_size = alloc_size;
  }
  return alloc_size;
}

mirror::Object* FreeListSpace::Alloc(Thread* self, size_t num_bytes, size_t* bytes_allocated,
                                     size_t* usable_size) {
  MutexLock mu(self, lock_);
  const size_t allocation_size = RoundUp(num_bytes, kAlignment);
  AllocationInfo temp_info;
  temp_info.SetPrevFreeBytes(allocation_size);
  temp_info.SetByteSize(0, false);
  AllocationInfo* new_info;
  // Find the smallest chunk at least num_bytes in size.
  auto it = free_blocks_.lower_bound(&temp_info);
  if (it != free_blocks_.end()) {
    AllocationInfo* info = *it;
    free_blocks_.erase(it);
    // Fit our object in the previous allocation info free space.
    new_info = info->GetPrevFreeInfo();
    // Remove the newly allocated block from the info and update the prev_free_.
    info->SetPrevFreeBytes(info->GetPrevFreeBytes() - allocation_size);
    if (info->GetPrevFreeBytes() > 0) {
      AllocationInfo* new_free = info - info->GetPrevFree();
      new_free->SetPrevFreeBytes(0);
      new_free->SetByteSize(info->GetPrevFreeBytes(), true);
      // If there is remaining space, insert back into the free set.
      free_blocks_.insert(info);
    }
  } else {
    // Try to steal some memory from the free space at the end of the space.
    if (LIKELY(free_end_ >= allocation_size)) {
      // Fit our object at the start of the end free block.
      new_info = GetAllocationInfoForAddress(reinterpret_cast<uintptr_t>(End()) - free_end_);
      free_end_ -= allocation_size;
    } else {
      return nullptr;
    }
  }
  DCHECK(bytes_allocated != nullptr);
  *bytes_allocated = allocation_size;
  if (usable_size != nullptr) {
    *usable_size = allocation_size;
  }
  // Need to do these inside of the lock.
  ++num_objects_allocated_;
  ++total_objects_allocated_;
  num_bytes_allocated_ += allocation_size;
  total_bytes_allocated_ += allocation_size;
  mirror::Object* obj = reinterpret_cast<mirror::Object*>(GetAddressForAllocationInfo(new_info));
  // We always put our object at the start of the free block, there can not be another free block
  // before it.
  if (kIsDebugBuild) {
    mprotect(obj, allocation_size, PROT_READ | PROT_WRITE);
  }
  new_info->SetPrevFreeBytes(0);
  new_info->SetByteSize(allocation_size, false);
  return obj;
}

void FreeListSpace::Dump(std::ostream& os) const {
  MutexLock mu(Thread::Current(), const_cast<Mutex&>(lock_));
  os << GetName() << " -"
     << " begin: " << reinterpret_cast<void*>(Begin())
     << " end: " << reinterpret_cast<void*>(End()) << "\n";
  uintptr_t free_end_start = reinterpret_cast<uintptr_t>(end_) - free_end_;
  const AllocationInfo* cur_info =
      GetAllocationInfoForAddress(reinterpret_cast<uintptr_t>(Begin()));
  const AllocationInfo* end_info = GetAllocationInfoForAddress(free_end_start);
  while (cur_info < end_info) {
    size_t size = cur_info->ByteSize();
    uintptr_t address = GetAddressForAllocationInfo(cur_info);
    if (cur_info->IsFree()) {
      os << "Free block at address: " << reinterpret_cast<const void*>(address)
         << " of length " << size << " bytes\n";
    } else {
      os << "Large object at address: " << reinterpret_cast<const void*>(address)
         << " of length " << size << " bytes\n";
    }
    cur_info = cur_info->GetNextInfo();
  }
  if (free_end_) {
    os << "Free block at address: " << reinterpret_cast<const void*>(free_end_start)
       << " of length " << free_end_ << " bytes\n";
  }
}

void LargeObjectSpace::SweepCallback(size_t num_ptrs, mirror::Object** ptrs, void* arg) {
  SweepCallbackContext* context = static_cast<SweepCallbackContext*>(arg);
  space::LargeObjectSpace* space = context->space->AsLargeObjectSpace();
  Thread* self = context->self;
  Locks::heap_bitmap_lock_->AssertExclusiveHeld(self);
  // If the bitmaps aren't swapped we need to clear the bits since the GC isn't going to re-swap
  // the bitmaps as an optimization.
  if (!context->swap_bitmaps) {
    accounting::LargeObjectBitmap* bitmap = space->GetLiveBitmap();
    for (size_t i = 0; i < num_ptrs; ++i) {
      bitmap->Clear(ptrs[i]);
    }
  }
  context->freed.objects += num_ptrs;
  context->freed.bytes += space->FreeList(self, num_ptrs, ptrs);
}

collector::ObjectBytePair LargeObjectSpace::Sweep(bool swap_bitmaps) {
  if (Begin() >= End()) {
    return collector::ObjectBytePair(0, 0);
  }
  accounting::LargeObjectBitmap* live_bitmap = GetLiveBitmap();
  accounting::LargeObjectBitmap* mark_bitmap = GetMarkBitmap();
  if (swap_bitmaps) {
    std::swap(live_bitmap, mark_bitmap);
  }
  AllocSpace::SweepCallbackContext scc(swap_bitmaps, this);
  accounting::LargeObjectBitmap::SweepWalk(*live_bitmap, *mark_bitmap,
                                           reinterpret_cast<uintptr_t>(Begin()),
                                           reinterpret_cast<uintptr_t>(End()), SweepCallback, &scc);
  return scc.freed;
}

void LargeObjectSpace::LogFragmentationAllocFailure(std::ostream& /*os*/,
                                                    size_t /*failed_alloc_bytes*/) {
  UNIMPLEMENTED(FATAL);
}

}  // namespace space
}  // namespace gc
}  // namespace art
