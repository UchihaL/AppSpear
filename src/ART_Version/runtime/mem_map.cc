/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "mem_map.h"
#include "thread-inl.h"

#include <inttypes.h>
#include <backtrace/BacktraceMap.h>
#include <memory>

// See CreateStartPos below.
#ifdef __BIONIC__
#include <sys/auxv.h>
#endif

#include "base/stringprintf.h"
#include "ScopedFd.h"
#include "utils.h"

#define USE_ASHMEM 1

#ifdef USE_ASHMEM
#include <cutils/ashmem.h>
#ifndef ANDROID_OS
#include <sys/resource.h>
#endif
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

namespace art {

static std::ostream& operator<<(
    std::ostream& os,
    std::pair<BacktraceMap::const_iterator, BacktraceMap::const_iterator> iters) {
  for (BacktraceMap::const_iterator it = iters.first; it != iters.second; ++it) {
    os << StringPrintf("0x%08x-0x%08x %c%c%c %s\n",
                       static_cast<uint32_t>(it->start),
                       static_cast<uint32_t>(it->end),
                       (it->flags & PROT_READ) ? 'r' : '-',
                       (it->flags & PROT_WRITE) ? 'w' : '-',
                       (it->flags & PROT_EXEC) ? 'x' : '-', it->name.c_str());
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, const MemMap::Maps& mem_maps) {
  os << "MemMap:" << std::endl;
  for (auto it = mem_maps.begin(); it != mem_maps.end(); ++it) {
    void* base = it->first;
    MemMap* map = it->second;
    CHECK_EQ(base, map->BaseBegin());
    os << *map << std::endl;
  }
  return os;
}

MemMap::Maps* MemMap::maps_ = nullptr;

#if USE_ART_LOW_4G_ALLOCATOR
// Handling mem_map in 32b address range for 64b architectures that do not support MAP_32BIT.

// The regular start of memory allocations. The first 64KB is protected by SELinux.
static constexpr uintptr_t LOW_MEM_START = 64 * KB;

// Generate random starting position.
// To not interfere with image position, take the image's address and only place it below. Current
// formula (sketch):
//
// ART_BASE_ADDR      = 0001XXXXXXXXXXXXXXX
// ----------------------------------------
//                    = 0000111111111111111
// & ~(kPageSize - 1) =~0000000000000001111
// ----------------------------------------
// mask               = 0000111111111110000
// & random data      = YYYYYYYYYYYYYYYYYYY
// -----------------------------------
// tmp                = 0000YYYYYYYYYYY0000
// + LOW_MEM_START    = 0000000000001000000
// --------------------------------------
// start
//
// getauxval as an entropy source is exposed in Bionic, but not in glibc before 2.16. When we
// do not have Bionic, simply start with LOW_MEM_START.

// Function is standalone so it can be tested somewhat in mem_map_test.cc.
#ifdef __BIONIC__
uintptr_t CreateStartPos(uint64_t input) {
  CHECK_NE(0, ART_BASE_ADDRESS);

  // Start with all bits below highest bit in ART_BASE_ADDRESS.
  constexpr size_t leading_zeros = CLZ(static_cast<uint32_t>(ART_BASE_ADDRESS));
  constexpr uintptr_t mask_ones = (1 << (31 - leading_zeros)) - 1;

  // Lowest (usually 12) bits are not used, as aligned by page size.
  constexpr uintptr_t mask = mask_ones & ~(kPageSize - 1);

  // Mask input data.
  return (input & mask) + LOW_MEM_START;
}
#endif

static uintptr_t GenerateNextMemPos() {
#ifdef __BIONIC__
  uint8_t* random_data = reinterpret_cast<uint8_t*>(getauxval(AT_RANDOM));
  // The lower 8B are taken for the stack guard. Use the upper 8B (with mask).
  return CreateStartPos(*reinterpret_cast<uintptr_t*>(random_data + 8));
#else
  // No auxv on host, see above.
  return LOW_MEM_START;
#endif
}

// Initialize linear scan to random position.
uintptr_t MemMap::next_mem_pos_ = GenerateNextMemPos();
#endif

#if !defined(__APPLE__)  // TODO: Reanable after b/16861075 BacktraceMap issue is addressed.
// Return true if the address range is contained in a single /proc/self/map entry.
static bool ContainedWithinExistingMap(uintptr_t begin,
                                       uintptr_t end,
                                       std::string* error_msg) {
  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(getpid(), true));
  if (map.get() == nullptr) {
    *error_msg = StringPrintf("Failed to build process map");
    return false;
  }
  for (BacktraceMap::const_iterator it = map->begin(); it != map->end(); ++it) {
    if ((begin >= it->start && begin < it->end)  // start of new within old
        && (end > it->start && end <= it->end)) {  // end of new within old
      return true;
    }
  }
  std::string maps;
  ReadFileToString("/proc/self/maps", &maps);
  *error_msg = StringPrintf("Requested region 0x%08" PRIxPTR "-0x%08" PRIxPTR " does not overlap "
                            "any existing map:\n%s\n",
                            begin, end, maps.c_str());
  return false;
}
#endif

// Return true if the address range does not conflict with any /proc/self/maps entry.
static bool CheckNonOverlapping(uintptr_t begin,
                                uintptr_t end,
                                std::string* error_msg) {
  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(getpid(), true));
  if (map.get() == nullptr) {
    *error_msg = StringPrintf("Failed to build process map");
    return false;
  }
  for (BacktraceMap::const_iterator it = map->begin(); it != map->end(); ++it) {
    if ((begin >= it->start && begin < it->end)      // start of new within old
        || (end > it->start && end < it->end)        // end of new within old
        || (begin <= it->start && end > it->end)) {  // start/end of new includes all of old
      std::ostringstream map_info;
      map_info << std::make_pair(it, map->end());
      *error_msg = StringPrintf("Requested region 0x%08" PRIxPTR "-0x%08" PRIxPTR " overlaps with "
                                "existing map 0x%08" PRIxPTR "-0x%08" PRIxPTR " (%s)\n%s",
                                begin, end,
                                static_cast<uintptr_t>(it->start), static_cast<uintptr_t>(it->end),
                                it->name.c_str(),
                                map_info.str().c_str());
      return false;
    }
  }
  return true;
}

// CheckMapRequest to validate a non-MAP_FAILED mmap result based on
// the expected value, calling munmap if validation fails, giving the
// reason in error_msg.
//
// If the expected_ptr is nullptr, nothing is checked beyond the fact
// that the actual_ptr is not MAP_FAILED. However, if expected_ptr is
// non-null, we check that pointer is the actual_ptr == expected_ptr,
// and if not, report in error_msg what the conflict mapping was if
// found, or a generic error in other cases.
static bool CheckMapRequest(byte* expected_ptr, void* actual_ptr, size_t byte_count,
                            std::string* error_msg) {
  // Handled first by caller for more specific error messages.
  CHECK(actual_ptr != MAP_FAILED);

  if (expected_ptr == nullptr) {
    return true;
  }

  uintptr_t actual = reinterpret_cast<uintptr_t>(actual_ptr);
  uintptr_t expected = reinterpret_cast<uintptr_t>(expected_ptr);
  uintptr_t limit = expected + byte_count;

  if (expected_ptr == actual_ptr) {
    return true;
  }

  // We asked for an address but didn't get what we wanted, all paths below here should fail.
  int result = munmap(actual_ptr, byte_count);
  if (result == -1) {
    PLOG(WARNING) << StringPrintf("munmap(%p, %zd) failed", actual_ptr, byte_count);
  }

  // We call this here so that we can try and generate a full error
  // message with the overlapping mapping. There's no guarantee that
  // that there will be an overlap though, since
  // - The kernel is not *required* to honour expected_ptr unless MAP_FIXED is
  //   true, even if there is no overlap
  // - There might have been an overlap at the point of mmap, but the
  //   overlapping region has since been unmapped.
  std::string error_detail;
  CheckNonOverlapping(expected, limit, &error_detail);

  std::ostringstream os;
  os <<  StringPrintf("Failed to mmap at expected address, mapped at "
                      "0x%08" PRIxPTR " instead of 0x%08" PRIxPTR,
                      actual, expected);
  if (!error_detail.empty()) {
    os << " : " << error_detail;
  }

  *error_msg = os.str();
  return false;
}

MemMap* MemMap::MapAnonymous(const char* name, byte* expected_ptr, size_t byte_count, int prot,
                             bool low_4gb, std::string* error_msg) {
  if (byte_count == 0) {
    return new MemMap(name, nullptr, 0, nullptr, 0, prot, false);
  }
  size_t page_aligned_byte_count = RoundUp(byte_count, kPageSize);

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  ScopedFd fd(-1);

#ifdef USE_ASHMEM
#ifdef HAVE_ANDROID_OS
  const bool use_ashmem = true;
#else
  // When not on Android ashmem is faked using files in /tmp. Ensure that such files won't
  // fail due to ulimit restrictions. If they will then use a regular mmap.
  struct rlimit rlimit_fsize;
  CHECK_EQ(getrlimit(RLIMIT_FSIZE, &rlimit_fsize), 0);
  const bool use_ashmem = (rlimit_fsize.rlim_cur == RLIM_INFINITY) ||
      (page_aligned_byte_count < rlimit_fsize.rlim_cur);
#endif
  if (use_ashmem) {
    // android_os_Debug.cpp read_mapinfo assumes all ashmem regions associated with the VM are
    // prefixed "dalvik-".
    std::string debug_friendly_name("dalvik-");
    debug_friendly_name += name;
    fd.reset(ashmem_create_region(debug_friendly_name.c_str(), page_aligned_byte_count));
    if (fd.get() == -1) {
      *error_msg = StringPrintf("ashmem_create_region failed for '%s': %s", name, strerror(errno));
      return nullptr;
    }
    flags = MAP_PRIVATE;
  }
#endif

  // We need to store and potentially set an error number for pretty printing of errors
  int saved_errno = 0;

#ifdef __LP64__
  // When requesting low_4g memory and having an expectation, the requested range should fit into
  // 4GB.
  if (low_4gb && (
      // Start out of bounds.
      (reinterpret_cast<uintptr_t>(expected_ptr) >> 32) != 0 ||
      // End out of bounds. For simplicity, this will fail for the last page of memory.
      (reinterpret_cast<uintptr_t>(expected_ptr + page_aligned_byte_count) >> 32) != 0)) {
    *error_msg = StringPrintf("The requested address space (%p, %p) cannot fit in low_4gb",
                              expected_ptr, expected_ptr + page_aligned_byte_count);
    return nullptr;
  }
#endif

  // TODO:
  // A page allocator would be a useful abstraction here, as
  // 1) It is doubtful that MAP_32BIT on x86_64 is doing the right job for us
  // 2) The linear scheme, even with simple saving of the last known position, is very crude
#if USE_ART_LOW_4G_ALLOCATOR
  // MAP_32BIT only available on x86_64.
  void* actual = MAP_FAILED;
  if (low_4gb && expected_ptr == nullptr) {
    bool first_run = true;

    for (uintptr_t ptr = next_mem_pos_; ptr < 4 * GB; ptr += kPageSize) {
      if (4U * GB - ptr < page_aligned_byte_count) {
        // Not enough memory until 4GB.
        if (first_run) {
          // Try another time from the bottom;
          ptr = LOW_MEM_START - kPageSize;
          first_run = false;
          continue;
        } else {
          // Second try failed.
          break;
        }
      }

      uintptr_t tail_ptr;

      // Check pages are free.
      bool safe = true;
      for (tail_ptr = ptr; tail_ptr < ptr + page_aligned_byte_count; tail_ptr += kPageSize) {
        if (msync(reinterpret_cast<void*>(tail_ptr), kPageSize, 0) == 0) {
          safe = false;
          break;
        } else {
          DCHECK_EQ(errno, ENOMEM);
        }
      }

      next_mem_pos_ = tail_ptr;  // update early, as we break out when we found and mapped a region

      if (safe == true) {
        actual = mmap(reinterpret_cast<void*>(ptr), page_aligned_byte_count, prot, flags, fd.get(),
                      0);
        if (actual != MAP_FAILED) {
          // Since we didn't use MAP_FIXED the kernel may have mapped it somewhere not in the low
          // 4GB. If this is the case, unmap and retry.
          if (reinterpret_cast<uintptr_t>(actual) + page_aligned_byte_count < 4 * GB) {
            break;
          } else {
            munmap(actual, page_aligned_byte_count);
            actual = MAP_FAILED;
          }
        }
      } else {
        // Skip over last page.
        ptr = tail_ptr;
      }
    }

    if (actual == MAP_FAILED) {
      LOG(ERROR) << "Could not find contiguous low-memory space.";
      saved_errno = ENOMEM;
    }
  } else {
    actual = mmap(expected_ptr, page_aligned_byte_count, prot, flags, fd.get(), 0);
    saved_errno = errno;
  }

#else
#if defined(__LP64__)
  if (low_4gb && expected_ptr == nullptr) {
    flags |= MAP_32BIT;
  }
#endif

  void* actual = mmap(expected_ptr, page_aligned_byte_count, prot, flags, fd.get(), 0);
  saved_errno = errno;
#endif

  if (actual == MAP_FAILED) {
    std::string maps;
    ReadFileToString("/proc/self/maps", &maps);

    *error_msg = StringPrintf("Failed anonymous mmap(%p, %zd, 0x%x, 0x%x, %d, 0): %s\n%s",
                              expected_ptr, page_aligned_byte_count, prot, flags, fd.get(),
                              strerror(saved_errno), maps.c_str());
    return nullptr;
  }
  std::ostringstream check_map_request_error_msg;
  if (!CheckMapRequest(expected_ptr, actual, page_aligned_byte_count, error_msg)) {
    return nullptr;
  }
  return new MemMap(name, reinterpret_cast<byte*>(actual), byte_count, actual,
                    page_aligned_byte_count, prot, false);
}

MemMap* MemMap::MapFileAtAddress(byte* expected_ptr, size_t byte_count, int prot, int flags, int fd,
                                 off_t start, bool reuse, const char* filename,
                                 std::string* error_msg) {
  CHECK_NE(0, prot);
  CHECK_NE(0, flags & (MAP_SHARED | MAP_PRIVATE));

  // Note that we do not allow MAP_FIXED unless reuse == true, i.e we
  // expect his mapping to be contained within an existing map.
  if (reuse) {
    // reuse means it is okay that it overlaps an existing page mapping.
    // Only use this if you actually made the page reservation yourself.
    CHECK(expected_ptr != nullptr);

#if !defined(__APPLE__)  // TODO: Reanable after b/16861075 BacktraceMap issue is addressed.
    uintptr_t expected = reinterpret_cast<uintptr_t>(expected_ptr);
    uintptr_t limit = expected + byte_count;
    DCHECK(ContainedWithinExistingMap(expected, limit, error_msg));
#endif
    flags |= MAP_FIXED;
  } else {
    CHECK_EQ(0, flags & MAP_FIXED);
    // Don't bother checking for an overlapping region here. We'll
    // check this if required after the fact inside CheckMapRequest.
  }

  if (byte_count == 0) {
    return new MemMap(filename, nullptr, 0, nullptr, 0, prot, false);
  }
  // Adjust 'offset' to be page-aligned as required by mmap.
  int page_offset = start % kPageSize;
  off_t page_aligned_offset = start - page_offset;
  // Adjust 'byte_count' to be page-aligned as we will map this anyway.
  size_t page_aligned_byte_count = RoundUp(byte_count + page_offset, kPageSize);
  // The 'expected_ptr' is modified (if specified, ie non-null) to be page aligned to the file but
  // not necessarily to virtual memory. mmap will page align 'expected' for us.
  byte* page_aligned_expected = (expected_ptr == nullptr) ? nullptr : (expected_ptr - page_offset);

  byte* actual = reinterpret_cast<byte*>(mmap(page_aligned_expected,
                                              page_aligned_byte_count,
                                              prot,
                                              flags,
                                              fd,
                                              page_aligned_offset));
  if (actual == MAP_FAILED) {
    auto saved_errno = errno;

    std::string maps;
    ReadFileToString("/proc/self/maps", &maps);

    *error_msg = StringPrintf("mmap(%p, %zd, 0x%x, 0x%x, %d, %" PRId64
                              ") of file '%s' failed: %s\n%s",
                              page_aligned_expected, page_aligned_byte_count, prot, flags, fd,
                              static_cast<int64_t>(page_aligned_offset), filename,
                              strerror(saved_errno), maps.c_str());
    return nullptr;
  }
  std::ostringstream check_map_request_error_msg;
  if (!CheckMapRequest(expected_ptr, actual, page_aligned_byte_count, error_msg)) {
    return nullptr;
  }
  return new MemMap(filename, actual + page_offset, byte_count, actual, page_aligned_byte_count,
                    prot, reuse);
}

MemMap::~MemMap() {
  if (base_begin_ == nullptr && base_size_ == 0) {
    return;
  }
  if (!reuse_) {
    int result = munmap(base_begin_, base_size_);
    if (result == -1) {
      PLOG(FATAL) << "munmap failed";
    }
  }

  // Remove it from maps_.
  MutexLock mu(Thread::Current(), *Locks::mem_maps_lock_);
  bool found = false;
  DCHECK(maps_ != nullptr);
  for (auto it = maps_->lower_bound(base_begin_), end = maps_->end();
       it != end && it->first == base_begin_; ++it) {
    if (it->second == this) {
      found = true;
      maps_->erase(it);
      break;
    }
  }
  CHECK(found) << "MemMap not found";
}

MemMap::MemMap(const std::string& name, byte* begin, size_t size, void* base_begin,
               size_t base_size, int prot, bool reuse)
    : name_(name), begin_(begin), size_(size), base_begin_(base_begin), base_size_(base_size),
      prot_(prot), reuse_(reuse) {
  if (size_ == 0) {
    CHECK(begin_ == nullptr);
    CHECK(base_begin_ == nullptr);
    CHECK_EQ(base_size_, 0U);
  } else {
    CHECK(begin_ != nullptr);
    CHECK(base_begin_ != nullptr);
    CHECK_NE(base_size_, 0U);

    // Add it to maps_.
    MutexLock mu(Thread::Current(), *Locks::mem_maps_lock_);
    DCHECK(maps_ != nullptr);
    maps_->insert(std::make_pair(base_begin_, this));
  }
};

MemMap* MemMap::RemapAtEnd(byte* new_end, const char* tail_name, int tail_prot,
                           std::string* error_msg) {
  DCHECK_GE(new_end, Begin());
  DCHECK_LE(new_end, End());
  DCHECK_LE(begin_ + size_, reinterpret_cast<byte*>(base_begin_) + base_size_);
  DCHECK(IsAligned<kPageSize>(begin_));
  DCHECK(IsAligned<kPageSize>(base_begin_));
  DCHECK(IsAligned<kPageSize>(reinterpret_cast<byte*>(base_begin_) + base_size_));
  DCHECK(IsAligned<kPageSize>(new_end));
  byte* old_end = begin_ + size_;
  byte* old_base_end = reinterpret_cast<byte*>(base_begin_) + base_size_;
  byte* new_base_end = new_end;
  DCHECK_LE(new_base_end, old_base_end);
  if (new_base_end == old_base_end) {
    return new MemMap(tail_name, nullptr, 0, nullptr, 0, tail_prot, false);
  }
  size_ = new_end - reinterpret_cast<byte*>(begin_);
  base_size_ = new_base_end - reinterpret_cast<byte*>(base_begin_);
  DCHECK_LE(begin_ + size_, reinterpret_cast<byte*>(base_begin_) + base_size_);
  size_t tail_size = old_end - new_end;
  byte* tail_base_begin = new_base_end;
  size_t tail_base_size = old_base_end - new_base_end;
  DCHECK_EQ(tail_base_begin + tail_base_size, old_base_end);
  DCHECK(IsAligned<kPageSize>(tail_base_size));

#ifdef USE_ASHMEM
  // android_os_Debug.cpp read_mapinfo assumes all ashmem regions associated with the VM are
  // prefixed "dalvik-".
  std::string debug_friendly_name("dalvik-");
  debug_friendly_name += tail_name;
  ScopedFd fd(ashmem_create_region(debug_friendly_name.c_str(), tail_base_size));
  int flags = MAP_PRIVATE | MAP_FIXED;
  if (fd.get() == -1) {
    *error_msg = StringPrintf("ashmem_create_region failed for '%s': %s",
                              tail_name, strerror(errno));
    return nullptr;
  }
#else
  ScopedFd fd(-1);
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#endif

  // Unmap/map the tail region.
  int result = munmap(tail_base_begin, tail_base_size);
  if (result == -1) {
    std::string maps;
    ReadFileToString("/proc/self/maps", &maps);
    *error_msg = StringPrintf("munmap(%p, %zd) failed for '%s'\n%s",
                              tail_base_begin, tail_base_size, name_.c_str(),
                              maps.c_str());
    return nullptr;
  }
  // Don't cause memory allocation between the munmap and the mmap
  // calls. Otherwise, libc (or something else) might take this memory
  // region. Note this isn't perfect as there's no way to prevent
  // other threads to try to take this memory region here.
  byte* actual = reinterpret_cast<byte*>(mmap(tail_base_begin, tail_base_size, tail_prot,
                                              flags, fd.get(), 0));
  if (actual == MAP_FAILED) {
    std::string maps;
    ReadFileToString("/proc/self/maps", &maps);
    *error_msg = StringPrintf("anonymous mmap(%p, %zd, 0x%x, 0x%x, %d, 0) failed\n%s",
                              tail_base_begin, tail_base_size, tail_prot, flags, fd.get(),
                              maps.c_str());
    return nullptr;
  }
  return new MemMap(tail_name, actual, tail_size, actual, tail_base_size, tail_prot, false);
}

void MemMap::MadviseDontNeedAndZero() {
  if (base_begin_ != nullptr || base_size_ != 0) {
    if (!kMadviseZeroes) {
      memset(base_begin_, 0, base_size_);
    }
    int result = madvise(base_begin_, base_size_, MADV_DONTNEED);
    if (result == -1) {
      PLOG(WARNING) << "madvise failed";
    }
  }
}

bool MemMap::Protect(int prot) {
  if (base_begin_ == nullptr && base_size_ == 0) {
    prot_ = prot;
    return true;
  }

  if (mprotect(base_begin_, base_size_, prot) == 0) {
    prot_ = prot;
    return true;
  }

  PLOG(ERROR) << "mprotect(" << reinterpret_cast<void*>(base_begin_) << ", " << base_size_ << ", "
              << prot << ") failed";
  return false;
}

bool MemMap::CheckNoGaps(MemMap* begin_map, MemMap* end_map) {
  MutexLock mu(Thread::Current(), *Locks::mem_maps_lock_);
  CHECK(begin_map != nullptr);
  CHECK(end_map != nullptr);
  CHECK(HasMemMap(begin_map));
  CHECK(HasMemMap(end_map));
  CHECK_LE(begin_map->BaseBegin(), end_map->BaseBegin());
  MemMap* map = begin_map;
  while (map->BaseBegin() != end_map->BaseBegin()) {
    MemMap* next_map = GetLargestMemMapAt(map->BaseEnd());
    if (next_map == nullptr) {
      // Found a gap.
      return false;
    }
    map = next_map;
  }
  return true;
}

void MemMap::DumpMaps(std::ostream& os) {
  MutexLock mu(Thread::Current(), *Locks::mem_maps_lock_);
  DumpMapsLocked(os);
}

void MemMap::DumpMapsLocked(std::ostream& os) {
  os << maps_;
}

bool MemMap::HasMemMap(MemMap* map) {
  void* base_begin = map->BaseBegin();
  for (auto it = maps_->lower_bound(base_begin), end = maps_->end();
       it != end && it->first == base_begin; ++it) {
    if (it->second == map) {
      return true;
    }
  }
  return false;
}

MemMap* MemMap::GetLargestMemMapAt(void* address) {
  size_t largest_size = 0;
  MemMap* largest_map = nullptr;
  DCHECK(maps_ != nullptr);
  for (auto it = maps_->lower_bound(address), end = maps_->end();
       it != end && it->first == address; ++it) {
    MemMap* map = it->second;
    CHECK(map != nullptr);
    if (largest_size < map->BaseSize()) {
      largest_size = map->BaseSize();
      largest_map = map;
    }
  }
  return largest_map;
}

void MemMap::Init() {
  MutexLock mu(Thread::Current(), *Locks::mem_maps_lock_);
  if (maps_ == nullptr) {
    // dex2oat calls MemMap::Init twice since its needed before the runtime is created.
    maps_ = new Maps;
  }
}

void MemMap::Shutdown() {
  MutexLock mu(Thread::Current(), *Locks::mem_maps_lock_);
  delete maps_;
  maps_ = nullptr;
}

std::ostream& operator<<(std::ostream& os, const MemMap& mem_map) {
  os << StringPrintf("[MemMap: %p-%p prot=0x%x %s]",
                     mem_map.BaseBegin(), mem_map.BaseEnd(), mem_map.GetProtect(),
                     mem_map.GetName().c_str());
  return os;
}

}  // namespace art
