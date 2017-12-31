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

#ifndef ART_COMPILER_UTILS_ARENA_CONTAINERS_H_
#define ART_COMPILER_UTILS_ARENA_CONTAINERS_H_

#include <deque>
#include <queue>
#include <set>
#include <vector>

#include "utils/arena_allocator.h"
#include "safe_map.h"

namespace art {

// Adapter for use of ArenaAllocator in STL containers.
// Use ArenaAllocator::Adapter() to create an adapter to pass to container constructors.
// For example,
//   struct Foo {
//     explicit Foo(ArenaAllocator* allocator)
//         : foo_vector(allocator->Adapter(kArenaAllocMisc)),
//           foo_map(std::less<int>(), allocator->Adapter()) {
//     }
//     ArenaVector<int> foo_vector;
//     ArenaSafeMap<int, int> foo_map;
//   };
template <typename T>
class ArenaAllocatorAdapter;

template <typename T>
using ArenaDeque = std::deque<T, ArenaAllocatorAdapter<T>>;

template <typename T>
using ArenaQueue = std::queue<T, ArenaDeque<T>>;

template <typename T>
using ArenaVector = std::vector<T, ArenaAllocatorAdapter<T>>;

template <typename T, typename Comparator = std::less<T>>
using ArenaSet = std::set<T, Comparator, ArenaAllocatorAdapter<T>>;

template <typename K, typename V, typename Comparator = std::less<K>>
using ArenaSafeMap =
    SafeMap<K, V, Comparator, ArenaAllocatorAdapter<std::pair<const K, V>>>;

// Implementation details below.

template <bool kCount>
class ArenaAllocatorAdapterKindImpl;

template <>
class ArenaAllocatorAdapterKindImpl<false> {
 public:
  // Not tracking allocations, ignore the supplied kind and arbitrarily provide kArenaAllocSTL.
  explicit ArenaAllocatorAdapterKindImpl(ArenaAllocKind kind) { }
  ArenaAllocatorAdapterKindImpl& operator=(const ArenaAllocatorAdapterKindImpl& other) = default;
  ArenaAllocKind Kind() { return kArenaAllocSTL; }
};

template <bool kCount>
class ArenaAllocatorAdapterKindImpl {
 public:
  explicit ArenaAllocatorAdapterKindImpl(ArenaAllocKind kind) : kind_(kind) { }
  ArenaAllocatorAdapterKindImpl& operator=(const ArenaAllocatorAdapterKindImpl& other) = default;
  ArenaAllocKind Kind() { return kind_; }

 private:
  ArenaAllocKind kind_;
};

typedef ArenaAllocatorAdapterKindImpl<kArenaAllocatorCountAllocations> ArenaAllocatorAdapterKind;

template <>
class ArenaAllocatorAdapter<void>
    : private DebugStackReference, private ArenaAllocatorAdapterKind {
 public:
  typedef void value_type;
  typedef void* pointer;
  typedef const void* const_pointer;

  template <typename U>
  struct rebind {
    typedef ArenaAllocatorAdapter<U> other;
  };

  explicit ArenaAllocatorAdapter(ArenaAllocator* arena_allocator,
                                 ArenaAllocKind kind = kArenaAllocSTL)
      : DebugStackReference(arena_allocator),
        ArenaAllocatorAdapterKind(kind),
        arena_allocator_(arena_allocator) {
  }
  template <typename U>
  ArenaAllocatorAdapter(const ArenaAllocatorAdapter<U>& other)
      : DebugStackReference(other),
        ArenaAllocatorAdapterKind(other),
        arena_allocator_(other.arena_allocator_) {
  }
  ArenaAllocatorAdapter(const ArenaAllocatorAdapter& other) = default;
  ArenaAllocatorAdapter& operator=(const ArenaAllocatorAdapter& other) = default;
  ~ArenaAllocatorAdapter() = default;

 private:
  ArenaAllocator* arena_allocator_;

  template <typename U>
  friend class ArenaAllocatorAdapter;
};

template <typename T>
class ArenaAllocatorAdapter : private DebugStackReference, private ArenaAllocatorAdapterKind {
 public:
  typedef T value_type;
  typedef T* pointer;
  typedef T& reference;
  typedef const T* const_pointer;
  typedef const T& const_reference;
  typedef size_t size_type;
  typedef ptrdiff_t difference_type;

  template <typename U>
  struct rebind {
    typedef ArenaAllocatorAdapter<U> other;
  };

  explicit ArenaAllocatorAdapter(ArenaAllocator* arena_allocator, ArenaAllocKind kind)
      : DebugStackReference(arena_allocator),
        ArenaAllocatorAdapterKind(kind),
        arena_allocator_(arena_allocator) {
  }
  template <typename U>
  ArenaAllocatorAdapter(const ArenaAllocatorAdapter<U>& other)
      : DebugStackReference(other),
        ArenaAllocatorAdapterKind(other),
        arena_allocator_(other.arena_allocator_) {
  }
  ArenaAllocatorAdapter(const ArenaAllocatorAdapter& other) = default;
  ArenaAllocatorAdapter& operator=(const ArenaAllocatorAdapter& other) = default;
  ~ArenaAllocatorAdapter() = default;

  size_type max_size() const {
    return static_cast<size_type>(-1) / sizeof(T);
  }

  pointer address(reference x) const { return &x; }
  const_pointer address(const_reference x) const { return &x; }

  pointer allocate(size_type n, ArenaAllocatorAdapter<void>::pointer hint = nullptr) {
    DCHECK_LE(n, max_size());
    return reinterpret_cast<T*>(arena_allocator_->Alloc(n * sizeof(T),
                                                        ArenaAllocatorAdapterKind::Kind()));
  }
  void deallocate(pointer p, size_type n) {
  }

  void construct(pointer p, const_reference val) {
    new (static_cast<void*>(p)) value_type(val);
  }
  void destroy(pointer p) {
    p->~value_type();
  }

 private:
  ArenaAllocator* arena_allocator_;

  template <typename U>
  friend class ArenaAllocatorAdapter;

  template <typename U>
  friend bool operator==(const ArenaAllocatorAdapter<U>& lhs,
                         const ArenaAllocatorAdapter<U>& rhs);
};

template <typename T>
inline bool operator==(const ArenaAllocatorAdapter<T>& lhs,
                       const ArenaAllocatorAdapter<T>& rhs) {
  return lhs.arena_allocator_ == rhs.arena_allocator_;
}

template <typename T>
inline bool operator!=(const ArenaAllocatorAdapter<T>& lhs,
                       const ArenaAllocatorAdapter<T>& rhs) {
  return !(lhs == rhs);
}

inline ArenaAllocatorAdapter<void> ArenaAllocator::Adapter(ArenaAllocKind kind) {
  return ArenaAllocatorAdapter<void>(this, kind);
}

}  // namespace art

#endif  // ART_COMPILER_UTILS_ARENA_CONTAINERS_H_
