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

#include "barrier.h"

#include "base/mutex.h"
#include "thread.h"

namespace art {

Barrier::Barrier(int count)
    : count_(count),
      lock_("GC barrier lock"),
      condition_("GC barrier condition", lock_) {
}

void Barrier::Pass(Thread* self) {
  MutexLock mu(self, lock_);
  SetCountLocked(self, count_ - 1);
}

void Barrier::Wait(Thread* self) {
  Increment(self, -1);
}

void Barrier::Init(Thread* self, int count) {
  MutexLock mu(self, lock_);
  SetCountLocked(self, count);
}

void Barrier::Increment(Thread* self, int delta) {
  MutexLock mu(self, lock_);
  SetCountLocked(self, count_ + delta);

  // Increment the count.  If it becomes zero after the increment
  // then all the threads have already passed the barrier.  If
  // it is non-zero then there is still one or more threads
  // that have not yet called the Pass function.  When the
  // Pass function is called by the last thread, the count will
  // be decremented to zero and a Broadcast will be made on the
  // condition variable, thus waking this up.
  if (count_ != 0) {
    condition_.Wait(self);
  }
}

void Barrier::Increment(Thread* self, int delta, uint32_t timeout_ms) {
  MutexLock mu(self, lock_);
  SetCountLocked(self, count_ + delta);
  if (count_ != 0) {
    condition_.TimedWait(self, timeout_ms, 0);
  }
}

void Barrier::SetCountLocked(Thread* self, int count) {
  count_ = count;
  if (count_ == 0) {
    condition_.Broadcast(self);
  }
}

Barrier::~Barrier() {
  CHECK(!count_) << "Attempted to destroy barrier with non zero count";
}

}  // namespace art
