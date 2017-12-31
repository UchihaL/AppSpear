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

#ifndef ART_RUNTIME_INVOKE_TYPE_H_
#define ART_RUNTIME_INVOKE_TYPE_H_

#include <iosfwd>

namespace art {

enum InvokeType {
  kStatic,     // <<static>>
  kDirect,     // <<direct>>
  kVirtual,    // <<virtual>>
  kSuper,      // <<super>>
  kInterface,  // <<interface>>
  kMaxInvokeType = kInterface
};

std::ostream& operator<<(std::ostream& os, const InvokeType& rhs);

}  // namespace art

#endif  // ART_RUNTIME_INVOKE_TYPE_H_
