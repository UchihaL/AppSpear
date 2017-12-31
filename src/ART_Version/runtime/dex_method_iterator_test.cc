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

#include "dex_method_iterator.h"

#include "base/stl_util.h"
#include "common_runtime_test.h"
#include "scoped_thread_state_change.h"
#include "thread-inl.h"

namespace art {

class DexMethodIteratorTest : public CommonRuntimeTest {
};

TEST_F(DexMethodIteratorTest, Basic) {
  ScopedObjectAccess soa(Thread::Current());
  std::vector<const DexFile*> dex_files;
  const char* jars[] = { "core-libart", "conscrypt", "okhttp", "core-junit", "bouncycastle" };
  for (size_t i = 0; i < 5; ++i) {
    dex_files.push_back(LoadExpectSingleDexFile(GetDexFileName(jars[i]).c_str()));
  }
  DexMethodIterator it(dex_files);
  while (it.HasNext()) {
    const DexFile& dex_file = it.GetDexFile();
    InvokeType invoke_type = it.GetInvokeType();
    uint32_t method_idx = it.GetMemberIndex();
    if (false) {
      LG << invoke_type << " " << PrettyMethod(method_idx, dex_file);
    }
    it.Next();
  }
  STLDeleteElements(&dex_files);
}

}  // namespace art
