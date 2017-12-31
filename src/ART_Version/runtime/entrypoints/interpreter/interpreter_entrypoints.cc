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

#include "class_linker.h"
#include "interpreter/interpreter.h"
#include "mirror/art_method-inl.h"
#include "mirror/object-inl.h"
#include "reflection.h"
#include "runtime.h"
#include "stack.h"

 //LBD
//#include "twodroid/Probe.h"

namespace art {

// TODO: Make the MethodHelper here be compaction safe.
extern "C" void artInterpreterToCompiledCodeBridge(Thread* self, MethodHelper& mh,
                                                   const DexFile::CodeItem* code_item,
                                                   ShadowFrame* shadow_frame, JValue* result) {
  mirror::ArtMethod* method = shadow_frame->GetMethod();


  /*if(gossip::diaos_check()){
      char flag[256] = {0};
      uint32_t shorty_len = 0;
      snprintf ( flag, 256, "%s%s%s", method->GetDeclaringClassDescriptor(), method->GetName(), method->GetShorty(&shorty_len) );


      method->SetEntryPointFromInterpreter(artInterpreterToCompiledCodeBridge);
      method->SetEntryPointFromQuickCompiledCode(gossip::getEP(flag));
  }*/

  //LBD
  //gossip::diaos_monitor_func_call(method->GetDeclaringClassDescriptor(),method->GetName(),method->GetReturnTypeDescriptor(),method->GetDeclaringClassDescriptor());
  //gossip::u4* diaos_args = (gossip::u4*)shadow_frame->GetVRegArgs(method->IsStatic() ? 0 : 1);
  //gossip::diaos_monitor_parameter(diaos_args, method);


  // Ensure static methods are initialized.
  if (method->IsStatic()) {
    mirror::Class* declaringClass = method->GetDeclaringClass();
    if (UNLIKELY(!declaringClass->IsInitialized())) {
      self->PushShadowFrame(shadow_frame);
      StackHandleScope<1> hs(self);
      Handle<mirror::Class> h_class(hs.NewHandle(declaringClass));
      if (UNLIKELY(!Runtime::Current()->GetClassLinker()->EnsureInitialized(h_class, true, true))) {
        self->PopShadowFrame();
        DCHECK(self->IsExceptionPending());
        return;
      }
      self->PopShadowFrame();
      CHECK(h_class->IsInitializing());
      // Reload from shadow frame in case the method moved, this is faster than adding a handle.
      method = shadow_frame->GetMethod();
    }
  }
  uint16_t arg_offset = (code_item == NULL) ? 0 : code_item->registers_size_ - code_item->ins_size_;
  if (kUsePortableCompiler) {
    InvokeWithShadowFrame(self, shadow_frame, arg_offset, mh, result);
  } else {
    method->Invoke(self, shadow_frame->GetVRegArgs(arg_offset),
                   (shadow_frame->NumberOfVRegs() - arg_offset) * sizeof(uint32_t),
                   result, mh.GetShorty());
  }
}

}  // namespace art
