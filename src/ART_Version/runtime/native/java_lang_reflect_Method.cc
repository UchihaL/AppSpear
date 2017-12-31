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

#include "class_linker.h"
#include "jni_internal.h"
#include "mirror/art_method.h"
#include "mirror/art_method-inl.h"
#include "mirror/class-inl.h"
#include "mirror/object-inl.h"
#include "mirror/object_array-inl.h"
#include "reflection.h"
#include "scoped_fast_native_object_access.h"
#include "well_known_classes.h"

namespace art {

static jobject Method_invoke(JNIEnv* env, jobject javaMethod, jobject javaReceiver,
                             jobject javaArgs, jboolean accessible) {
  ScopedFastNativeObjectAccess soa(env);
  return InvokeMethod(soa, javaMethod, javaReceiver, javaArgs, (accessible == JNI_TRUE));
}

static jobject Method_getExceptionTypesNative(JNIEnv* env, jobject javaMethod) {
  ScopedFastNativeObjectAccess soa(env);
  mirror::ArtMethod* proxy_method = mirror::ArtMethod::FromReflectedMethod(soa, javaMethod);
  CHECK(proxy_method->GetDeclaringClass()->IsProxyClass());
  mirror::Class* proxy_class = proxy_method->GetDeclaringClass();
  int throws_index = -1;
  size_t num_virt_methods = proxy_class->NumVirtualMethods();
  for (size_t i = 0; i < num_virt_methods; i++) {
    if (proxy_class->GetVirtualMethod(i) == proxy_method) {
      throws_index = i;
      break;
    }
  }
  CHECK_NE(throws_index, -1);
  mirror::ObjectArray<mirror::Class>* declared_exceptions =
          proxy_class->GetThrows()->Get(throws_index);
  return soa.AddLocalReference<jobject>(declared_exceptions->Clone(soa.Self()));
}

static JNINativeMethod gMethods[] = {
  NATIVE_METHOD(Method, invoke, "!(Ljava/lang/Object;[Ljava/lang/Object;Z)Ljava/lang/Object;"),
  NATIVE_METHOD(Method, getExceptionTypesNative, "!()[Ljava/lang/Class;"),
};

void register_java_lang_reflect_Method(JNIEnv* env) {
  REGISTER_NATIVE_METHODS("java/lang/reflect/Method");
}

}  // namespace art
