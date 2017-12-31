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
#include "reflection.h"
#include "scoped_fast_native_object_access.h"
#include "well_known_classes.h"

namespace art {

/*
 * We get here through Constructor.newInstance().  The Constructor object
 * would not be available if the constructor weren't public (per the
 * definition of Class.getConstructor), so we can skip the method access
 * check.  We can also safely assume the constructor isn't associated
 * with an interface, array, or primitive class.
 */
static jobject Constructor_newInstance(JNIEnv* env, jobject javaMethod, jobjectArray javaArgs,
                                       jboolean accessible) {
  ScopedFastNativeObjectAccess soa(env);
  mirror::ArtMethod* m = mirror::ArtMethod::FromReflectedMethod(soa, javaMethod);
  StackHandleScope<1> hs(soa.Self());
  Handle<mirror::Class> c(hs.NewHandle(m->GetDeclaringClass()));
  if (UNLIKELY(c->IsAbstract())) {
    ThrowLocation throw_location = soa.Self()->GetCurrentLocationForThrow();
    soa.Self()->ThrowNewExceptionF(throw_location, "Ljava/lang/InstantiationException;",
                                   "Can't instantiate %s %s",
                                   c->IsInterface() ? "interface" : "abstract class",
                                   PrettyDescriptor(c.Get()).c_str());
    return nullptr;
  }

  if (!Runtime::Current()->GetClassLinker()->EnsureInitialized(c, true, true)) {
    DCHECK(soa.Self()->IsExceptionPending());
    return nullptr;
  }

  bool movable = true;
  if (!kMovingMethods && c->IsArtMethodClass()) {
    movable = false;
  } else if (!kMovingFields && c->IsArtFieldClass()) {
    movable = false;
  } else if (!kMovingClasses && c->IsClassClass()) {
    movable = false;
  }
  mirror::Object* receiver =
      movable ? c->AllocObject(soa.Self()) : c->AllocNonMovableObject(soa.Self());
  if (receiver == nullptr) {
    return nullptr;
  }

  jobject javaReceiver = soa.AddLocalReference<jobject>(receiver);
  InvokeMethod(soa, javaMethod, javaReceiver, javaArgs, (accessible == JNI_TRUE));

  // Constructors are ()V methods, so we shouldn't touch the result of InvokeMethod.
  return javaReceiver;
}

static JNINativeMethod gMethods[] = {
  NATIVE_METHOD(Constructor, newInstance, "!([Ljava/lang/Object;Z)Ljava/lang/Object;"),
};

void register_java_lang_reflect_Constructor(JNIEnv* env) {
  REGISTER_NATIVE_METHODS("java/lang/reflect/Constructor");
}

}  // namespace art
