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
#include "mirror/class_loader.h"
#include "mirror/object-inl.h"
#include "scoped_fast_native_object_access.h"
#include "ScopedUtfChars.h"
#include "zip_archive.h"

namespace art {

static jclass VMClassLoader_findLoadedClass(JNIEnv* env, jclass, jobject javaLoader, jstring javaName) {
  ScopedFastNativeObjectAccess soa(env);
  mirror::ClassLoader* loader = soa.Decode<mirror::ClassLoader*>(javaLoader);
  ScopedUtfChars name(env, javaName);
  if (name.c_str() == NULL) {
    return NULL;
  }
  ClassLinker* cl = Runtime::Current()->GetClassLinker();
  std::string descriptor(DotToDescriptor(name.c_str()));
  mirror::Class* c = cl->LookupClass(descriptor.c_str(), loader);
  if (c != NULL && c->IsResolved()) {
    return soa.AddLocalReference<jclass>(c);
  }
  if (loader != nullptr) {
    // Try the common case.
    StackHandleScope<1> hs(soa.Self());
    c = cl->FindClassInPathClassLoader(soa, soa.Self(), descriptor.c_str(), hs.NewHandle(loader));
    if (c != nullptr) {
      return soa.AddLocalReference<jclass>(c);
    }
  }
  // Class wasn't resolved so it may be erroneous or not yet ready, force the caller to go into
  // the regular loadClass code.
  return NULL;
}

static jint VMClassLoader_getBootClassPathSize(JNIEnv*, jclass) {
  return Runtime::Current()->GetClassLinker()->GetBootClassPath().size();
}

/*
 * Returns a string URL for a resource with the specified 'javaName' in
 * entry 'index' of the boot class path.
 *
 * We return a newly-allocated String in the following form:
 *
 *   jar:file://path!/name
 *
 * Where "path" is the bootstrap class path entry and "name" is the string
 * passed into this method.  "path" needs to be an absolute path (starting
 * with '/'); if it's not we'd need to make it absolute as part of forming
 * the URL string.
 */
static jstring VMClassLoader_getBootClassPathResource(JNIEnv* env, jclass, jstring javaName, jint index) {
  ScopedUtfChars name(env, javaName);
  if (name.c_str() == nullptr) {
    return nullptr;
  }

  const std::vector<const DexFile*>& path = Runtime::Current()->GetClassLinker()->GetBootClassPath();
  if (index < 0 || size_t(index) >= path.size()) {
    return nullptr;
  }
  const DexFile* dex_file = path[index];

  // For multidex locations, e.g., x.jar:classes2.dex, we want to look into x.jar.
  const std::string& location(dex_file->GetBaseLocation());

  std::string error_msg;
  std::unique_ptr<ZipArchive> zip_archive(ZipArchive::Open(location.c_str(), &error_msg));
  if (zip_archive.get() == nullptr) {
    LOG(WARNING) << "Failed to open zip archive '" << location << "': " << error_msg;
    return nullptr;
  }
  std::unique_ptr<ZipEntry> zip_entry(zip_archive->Find(name.c_str(), &error_msg));
  if (zip_entry.get() == nullptr) {
    return nullptr;
  }

  std::string url;
  StringAppendF(&url, "jar:file://%s!/%s", location.c_str(), name.c_str());
  return env->NewStringUTF(url.c_str());
}

static JNINativeMethod gMethods[] = {
  NATIVE_METHOD(VMClassLoader, findLoadedClass, "!(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Class;"),
  NATIVE_METHOD(VMClassLoader, getBootClassPathResource, "(Ljava/lang/String;I)Ljava/lang/String;"),
  NATIVE_METHOD(VMClassLoader, getBootClassPathSize, "!()I"),
};

void register_java_lang_VMClassLoader(JNIEnv* env) {
  REGISTER_NATIVE_METHODS("java/lang/VMClassLoader");
}

}  // namespace art
