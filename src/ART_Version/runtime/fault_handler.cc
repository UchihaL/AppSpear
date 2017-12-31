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

#include "fault_handler.h"

#include <setjmp.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include "mirror/art_method.h"
#include "mirror/class.h"
#include "sigchain.h"
#include "thread-inl.h"
#include "verify_object-inl.h"

// Note on nested signal support
// -----------------------------
//
// Typically a signal handler should not need to deal with signals that occur within it.
// However, when a SIGSEGV occurs that is in generated code and is not one of the
// handled signals (implicit checks), we call a function to try to dump the stack
// to the log.  This enhances the debugging experience but may have the side effect
// that it may not work.  If the cause of the original SIGSEGV is a corrupted stack or other
// memory region, the stack backtrace code may run into trouble and may either crash
// or fail with an abort (SIGABRT).  In either case we don't want that (new) signal to
// mask the original signal and thus prevent useful debug output from being presented.
//
// In order to handle this situation, before we call the stack tracer we do the following:
//
// 1. shutdown the fault manager so that we are talking to the real signal management
//    functions rather than those in sigchain.
// 2. use pthread_sigmask to allow SIGSEGV and SIGABRT signals to be delivered to the
//    thread running the signal handler.
// 3. set the handler for SIGSEGV and SIGABRT to a secondary signal handler.
// 4. save the thread's state to the TLS of the current thread using 'setjmp'
//
// We then call the stack tracer and one of two things may happen:
// a. it completes successfully
// b. it crashes and a signal is raised.
//
// In the former case, we fall through and everything is fine.  In the latter case
// our secondary signal handler gets called in a signal context.  This results in
// a call to FaultManager::HandledNestedSignal(), an archirecture specific function
// whose purpose is to call 'longjmp' on the jmp_buf saved in the TLS of the current
// thread.  This results in a return with a non-zero value from 'setjmp'.  We detect this
// and write something to the log to tell the user that it happened.
//
// Regardless of how we got there, we reach the code after the stack tracer and we
// restore the signal states to their original values, reinstate the fault manager (thus
// reestablishing the signal chain) and continue.

// This is difficult to test with a runtime test.  To invoke the nested signal code
// on any signal, uncomment the following line and run something that throws a
// NullPointerException.
// #define TEST_NESTED_SIGNAL

namespace art {
// Static fault manger object accessed by signal handler.
FaultManager fault_manager;

extern "C" {
void art_sigsegv_fault() {
  // Set a breakpoint here to be informed when a SIGSEGV is unhandled by ART.
  VLOG(signals)<< "Caught unknown SIGSEGV in ART fault handler - chaining to next handler.";
}
}

// Signal handler called on SIGSEGV.
static void art_fault_handler(int sig, siginfo_t* info, void* context) {
  fault_manager.HandleFault(sig, info, context);
}

// Signal handler for dealing with a nested signal.
static void art_nested_signal_handler(int sig, siginfo_t* info, void* context) {
  fault_manager.HandleNestedSignal(sig, info, context);
}

FaultManager::FaultManager() : initialized_(false) {
  sigaction(SIGSEGV, nullptr, &oldaction_);
}

FaultManager::~FaultManager() {
}

static void SetUpArtAction(struct sigaction* action) {
  action->sa_sigaction = art_fault_handler;
  sigemptyset(&action->sa_mask);
  action->sa_flags = SA_SIGINFO | SA_ONSTACK;
#if !defined(__APPLE__) && !defined(__mips__)
  action->sa_restorer = nullptr;
#endif
}

void FaultManager::EnsureArtActionInFrontOfSignalChain() {
  if (initialized_) {
    struct sigaction action;
    SetUpArtAction(&action);
    EnsureFrontOfChain(SIGSEGV, &action);
  } else {
    LOG(WARNING) << "Can't call " << __FUNCTION__ << " due to unitialized fault manager";
  }
}

void FaultManager::Init() {
  CHECK(!initialized_);
  struct sigaction action;
  SetUpArtAction(&action);

  // Set our signal handler now.
  int e = sigaction(SIGSEGV, &action, &oldaction_);
  if (e != 0) {
    VLOG(signals) << "Failed to claim SEGV: " << strerror(errno);
  }
  // Make sure our signal handler is called before any user handlers.
  ClaimSignalChain(SIGSEGV, &oldaction_);
  initialized_ = true;
}

void FaultManager::Shutdown() {
  if (initialized_) {
    UnclaimSignalChain(SIGSEGV);
    initialized_ = false;
  }
}

void FaultManager::HandleFault(int sig, siginfo_t* info, void* context) {
  // BE CAREFUL ALLOCATING HERE INCLUDING USING LOG(...)
  //
  // If malloc calls abort, it will be holding its lock.
  // If the handler tries to call malloc, it will deadlock.
  VLOG(signals) << "Handling fault";
  if (IsInGeneratedCode(info, context, true)) {
    VLOG(signals) << "in generated code, looking for handler";
    for (const auto& handler : generated_code_handlers_) {
      VLOG(signals) << "invoking Action on handler " << handler;
      if (handler->Action(sig, info, context)) {
#ifdef TEST_NESTED_SIGNAL
        // In test mode we want to fall through to stack trace handler
        // on every signal (in reality this will cause a crash on the first
        // signal).
        break;
#else
        // We have handled a signal so it's time to return from the
        // signal handler to the appropriate place.
        return;
#endif
      }
    }
  }

  // We hit a signal we didn't handle.  This might be something for which
  // we can give more information about so call all registered handlers to see
  // if it is.
  for (const auto& handler : other_handlers_) {
    if (handler->Action(sig, info, context)) {
      return;
    }
  }

  // Set a breakpoint in this function to catch unhandled signals.
  art_sigsegv_fault();

  // Pass this on to the next handler in the chain, or the default if none.
  InvokeUserSignalHandler(sig, info, context);
}

void FaultManager::AddHandler(FaultHandler* handler, bool generated_code) {
  if (generated_code) {
    generated_code_handlers_.push_back(handler);
  } else {
    other_handlers_.push_back(handler);
  }
}

void FaultManager::RemoveHandler(FaultHandler* handler) {
  auto it = std::find(generated_code_handlers_.begin(), generated_code_handlers_.end(), handler);
  if (it != generated_code_handlers_.end()) {
    generated_code_handlers_.erase(it);
    return;
  }
  auto it2 = std::find(other_handlers_.begin(), other_handlers_.end(), handler);
  if (it2 != other_handlers_.end()) {
    other_handlers_.erase(it);
    return;
  }
  LOG(FATAL) << "Attempted to remove non existent handler " << handler;
}

// This function is called within the signal handler.  It checks that
// the mutator_lock is held (shared).  No annotalysis is done.
bool FaultManager::IsInGeneratedCode(siginfo_t* siginfo, void* context, bool check_dex_pc) {
  // We can only be running Java code in the current thread if it
  // is in Runnable state.
  VLOG(signals) << "Checking for generated code";
  Thread* thread = Thread::Current();
  if (thread == nullptr) {
    VLOG(signals) << "no current thread";
    return false;
  }

  ThreadState state = thread->GetState();
  if (state != kRunnable) {
    VLOG(signals) << "not runnable";
    return false;
  }

  // Current thread is runnable.
  // Make sure it has the mutator lock.
  if (!Locks::mutator_lock_->IsSharedHeld(thread)) {
    VLOG(signals) << "no lock";
    return false;
  }

  mirror::ArtMethod* method_obj = 0;
  uintptr_t return_pc = 0;
  uintptr_t sp = 0;

  // Get the architecture specific method address and return address.  These
  // are in architecture specific files in arch/<arch>/fault_handler_<arch>.
  GetMethodAndReturnPcAndSp(siginfo, context, &method_obj, &return_pc, &sp);

  // If we don't have a potential method, we're outta here.
  VLOG(signals) << "potential method: " << method_obj;
  if (method_obj == 0 || !IsAligned<kObjectAlignment>(method_obj)) {
    VLOG(signals) << "no method";
    return false;
  }

  // Verify that the potential method is indeed a method.
  // TODO: check the GC maps to make sure it's an object.
  // Check that the class pointer inside the object is not null and is aligned.
  // TODO: Method might be not a heap address, and GetClass could fault.
  mirror::Class* cls = method_obj->GetClass<kVerifyNone>();
  if (cls == nullptr) {
    VLOG(signals) << "not a class";
    return false;
  }
  if (!IsAligned<kObjectAlignment>(cls)) {
    VLOG(signals) << "not aligned";
    return false;
  }


  if (!VerifyClassClass(cls)) {
    VLOG(signals) << "not a class class";
    return false;
  }

  // Now make sure the class is a mirror::ArtMethod.
  if (!cls->IsArtMethodClass()) {
    VLOG(signals) << "not a method";
    return false;
  }

  // We can be certain that this is a method now.  Check if we have a GC map
  // at the return PC address.
  if (true || kIsDebugBuild) {
    VLOG(signals) << "looking for dex pc for return pc " << std::hex << return_pc;
    const void* code = Runtime::Current()->GetInstrumentation()->GetQuickCodeFor(method_obj);
    uint32_t sought_offset = return_pc - reinterpret_cast<uintptr_t>(code);
    VLOG(signals) << "pc offset: " << std::hex << sought_offset;
  }
  uint32_t dexpc = method_obj->ToDexPc(return_pc, false);
  VLOG(signals) << "dexpc: " << dexpc;
  return !check_dex_pc || dexpc != DexFile::kDexNoIndex;
}

FaultHandler::FaultHandler(FaultManager* manager) : manager_(manager) {
}

//
// Null pointer fault handler
//
NullPointerHandler::NullPointerHandler(FaultManager* manager) : FaultHandler(manager) {
  manager_->AddHandler(this, true);
}

//
// Suspension fault handler
//
SuspensionHandler::SuspensionHandler(FaultManager* manager) : FaultHandler(manager) {
  manager_->AddHandler(this, true);
}

//
// Stack overflow fault handler
//
StackOverflowHandler::StackOverflowHandler(FaultManager* manager) : FaultHandler(manager) {
  manager_->AddHandler(this, true);
}

//
// Stack trace handler, used to help get a stack trace from SIGSEGV inside of compiled code.
//
JavaStackTraceHandler::JavaStackTraceHandler(FaultManager* manager) : FaultHandler(manager) {
  manager_->AddHandler(this, false);
}

bool JavaStackTraceHandler::Action(int sig, siginfo_t* siginfo, void* context) {
  // Make sure that we are in the generated code, but we may not have a dex pc.

#ifdef TEST_NESTED_SIGNAL
  bool in_generated_code = true;
#else
  bool in_generated_code = manager_->IsInGeneratedCode(siginfo, context, false);
#endif
  if (in_generated_code) {
    LOG(ERROR) << "Dumping java stack trace for crash in generated code";
    mirror::ArtMethod* method = nullptr;
    uintptr_t return_pc = 0;
    uintptr_t sp = 0;
    Thread* self = Thread::Current();

    // Shutdown the fault manager so that it will remove the signal chain for
    // SIGSEGV and we call the real sigaction.
    fault_manager.Shutdown();

    // The action for SIGSEGV should be the default handler now.

    // Unblock the signals we allow so that they can be delivered in the signal handler.
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGSEGV);
    sigaddset(&sigset, SIGABRT);
    pthread_sigmask(SIG_UNBLOCK, &sigset, nullptr);

    // If we get a signal in this code we want to invoke our nested signal
    // handler.
    struct sigaction action, oldsegvaction, oldabortaction;
    action.sa_sigaction = art_nested_signal_handler;

    // Explictly mask out SIGSEGV and SIGABRT from the nested signal handler.  This
    // should be the default but we definitely don't want these happening in our
    // nested signal handler.
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGSEGV);
    sigaddset(&action.sa_mask, SIGABRT);

    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
#if !defined(__APPLE__) && !defined(__mips__)
    action.sa_restorer = nullptr;
#endif

    // Catch SIGSEGV and SIGABRT to invoke our nested handler
    int e1 = sigaction(SIGSEGV, &action, &oldsegvaction);
    int e2 = sigaction(SIGABRT, &action, &oldabortaction);
    if (e1 != 0 || e2 != 0) {
      LOG(ERROR) << "Unable to register nested signal handler - no stack trace possible";
      // If sigaction failed we have a serious problem.  We cannot catch
      // any failures in the stack tracer and it's likely to occur since
      // the program state is bad.  Therefore we don't even try to give
      // a stack trace.
    } else {
      // Save the current state and try to dump the stack.  If this causes a signal
      // our nested signal handler will be invoked and this will longjmp to the saved
      // state.
      if (setjmp(*self->GetNestedSignalState()) == 0) {
        manager_->GetMethodAndReturnPcAndSp(siginfo, context, &method, &return_pc, &sp);
        // Inside of generated code, sp[0] is the method, so sp is the frame.
        StackReference<mirror::ArtMethod>* frame =
            reinterpret_cast<StackReference<mirror::ArtMethod>*>(sp);
        self->SetTopOfStack(frame, 0);  // Since we don't necessarily have a dex pc, pass in 0.
#ifdef TEST_NESTED_SIGNAL
        // To test the nested signal handler we raise a signal here.  This will cause the
        // nested signal handler to be called and perform a longjmp back to the setjmp
        // above.
        abort();
#endif
        self->DumpJavaStack(LOG(ERROR));
      } else {
        LOG(ERROR) << "Stack trace aborted due to nested signal - original signal being reported";
      }

      // Restore the signal handlers.
      sigaction(SIGSEGV, &oldsegvaction, nullptr);
      sigaction(SIGABRT, &oldabortaction, nullptr);
    }

    // Now put the fault manager back in place.
    fault_manager.Init();

    // And we're done.
  }

  return false;  // Return false since we want to propagate the fault to the main signal handler.
}

}   // namespace art

