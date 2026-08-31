// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Fork safety, in its own binary.
//!
//! These tests must not share a process with the rest of the suite. `fork()` in
//! a multi-threaded program gives the child the parent's mutexes in whatever
//! state they were in at fork time, and only the forking thread survives -- so
//! a lock another thread held is locked forever in the child. The unit tests
//! run in parallel and hammer the global registry, which makes that near
//! certain rather than merely possible.
//!
//! Running here, single-threaded, means no other thread can hold the registry
//! lock when the fork happens.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::atomic::{AtomicBool, Ordering};

use c2pa_c::{checkout_shared, cimpl_free, to_c_string, track_box, untrack_owned};

/// Runs `child` in a forked process and returns its exit code.
///
/// Deliberately does not `exec()`: that is the case these tests are about, and
/// what `multiprocessing`'s default start method does on Linux.
fn in_forked_child(child: impl FnOnce()) -> i32 {
    // SAFETY: the child only runs the closure and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        child();
        // _exit, not exit: skip atexit handlers and static destructors, so the
        // child cannot run the parent's cleanup on the way out.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    // SAFETY: pid is a child of this process and status is a valid pointer.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status), "child did not exit normally");
    libc::WEXITSTATUS(status)
}

#[test]
fn forked_child_registry_calls_are_refused() {
    let ptr = track_box(Box::into_raw(Box::new(1i32)));
    let addr = ptr as usize;

    let code = in_forked_child(move || {
        let ptr = addr as *mut i32;
        // Every entry point must refuse before taking the inherited lock.
        if checkout_shared::<i32>(ptr).is_ok() {
            unsafe { libc::_exit(1) };
        }
        if untrack_owned::<i32>(ptr).is_ok() {
            unsafe { libc::_exit(2) };
        }
        if cimpl_free(ptr as *mut std::ffi::c_void) == 0 {
            unsafe { libc::_exit(3) };
        }
    });

    assert_eq!(code, 0, "a child call succeeded instead of being refused");
    // The parent's handle is untouched.
    assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);
}

#[test]
fn forked_child_does_not_run_cleanup_for_inherited_entries() {
    // The load-bearing case: dropping an inherited Arc reaches EntryInner::drop
    // without any registry call, so an entry-point-only check would miss it.
    // The child frees through the public API, which is refused before the lock;
    // what this proves is that no cleanup ran in the child regardless of path.
    static FREED: AtomicBool = AtomicBool::new(false);
    struct Sentinel;
    impl Drop for Sentinel {
        fn drop(&mut self) {
            FREED.store(true, Ordering::SeqCst);
        }
    }

    let ptr = track_box(Box::into_raw(Box::new(Sentinel)));
    let addr = ptr as usize;

    let code = in_forked_child(move || {
        // Exercise the free path, then confirm the sentinel never ran.
        let _ = cimpl_free(addr as *mut std::ffi::c_void);
        if FREED.load(Ordering::SeqCst) {
            unsafe { libc::_exit(1) };
        }
    });

    assert_eq!(code, 0, "the child ran cleanup on an inherited entry");
    assert!(!FREED.load(Ordering::SeqCst), "cleanup ran in the parent early");

    // The parent still owns it, and freeing here does run cleanup.
    assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);
    assert!(FREED.load(Ordering::SeqCst), "parent free stopped working");
}

#[test]
fn forked_child_can_create_handles_without_deadlocking() {
    // The hazard this guard exists for: fork() while another thread holds the
    // registry lock. Only the forking thread survives, so that lock can never
    // be released in the child -- any path that takes it blocks forever.
    //
    // This is the multiprocessing-on-Linux case. The child here exercises the
    // two WRITE paths (track_by_id via track_box, track_by_address via
    // to_c_string), which is what a child calling c2pa_reader_new() or
    // c2pa_error() would hit. Both must refuse rather than block.
    let holder_ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    let holder_gate = std::sync::Arc::clone(&holder_ready);

    // A background thread holds the registry lock across the fork, by keeping a
    // checkout alive -- the public way to pin registry state from another
    // thread.
    let pinned = track_box(Box::into_raw(Box::new(99i32)));
    let pinned_addr = pinned as usize;
    let holder = std::thread::spawn(move || {
        let guard = checkout_shared::<i32>(pinned_addr as *mut i32).expect("fresh handle");
        holder_gate.wait();
        std::thread::sleep(std::time::Duration::from_millis(500));
        drop(guard);
    });
    holder_ready.wait();

    let code = in_forked_child(|| {
        // Both write paths must return without taking the inherited lock.
        let p = track_box(Box::into_raw(Box::new(7i32)));
        if !p.is_null() {
            unsafe { libc::_exit(1) };
        }
        let s = to_c_string("hello".to_string());
        if !s.is_null() {
            unsafe { libc::_exit(2) };
        }
    });

    assert_eq!(code, 0, "a child write path did not refuse");
    holder.join().unwrap();
    assert_eq!(cimpl_free(pinned as *mut std::ffi::c_void), 0);
}
