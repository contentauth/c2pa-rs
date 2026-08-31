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
//! Everything lives in one `#[test]` so libtest cannot run any of it
//! concurrently: a second test thread forking while this one holds a lock is
//! the same hazard from the other side. The child also allocates, which is not
//! async-signal-safe after `fork()` in a multi-threaded process, so keeping the
//! forking thread the only thread is what makes that safe here.

// fork, waitpid, WIFEXITED and WEXITSTATUS are Unix-only. Windows is a Tier-1
// target that builds this test target, so gate on the platform, not on wasm.
#![cfg(unix)]

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
fn registry_refuses_every_path_in_a_forked_child() {
    read_paths_are_refused();
    inherited_entries_do_not_run_cleanup();
    write_paths_are_refused();
}

/// Read and free paths must refuse before taking the inherited lock.
fn read_paths_are_refused() {
    let ptr = track_box(Box::into_raw(Box::new(1i32)));
    let addr = ptr as usize;

    let code = in_forked_child(move || {
        let ptr = addr as *mut i32;
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

/// A child must not run cleanup for anything it inherited.
///
/// This goes through the public free path, which `check_same_process` refuses
/// before the drop is reached. The drop path itself -- an inherited `Arc` going
/// out of scope with no registry call to intercept it -- is covered by
/// `test_inherited_entry_drop_does_not_run_cleanup` in `cimpl::utils`, which
/// can reach it because the entry's fields are private to that module.
fn inherited_entries_do_not_run_cleanup() {
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
        let _ = cimpl_free(addr as *mut std::ffi::c_void);
        if FREED.load(Ordering::SeqCst) {
            unsafe { libc::_exit(1) };
        }
    });

    assert_eq!(code, 0, "the child ran cleanup on an inherited entry");
    assert!(
        !FREED.load(Ordering::SeqCst),
        "cleanup ran in the parent early"
    );

    // The parent still owns it, and freeing here does run cleanup.
    assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);
    assert!(FREED.load(Ordering::SeqCst), "parent free stopped working");
}

/// Both write paths must refuse rather than take the inherited lock.
///
/// This is what a child calling `c2pa_reader_new()` (track_by_id, through
/// `track_box`) or `c2pa_error()` (track_by_address, through `to_c_string`)
/// would hit.
///
/// The check being verified is a precondition, not a lock-contention fix: no
/// public API holds the registry lock across a call, so a caller cannot
/// construct the fork-while-locked interleaving from outside the crate. That is
/// the point of checking the pid rather than trying to make the lock
/// fork-safe. What this asserts is the observable half -- both paths refuse,
/// and neither returns a handle the child could go on to use.
fn write_paths_are_refused() {
    let code = in_forked_child(|| {
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
}
