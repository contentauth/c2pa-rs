// Copyright 2026 Adobe. All rights reserved.
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

//! A tiny MP3 must not make the SDK allocate gigabytes. This is its own test binary because it
//! replaces the global allocator to record the largest single allocation.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    io::Cursor,
    sync::atomic::{AtomicUsize, Ordering},
};

use c2pa::{Context, Reader};

struct LargestAllocation;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for LargestAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: LargestAllocation = LargestAllocation;

#[test]
fn test_oversized_id3_frame_does_not_allocate() {
    // A 445-byte MP3 whose ID3v2.3 frame header declares 0x40000003 bytes.
    let data = include_bytes!("fixtures/id3v23_frame_size_bomb.mp3");
    let context = Context::new().into_shared();

    LARGEST.store(0, Ordering::Relaxed);
    let result = Reader::from_shared_context(&context).with_stream("audio/mpeg", Cursor::new(data));

    assert!(result.is_err());
    let largest = LARGEST.load(Ordering::Relaxed);
    assert!(
        largest < 64 * 1024 * 1024,
        "allocated {largest} bytes at once"
    );
}
