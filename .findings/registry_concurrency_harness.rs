mod shim;
#[allow(dead_code, unused_imports)]
mod registry;

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, Instant},
};

use registry::*;

/// Object whose liveness we can observe from outside the allocation.
struct Obj {
    magic: u64,
    a: u64,
    b: u64,
    freed: Arc<AtomicBool>,
    in_use: Arc<AtomicUsize>,
}

impl Drop for Obj {
    fn drop(&mut self) {
        self.magic = 0xDEAD_DEAD_DEAD_DEAD;
        self.freed.store(true, Ordering::SeqCst);
    }
}

const MAGIC: u64 = 0x0123_4567_89AB_CDEF;

fn new_obj(freed: &Arc<AtomicBool>, in_use: &Arc<AtomicUsize>) -> *mut Obj {
    track_box(Box::into_raw(Box::new(Obj {
        magic: MAGIC,
        a: 0,
        b: 0,
        freed: freed.clone(),
        in_use: in_use.clone(),
    })))
}

fn t1_sanity() {
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let h = new_obj(&freed, &in_use);
    assert!(h as usize % 2 == 1, "handle ids must be odd");
    {
        let g = checkout_shared::<Obj>(h).unwrap();
        assert_eq!(g.magic, MAGIC);
        let g2 = checkout_shared::<Obj>(h).unwrap();
        assert_eq!(g2.magic, MAGIC);
        assert!(
            checkout_exclusive::<Obj>(h).is_err(),
            "exclusive must not coexist with shared"
        );
    }
    {
        let mut g = checkout_exclusive::<Obj>(h).unwrap();
        g.a = 7;
        assert!(checkout_shared::<Obj>(h).is_err());
    }
    assert_eq!(cimpl_free(h as *mut std::ffi::c_void), 0);
    assert!(freed.load(Ordering::SeqCst));
    assert_eq!(cimpl_free(h as *mut std::ffi::c_void), -1);
    println!("T1 sanity ...................... ok");
}

/// Exclusive writers mutate two fields non-atomically; shared readers require
/// them to agree. A protocol violation shows up as a torn pair or as a read of
/// a freed object.
fn t2_exclusion_stress() {
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let h = new_obj(&freed, &in_use) as usize;
    let torn = Arc::new(AtomicU64::new(0));
    let writes = Arc::new(AtomicU64::new(0));
    let reads = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(9));

    let mut handles = Vec::new();
    for t in 0..8 {
        let (torn, writes, reads, refused, stop, barrier) = (
            torn.clone(),
            writes.clone(),
            reads.clone(),
            refused.clone(),
            stop.clone(),
            barrier.clone(),
        );
        handles.push(thread::spawn(move || {
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                if t % 2 == 0 {
                    match checkout_exclusive::<Obj>(h as *mut Obj) {
                        Ok(mut g) => {
                            let v = writes.fetch_add(1, Ordering::Relaxed);
                            let prev = g.in_use.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(prev, 0, "exclusive borrow overlapped another borrow");
                            g.a = v;
                            thread::yield_now();
                            g.b = v;
                            g.in_use.fetch_sub(1, Ordering::SeqCst);
                        }
                        Err(_) => {
                            refused.fetch_add(1 << 32, Ordering::Relaxed);
                        }
                    }
                } else {
                    match checkout_shared::<Obj>(h as *mut Obj) {
                        Ok(g) => {
                            reads.fetch_add(1, Ordering::Relaxed);
                            assert_eq!(g.magic, MAGIC, "read a freed object");
                            let (a, b) = (g.a, g.b);
                            if a != b {
                                torn.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            refused.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }
    barrier.wait();
    thread::sleep(Duration::from_millis(1500));
    stop.store(true, Ordering::Relaxed);
    for t in handles {
        t.join().unwrap();
    }
    println!(
        "T2 exclusion stress ............ writes={} (refused {}) reads={} (refused {}) torn={}",
        writes.load(Ordering::Relaxed),
        refused.load(Ordering::Relaxed) >> 32,
        reads.load(Ordering::Relaxed),
        refused.load(Ordering::Relaxed) & 0xffff_ffff,
        torn.load(Ordering::Relaxed)
    );
    assert_eq!(torn.load(Ordering::Relaxed), 0);
    cimpl_free(h as *mut std::ffi::c_void);
}

/// free() racing live borrows: the object must not be dropped while a guard
/// can still dereference it, and must be dropped exactly once afterwards.
fn t3_free_vs_borrow() {
    let mut uaf = 0u64;
    let mut leaked = 0u64;
    for _ in 0..2000 {
        let freed = Arc::new(AtomicBool::new(false));
        let in_use = Arc::new(AtomicUsize::new(0));
        let h = new_obj(&freed, &in_use) as usize;
        let barrier = Arc::new(Barrier::new(2));
        let b2 = barrier.clone();
        let f2 = freed.clone();
        let user = thread::spawn(move || {
            b2.wait();
            let mut bad = 0u64;
            if let Ok(g) = checkout_shared::<Obj>(h as *mut Obj) {
                for _ in 0..200 {
                    if g.magic != MAGIC || f2.load(Ordering::SeqCst) {
                        bad += 1;
                        break;
                    }
                    std::hint::spin_loop();
                }
            }
            bad
        });
        barrier.wait();
        let _ = cimpl_free(h as *mut std::ffi::c_void);
        uaf += user.join().unwrap();
        if !freed.load(Ordering::SeqCst) {
            leaked += 1;
        }
    }
    println!("T3 free vs borrow .............. use-after-free={uaf} leaked={leaked}");
    assert_eq!(uaf, 0);
    assert_eq!(leaked, 0);
}

/// Two handles acquired in opposite orders by two calls.
fn t4_lock_order_inversion() {
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let a = new_obj(&freed, &in_use) as usize;
    let b = new_obj(&freed, &in_use) as usize;
    let ok = Arc::new(AtomicU64::new(0));
    let fail = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(3));
    let mut hs = Vec::new();
    for t in 0..2 {
        let (ok, fail, barrier) = (ok.clone(), fail.clone(), barrier.clone());
        hs.push(thread::spawn(move || {
            let (first, second) = if t == 0 { (a, b) } else { (b, a) };
            barrier.wait();
            let deadline = Instant::now() + Duration::from_millis(2000);
            while Instant::now() < deadline {
                match checkout_exclusive::<Obj>(first as *mut Obj) {
                    Ok(_g1) => match checkout_exclusive::<Obj>(second as *mut Obj) {
                        Ok(_g2) => {
                            ok.fetch_add(1, Ordering::Relaxed);
                            thread::sleep(Duration::from_micros(50));
                        }
                        Err(_) => {
                            fail.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    Err(_) => {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    barrier.wait();
    for t in hs {
        t.join().unwrap();
    }
    println!(
        "T4 AB/BA inversion ............. succeeded={} PointerInUse={}",
        ok.load(Ordering::Relaxed),
        fail.load(Ordering::Relaxed)
    );
    cimpl_free(a as *mut std::ffi::c_void);
    cimpl_free(b as *mut std::ffi::c_void);
}

/// One long-running exclusive borrow (a sign call) versus readers.
fn t5_reader_refusal_under_long_write() {
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let h = new_obj(&freed, &in_use) as usize;
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let writer = thread::spawn(move || {
        let _g = checkout_exclusive::<Obj>(h as *mut Obj).unwrap();
        while !s2.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(1));
        }
    });
    thread::sleep(Duration::from_millis(20));
    let start = Instant::now();
    let mut refused = 0;
    let mut waited = Duration::ZERO;
    for _ in 0..20 {
        let t = Instant::now();
        if checkout_shared::<Obj>(h as *mut Obj).is_err() {
            refused += 1;
        }
        waited += t.elapsed();
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    println!(
        "T5 reads during a long write ... refused={}/20 avg_block={:?} total={:?}",
        refused,
        waited / 20,
        start.elapsed()
    );
    cimpl_free(h as *mut std::ffi::c_void);
}

/// A writer that times out must leave the state usable for everyone else.
fn t6_writer_pending_cleanup() {
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let h = new_obj(&freed, &in_use) as usize;
    let hold = checkout_shared::<Obj>(h as *mut Obj).unwrap();
    let w = thread::spawn(move || checkout_exclusive::<Obj>(h as *mut Obj).is_ok());
    thread::sleep(Duration::from_millis(3));
    let blocked = checkout_shared::<Obj>(h as *mut Obj).is_err();
    let got = w.join().unwrap();
    drop(hold);
    let after = checkout_shared::<Obj>(h as *mut Obj).is_ok();
    println!(
        "T6 writer-pending .............. writer_got={got} new_reader_blocked_while_pending={blocked} reader_ok_after={after}"
    );
    assert!(after, "WRITER_PENDING left set after the writer gave up");
    cimpl_free(h as *mut std::ffi::c_void);
}

/// Address-keyed buffers (to_c_string / to_c_bytes) can be recycled by the
/// allocator, so a stale C pointer can key a different live buffer.
fn t7_address_key_aba() {
    let first = to_c_string("aaaaaaaaaaaaaaaa".to_string());
    let first_addr = first as usize;
    assert_eq!(cimpl_free(first as *mut std::ffi::c_void), 0);

    let mut collided = None;
    let mut keep = Vec::new();
    for _ in 0..64 {
        let p = to_c_string("bbbbbbbbbbbbbbbb".to_string());
        if p as usize == first_addr {
            collided = Some(p);
            break;
        }
        keep.push(p);
    }
    match collided {
        Some(p) => {
            let rc = cimpl_free(first as *mut std::ffi::c_void);
            let second_free = cimpl_free(p as *mut std::ffi::c_void);
            println!(
                "T7 address ABA ................. stale free of 0x{first_addr:x} returned {rc} (0 = it freed the *new* buffer); freeing the new handle then returned {second_free}"
            );
            assert_eq!(rc, 0, "expected the stale pointer to be accepted");
            assert_eq!(second_free, -1, "expected the live buffer to be gone");
        }
        None => println!("T7 address ABA ................. allocator did not reuse the address"),
    }
    for p in keep {
        cimpl_free(p as *mut std::ffi::c_void);
    }
}

/// untrack (ownership transfer) racing free().
fn t8_untrack_race() {
    let mut both = 0;
    let mut orphaned = 0;
    for _ in 0..3000 {
        let freed = Arc::new(AtomicBool::new(false));
        let in_use = Arc::new(AtomicUsize::new(0));
        let h = new_obj(&freed, &in_use) as usize;
        let barrier = Arc::new(Barrier::new(2));
        let b2 = barrier.clone();
        let taker = thread::spawn(move || {
            b2.wait();
            untrack_owned::<Obj>(h as *mut Obj).is_ok()
        });
        barrier.wait();
        let freed_ok = cimpl_free(h as *mut std::ffi::c_void) == 0;
        let taken = taker.join().unwrap();
        if taken && freed_ok {
            both += 1;
        }
        if !taken && !freed_ok {
            orphaned += 1;
        }
    }
    println!("T8 untrack vs free ............. double_ownership={both} orphaned={orphaned}");
    assert_eq!(both, 0);
}

/// A panic while a borrow is live must not leave the handle permanently
/// checked out.
fn t9_panic_releases_borrow() {
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let h = new_obj(&freed, &in_use) as usize;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| {
        let _g = checkout_exclusive::<Obj>(h as *mut Obj).unwrap();
        panic!("boom");
    });
    std::panic::set_hook(prev);
    assert!(r.is_err());
    let ok = checkout_exclusive::<Obj>(h as *mut Obj).is_ok();
    println!("T9 panic with a live borrow .... reusable_after_panic={ok}");
    assert!(ok);
    cimpl_free(h as *mut std::ffi::c_void);
}


/// Two concurrent "sign" calls sharing one signer handle, and a callback that
/// re-enters the FFI with a handle its caller already holds.
fn t10_shared_signer_and_reentrancy() {
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let h = new_obj(&freed, &in_use) as usize;
    let barrier = Arc::new(Barrier::new(2));
    let b2 = barrier.clone();
    let signer_a = thread::spawn(move || {
        let _g = checkout_exclusive::<Obj>(h as *mut Obj).unwrap();
        b2.wait();
        thread::sleep(Duration::from_millis(300)); // a slow sign (TSA round trip)
    });
    barrier.wait();
    let t = Instant::now();
    let second = checkout_exclusive::<Obj>(h as *mut Obj);
    let waited = t.elapsed();
    println!(
        "T10 second sign, same signer ... result={} after {:?}",
        if second.is_ok() { "acquired" } else { "PointerInUse" },
        waited
    );
    drop(second);
    signer_a.join().unwrap();

    // Re-entrant checkout on the same thread (a stream callback that calls back
    // into the FFI with the handle the caller is holding).
    let outer = checkout_exclusive::<Obj>(h as *mut Obj).unwrap();
    let t = Instant::now();
    let inner = checkout_shared::<Obj>(h as *mut Obj);
    println!(
        "T11 re-entrant checkout ........ result={} after {:?}",
        if inner.is_ok() { "acquired" } else { "PointerInUse" },
        t.elapsed()
    );
    drop(inner);
    drop(outer);
    cimpl_free(h as *mut std::ffi::c_void);
}

fn main() {
    t1_sanity();
    t2_exclusion_stress();
    t3_free_vs_borrow();
    t4_lock_order_inversion();
    t5_reader_refusal_under_long_write();
    t6_writer_pending_cleanup();
    t7_address_key_aba();
    t8_untrack_race();
    t9_panic_releases_borrow();
    t10_shared_signer_and_reentrancy();
    t12_spin_cost();
    println!("all harness checks finished");
}

/// How much CPU the refusal path burns: yield_now() spinning, not parking.
fn t12_spin_cost() {
    fn cpu_ticks() -> f64 {
        let s = std::fs::read_to_string("/proc/self/stat").unwrap();
        let after = &s[s.rfind(')').unwrap() + 1..];
        let f: Vec<&str> = after.split_whitespace().collect();
        // utime and stime are fields 14 and 15 of stat; index 11 and 12 here.
        let hz = 100.0;
        (f[11].parse::<f64>().unwrap() + f[12].parse::<f64>().unwrap()) / hz
    }
    let freed = Arc::new(AtomicBool::new(false));
    let in_use = Arc::new(AtomicUsize::new(0));
    let h = new_obj(&freed, &in_use) as usize;
    let hold = checkout_exclusive::<Obj>(h as *mut Obj).unwrap();
    let before = cpu_ticks();
    let wall = Instant::now();
    let mut hs = Vec::new();
    for _ in 0..4 {
        hs.push(thread::spawn(move || {
            for _ in 0..25 {
                let _ = checkout_exclusive::<Obj>(h as *mut Obj);
            }
        }));
    }
    for t in hs {
        t.join().unwrap();
    }
    let cpu = cpu_ticks() - before;
    println!(
        "T12 refusal cost ............... 100 refused exclusive checkouts: wall={:?} cpu={:.2}s",
        wall.elapsed(),
        cpu
    );
    drop(hold);
    cimpl_free(h as *mut std::ffi::c_void);
}
