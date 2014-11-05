//! Secure Buffer
use alloc::heap;
use libc::consts::os::posix88::{MAP_ANON, MAP_PRIVATE, MAP_FAILED,
                                PROT_READ, PROT_WRITE, PROT_NONE};
use libc::funcs::posix88::mman;
use libc::types::common::c95::c_void;
use libc::types::os::arch::c95::size_t;
use serialize::{Encodable, Encoder, Decodable, Decoder};
use serialize::hex::ToHex;
use std::fmt;
use std::intrinsics;
use std::iter::AdditiveIterator;
use std::mem;
use std::ops;
use std::os;
use std::ptr;
use std::rand::Rng;
use std::raw::Slice;
use std::slice::{Items, MutItems};

use utils;


/// Trait for allocators.
pub trait Allocator {
    fn new() -> Self;

    unsafe fn allocate(&self, size: uint, align: uint) -> *mut u8;

    unsafe fn deallocate(&self, ptr: *mut u8, size: uint, align: uint);
}

/// Default allocator used to allocate and deallocate memory for secure
/// buffers.
pub type DefaultAllocator = GuardedHeapAllocator;


/// Standard heap allocator, use Rust's allocator (currently jemalloc),
/// does not implement guarded pages.
pub struct StdHeapAllocator;

impl Allocator for StdHeapAllocator {
    fn new() -> StdHeapAllocator {
        StdHeapAllocator
    }

    unsafe fn allocate(&self, size: uint, align: uint) -> *mut u8 {
        heap::allocate(size, align)
    }

    unsafe fn deallocate(&self, ptr: *mut u8, size: uint, align: uint) {
        heap::deallocate(ptr, size, align)
    }
}


#[cfg(target_os = "freebsd")]
mod impmap {
    use libc::consts::os::extra::MAP_NOCORE;
    use libc::types::os::arch::c95::c_int;

    pub fn additional_map_flags() -> c_int {
        MAP_NOCORE
    }
}

#[cfg(not(target_os = "freebsd"))]
mod impmap {
    use libc::types::os::arch::c95::c_int;

    pub fn additional_map_flags() -> c_int {
        0
    }
}


fn round_up(size: uint, page_size: uint) -> uint {
    assert!(size > 0 && page_size > 0);
    if size % page_size == 0 {
        size
    } else {
        size + page_size - (size % page_size)
    }
}


/// Guarded heap allocator, add a guarded page before and after
/// each allocated buffer.
// It's very slow and not very space-efficient especially for small
// buffers. Using a pool of buffers guarded by two pages would be
// better for performances.
pub struct GuardedHeapAllocator;

impl Allocator for GuardedHeapAllocator {
    fn new() -> GuardedHeapAllocator {
        GuardedHeapAllocator
    }

    unsafe fn allocate(&self, size: uint, _: uint) -> *mut u8 {
        let page_size = os::page_size();
        let full_size = round_up(size, page_size) + 2 * page_size;

        let null_addr: *const u8 = ptr::null();
        let ptr = mman::mmap(null_addr as *mut c_void,
                             full_size as size_t,
                             PROT_READ | PROT_WRITE,
                             MAP_ANON | MAP_PRIVATE |
                             impmap::additional_map_flags(),
                             -1,
                             0);
        if ptr == MAP_FAILED {
            let errno = os::errno();
            panic!("mmap failed: {} ({})",
                   os::error_string(errno as uint), errno);
        }

        let before_page = ptr;
        let mut ret = mman::mprotect(before_page, page_size as size_t,
                                     PROT_NONE);
        if ret != 0 {
            let errno = os::errno();
            panic!("mprotect failed: {} ({})",
                   os::error_string(errno as uint), errno);
        }

        let after_page = intrinsics::offset(ptr as *const c_void,
                                            (full_size - page_size) as int);
        ret = mman::mprotect(after_page as *mut c_void, page_size as size_t,
                             PROT_NONE);
        if ret != 0 {
            let errno = os::errno();
            panic!("mprotect failed: {} ({})",
                   os::error_string(errno as uint), errno);
        }

        intrinsics::offset(ptr as *const c_void, page_size as int) as *mut u8
    }

    unsafe fn deallocate(&self, ptr: *mut u8, size: uint, _: uint) {
        let page_size = os::page_size();
        let full_size = round_up(size, page_size) + 2 * page_size;

        let start_page = intrinsics::offset(ptr as *const c_void,
                                            -(page_size as int));

        let ret = mman::munmap(start_page as *mut c_void,
                               full_size as size_t);
        if ret != 0 {
            let errno = os::errno();
            panic!("munmap failed: {} ({})",
                   os::error_string(errno as uint), errno);
        }
    }
}


#[cfg(any(target_os = "linux", target_os = "android"))]
mod impadv {
    use libc::consts::os::bsd44::MADV_DONTFORK;
    use libc::EINVAL;
    use libc::funcs::bsd44;
    use libc::types::common::c95::c_void;
    use libc::types::os::arch::c95::{c_int, size_t};
    use std::os;


    pub unsafe fn madvise(ptr: *mut u8, size: uint) {
        let dont_dump: c_int = 16;
        let ret = bsd44::madvise(ptr as *mut c_void, size as size_t,
                                 dont_dump | MADV_DONTFORK);
        if ret != 0 {
            let errno = os::errno();
            // FIXME: EINVAL errors are currently ignored because
            // MADV_DONTDUMP and MADV_DONTFORK are not valid advices on
            // old kernels respectively Linux < 3.4 and Linux < 2.6.16.
            // There should be a better way to check for the availability
            // of this flag in the kernel and in the libc.
            if errno != EINVAL as int {
                panic!("madvise failed: {} ({})",
                       os::error_string(errno as uint), errno);
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod impadv {
    use libc::funcs::bsd44;
    use libc::types::common::c95::c_void;
    use libc::consts::os::bsd44::MADV_ZERO_WIRED_PAGES;
    use libc::types::os::arch::c95::size_t;
    use std::os;


    pub unsafe fn madvise(ptr: *mut u8, size: uint) {
        let ret = bsd44::madvise(ptr as *mut c_void, size as size_t,
                                 MADV_ZERO_WIRED_PAGES);
        if ret != 0 {
            let errno = os::errno();
            panic!("madvise failed: {} ({})",
                   os::error_string(errno as uint), errno);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android",
              target_os = "macos", target_os = "ios")))]
mod impadv {
    pub unsafe fn madvise(_: *mut u8, _: uint) {
    }
}


#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
mod impinh {
    pub use libc::types::common::c95::c_void;
    pub use libc::types::os::arch::c95::{c_int, size_t};
    use std::os;


    mod bsdext {
        extern {
            pub fn minherit(addr: *mut super::c_void, len: super::size_t,
                            inherit: super::c_int) -> super::c_int;
        }
    }

    pub unsafe fn minherit(ptr: *mut u8, size: uint) {
        // Value named INHERIT_NONE on freebsd and VM_INHERIT_NONE on
        // macos/ios.
        let inherit_none: c_int = 2;
        let ret = bsdext::minherit(ptr as *mut c_void, size as size_t,
                                   inherit_none);
        if ret != 0 {
            let errno = os::errno();
            panic!("minherit failed: {} ({})",
                   os::error_string(errno as uint), errno);
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios",
              target_os = "freebsd")))]
mod impinh {
    pub unsafe fn minherit(_: *mut u8, _: uint) {
    }
}


unsafe fn alloc<A: Allocator, T>(count: uint) -> *mut T {
    let size_of_t = mem::size_of::<T>();

    assert!(size_of_t != 0 && count != 0);

    let size = count.checked_mul(&size_of_t)
                    .expect("alloc length overflow");

    // allocate
    let allocator: A = Allocator::new();
    let ptr = allocator.allocate(size, mem::min_align_of::<T>()) as *mut T;

    // mlock
    let ret = mman::mlock(ptr as *const c_void, size as size_t);
    if ret != 0 {
        let errno = os::errno();
        panic!("mlock failed: {} ({})",
               os::error_string(errno as uint), errno);
    }

    // madvise and minherit
    self::impadv::madvise(ptr as *mut u8, size);
    self::impinh::minherit(ptr as *mut u8, size);

    ptr
}

unsafe fn dealloc<A: Allocator, T>(ptr: *mut T, count: uint) {
    let size_of_t = mem::size_of::<T>();

    assert!(!ptr.is_null());
    assert!(size_of_t != 0);
    assert!(count != 0);

    let size = count.checked_mul(&size_of_t)
                    .expect("alloc length overflow");

    // zero-out
    // FIXME: not sure how much this llvm intrinsics could not be
    // optimized-out, maybe it would be better to use memset_s.
    intrinsics::volatile_set_memory(ptr, 0, count);

    // munlock
    let ret = mman::munlock(ptr as *const c_void, size as size_t);
    if ret != 0 {
        let errno = os::errno();
        panic!("munlock failed: {} ({})",
               os::error_string(errno as uint), errno);
    }

    // deallocate
    let allocator: A = Allocator::new();
    allocator.deallocate(ptr as *mut u8, size, mem::min_align_of::<T>())
}


/// Secure Buffer.
pub struct SBuf<A, T> {
    len: uint,
    ptr: *mut T
}

impl<A: Allocator, T: Copy> SBuf<A, T> {
    fn from_raw_parts(length: uint, ptr: *mut T) -> SBuf<A, T> {
        SBuf {
            len: length,
            ptr: ptr
        }
    }

    fn size(&self) -> uint {
        self.len * mem::size_of::<T>()
    }

    pub fn len(&self) -> uint {
        self.len
    }

    fn with_length(length: uint) -> SBuf<A, T> {
        if mem::size_of::<T>() == 0 || length == 0 {
            return SBuf::from_raw_parts(0, 0 as *mut T);
        }

        let ptr = unsafe {
            alloc::<A, T>(length)
        };
        SBuf::from_raw_parts(length, ptr)
    }

    /// New allocated buffer with its memory zeroed-out.
    #[allow(experimental)]
    pub fn new_zero(length: uint) -> SBuf<A, T> {
        let n = SBuf::with_length(length);
        unsafe {
            ptr::zero_memory(n.ptr, length);
        }
        n
    }

    /// New allocated buffer with its memory randomly generated.
    pub fn new_rand(length: uint) -> SBuf<A, T> {
        let mut n = SBuf::with_length(length);
        let rng = &mut utils::urandom_rng();
        rng.fill_bytes(unsafe {
            mem::transmute(Slice {
                data: n.as_mut_ptr() as *const u8,
                len: n.size()
            })
        });
        n
    }

    /// New allocated buffer with its `length` elements initialized from
    /// provided closure `op`.
    pub fn from_fn(length: uint, op: |uint| -> T) -> SBuf<A, T> {
        let mut n = SBuf::with_length(length);
        for i in range(0u, length) {
            n[i] = op(i);
        }
        n
    }

    /// New buffer from slice.
    pub fn from_slice(values: &[T]) -> SBuf<A, T> {
        unsafe {
            SBuf::from_buf(values.as_ptr(), values.len())
        }
    }

    /// New buffer from unsafe buffer.
    pub unsafe fn from_buf(buf: *const T, length: uint) -> SBuf<A, T> {
        assert!(!buf.is_null());
        let n = SBuf::with_length(length);
        ptr::copy_nonoverlapping_memory(n.ptr, buf, n.len);
        n
    }

    /// Build a new instance by concatenating `items` together.
    pub fn from_slices(items: &[&[T]]) -> SBuf<A, T> {
        let length = items.iter().map(|x| x.len()).sum();
        let n = SBuf::with_length(length);
        let mut idx: int = 0;

        unsafe {
            for it in items.iter() {
                ptr::copy_nonoverlapping_memory(n.ptr.offset(idx),
                                                it.as_ptr(), it.len());
                idx += it.len() as int;
            }
        }
        n
    }

    /// Build a new instance by concatenating `items` together.
    pub fn from_sbufs(items: &[&SBuf<A, T>]) -> SBuf<A, T> {
        let v: Vec<&[T]> = items.iter().map(|x| (*x)[]).collect();
        SBuf::from_slices(v[])
    }

    /// Return an immutable pointer to buffer's memory.
    pub fn as_ptr(&self) -> *const T {
        // (seb) Comment copied from vec.rs:
        // If we have a 0-sized vector, then the base pointer should not be NULL
        // because an iterator over the slice will attempt to yield the base
        // pointer as the first element in the vector, but this will end up
        // being Some(NULL) which is optimized to None.
        if mem::size_of::<T>() == 0 {
            heap::EMPTY as *const T
        } else {
            self.ptr as *const T
        }
    }

    /// Return a mutable pointer to buffer's memory.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        // see above for the 0-size check
        if mem::size_of::<T>() == 0 {
            heap::EMPTY as *mut T
        } else {
            self.ptr
        }
    }

    /// Work with `self` as a slice.
    pub fn as_slice(&self) -> &[T] {
        unsafe {
            mem::transmute(Slice {
                data: self.as_ptr(),
                len: self.len
            })
        }
    }

    /// Work with `self` as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe {
            mem::transmute(Slice {
                data: self.as_mut_ptr() as *const T,
                len: self.len
            })
        }
    }

    /// Cast `self` with another type and return a slice on it.
    pub fn as_cast<U>(&self) -> &[U] {
        let bytes_size = self.size();
        let dst_type_size = mem::size_of::<U>();
        assert!(bytes_size > 0 && bytes_size % dst_type_size == 0);
        unsafe {
            mem::transmute(Slice {
                data: self.ptr as *const U,
                len: bytes_size / dst_type_size
            })
        }
    }

    /// Cast `self` with another type and return a mut slice on it.
    pub fn as_mut_cast<U>(&mut self) -> &mut [U] {
        let bytes_size = self.size();
        let dst_type_size = mem::size_of::<U>();
        assert!(bytes_size > 0 && bytes_size % dst_type_size == 0);
        unsafe {
            mem::transmute(Slice {
                data: self.ptr as *const U,
                len: bytes_size / dst_type_size
            })
        }
    }

    /// Return a reference to the value at index `index`. Fails if
    /// `index` is out of bounds.
    pub fn get(&self, index: uint) -> &T {
        &self[][index]
    }

    /// Return a mutable reference to the value at index `index`. Fails
    /// if `index` is out of bounds.
    pub fn get_mut(&mut self, index: uint) -> &mut T {
        &mut self[mut][index]
    }

    /// Return an iterator over references to the elements of the buffer
    /// in order.
    pub fn iter(&self) -> Items<T> {
        self[].iter()
    }

    /// Return an iterator over mutable references to the elements of the
    /// buffer in order.
    pub fn iter_mut(&mut self) -> MutItems<T> {
        self[mut].iter_mut()
    }

    /// Return a slice of self spanning the interval [`start`, `end`).
    /// Fails when the slice (or part of it) is outside the bounds of self,
    /// or when `start` > `end`.
    pub fn slice(&self, start: uint, end: uint) -> &[T] {
        self[][start..end]
    }

    /// Return a mutable slice of `self` between `start` and `end`.
    /// Fails when `start` or `end` point outside the bounds of `self`, or when
    /// `start` > `end`.
    pub fn slice_mut(&mut self, start: uint, end: uint) -> &mut [T] {
        self[mut][mut start..end]
    }

    /// Return a slice of `self` from `start` to the end of the buffer.
    /// Fails when `start` points outside the bounds of self.
    pub fn slice_from(&self, start: uint) -> &[T] {
        self[][start..]
    }

    /// Return a mutable slice of self from `start` to the end of the buffer.
    /// Fails when `start` points outside the bounds of self.
    pub fn slice_from_mut(&mut self, start: uint) -> &mut [T] {
        self[mut][mut start..]
    }

    /// Return a slice of self from the start of the buffer to `end`.
    /// Fails when `end` points outside the bounds of self.
    pub fn slice_to(&self, end: uint) -> &[T] {
        self[][..end]
    }

    /// Return a mutable slice of self from the start of the buffer to `end`.
    /// Fails when `end` points outside the bounds of self.
    pub fn slice_to_mut(&mut self, end: uint) -> &mut [T] {
        self[mut][mut ..end]
    }

    /// Return a pair of mutable slices that divides the buffer at an index.
    ///
    /// The first will contain all indices from `[0, mid)` (excluding the
    /// index `mid` itself) and the second will contain all indices from
    /// `[mid, len)` (excluding the index `len` itself). Fails if
    /// `mid > len`.
    pub fn split_at_mut(&mut self, mid: uint) -> (&mut [T], &mut [T]) {
        self[mut].split_at_mut(mid)
    }

    /// Reverse the order of elements in a buffer, in place.
    pub fn reverse(&mut self) {
        self[mut].reverse()
    }
}

impl<A: Allocator, T: FromPrimitive + Copy> SBuf<A, T> {
    /// New buffer from bytes.
    pub fn from_bytes(bytes: &[u8]) -> SBuf<A, T> {
        let len = bytes.len();
        let mut n: SBuf<A, T> = SBuf::with_length(len);

        for i in range(0u, len) {
            n[i] = FromPrimitive::from_u8(bytes[i]).unwrap();
        }
        n
    }
}

#[unsafe_destructor]
impl<A: Allocator, T: Copy> Drop for SBuf<A, T> {
    fn drop(&mut self) {
        if self.len != 0 && !self.ptr.is_null() && mem::size_of::<T>() != 0 {
            unsafe {
                // There is no explicit drop on each T elements, as T
                // is contrained to Copy it should not be an issue?
                // It would create an issue to use ptr::read() as it could
                // copy memory slot to temporary objects.
                dealloc::<A, T>(self.ptr, self.len)
            }
        }
    }
}

impl<A: Allocator, T: Copy> Clone for SBuf<A, T> {
    fn clone(&self) -> SBuf<A, T> {
        SBuf::from_slice(self[])
    }
}

impl<A: Allocator, T: Copy> Index<uint, T> for SBuf<A, T> {
    fn index(&self, index: &uint) -> &T {
        self.get(*index)
    }
}

impl<A: Allocator, T: Copy> IndexMut<uint, T> for SBuf<A, T> {
    fn index_mut(&mut self, index: &uint) -> &mut T {
        self.get_mut(*index)
    }
}

impl<A: Allocator, T: Copy> ops::Slice<uint, [T]> for SBuf<A, T> {
    fn as_slice_<'a>(&'a self) -> &'a [T] {
        self.as_slice()
    }

    fn slice_from_or_fail<'a>(&'a self, start: &uint) -> &'a [T] {
        self.as_slice().slice_from_or_fail(start)
    }

    fn slice_to_or_fail<'a>(&'a self, end: &uint) -> &'a [T] {
        self.as_slice().slice_to_or_fail(end)
    }

    fn slice_or_fail<'a>(&'a self, start: &uint, end: &uint) -> &'a [T] {
        self.as_slice().slice_or_fail(start, end)
    }
}

impl<A: Allocator, T: Copy> ops::SliceMut<uint, [T]> for SBuf<A, T> {
    fn as_mut_slice_<'a>(&'a mut self) -> &'a mut [T] {
        self.as_mut_slice()
    }

    fn slice_from_or_fail_mut<'a>(&'a mut self, start: &uint) -> &'a mut [T] {
        self.as_mut_slice().slice_from_or_fail_mut(start)
    }

    fn slice_to_or_fail_mut<'a>(&'a mut self, end: &uint) -> &'a mut [T] {
        self.as_mut_slice().slice_to_or_fail_mut(end)
    }

    fn slice_or_fail_mut<'a>(&'a mut self, start: &uint, end: &uint) -> &'a mut [T] {
        self.as_mut_slice().slice_or_fail_mut(start, end)
    }
}

impl<A: Allocator, T: Copy> ops::Deref<[T]> for SBuf<A, T> {
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<A: Allocator, T: Copy> ops::DerefMut<[T]> for SBuf<A, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<A: Allocator, T: Copy> PartialEq for SBuf<A, T> {
    fn eq(&self, other: &SBuf<A, T>) -> bool {
        utils::bytes_eq(self[], other[])
    }
}

impl<A: Allocator, T: Copy> Eq for SBuf<A, T> {
}

impl<A: Allocator, T: fmt::Show + Copy> fmt::Show for SBuf<A, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self[].fmt(f)
    }
}

impl<A: Allocator,
     E,
     S: Encoder<E>,
     T: Encodable<S, E> + Copy> Encodable<S, E> for SBuf<A, T> {
    fn encode(&self, s: &mut S) -> Result<(), E> {
        self[].encode(s)
    }
}

impl<A: Allocator,
     E,
     D: Decoder<E>,
     T: Decodable<D, E> + Copy> Decodable<D, E> for SBuf<A, T> {
    fn decode(d: &mut D) -> Result<SBuf<A, T>, E> {
        d.read_seq(|d, len| {
            let mut n = SBuf::with_length(len);
            for i in range(0u, len) {
                n[i] = try!(d.read_seq_elt(i, |d| Decodable::decode(d)));
            }
            Ok(n)
        })
    }
}

impl<A: Allocator> ToHex for SBuf<A, u8> {
    fn to_hex(&self) -> String {
        self[].to_hex()
    }
}


#[cfg(test)]
mod test {
    use sbuf::{StdHeapAllocator, SBuf};


    #[test]
    fn test_basic() {
        let mut r: [i64, ..256] = [0, ..256];
        let mut s: [u8, ..256] = [0, ..256];

        let a: SBuf<StdHeapAllocator, i64> = SBuf::new_zero(256);
        assert!(a[] == r);

        for i in range(0u, 256) {
            r[i] = i as i64;
            s[i] = i as u8;
        }

        let b: SBuf<StdHeapAllocator, i64> = SBuf::from_bytes(s[]);
        assert!(b[] == r);

        let c: SBuf<StdHeapAllocator, i64> = SBuf::from_slice(r[]);
        assert!(c[] == r);

        let d: SBuf<StdHeapAllocator, i64> = unsafe {
            SBuf::from_buf(c.as_ptr(), c.len())
        };
        assert!(d == c);
    }
}
