use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use rand_core::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};

// LIBRARY
#[no_mangle]
pub extern "C" fn lib_initialize() -> bool {
	true
}

#[no_mangle]
pub extern "C" fn lib_deinitialize() -> bool {
	true
}

// SOCKET
#[no_mangle]
pub extern "C" fn server_open(password: *const i8) -> bool {
	true
}


// CRYPTO
#[no_mangle]
pub extern "C" fn crypto_get_keys(secret: *mut u8, public: *mut u8) {
	let s = StaticSecret::new(OsRng);
	let p = PublicKey::from(&s);
	let s_bytes = s.to_bytes();
	let p_bytes = p.to_bytes();

	unsafe {
		for elem in 0..32 {
			*(secret.offset(elem)) = s_bytes[elem as usize];
			*(public.offset(elem)) = p_bytes[elem as usize];
		}
	}
}
#[no_mangle]
pub extern "C" fn crypto_get_shared(secret: *mut u8, public: *mut u8, payload: *mut u8) {
	let mut s_bytes: [u8; 32] = [0; 32];
	let mut p_bytes: [u8; 32] = [0; 32];

	unsafe {
		for elem in 0..32 {
			s_bytes[elem] = *(secret.offset(elem as isize));
			p_bytes[elem] = *(public.offset(elem as isize));
		}
	}

	let s = StaticSecret::from(s_bytes);
	let p = PublicKey::from(p_bytes);

	let shared = s.diffie_hellman(&p);
	let bytes = shared.as_bytes();
	unsafe {
		for i in 0..32 {
			*(payload.offset(i)) = bytes[i as usize];
		}
	}
	/*
	s_bytes = s.to_bytes();
	p_bytes = p.to_bytes();
	unsafe {
		for elem in 0..32 {
			*(secret.offset(elem as isize)) = s_bytes[elem];
			*(public.offset(elem as isize)) = p_bytes[elem];
		}
	}
	*/
}