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
pub extern "C" fn crypto_get_secret() -> *const c_void {
	let secret = StaticSecret::new(OsRng);
	let boxed_secret = Box::new(secret);
	return Box::into_raw(boxed_secret) as *mut c_void;
}
#[no_mangle]
pub extern "C" fn crypto_get_public(secret_ptr: *mut c_void) -> *const c_void {
	let mut boxed_secret = unsafe { Box::from_raw(secret_ptr as *mut StaticSecret) };

	let secret = *boxed_secret;
	let public = PublicKey::from(&secret);
	*boxed_secret = secret;
	Box::into_raw(boxed_secret); // stop managing the memory

	let boxed_public = Box::from(public);
	return Box::into_raw(boxed_public) as *mut c_void;
}
#[no_mangle]
pub extern "C" fn crypto_get_shared(secret_ptr: *mut c_void, public_ptr: *mut c_void, payload: *mut u8) {
	let mut boxed_secret = unsafe { Box::from_raw(secret_ptr as *mut StaticSecret) };
	let mut boxed_public = unsafe { Box::from_raw(public_ptr as *mut PublicKey) };

	let secret = *boxed_secret;
	let public = *boxed_public;

	let shared = secret.diffie_hellman(&public);
	let bytes = shared.as_bytes();
	unsafe {
		for i in 0..32 {
			*(payload.offset(i)) = bytes[i as usize];
		}
	}
	*boxed_secret = secret;
	*boxed_public = public;

	Box::into_raw(boxed_secret);
	Box::into_raw(boxed_public);
}
#[no_mangle]
pub extern "C" fn crypto_drop_secret(secret_ptr: *mut c_void) { let _ = unsafe { Box::from_raw(secret_ptr as *mut StaticSecret) }; }
#[no_mangle]
pub extern "C" fn crypto_drop_public(public_ptr: *mut c_void) { let _ = unsafe { Box::from_raw(public_ptr as *mut PublicKey) }; }