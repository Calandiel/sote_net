use rand_core::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use sha3::{Digest, Sha3_256};


// SOCKET
#[no_mangle]
pub extern "C" fn socket_open(ip_a: u8, ip_b: u8, ip_c: u8, ip_d: u8, port: u16, target_ptr: *mut *mut c_void) -> i32 {
	let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip_a, ip_b, ip_c, ip_d)), port);
	let socket = match UdpSocket::bind(addr) {
		Ok(s) => s,
		Err(_) => {
			return 1;
		}
	};
	match socket.set_nonblocking(true) {
		Ok(_) => { },
		Err(_) => { return 2; }
	};
	let boxed_socket = Box::new(socket);

	let raw_socket = Box::into_raw(boxed_socket);
	unsafe {
		*target_ptr = raw_socket as *const UdpSocket as *mut c_void;
	}
	return 0;
}
#[no_mangle]
pub extern "C" fn socket_close(socket_ptr: *mut c_void) {
	unsafe { Box::from_raw(socket_ptr as *mut UdpSocket) };
}
#[no_mangle]
pub extern "C" fn socket_recv_from(
	socket_ptr: *mut c_void,
	buffer_ptr: *mut u8, buffer_size: u32,
	packet_size: *mut u32,
	addr: *mut u8, addr_port: *mut u16) -> i32 {

	let mut boxed_socket = unsafe { Box::from_raw(socket_ptr as *mut UdpSocket) };
	let socket = *boxed_socket;

	let buff = unsafe { std::slice::from_raw_parts_mut(buffer_ptr, buffer_size as usize) };
	let (number_of_bytes, src_addr) = match socket.recv_from(buff) {
		Ok(r) => r,
		Err(_) => {
			*boxed_socket = socket;
			Box::into_raw(boxed_socket);
			return 1;
		}
	};
	unsafe {
		*packet_size = number_of_bytes as u32;
		*addr_port = src_addr.port();
		match src_addr.ip() {
			IpAddr::V4(v) => {
				let p = v.octets();
				for elem in 0..4 {
					*addr.offset(elem) = p[elem as usize];
				}
			},
			IpAddr::V6(_) => {
				*boxed_socket = socket;
				Box::into_raw(boxed_socket);
				return 2;
			}
		};
	}

	*boxed_socket = socket;
	Box::into_raw(boxed_socket);
	return 0;
}
#[no_mangle]
pub extern "C" fn socket_send_to(socket_ptr: *mut c_void, ip_a: u8, ip_b: u8, ip_c: u8, ip_d: u8, port: u16, buffer_ptr: *mut u8, buffer_size: u32) -> i32 {
	let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip_a, ip_b, ip_c, ip_d)), port);
	let mut boxed_socket = unsafe { Box::from_raw(socket_ptr as *mut UdpSocket) };
	let socket = *boxed_socket;

	let buff = unsafe { std::slice::from_raw_parts_mut(buffer_ptr, buffer_size as usize) };
	match socket.send_to(buff, addr) {
		Err(_) => {
			*boxed_socket = socket;
			Box::into_raw(boxed_socket);
			return 1;
		},
		_ => {}
	};


	*boxed_socket = socket;
	Box::into_raw(boxed_socket);
	return 0;
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
}


// HASH
#[no_mangle]
pub extern "C" fn hash_sha3(sha_ptr : *mut *mut c_void) {
	// create a SHA3-256 object
	let hasher = Sha3_256::new();
	// box it
	let b = Box::new(hasher);
	// get a pointer
	let ptr = Box::into_raw(b);

	// write the result
	unsafe {
		*sha_ptr = ptr as *mut c_void;
	}
}

#[no_mangle]
pub extern "C" fn hash_digest(sha_ptr : *mut c_void, input_buffer : *const u8, input_buffer_size : u32) {
	let mut b = unsafe { Box::from_raw(sha_ptr as *mut Sha3_256) };
	let mut hasher = *b;

	let buffer = unsafe { std::slice::from_raw_parts(input_buffer, input_buffer_size as usize) };
	hasher.update(buffer);

	*b = hasher;
	Box::into_raw(b);
}

#[no_mangle]
pub extern "C" fn hash_finalize(sha_ptr : *mut c_void, output_buffer : *mut u8, output_buffer_size : u32) -> i32 {
	if output_buffer_size != 32 {
		return 1;
	}
	
	let b = unsafe { Box::from_raw(sha_ptr as *mut Sha3_256) };
	let hasher = *b;

	let result = hasher.finalize();

	for elem in 0..32 {
		unsafe {
			*(output_buffer.offset(elem)) = result[elem as usize];
		}
	}

	return 0;
}