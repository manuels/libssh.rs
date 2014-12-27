#![allow(unused_imports)]

extern crate libc;

use libssh_server::*;
use libssh;
use ssh_key;
use ssh_session::SSHSession;

use std::mem;
use std::ptr;
use self::libc::types::common::c95::c_void;

pub struct SSHMessage {
	_msg: *mut ssh_message_struct
}

impl Drop for SSHMessage {
	fn drop(&mut self) {
		/*
		 * not necessary: issues "double free()" panic
		unsafe {
			ssh_message_free(self._msg)
		}*/
	}
}
impl SSHMessage {
	pub fn from_session(session: &SSHSession) -> Result<SSHMessage, &'static str> {
		let session: *mut ssh_session_struct = unsafe {
			mem::transmute(session.raw())
		};
		assert!(session.is_not_null());

		let msg = unsafe { ssh_message_get(session) };
		if msg.is_null() {
			Err("ssh_message_get() returned NULL")
		}
		else {
			Ok(SSHMessage { _msg: msg })
		}
	}

	pub fn raw(self: &Self) -> *mut ssh_message_struct {
		self._msg
	}

	pub fn get_type(self: &Self) -> ssh_requests_e {
		assert!(self._msg.is_not_null());

		let ityp = unsafe { ssh_message_type(self._msg) };
		ssh_requests_e::from_u32(ityp as u32)
	}

	pub fn get_subtype(self: &Self) -> i32 {
		assert!(self._msg.is_not_null());

		unsafe { ssh_message_subtype(self._msg) }
	}

	pub fn reply_default(&self) -> Result<(), &'static str> {
		assert!(self._msg.is_not_null());

		let res = unsafe { ssh_message_reply_default(self._msg) };
		match res {
			SSH_OK => Ok(()),
			_      => Err("ssh_message_reply_default() failed"),
		}
	}
}
