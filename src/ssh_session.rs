#![allow(unused_imports)]

extern crate libc;

use libssh::*;
use libssh_server;
use ssh_key::SSHKey;
use ssh_message::SSHMessage;

use std::mem;
use std::ptr;
use self::libc::types::common::c95::c_void;

pub struct SSHSession {
	_session: *mut ssh_session_struct
}

impl SSHSession {
	pub fn new(host: Option<&str>) -> Result<SSHSession, ()> {
		let ptr = unsafe { ssh_new() };
		assert!(ptr.is_not_null());

		let session = SSHSession {_session: ptr};
		if host.is_some() {
			try!(session.set_host(host.unwrap()))
		}

		Ok(session)
	}

	pub fn set_host(&self, host: &str) -> Result<(),()> {
		assert!(self._session.is_not_null());

		let opt = ssh_options_e::SSH_OPTIONS_HOST as u32;
		let res = host.with_c_str(|h| {
			unsafe { ssh_options_set(self._session, opt, h as *const c_void) }
		});

		match res {
			SSH_OK => Ok(()),
			_           => Err(())
		}
	}

	pub fn connect(&self, verify_public_key: |remote_public_key: &SSHKey| -> bool)
			-> Result<(), String>
	{
		assert!(self._session.is_not_null());

		let res = unsafe { ssh_connect(self._session) };
		if res != SSH_OK {
			let ptr = self._session as *mut c_void;

			let err_msg = unsafe {
				let err = ssh_get_error(ptr);
				assert!(err.is_not_null());

				String::from_raw_buf(err as *const u8)
			};
			return Err(err_msg);
		}

		let remote_public_key = try!(
			SSHKey::from_session(self).map_err(|err| err.to_string())
		);
		if !verify_public_key(&remote_public_key) {
			self.disconnect();
			return Err("authentication failed".to_string());
		}
		else {
			Ok(())
		}
	}

	pub fn disconnect(&self) {
		assert!(self._session.is_not_null());

		unsafe {
			ssh_disconnect(self._session);
		}
	}

	pub fn auth_by_public_key(&self, username: Option<&str>, pubkey: &SSHKey)
		-> Result<(),ssh_auth_e>
	{
		/*
		    SSH_AUTH_ERROR: A serious error happened.
		    SSH_AUTH_DENIED: The server doesn't accept that public key as an authentication token. Try another key or another method.
		    SSH_AUTH_PARTIAL: You've been partially authenticated, you still have to use another method.
		    SSH_AUTH_SUCCESS: The public key is accepted, you want now to use ssh_userauth_pubkey(). SSH_AUTH_AGAIN: In nonblocking mode, you've got to call this again later.
		*/
		assert!(self._session.is_not_null());

		let key = pubkey.raw();
		let func = |:usr| unsafe {
			ssh_userauth_try_publickey(self._session, usr, key)
		};

		let ires = if username.is_none() { func(ptr::null()) } else
			{ username.unwrap().with_c_str(func) };

		let res = ssh_auth_e::from_i32(ires);
		match res {
			ssh_auth_e::SSH_AUTH_SUCCESS => Ok(()),
			ssh_auth_e::SSH_AUTH_PARTIAL |
			ssh_auth_e::SSH_AUTH_DENIED |
			ssh_auth_e::SSH_AUTH_AGAIN |
			ssh_auth_e::SSH_AUTH_ERROR => Err(res),
			x => {panic!("{}", x);}
		}
	}

	pub fn raw(&self) -> *mut ssh_session_struct {
		assert!(self._session.is_not_null());
		self._session
	}

	pub fn set_port(&self, port: &str) -> Result<(),&'static str> {
		assert!(self._session.is_not_null());

		let opt = ssh_options_e::SSH_OPTIONS_PORT as u32;
		let res = port.with_c_str(|p| unsafe {
			ssh_options_set(self._session, opt, p as *const c_void)
		});

		match res {
			SSH_OK => Ok(()),
			_              => Err("ssh_options_set() failed for setting port")
		}
	}

	pub fn auth_with_public_key<'a>(&self, verify_public_key: |&SSHKey| -> bool)
			-> Result<(),&'a str>
	{
		const MAX_ATTEMPTS: uint = 5;

		for _  in range(0, MAX_ATTEMPTS) {
			let msg = try!(SSHMessage::from_session(self));

			let type_ = msg.get_type();
			let subtype = msg.get_subtype();

			match (type_, subtype) {
				(libssh_server::ssh_requests_e::SSH_REQUEST_AUTH,
						libssh_server::SSH_AUTH_METHOD_PUBLICKEY) =>
				{
					let remote_public_key = try!(SSHKey::from_message(&msg));
					
					if verify_public_key(&remote_public_key) {
						return Ok(());
					}
				},

				_ => {
					try!(msg.reply_default())
				}
			}
		}
		Err("authentication with public key failed")
	}

	pub fn handle_key_exchange(&self) -> Result<(),&'static str> {
		assert!(self._session.is_not_null());

		let session: *mut libssh_server::ssh_session_struct = unsafe {
			mem::transmute(self._session)
		};
		let res = unsafe { libssh_server::ssh_handle_key_exchange(session) };
		match res {
			SSH_OK => Ok(()),
			_              => Err("ssh_handle_key_exchange() failed")
		}
	}

	pub fn set_log_level(&self, level: i32) -> Result<(),&'static str> {
		assert!(self._session.is_not_null());
		let res = unsafe { ssh_set_log_level(level) };
		match res {
			SSH_OK => Ok(()),
			_              => Err("ssh_set_log_level() failed")
		}
	}
}

impl Drop for SSHSession {
	fn drop(&mut self) {
		unsafe {
			ssh_disconnect(self._session);
			ssh_free(self._session);
		}
	}
}
