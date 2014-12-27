extern crate libc;

use libssh_server as libssh;
use ssh_key;
use ssh_session;
use ssh_message;

use std::mem;
use std::ptr;
use self::libc::types::common::c95::c_void;

pub struct SSHBind {
	_bind: *mut libssh::ssh_bind_struct
}

impl SSHBind {
	pub fn new(priv_key_file: &str, host: Option<&str>, port: Option<&str>)
		-> Result<SSHBind, &'static str>
	{
		let ptr = unsafe { libssh::ssh_bind_new() };
		assert!(ptr.is_not_null());

		let bind = SSHBind { _bind: ptr };
		
		if host.is_some() {
			try!(bind.set_host(host.unwrap()));
		}
		try!(bind.set_port(port.unwrap_or("22")));

		try!(bind.set_private_key_file(priv_key_file));

		Ok(bind)
	}

	pub fn set_host(&self, host: &str) -> Result<(),&'static str> {
		assert!(self._bind.is_not_null());

		let opt = libssh::ssh_bind_options_e::SSH_BIND_OPTIONS_BINDADDR as u32;
		let res = host.with_c_str(|h| {
			unsafe { libssh::ssh_bind_options_set(self._bind, opt, h as *const c_void) }
		});

		match res {
			libssh::SSH_OK => Ok(()),
			_              => Err("ssh_bind_options_set() failed for setting host")
		}
	}

	pub fn set_port(&self, port: &str) -> Result<(),&'static str> {
		assert!(self._bind.is_not_null());

		let opt = libssh::ssh_bind_options_e::SSH_BIND_OPTIONS_BINDPORT as u32;
		let res = port.with_c_str(|p| unsafe {
			libssh::ssh_bind_options_set(self._bind, opt, p as *const c_void)
		});

		match res {
			libssh::SSH_OK => Ok(()),
			_              => Err("ssh_bind_options_set() failed for setting port")
		}
	}

	pub fn set_private_key_file(&self, key_file: &str) -> Result<(),&'static str> {
		assert!(self._bind.is_not_null());

		let opt_type = libssh::ssh_bind_options_e::SSH_BIND_OPTIONS_HOSTKEY as u32;
		let res = "ssh-rsa".with_c_str(|typ| unsafe {
			libssh::ssh_bind_options_set(self._bind, opt_type, typ as *const c_void)
		});
		if res != libssh::SSH_OK {
			return Err("ssh_bind_options_set() failed for private key (HOSTKEY)");
		}

		let opt_key = libssh::ssh_bind_options_e::SSH_BIND_OPTIONS_RSAKEY as u32;
		let res = key_file.with_c_str(|pkey_file| unsafe {
			libssh::ssh_bind_options_set(self._bind, opt_key, pkey_file as *const c_void)
		});

		match res {
			libssh::SSH_OK => Ok(()),
			_              => Err("ssh_bind_options_set() failed for private key (RSAKEY)")
		}
	}

	pub fn listen(&self) -> Result<(),&'static str> {
		assert!(self._bind.is_not_null());

		let res = unsafe { libssh::ssh_bind_listen(self._bind) };
		debug!("listen={}", res);
		match res {
			libssh::SSH_OK => Ok(()),
			_              => Err("ssh_bind_listen() failed")
		}
	}

	pub fn accept(&self, session: &ssh_session::SSHSession) -> Result<(),&'static str> {
		assert!(self._bind.is_not_null());

		let res = unsafe { libssh::ssh_bind_accept(self._bind, mem::transmute(session.raw())) };
		match res {
			libssh::SSH_OK => Ok(()),
			_              => Err("ssh_bind_accept() failed")
		}
	}

	pub fn set_log_level(&self, level: i32) -> Result<(),&'static str> {
		assert!(self._bind.is_not_null());
		let res = unsafe { libssh::ssh_set_log_level(level) };
		match res {
			libssh::SSH_OK => Ok(()),
			_              => Err("ssh_set_log_level() failed")
		}
	}
}
