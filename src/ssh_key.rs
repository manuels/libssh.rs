#![allow(unused_imports)]
#[phase(plugin, link)] extern crate log;

extern crate libc;

use libssh::*;
use libssh_server;
use ssh_message::SSHMessage;
use ssh_session::SSHSession;

use self::libc::types::common::c95::c_void;
use std::ptr;
use std::mem;

type AuthCb = extern fn(*const i8, *mut i8, u64, i32, i32, *mut libc::types::common::c95::c_void) -> i32;

pub struct SSHKey {
	_key: *mut ssh_key_struct
}

impl Drop for SSHKey {
	fn drop(&mut self) {
		unsafe {
			ssh_key_free(self._key)
		}
	}
}

impl SSHKey {
	pub fn raw(&self) -> *mut ssh_key_struct {
		assert!(self._key.is_not_null());
		self._key
	}

	pub fn private_key_from_base64(b64_key: &str) -> Result<SSHKey, ()> {
		b64_key.with_c_str(|b64_ptr| {
			let mut key = 0 as *mut ssh_key_struct;

			let pwd = ptr::null();
			let auth_fn: Option<AuthCb> = Option::None;
			let auth_data = 0 as *mut c_void;

			let func = ssh_pki_import_privkey_base64;
			let res = unsafe {
				func(b64_ptr, pwd, auth_fn, auth_data, &mut key)
			};
			match res {
				SSH_OK => {
					assert!(key.is_not_null());
					Ok(SSHKey { _key: key })
				},
				_ => Err(()),
			}
		})
	}

	pub fn public_key_from_base64(b64_key: &str, typ: u32) -> Result<SSHKey, ()> {
		let mut key = 0 as *mut ssh_key_struct;

		b64_key.with_c_str(|b64_ptr| {
			let res = unsafe {
				ssh_pki_import_pubkey_base64(b64_ptr, typ, &mut key)
			};

			match res {
				SSH_OK => {
					assert!(key.is_not_null());
					Ok(SSHKey { _key: key })
				},
				_ => Err(()),
			}
		})
	}

	/* used by client to get server's public key */
	pub fn from_session(session: &SSHSession)
			-> Result<SSHKey, &'static str>
	{
		let session_ptr = session.raw();
		assert!(session_ptr.is_not_null());

		let mut key = 0 as *mut ssh_key_struct;

		let res = unsafe {
			ssh_get_publickey(session_ptr, &mut key)
		};
		
		match res {
			SSH_OK => {
				assert!(key.is_not_null());
				Ok(SSHKey { _key: key })
			},
			_ => Err("ssh_get_publickey() failed")
		}
	}

	/* used by server to get client's public key */
	pub fn from_message<'a>(message: &SSHMessage)
		-> Result<SSHKey, &'a str>
	{
		let msg = message.raw();
		assert!(msg.is_not_null());

		let type_ = message.get_type();
		let subtype = message.get_subtype();

		let is_correct_msg_type =
		    type_ == libssh_server::ssh_requests_e::SSH_REQUEST_AUTH
		     && subtype == libssh_server::SSH_AUTH_METHOD_PUBLICKEY;

		if !is_correct_msg_type {
		   	//let msg:String = format!("auth_public_key() expected corresponding message, but got {}:{}",
		   	//		type_, subtype);
		   	let msg = "auth_public_key() expected corresponding message";
		   	return Err(msg)
		}

		let pubkey = unsafe { libssh_server::ssh_message_auth_pubkey(msg) };

		if pubkey.is_null() {
			Err("ssh_message_auth_pubkey() returned NULL")
		}
		else {
			Ok(SSHKey { _key: unsafe {
				mem::transmute(pubkey) }
			})
		}
	}

	pub fn is_private(&self) -> bool {
		assert!(self._key.is_not_null());
		unsafe { ssh_key_is_private(self._key) != 0 }
	}

	pub fn is_public(&self) -> bool {
		assert!(self._key.is_not_null());
		unsafe { ssh_key_is_public(self._key) != 0 }
	}

	/*pub fn get_publickey_hash(&self) -> SSHHash {
	}*/
}

impl PartialEq for SSHKey {
	fn eq(&self, other: &SSHKey) -> bool {
		if self.is_private() ^ self.is_private() {
			// one is a private key, the other not
			return false;
		}

		let what = if self.is_private() {
			ssh_keycmp_e::SSH_KEY_CMP_PRIVATE
		} else {
			ssh_keycmp_e::SSH_KEY_CMP_PUBLIC
		} as u32;

		unsafe { ssh_key_cmp(self._key, other._key, what) == 0 }
	}
}

#[cfg(test)]
mod tests {
	const INVALID_PRIVATE_KEY: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAtVRiaUPBXiqVNw4By07q+nqDAfIKzuo2Nrdm2TbNMaZzcbY4
dYOwr4fj4FcwRx3PkDDTZsDw83GRUqoyk/wbz+TsgRe40S2AlhtJvH+77vcAIoSb
UMCjdBcQxdu+b6nZKJ9kMh+nus6y9/syx3prci6PPcRhyYRjV8UfjgXVYGyXMWgs
rGs5y/Y228ugiwEfgUF+DInmzlnVDbDqzx+nEY09aVPcnckTH9eBddwNN7YCDcY8
/Ag8+ASbuNo7O7zr2i5/n811UTio6ED2GiP0rjgNuW7bYOgiGsHouWoFDVpSn94s
pxA3t9wO+6WCF2px/6AfxM2SNJwy1lewcqBV4QIDAQABAoIBAQCA2TKIzC2WZTnc
giaCOlS8odt/wWcuurzFSrNZfBh4xGdaEPqzfl1JjY0+d5YFoshAFIHTjRxqUHPM
QsZn44g7xNbNsHaSpPuvLjrKKBX56yf8XzAiRJChSFaR0eDTZeS6efBvsZC1LHV9
wtDFcFbzLuR4Jpi5fi udfjskfjjdaskfjad   qAvbxXmBlnAXACKLWLr7lT0VC
kfQHcYxMwKUTJzqDEADC00Dadr6HiaZgvlZfq2CkQaFIqya1LOaG2LocDW2MhHSe
Ojy5L/zlKkRk923/vNxha9zOyr+MOHkDuY767RzQhmVBVtfZzEgiM0PQSdjVShWX
0CHr9hgBAoGBAOIKaLupK04KHQ4zxTVIDjaeW2M83///hiJoXOH8MGGJ3h9skbgJ
ughWmjBohpLJFvIKNs14cwjPi8tDtfkK3QTL/6ACjl8QuN2YlCzY1avltQIPPiou
W53HRrNwhZysdLgH06o/CX6OvW0NJnqTt58q4uXvkyfDEybjLSo7I7khAoGBAM1c
7HoJcNITL5B5mWvh/fqolQyHyMo/4yiLqRsr52rgYGGkiY4lJXPLmtBJFNS7vw/0
7wrnYt6XI/TMTZtIVVovX7jWi+bZh9/VhwxKljFnGav6msAONooscE5PWpiYQ8fs
QsOZx/UcG0kz1QQMNGpWVBM019sA+YgLbq4l5UTBAoGBAINsOeiiOyNsjegsAYUx
F9J5z/iq9DILhxmKRDbAQgDz/8mVfkPao+clMxDiNRwy/rxLZAGi/n8o7MaJ38uk
nUykr0OBOPXc6x8sDzrj95eyPsOrySENQwdBTcIWshidzF8TbeWWMRb8Nvaopq6u
JBzO+o1l9dEwgnohq6jaKbMBAoGBAJrgFpOepRA5Wei6XAMph1JPa0Ds8nfdIKKG
WT1dqgRHPUjGPtsNlqYyignE48nf4aLWFKUDhePa1koa/fg63+vIyIbsfsvViAw9
y8BwS77sQ0cZEzX+QhGInBXi8K8ePhf7TQqY4l0vGkDlryODVNBRVMy7UIMgxA9e
l9UMTVDBAoGBAK7W+4IKkC2tMVEUNoZV6JlSp+WQROKWvyvtv01MiDtJYcfNMFL8
ikwcwZIsiVeoAm6m5J1wKxAdpkz/JDR+x20SJrnFeITAMGaUsqf6JP4SqyazD+0C
7Spmt4KQ/ybYFHnyVelZMs/QiU5eNZGXVzY3RWze7pyZDg1RVYeztOKf
-----END RSA PRIVATE KEY-----
";

	const PRIVATE_KEY1: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAtVRiaUPBXiqVNw4By07q+nqDAfIKzuo2Nrdm2TbNMaZzcbY4
dYOwr4fj4FcwRx3PkDDTZsDw83GRUqoyk/wbz+TsgRe40S2AlhtJvH+77vcAIoSb
UMCjdBcQxdu+b6nZKJ9kMh+nus6y9/syx3prci6PPcRhyYRjV8UfjgXVYGyXMWgs
rGs5y/Y228ugiwEfgUF+DInmzlnVDbDqzx+nEY09aVPcnckTH9eBddwNN7YCDcY8
/Ag8+ASbuNo7O7zr2i5/n811UTio6ED2GiP0rjgNuW7bYOgiGsHouWoFDVpSn94s
pxA3t9wO+6WCF2px/6AfxM2SNJwy1lewcqBV4QIDAQABAoIBAQCA2TKIzC2WZTnc
giaCOlS8odt/wWcuurzFSrNZfBh4xGdaEPqzfl1JjY0+d5YFoshAFIHTjRxqUHPM
QsZn44g7xNbNsHaSpPuvLjrKKBX56yf8XzAiRJChSFaR0eDTZeS6efBvsZC1LHV9
wtDFcFbzLuR4Jpi54knZL2iJudlyhuSn8avvvNrqAvbxXmBlnAXACKLWLr7lT0VC
kfQHcYxMwKUTJzq2G2RAXH2Vdr6HiaZgvlZfq2CkQaFIqya1LOaG2LocDW2MhHSe
Ojy5L/zlKkRk923/vNxha9zOyr+MOHkDuY767RzQhmVBVtfZzEgiM0PQSdjVShWX
0CHr9hgBAoGBAOIKaLupK04KHQ4zxTVIDjaeW2M83///hiJoXOH8MGGJ3h9skbgJ
ughWmjBohpLJFvIKNs14cwjPi8tDtfkK3QTL/6ACjl8QuN2YlCzY1avltQIPPiou
W53HRrNwhZysdLgH06o/CX6OvW0NJnqTt58q4uXvkyfDEybjLSo7I7khAoGBAM1c
7HoJcNITL5B5mWvh/fqolQyHyMo/4yiLqRsr52rgYGGkiY4lJXPLmtBJFNS7vw/0
7wrnYt6XI/TMTZtIVVovX7jWi+bZh9/VhwxKljFnGav6msAONooscE5PWpiYQ8fs
QsOZx/UcG0kz1QQMNGpWVBM019sA+YgLbq4l5UTBAoGBAINsOeiiOyNsjegsAYUx
F9J5z/iq9DILhxmKRDbAQgDz/8mVfkPao+clMxDiNRwy/rxLZAGi/n8o7MaJ38uk
nUykr0OBOPXc6x8sDzrj95eyPsOrySENQwdBTcIWshidzF8TbeWWMRb8Nvaopq6u
JBzO+o1l9dEwgnohq6jaKbMBAoGBAJrgFpOepRA5Wei6XAMph1JPa0Ds8nfdIKKG
WT1dqgRHPUjGPtsNlqYyignE48nf4aLWFKUDhePa1koa/fg63+vIyIbsfsvViAw9
y8BwS77sQ0cZEzX+QhGInBXi8K8ePhf7TQqY4l0vGkDlryODVNBRVMy7UIMgxA9e
l9UMTVDBAoGBAK7W+4IKkC2tMVEUNoZV6JlSp+WQROKWvyvtv01MiDtJYcfNMFL8
ikwcwZIsiVeoAm6m5J1wKxAdpkz/JDR+x20SJrnFeITAMGaUsqf6JP4SqyazD+0C
7Spmt4KQ/ybYFHnyVelZMs/QiU5eNZGXVzY3RWze7pyZDg1RVYeztOKf
-----END RSA PRIVATE KEY-----
";

	const PRIVATE_KEY2: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp0cpxxgI0hmdkXeWXOVlEsiPkPmR5Lpv+Xw64TAZPOy+wt3P
m3DcfDHzNpoJQCJoAE0RMI+YtksCsQy7d1V+XHGzS9Ipflvcvj8eI0TeMHeed26C
E6FNRJeYbptjf9muoLVKzQsVHvmrsuEXZLAZfamoCtWfMwMBLmbW63l0HhBCSZH5
35oPCg6bpMMBS1MkYBf34TZVujRFEqVwdj5+FBG+OI2SVELfoh185biWFWJHt3rL
zPj+eiC4tLHzw1n9WlsRqtnyl3eF1BqbrBiEj9kaVBIzGD0d7LsAISpQC8y8nTOU
CHARRxSiHLZCXLWwc2Djss+YYUEn7vCX6VCTPQIDAQABAoIBAHMUu0I0X8UjSErO
igyI6Ls+bb6gY+WG+ggalmtb6tEGUsq/TNe0kouC1b8nw9tykDg8zOmqsLYg7s4d
Y09a6t7wfhhYkqFS04+y3qoG9BFGCihCR4z3uK/K11yo3JAVk1UOxFJCIJq5y4z5
3F0x5aeVM32Yr7iphYOFzrAbU25mRkBscIgNE8yEvdkrt6XHf/6oUz3i+G7NqjSA
FypAV/gabrd0dSH4uSW7snT80kON8XBs+n4o+1hie03F/yRcQu65QiP+x8LFTeQw
2v+rQVw5MkRoXd/eNDFi0qHIIYk9vw7zwJfNkEbhQ1mVdAQedGz8vCE6qFbEgEaD
M1YdrSECgYEA1eLywmirS7++jHZ/MwH/I7oxbZSLfdR1QQPHMw6Do6lQELwbutRM
Dqugrb61Atf+/53rypW8nfvzmlYefiTvHy4O8fBDVIEN7TnxhI6OBMeedpmFSXpk
aRnsR1DWKpaijlEjWHkt730A0vj3hPxgCqQ47HBgdi6DBcVzs2wcruUCgYEAyDbj
taXPzVNQmLv7edYGpGu79NsLo3l9k+93tFDVazw8MlmR6bk4k8Ca48JjcIjFs91Q
SAS+wvljTgFzbNa3oyJasEUfyTDtjvD1zmsJkhXDcjDxUbPmKaMxRIVjJUM0Bk8u
gRI1BW/hdMPi0cj/nloCLzLQvUVbFnRB8IwStXkCgYEAs93jupudGdmI28S22WVf
c2McOAPIfqvRYzhTJ1uYVmSHIVufkjEAOQIZ4KLUxCxyk/HxHW9orA76YBr2D6zt
rnHkPY+If6L73DhzI79iLSDV4PTfwtf7Yuta6OpRAIWm9DnFmJxnhdPAgqq+NIas
Gaba+/LRG/GnW44d65AKWwUCgYB74SqHrC6lVpWZy0ZQHlNBzL8hQ58x6OwAarzg
PtuuXDjK1ozn1ojhMt0ja5VnfdkF7zvLM9Rsgy4kh9VJVJmPQKRoSHzgWXvDY+hT
bfsf/oNN1maaLPuOa8ECKp4r4icAeGHHzuIrmQwg2UswjnNLIVoUphZt5cn0XL6n
/aNd0QKBgFmYboogy/1vfUXmhSjiC7uLtMN/Vrf/xiNErOzTTEgk0jO2z2J2z+Ei
VbgrG8EKdnrWZnq7sOO2Lq2gpUlIJ2xbT56tNZiIixxsUFZRmc9PskWpdY9SaoA7
Tx3SzpHbXS2FWmS1krpoNfRCgvTostouGlqjmZJhxPNgV4DNMS1D
-----END RSA PRIVATE KEY-----
";

	const INVALID_PUBLIC_KEY: &'static str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC1VGJpQ8FeKpU3DgHLTur6eoMB8grO6jY2t2bZNs0xpnNxtjh1g7Cvh+PgVzBHHc+QMNNmwPDzcZFSqjKT/BvP5OyBF7jRLYCWG0m8f7vu9wAihJtQwKN0FxDF275vqdkon2QyH6e6zrL3+zLHemtyLo89xGHJhGNXxR+OBdVgbJcxaCysaznL9jbby6CLAR+BQX4MiebOWdUNsOrPH6cRjT1pU9ydyRMf14F13A03tgINxjz8CDz4BJu42js7vOvaLn+fzXVROKjoQPYaI/SuOasdfjksd hdafhdksjfkdsafsdnEDe33A77pYIXanH/oB/EzZI0nDLWV7ByoFXh";
	const PUBLIC_KEY1: &'static str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC1VGJpQ8FeKpU3DgHLTur6eoMB8grO6jY2t2bZNs0xpnNxtjh1g7Cvh+PgVzBHHc+QMNNmwPDzcZFSqjKT/BvP5OyBF7jRLYCWG0m8f7vu9wAihJtQwKN0FxDF275vqdkon2QyH6e6zrL3+zLHemtyLo89xGHJhGNXxR+OBdVgbJcxaCysaznL9jbby6CLAR+BQX4MiebOWdUNsOrPH6cRjT1pU9ydyRMf14F13A03tgINxjz8CDz4BJu42js7vOvaLn+fzXVROKjoQPYaI/SuOA25bttg6CIawei5agUNWlKf3iynEDe33A77pYIXanH/oB/EzZI0nDLWV7ByoFXh";
	const PUBLIC_KEY2: &'static str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCnRynHGAjSGZ2Rd5Zc5WUSyI+Q+ZHkum/5fDrhMBk87L7C3c+bcNx8MfM2mglAImgATREwj5i2SwKxDLt3VX5ccbNL0il+W9y+Px4jRN4wd553boIToU1El5hum2N/2a6gtUrNCxUe+auy4RdksBl9qagK1Z8zAwEuZtbreXQeEEJJkfnfmg8KDpukwwFLUyRgF/fhNlW6NEUSpXB2Pn4UEb44jZJUQt+iHXzluJYVYke3esvM+P56ILi0sfPDWf1aWxGq2fKXd4XUGpusGISP2RpUEjMYPR3suwAhKlALzLydM5QIcBFHFKIctkJctbBzYOOyz5hhQSfu8JfpUJM9";

	#[test]
	#[should_fail]
	fn invalid_private_key_fails() {
		::ssh_initialize();

		super::SSHKey::private_key_from_base64(INVALID_PRIVATE_KEY.deref()).unwrap();
	}

	#[test]
	#[should_fail]
	fn invalid_public_key_fails() {
		::ssh_initialize();

		let typ = ::ssh_keytypes_e::SSH_KEYTYPE_RSA as u32;
		super::SSHKey::public_key_from_base64(INVALID_PUBLIC_KEY.deref(), typ).unwrap();
	}

	#[test]
	fn same_private_key_is_equal() {
		::ssh_initialize();

		let key1 = super::SSHKey::private_key_from_base64(PRIVATE_KEY1.deref()).unwrap();
		assert!(key1 == key1);
	}

	#[test]
	fn same_public_key_is_equal() {
		::ssh_initialize();

		let typ = ::ssh_keytypes_e::SSH_KEYTYPE_RSA as u32;
		let key1 = super::SSHKey::public_key_from_base64(PUBLIC_KEY1.deref(), typ).unwrap();
		assert!(key1 == key1);
	}

	#[test]
	#[should_fail]
	fn different_private_keys_are_not_equal() {
		::ssh_initialize();

		let key1 = super::SSHKey::private_key_from_base64(PRIVATE_KEY1.deref()).unwrap();
		let key2 = super::SSHKey::private_key_from_base64(PRIVATE_KEY2.deref()).unwrap();

		assert!(key1 == key2);
	}

	#[test]
	#[should_fail]
	fn different_public_keys_are_not_equal() {
		::ssh_initialize();

		let typ = ::ssh_keytypes_e::SSH_KEYTYPE_RSA as u32;
		let key1 = super::SSHKey::public_key_from_base64(PUBLIC_KEY1.deref(), typ).unwrap();
		let key2 = super::SSHKey::public_key_from_base64(PUBLIC_KEY2.deref(), typ).unwrap();

		assert!(key1 == key2);
	}


	#[test]
	fn public_key_is_public_key() {
		::ssh_initialize();

		let typ = ::ssh_keytypes_e::SSH_KEYTYPE_RSA as u32;
		let key1 = super::SSHKey::public_key_from_base64(PUBLIC_KEY1.deref(), typ).unwrap();
		assert!(key1.is_public());
	}

	#[test]
	#[should_fail]
	fn public_key_is_not_private_key() {
		::ssh_initialize();

		let typ = ::ssh_keytypes_e::SSH_KEYTYPE_RSA as u32;
		let key1 = super::SSHKey::public_key_from_base64(PUBLIC_KEY1.deref(), typ).unwrap();
		assert!(key1.is_private());
	}

	#[test]
	fn private_key_is_private_key() {
		::ssh_initialize();

		let key1 = super::SSHKey::private_key_from_base64(PRIVATE_KEY1.deref()).unwrap();
		assert!(key1.is_private());
	}

	#[test]
	fn private_key_has_also_public_key() {
		::ssh_initialize();

		let key1 = super::SSHKey::private_key_from_base64(PRIVATE_KEY1.deref()).unwrap();
		assert!(key1.is_public());
	}
}
