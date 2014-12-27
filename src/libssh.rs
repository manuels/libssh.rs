#![crate_type = "lib"]
#![crate_name = "libssh"]

extern crate libc;
use std::mem;

use std::collections::enum_set::CLike;


/*
int ssh_blocking_flush()
	(ssh_session) session [struct ssh_session_struct *]
	(int) timeout
*/
extern "C" {
	pub fn ssh_blocking_flush(session: *mut ssh_session_struct, timeout: libc::c_int) -> libc::c_int;
}


/*
ssh_channel ssh_channel_accept_x11() [struct ssh_channel_struct *]
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) timeout_ms
*/
extern "C" {
	pub fn ssh_channel_accept_x11(channel: *mut ssh_channel_struct, timeout_ms: libc::c_int) -> *mut ssh_channel_struct;
}


/*
int ssh_channel_change_pty_size()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) cols
	(int) rows
*/
extern "C" {
	pub fn ssh_channel_change_pty_size(channel: *mut ssh_channel_struct, cols: libc::c_int, rows: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_close()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_close(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
void ssh_channel_free()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_free(channel: *mut ssh_channel_struct);
}


/*
int ssh_channel_get_exit_status()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_get_exit_status(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
ssh_session ssh_channel_get_session() [struct ssh_session_struct *]
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_get_session(channel: *mut ssh_channel_struct) -> *mut ssh_session_struct;
}


/*
int ssh_channel_is_closed()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_is_closed(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_is_eof()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_is_eof(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_is_open()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_is_open(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
ssh_channel ssh_channel_new() [struct ssh_channel_struct *]
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_channel_new(session: *mut ssh_session_struct) -> *mut ssh_channel_struct;
}


/*
int ssh_channel_open_auth_agent()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_open_auth_agent(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_open_forward()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) remotehost
	(int) remoteport
	(const char *) sourcehost
	(int) localport
*/
extern "C" {
	pub fn ssh_channel_open_forward(channel: *mut ssh_channel_struct, remotehost: *const libc::c_char, remoteport: libc::c_int, sourcehost: *const libc::c_char, localport: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_open_session()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_open_session(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_open_x11()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) orig_addr
	(int) orig_port
*/
extern "C" {
	pub fn ssh_channel_open_x11(channel: *mut ssh_channel_struct, orig_addr: *const libc::c_char, orig_port: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_poll()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) is_stderr
*/
extern "C" {
	pub fn ssh_channel_poll(channel: *mut ssh_channel_struct, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_poll_timeout()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) timeout
	(int) is_stderr
*/
extern "C" {
	pub fn ssh_channel_poll_timeout(channel: *mut ssh_channel_struct, timeout: libc::c_int, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_read()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(void *) dest
	(uint32_t) count [unsigned int]
	(int) is_stderr
*/
extern "C" {
	pub fn ssh_channel_read(channel: *mut ssh_channel_struct, dest: *mut libc::c_void, count: libc::c_uint, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_read_timeout()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(void *) dest
	(uint32_t) count [unsigned int]
	(int) is_stderr
	(int) timeout_ms
*/
extern "C" {
	pub fn ssh_channel_read_timeout(channel: *mut ssh_channel_struct, dest: *mut libc::c_void, count: libc::c_uint, is_stderr: libc::c_int, timeout_ms: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_read_nonblocking()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(void *) dest
	(uint32_t) count [unsigned int]
	(int) is_stderr
*/
extern "C" {
	pub fn ssh_channel_read_nonblocking(channel: *mut ssh_channel_struct, dest: *mut libc::c_void, count: libc::c_uint, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_request_env()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) name
	(const char *) value
*/
extern "C" {
	pub fn ssh_channel_request_env(channel: *mut ssh_channel_struct, name: *const libc::c_char, value: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_channel_request_exec()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) cmd
*/
extern "C" {
	pub fn ssh_channel_request_exec(channel: *mut ssh_channel_struct, cmd: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_channel_request_pty()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_request_pty(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_request_pty_size()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) term
	(int) cols
	(int) rows
*/
extern "C" {
	pub fn ssh_channel_request_pty_size(channel: *mut ssh_channel_struct, term: *const libc::c_char, cols: libc::c_int, rows: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_request_shell()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_request_shell(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_request_send_signal()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) signum
*/
extern "C" {
	pub fn ssh_channel_request_send_signal(channel: *mut ssh_channel_struct, signum: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_channel_request_sftp()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_request_sftp(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_request_subsystem()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) subsystem
*/
extern "C" {
	pub fn ssh_channel_request_subsystem(channel: *mut ssh_channel_struct, subsystem: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_channel_request_x11()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) single_connection
	(const char *) protocol
	(const char *) cookie
	(int) screen_number
*/
extern "C" {
	pub fn ssh_channel_request_x11(channel: *mut ssh_channel_struct, single_connection: libc::c_int, protocol: *const libc::c_char, cookie: *const libc::c_char, screen_number: libc::c_int) -> libc::c_int;
}


/*
int ssh_channel_send_eof()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_send_eof(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int ssh_channel_select()
	(ssh_channel *) readchans [struct ssh_channel_struct **]
	(ssh_channel *) writechans [struct ssh_channel_struct **]
	(ssh_channel *) exceptchans [struct ssh_channel_struct **]
	(struct timeval *) timeout [struct timeval *]
*/
extern "C" {
	pub fn ssh_channel_select(readchans: *mut *mut ssh_channel_struct, writechans: *mut *mut ssh_channel_struct, exceptchans: *mut *mut ssh_channel_struct, timeout: *mut timeval) -> libc::c_int;
}


/*
void ssh_channel_set_blocking()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) blocking
*/
extern "C" {
	pub fn ssh_channel_set_blocking(channel: *mut ssh_channel_struct, blocking: libc::c_int);
}


/*
int ssh_channel_write()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const void *) data
	(uint32_t) len [unsigned int]
*/
extern "C" {
	pub fn ssh_channel_write(channel: *mut ssh_channel_struct, data: *const libc::c_void, len: libc::c_uint) -> libc::c_int;
}


/*
uint32_t ssh_channel_window_size() [unsigned int]
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_channel_window_size(channel: *mut ssh_channel_struct) -> libc::c_uint;
}


/*
char * ssh_basename()
	(const char *) path
*/
extern "C" {
	pub fn ssh_basename(path: *const libc::c_char) -> *mut libc::c_char;
}


/*
void ssh_clean_pubkey_hash()
	(unsigned char **) hash
*/
extern "C" {
	pub fn ssh_clean_pubkey_hash(hash: *mut *mut libc::c_uchar);
}


/*
int ssh_connect()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_connect(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
const char * ssh_copyright()
*/
extern "C" {
	pub fn ssh_copyright() -> *const libc::c_char;
}


/*
void ssh_disconnect()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_disconnect(session: *mut ssh_session_struct);
}


/*
char * ssh_dirname()
	(const char *) path
*/
extern "C" {
	pub fn ssh_dirname(path: *const libc::c_char) -> *mut libc::c_char;
}


/*
int ssh_finalize()
*/
extern "C" {
	pub fn ssh_finalize() -> libc::c_int;
}


/*
ssh_channel ssh_forward_accept() [struct ssh_channel_struct *]
	(ssh_session) session [struct ssh_session_struct *]
	(int) timeout_ms
*/
extern "C" {
	pub fn ssh_forward_accept(session: *mut ssh_session_struct, timeout_ms: libc::c_int) -> *mut ssh_channel_struct;
}


/*
ssh_channel ssh_channel_accept_forward() [struct ssh_channel_struct *]
	(ssh_session) session [struct ssh_session_struct *]
	(int) timeout_ms
	(int *) destination_port
*/
extern "C" {
	pub fn ssh_channel_accept_forward(session: *mut ssh_session_struct, timeout_ms: libc::c_int, destination_port: *mut libc::c_int) -> *mut ssh_channel_struct;
}


/*
int ssh_forward_cancel()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) address
	(int) port
*/
extern "C" {
	pub fn ssh_forward_cancel(session: *mut ssh_session_struct, address: *const libc::c_char, port: libc::c_int) -> libc::c_int;
}


/*
int ssh_forward_listen()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) address
	(int) port
	(int *) bound_port
*/
extern "C" {
	pub fn ssh_forward_listen(session: *mut ssh_session_struct, address: *const libc::c_char, port: libc::c_int, bound_port: *mut libc::c_int) -> libc::c_int;
}


/*
void ssh_free()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_free(session: *mut ssh_session_struct);
}


/*
const char * ssh_get_disconnect_message()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_disconnect_message(session: *mut ssh_session_struct) -> *const libc::c_char;
}


/*
const char * ssh_get_error()
	(void *) error
*/
extern "C" {
	pub fn ssh_get_error(error: *mut libc::c_void) -> *const libc::c_char;
}


/*
int ssh_get_error_code()
	(void *) error
*/
extern "C" {
	pub fn ssh_get_error_code(error: *mut libc::c_void) -> libc::c_int;
}


/*
socket_t ssh_get_fd() [int]
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_fd(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
char * ssh_get_hexa()
	(const unsigned char *) what
	(size_t) len [unsigned long]
*/
extern "C" {
	pub fn ssh_get_hexa(what: *const libc::c_uchar, len: libc::c_ulong) -> *mut libc::c_char;
}


/*
char * ssh_get_issue_banner()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_issue_banner(session: *mut ssh_session_struct) -> *mut libc::c_char;
}


/*
int ssh_get_openssh_version()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_openssh_version(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_get_publickey()
	(ssh_session) session [struct ssh_session_struct *]
	(ssh_key *) key [struct ssh_key_struct **]
*/
extern "C" {
	pub fn ssh_get_publickey(session: *mut ssh_session_struct, key: *mut *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_get_publickey_hash()
	(const ssh_key) key [struct ssh_key_struct *const]
	(enum ssh_publickey_hash_type) type [enum ssh_publickey_hash_type]
	(unsigned char **) hash
	(size_t *) hlen [unsigned long *]
*/
extern "C" {
	pub fn ssh_get_publickey_hash(key: *mut ssh_key_struct, type_: libc::c_uint, hash: *mut *mut libc::c_uchar, hlen: *mut libc::c_ulong) -> libc::c_int;
}


/*
int ssh_get_pubkey_hash()
	(ssh_session) session [struct ssh_session_struct *]
	(unsigned char **) hash
*/
extern "C" {
	pub fn ssh_get_pubkey_hash(session: *mut ssh_session_struct, hash: *mut *mut libc::c_uchar) -> libc::c_int;
}


/*
int ssh_get_random()
	(void *) where
	(int) len
	(int) strong
*/
extern "C" {
	pub fn ssh_get_random(where_: *mut libc::c_void, len: libc::c_int, strong: libc::c_int) -> libc::c_int;
}


/*
int ssh_get_version()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_version(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_get_status()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_status(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_get_poll_flags()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_poll_flags(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_init()
*/
extern "C" {
	pub fn ssh_init() -> libc::c_int;
}


/*
int ssh_is_blocking()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_is_blocking(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_is_connected()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_is_connected(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_is_server_known()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_is_server_known(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_set_log_level()
	(int) level
*/
extern "C" {
	pub fn ssh_set_log_level(level: libc::c_int) -> libc::c_int;
}


/*
int ssh_get_log_level()
*/
extern "C" {
	pub fn ssh_get_log_level() -> libc::c_int;
}


/*
void * ssh_get_log_userdata()
*/
extern "C" {
	pub fn ssh_get_log_userdata() -> *mut libc::c_void;
}


/*
int ssh_set_log_userdata()
	(void *) data
*/
extern "C" {
	pub fn ssh_set_log_userdata(data: *mut libc::c_void) -> libc::c_int;
}


/*
void _ssh_log()
	(int) verbosity
	(const char *) function
	(const char *) format
*/
extern "C" {
	pub fn _ssh_log(verbosity: libc::c_int, function: *const libc::c_char, format: *const libc::c_char);
}


/*
void ssh_log()
	(ssh_session) session [struct ssh_session_struct *]
	(int) prioriry
	(const char *) format
*/
extern "C" {
	pub fn ssh_log(session: *mut ssh_session_struct, prioriry: libc::c_int, format: *const libc::c_char);
}


/*
ssh_channel ssh_message_channel_request_open_reply_accept() [struct ssh_channel_struct *]
	(ssh_message) msg [struct ssh_message_struct *]
*/
extern "C" {
	pub fn ssh_message_channel_request_open_reply_accept(msg: *mut ssh_message_struct) -> *mut ssh_channel_struct;
}


/*
int ssh_message_channel_request_reply_success()
	(ssh_message) msg [struct ssh_message_struct *]
*/
extern "C" {
	pub fn ssh_message_channel_request_reply_success(msg: *mut ssh_message_struct) -> libc::c_int;
}


/*
void ssh_message_free()
	(ssh_message) msg [struct ssh_message_struct *]
*/
extern "C" {
	pub fn ssh_message_free(msg: *mut ssh_message_struct);
}


/*
ssh_message ssh_message_get() [struct ssh_message_struct *]
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_message_get(session: *mut ssh_session_struct) -> *mut ssh_message_struct;
}


/*
int ssh_message_subtype()
	(ssh_message) msg [struct ssh_message_struct *]
*/
extern "C" {
	pub fn ssh_message_subtype(msg: *mut ssh_message_struct) -> libc::c_int;
}


/*
int ssh_message_type()
	(ssh_message) msg [struct ssh_message_struct *]
*/
extern "C" {
	pub fn ssh_message_type(msg: *mut ssh_message_struct) -> libc::c_int;
}


/*
int ssh_mkdir()
	(const char *) pathname
	(mode_t) mode [unsigned int]
*/
extern "C" {
	pub fn ssh_mkdir(pathname: *const libc::c_char, mode: libc::c_uint) -> libc::c_int;
}


/*
ssh_session ssh_new() [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_new() -> *mut ssh_session_struct;
}


/*
int ssh_options_copy()
	(ssh_session) src [struct ssh_session_struct *]
	(ssh_session *) dest [struct ssh_session_struct **]
*/
extern "C" {
	pub fn ssh_options_copy(src: *mut ssh_session_struct, dest: *mut *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_options_getopt()
	(ssh_session) session [struct ssh_session_struct *]
	(int *) argcptr
	(char **) argv
*/
extern "C" {
	pub fn ssh_options_getopt(session: *mut ssh_session_struct, argcptr: *mut libc::c_int, argv: *mut *mut libc::c_char) -> libc::c_int;
}


/*
int ssh_options_parse_config()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) filename
*/
extern "C" {
	pub fn ssh_options_parse_config(session: *mut ssh_session_struct, filename: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_options_set()
	(ssh_session) session [struct ssh_session_struct *]
	(enum ssh_options_e) type [enum ssh_options_e]
	(const void *) value
*/
extern "C" {
	pub fn ssh_options_set(session: *mut ssh_session_struct, type_: libc::c_uint, value: *const libc::c_void) -> libc::c_int;
}


/*
int ssh_options_get()
	(ssh_session) session [struct ssh_session_struct *]
	(enum ssh_options_e) type [enum ssh_options_e]
	(char **) value
*/
extern "C" {
	pub fn ssh_options_get(session: *mut ssh_session_struct, type_: libc::c_uint, value: *mut *mut libc::c_char) -> libc::c_int;
}


/*
int ssh_options_get_port()
	(ssh_session) session [struct ssh_session_struct *]
	(unsigned int *) port_target
*/
extern "C" {
	pub fn ssh_options_get_port(session: *mut ssh_session_struct, port_target: *mut libc::c_uint) -> libc::c_int;
}


/*
int ssh_pcap_file_close()
	(ssh_pcap_file) pcap [struct ssh_pcap_file_struct *]
*/
extern "C" {
	pub fn ssh_pcap_file_close(pcap: *mut ssh_pcap_file_struct) -> libc::c_int;
}


/*
void ssh_pcap_file_free()
	(ssh_pcap_file) pcap [struct ssh_pcap_file_struct *]
*/
extern "C" {
	pub fn ssh_pcap_file_free(pcap: *mut ssh_pcap_file_struct);
}


/*
ssh_pcap_file ssh_pcap_file_new() [struct ssh_pcap_file_struct *]
*/
extern "C" {
	pub fn ssh_pcap_file_new() -> *mut ssh_pcap_file_struct;
}


/*
int ssh_pcap_file_open()
	(ssh_pcap_file) pcap [struct ssh_pcap_file_struct *]
	(const char *) filename
*/
extern "C" {
	pub fn ssh_pcap_file_open(pcap: *mut ssh_pcap_file_struct, filename: *const libc::c_char) -> libc::c_int;
}


/*
ssh_key ssh_key_new() [struct ssh_key_struct *]
*/
extern "C" {
	pub fn ssh_key_new() -> *mut ssh_key_struct;
}


/*
void ssh_key_free()
	(ssh_key) key [struct ssh_key_struct *]
*/
extern "C" {
	pub fn ssh_key_free(key: *mut ssh_key_struct);
}


/*
enum ssh_keytypes_e ssh_key_type() [enum ssh_keytypes_e]
	(const ssh_key) key [struct ssh_key_struct *const]
*/
extern "C" {
	pub fn ssh_key_type(key: *mut ssh_key_struct) -> libc::c_uint;
}


/*
const char * ssh_key_type_to_char()
	(enum ssh_keytypes_e) type [enum ssh_keytypes_e]
*/
extern "C" {
	pub fn ssh_key_type_to_char(type_: libc::c_uint) -> *const libc::c_char;
}


/*
enum ssh_keytypes_e ssh_key_type_from_name() [enum ssh_keytypes_e]
	(const char *) name
*/
extern "C" {
	pub fn ssh_key_type_from_name(name: *const libc::c_char) -> libc::c_uint;
}


/*
int ssh_key_is_public()
	(const ssh_key) k [struct ssh_key_struct *const]
*/
extern "C" {
	pub fn ssh_key_is_public(k: *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_key_is_private()
	(const ssh_key) k [struct ssh_key_struct *const]
*/
extern "C" {
	pub fn ssh_key_is_private(k: *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_key_cmp()
	(const ssh_key) k1 [struct ssh_key_struct *const]
	(const ssh_key) k2 [struct ssh_key_struct *const]
	(enum ssh_keycmp_e) what [enum ssh_keycmp_e]
*/
extern "C" {
	pub fn ssh_key_cmp(k1: *mut ssh_key_struct, k2: *mut ssh_key_struct, what: libc::c_uint) -> libc::c_int;
}


/*
int ssh_pki_generate()
	(enum ssh_keytypes_e) type [enum ssh_keytypes_e]
	(int) parameter
	(ssh_key *) pkey [struct ssh_key_struct **]
*/
extern "C" {
	pub fn ssh_pki_generate(type_: libc::c_uint, parameter: libc::c_int, pkey: *mut *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_pki_import_privkey_base64()
	(const char *) b64_key
	(const char *) passphrase
	(ssh_auth_callback) auth_fn [int (*)(const char *, char *, unsigned long, int, int, void *)]
	(void *) auth_data
	(ssh_key *) pkey [struct ssh_key_struct **]
*/
extern "C" {
	pub fn ssh_pki_import_privkey_base64(b64_key: *const libc::c_char, passphrase: *const libc::c_char, auth_fn: Option<extern fn(*const libc::c_char, *mut libc::c_char, libc::c_ulong, libc::c_int, libc::c_int, *mut libc::c_void) -> libc::c_int>, auth_data: *mut libc::c_void, pkey: *mut *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_pki_import_privkey_file()
	(const char *) filename
	(const char *) passphrase
	(ssh_auth_callback) auth_fn [int (*)(const char *, char *, unsigned long, int, int, void *)]
	(void *) auth_data
	(ssh_key *) pkey [struct ssh_key_struct **]
*/
extern "C" {
	pub fn ssh_pki_import_privkey_file(filename: *const libc::c_char, passphrase: *const libc::c_char, auth_fn: Option<extern fn(*const libc::c_char, *mut libc::c_char, libc::c_ulong, libc::c_int, libc::c_int, *mut libc::c_void) -> libc::c_int>, auth_data: *mut libc::c_void, pkey: *mut *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_pki_export_privkey_file()
	(const ssh_key) privkey [struct ssh_key_struct *const]
	(const char *) passphrase
	(ssh_auth_callback) auth_fn [int (*)(const char *, char *, unsigned long, int, int, void *)]
	(void *) auth_data
	(const char *) filename
*/
extern "C" {
	pub fn ssh_pki_export_privkey_file(privkey: *mut ssh_key_struct, passphrase: *const libc::c_char, auth_fn: Option<extern fn(*const libc::c_char, *mut libc::c_char, libc::c_ulong, libc::c_int, libc::c_int, *mut libc::c_void) -> libc::c_int>, auth_data: *mut libc::c_void, filename: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_pki_import_pubkey_base64()
	(const char *) b64_key
	(enum ssh_keytypes_e) type [enum ssh_keytypes_e]
	(ssh_key *) pkey [struct ssh_key_struct **]
*/
extern "C" {
	pub fn ssh_pki_import_pubkey_base64(b64_key: *const libc::c_char, type_: libc::c_uint, pkey: *mut *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_pki_import_pubkey_file()
	(const char *) filename
	(ssh_key *) pkey [struct ssh_key_struct **]
*/
extern "C" {
	pub fn ssh_pki_import_pubkey_file(filename: *const libc::c_char, pkey: *mut *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_pki_export_privkey_to_pubkey()
	(const ssh_key) privkey [struct ssh_key_struct *const]
	(ssh_key *) pkey [struct ssh_key_struct **]
*/
extern "C" {
	pub fn ssh_pki_export_privkey_to_pubkey(privkey: *mut ssh_key_struct, pkey: *mut *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_pki_export_pubkey_base64()
	(const ssh_key) key [struct ssh_key_struct *const]
	(char **) b64_key
*/
extern "C" {
	pub fn ssh_pki_export_pubkey_base64(key: *mut ssh_key_struct, b64_key: *mut *mut libc::c_char) -> libc::c_int;
}


/*
int ssh_pki_export_pubkey_file()
	(const ssh_key) key [struct ssh_key_struct *const]
	(const char *) filename
*/
extern "C" {
	pub fn ssh_pki_export_pubkey_file(key: *mut ssh_key_struct, filename: *const libc::c_char) -> libc::c_int;
}


/*
void ssh_print_hexa()
	(const char *) descr
	(const unsigned char *) what
	(size_t) len [unsigned long]
*/
extern "C" {
	pub fn ssh_print_hexa(descr: *const libc::c_char, what: *const libc::c_uchar, len: libc::c_ulong);
}


/*
int ssh_send_ignore()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) data
*/
extern "C" {
	pub fn ssh_send_ignore(session: *mut ssh_session_struct, data: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_send_debug()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) message
	(int) always_display
*/
extern "C" {
	pub fn ssh_send_debug(session: *mut ssh_session_struct, message: *const libc::c_char, always_display: libc::c_int) -> libc::c_int;
}


/*
void ssh_gssapi_set_creds()
	(ssh_session) session [struct ssh_session_struct *]
	(const ssh_gssapi_creds) creds [void *const]
*/
extern "C" {
	pub fn ssh_gssapi_set_creds(session: *mut ssh_session_struct, creds: *mut libc::c_void);
}


/*
int ssh_scp_accept_request()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_accept_request(scp: *mut ssh_scp_struct) -> libc::c_int;
}


/*
int ssh_scp_close()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_close(scp: *mut ssh_scp_struct) -> libc::c_int;
}


/*
int ssh_scp_deny_request()
	(ssh_scp) scp [struct ssh_scp_struct *]
	(const char *) reason
*/
extern "C" {
	pub fn ssh_scp_deny_request(scp: *mut ssh_scp_struct, reason: *const libc::c_char) -> libc::c_int;
}


/*
void ssh_scp_free()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_free(scp: *mut ssh_scp_struct);
}


/*
int ssh_scp_init()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_init(scp: *mut ssh_scp_struct) -> libc::c_int;
}


/*
int ssh_scp_leave_directory()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_leave_directory(scp: *mut ssh_scp_struct) -> libc::c_int;
}


/*
ssh_scp ssh_scp_new() [struct ssh_scp_struct *]
	(ssh_session) session [struct ssh_session_struct *]
	(int) mode
	(const char *) location
*/
extern "C" {
	pub fn ssh_scp_new(session: *mut ssh_session_struct, mode: libc::c_int, location: *const libc::c_char) -> *mut ssh_scp_struct;
}


/*
int ssh_scp_pull_request()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_pull_request(scp: *mut ssh_scp_struct) -> libc::c_int;
}


/*
int ssh_scp_push_directory()
	(ssh_scp) scp [struct ssh_scp_struct *]
	(const char *) dirname
	(int) mode
*/
extern "C" {
	pub fn ssh_scp_push_directory(scp: *mut ssh_scp_struct, dirname: *const libc::c_char, mode: libc::c_int) -> libc::c_int;
}


/*
int ssh_scp_push_file()
	(ssh_scp) scp [struct ssh_scp_struct *]
	(const char *) filename
	(size_t) size [unsigned long]
	(int) perms
*/
extern "C" {
	pub fn ssh_scp_push_file(scp: *mut ssh_scp_struct, filename: *const libc::c_char, size: libc::c_ulong, perms: libc::c_int) -> libc::c_int;
}


/*
int ssh_scp_push_file64()
	(ssh_scp) scp [struct ssh_scp_struct *]
	(const char *) filename
	(uint64_t) size [unsigned long]
	(int) perms
*/
extern "C" {
	pub fn ssh_scp_push_file64(scp: *mut ssh_scp_struct, filename: *const libc::c_char, size: libc::c_ulong, perms: libc::c_int) -> libc::c_int;
}


/*
int ssh_scp_read()
	(ssh_scp) scp [struct ssh_scp_struct *]
	(void *) buffer
	(size_t) size [unsigned long]
*/
extern "C" {
	pub fn ssh_scp_read(scp: *mut ssh_scp_struct, buffer: *mut libc::c_void, size: libc::c_ulong) -> libc::c_int;
}


/*
const char * ssh_scp_request_get_filename()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_request_get_filename(scp: *mut ssh_scp_struct) -> *const libc::c_char;
}


/*
int ssh_scp_request_get_permissions()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_request_get_permissions(scp: *mut ssh_scp_struct) -> libc::c_int;
}


/*
size_t ssh_scp_request_get_size() [unsigned long]
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_request_get_size(scp: *mut ssh_scp_struct) -> libc::c_ulong;
}


/*
uint64_t ssh_scp_request_get_size64() [unsigned long]
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_request_get_size64(scp: *mut ssh_scp_struct) -> libc::c_ulong;
}


/*
const char * ssh_scp_request_get_warning()
	(ssh_scp) scp [struct ssh_scp_struct *]
*/
extern "C" {
	pub fn ssh_scp_request_get_warning(scp: *mut ssh_scp_struct) -> *const libc::c_char;
}


/*
int ssh_scp_write()
	(ssh_scp) scp [struct ssh_scp_struct *]
	(const void *) buffer
	(size_t) len [unsigned long]
*/
extern "C" {
	pub fn ssh_scp_write(scp: *mut ssh_scp_struct, buffer: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
int ssh_select()
	(ssh_channel *) channels [struct ssh_channel_struct **]
	(ssh_channel *) outchannels [struct ssh_channel_struct **]
	(socket_t) maxfd [int]
	(fd_set *) readfds [fd_set *]
	(struct timeval *) timeout [struct timeval *]
*/
extern "C" {
	pub fn ssh_select(channels: *mut *mut ssh_channel_struct, outchannels: *mut *mut ssh_channel_struct, maxfd: libc::c_int, readfds: *mut fd_set, timeout: *mut timeval) -> libc::c_int;
}


/*
int ssh_service_request()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) service
*/
extern "C" {
	pub fn ssh_service_request(session: *mut ssh_session_struct, service: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_set_agent_channel()
	(ssh_session) session [struct ssh_session_struct *]
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn ssh_set_agent_channel(session: *mut ssh_session_struct, channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
void ssh_set_blocking()
	(ssh_session) session [struct ssh_session_struct *]
	(int) blocking
*/
extern "C" {
	pub fn ssh_set_blocking(session: *mut ssh_session_struct, blocking: libc::c_int);
}


/*
void ssh_set_fd_except()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_set_fd_except(session: *mut ssh_session_struct);
}


/*
void ssh_set_fd_toread()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_set_fd_toread(session: *mut ssh_session_struct);
}


/*
void ssh_set_fd_towrite()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_set_fd_towrite(session: *mut ssh_session_struct);
}


/*
void ssh_silent_disconnect()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_silent_disconnect(session: *mut ssh_session_struct);
}


/*
int ssh_set_pcap_file()
	(ssh_session) session [struct ssh_session_struct *]
	(ssh_pcap_file) pcapfile [struct ssh_pcap_file_struct *]
*/
extern "C" {
	pub fn ssh_set_pcap_file(session: *mut ssh_session_struct, pcapfile: *mut ssh_pcap_file_struct) -> libc::c_int;
}


/*
int ssh_userauth_none()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
*/
extern "C" {
	pub fn ssh_userauth_none(session: *mut ssh_session_struct, username: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_userauth_list()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
*/
extern "C" {
	pub fn ssh_userauth_list(session: *mut ssh_session_struct, username: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_userauth_try_publickey()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(const ssh_key) pubkey [struct ssh_key_struct *const]
*/
extern "C" {
	pub fn ssh_userauth_try_publickey(session: *mut ssh_session_struct, username: *const libc::c_char, pubkey: *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_userauth_publickey()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(const ssh_key) privkey [struct ssh_key_struct *const]
*/
extern "C" {
	pub fn ssh_userauth_publickey(session: *mut ssh_session_struct, username: *const libc::c_char, privkey: *mut ssh_key_struct) -> libc::c_int;
}


/*
int ssh_userauth_agent()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
*/
extern "C" {
	pub fn ssh_userauth_agent(session: *mut ssh_session_struct, username: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_userauth_publickey_auto()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(const char *) passphrase
*/
extern "C" {
	pub fn ssh_userauth_publickey_auto(session: *mut ssh_session_struct, username: *const libc::c_char, passphrase: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_userauth_password()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(const char *) password
*/
extern "C" {
	pub fn ssh_userauth_password(session: *mut ssh_session_struct, username: *const libc::c_char, password: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_userauth_kbdint()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) user
	(const char *) submethods
*/
extern "C" {
	pub fn ssh_userauth_kbdint(session: *mut ssh_session_struct, user: *const libc::c_char, submethods: *const libc::c_char) -> libc::c_int;
}


/*
const char * ssh_userauth_kbdint_getinstruction()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_userauth_kbdint_getinstruction(session: *mut ssh_session_struct) -> *const libc::c_char;
}


/*
const char * ssh_userauth_kbdint_getname()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_userauth_kbdint_getname(session: *mut ssh_session_struct) -> *const libc::c_char;
}


/*
int ssh_userauth_kbdint_getnprompts()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_userauth_kbdint_getnprompts(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
const char * ssh_userauth_kbdint_getprompt()
	(ssh_session) session [struct ssh_session_struct *]
	(unsigned int) i
	(char *) echo
*/
extern "C" {
	pub fn ssh_userauth_kbdint_getprompt(session: *mut ssh_session_struct, i: libc::c_uint, echo: *mut libc::c_char) -> *const libc::c_char;
}


/*
int ssh_userauth_kbdint_getnanswers()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_userauth_kbdint_getnanswers(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
const char * ssh_userauth_kbdint_getanswer()
	(ssh_session) session [struct ssh_session_struct *]
	(unsigned int) i
*/
extern "C" {
	pub fn ssh_userauth_kbdint_getanswer(session: *mut ssh_session_struct, i: libc::c_uint) -> *const libc::c_char;
}


/*
int ssh_userauth_kbdint_setanswer()
	(ssh_session) session [struct ssh_session_struct *]
	(unsigned int) i
	(const char *) answer
*/
extern "C" {
	pub fn ssh_userauth_kbdint_setanswer(session: *mut ssh_session_struct, i: libc::c_uint, answer: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_userauth_gssapi()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_userauth_gssapi(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
const char * ssh_version()
	(int) req_version
*/
extern "C" {
	pub fn ssh_version(req_version: libc::c_int) -> *const libc::c_char;
}


/*
int ssh_write_knownhost()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_write_knownhost(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
void ssh_string_burn()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_string_burn(str: *mut ssh_string_struct);
}


/*
ssh_string ssh_string_copy() [struct ssh_string_struct *]
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_string_copy(str: *mut ssh_string_struct) -> *mut ssh_string_struct;
}


/*
void * ssh_string_data()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_string_data(str: *mut ssh_string_struct) -> *mut libc::c_void;
}


/*
int ssh_string_fill()
	(ssh_string) str [struct ssh_string_struct *]
	(const void *) data
	(size_t) len [unsigned long]
*/
extern "C" {
	pub fn ssh_string_fill(str: *mut ssh_string_struct, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
void ssh_string_free()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_string_free(str: *mut ssh_string_struct);
}


/*
ssh_string ssh_string_from_char() [struct ssh_string_struct *]
	(const char *) what
*/
extern "C" {
	pub fn ssh_string_from_char(what: *const libc::c_char) -> *mut ssh_string_struct;
}


/*
size_t ssh_string_len() [unsigned long]
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_string_len(str: *mut ssh_string_struct) -> libc::c_ulong;
}


/*
ssh_string ssh_string_new() [struct ssh_string_struct *]
	(size_t) size [unsigned long]
*/
extern "C" {
	pub fn ssh_string_new(size: libc::c_ulong) -> *mut ssh_string_struct;
}


/*
const char * ssh_string_get_char()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_string_get_char(str: *mut ssh_string_struct) -> *const libc::c_char;
}


/*
char * ssh_string_to_char()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_string_to_char(str: *mut ssh_string_struct) -> *mut libc::c_char;
}


/*
void ssh_string_free_char()
	(char *) s
*/
extern "C" {
	pub fn ssh_string_free_char(s: *mut libc::c_char);
}


/*
int ssh_getpass()
	(const char *) prompt
	(char *) buf
	(size_t) len [unsigned long]
	(int) echo
	(int) verify
*/
extern "C" {
	pub fn ssh_getpass(prompt: *const libc::c_char, buf: *mut libc::c_char, len: libc::c_ulong, echo: libc::c_int, verify: libc::c_int) -> libc::c_int;
}


/*
ssh_event ssh_event_new() [struct ssh_event_struct *]
*/
extern "C" {
	pub fn ssh_event_new() -> *mut ssh_event_struct;
}


/*
int ssh_event_add_fd()
	(ssh_event) event [struct ssh_event_struct *]
	(socket_t) fd [int]
	(short) events
	(ssh_event_callback) cb [int (*)(int, int, void *)]
	(void *) userdata
*/
extern "C" {
	pub fn ssh_event_add_fd(event: *mut ssh_event_struct, fd: libc::c_int, events: libc::c_short, cb: Option<extern fn(libc::c_int, libc::c_int, *mut libc::c_void) -> libc::c_int>, userdata: *mut libc::c_void) -> libc::c_int;
}


/*
int ssh_event_add_session()
	(ssh_event) event [struct ssh_event_struct *]
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_event_add_session(event: *mut ssh_event_struct, session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_event_dopoll()
	(ssh_event) event [struct ssh_event_struct *]
	(int) timeout
*/
extern "C" {
	pub fn ssh_event_dopoll(event: *mut ssh_event_struct, timeout: libc::c_int) -> libc::c_int;
}


/*
int ssh_event_remove_fd()
	(ssh_event) event [struct ssh_event_struct *]
	(socket_t) fd [int]
*/
extern "C" {
	pub fn ssh_event_remove_fd(event: *mut ssh_event_struct, fd: libc::c_int) -> libc::c_int;
}


/*
int ssh_event_remove_session()
	(ssh_event) event [struct ssh_event_struct *]
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_event_remove_session(event: *mut ssh_event_struct, session: *mut ssh_session_struct) -> libc::c_int;
}


/*
void ssh_event_free()
	(ssh_event) event [struct ssh_event_struct *]
*/
extern "C" {
	pub fn ssh_event_free(event: *mut ssh_event_struct);
}


/*
const char * ssh_get_clientbanner()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_clientbanner(session: *mut ssh_session_struct) -> *const libc::c_char;
}


/*
const char * ssh_get_serverbanner()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_serverbanner(session: *mut ssh_session_struct) -> *const libc::c_char;
}


/*
const char * ssh_get_cipher_in()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_cipher_in(session: *mut ssh_session_struct) -> *const libc::c_char;
}


/*
const char * ssh_get_cipher_out()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_cipher_out(session: *mut ssh_session_struct) -> *const libc::c_char;
}


/*
int ssh_auth_list()
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_auth_list(session: *mut ssh_session_struct) -> libc::c_int;
}


/*
int ssh_userauth_offer_pubkey()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(int) type
	(ssh_string) publickey [struct ssh_string_struct *]
*/
extern "C" {
	pub fn ssh_userauth_offer_pubkey(session: *mut ssh_session_struct, username: *const libc::c_char, type_: libc::c_int, publickey: *mut ssh_string_struct) -> libc::c_int;
}


/*
int ssh_userauth_pubkey()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(ssh_string) publickey [struct ssh_string_struct *]
	(ssh_private_key) privatekey [struct ssh_private_key_struct *]
*/
extern "C" {
	pub fn ssh_userauth_pubkey(session: *mut ssh_session_struct, username: *const libc::c_char, publickey: *mut ssh_string_struct, privatekey: *mut ssh_private_key_struct) -> libc::c_int;
}


/*
int ssh_userauth_agent_pubkey()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(ssh_public_key) publickey [struct ssh_public_key_struct *]
*/
extern "C" {
	pub fn ssh_userauth_agent_pubkey(session: *mut ssh_session_struct, username: *const libc::c_char, publickey: *mut ssh_public_key_struct) -> libc::c_int;
}


/*
int ssh_userauth_autopubkey()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) passphrase
*/
extern "C" {
	pub fn ssh_userauth_autopubkey(session: *mut ssh_session_struct, passphrase: *const libc::c_char) -> libc::c_int;
}


/*
int ssh_userauth_privatekey_file()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) username
	(const char *) filename
	(const char *) passphrase
*/
extern "C" {
	pub fn ssh_userauth_privatekey_file(session: *mut ssh_session_struct, username: *const libc::c_char, filename: *const libc::c_char, passphrase: *const libc::c_char) -> libc::c_int;
}


/*
void buffer_free()
	(ssh_buffer) buffer [struct ssh_buffer_struct *]
*/
extern "C" {
	pub fn buffer_free(buffer: *mut ssh_buffer_struct);
}


/*
void * buffer_get()
	(ssh_buffer) buffer [struct ssh_buffer_struct *]
*/
extern "C" {
	pub fn buffer_get(buffer: *mut ssh_buffer_struct) -> *mut libc::c_void;
}


/*
uint32_t buffer_get_len() [unsigned int]
	(ssh_buffer) buffer [struct ssh_buffer_struct *]
*/
extern "C" {
	pub fn buffer_get_len(buffer: *mut ssh_buffer_struct) -> libc::c_uint;
}


/*
ssh_buffer buffer_new() [struct ssh_buffer_struct *]
*/
extern "C" {
	pub fn buffer_new() -> *mut ssh_buffer_struct;
}


/*
ssh_channel channel_accept_x11() [struct ssh_channel_struct *]
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) timeout_ms
*/
extern "C" {
	pub fn channel_accept_x11(channel: *mut ssh_channel_struct, timeout_ms: libc::c_int) -> *mut ssh_channel_struct;
}


/*
int channel_change_pty_size()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) cols
	(int) rows
*/
extern "C" {
	pub fn channel_change_pty_size(channel: *mut ssh_channel_struct, cols: libc::c_int, rows: libc::c_int) -> libc::c_int;
}


/*
ssh_channel channel_forward_accept() [struct ssh_channel_struct *]
	(ssh_session) session [struct ssh_session_struct *]
	(int) timeout_ms
*/
extern "C" {
	pub fn channel_forward_accept(session: *mut ssh_session_struct, timeout_ms: libc::c_int) -> *mut ssh_channel_struct;
}


/*
int channel_close()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_close(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_forward_cancel()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) address
	(int) port
*/
extern "C" {
	pub fn channel_forward_cancel(session: *mut ssh_session_struct, address: *const libc::c_char, port: libc::c_int) -> libc::c_int;
}


/*
int channel_forward_listen()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) address
	(int) port
	(int *) bound_port
*/
extern "C" {
	pub fn channel_forward_listen(session: *mut ssh_session_struct, address: *const libc::c_char, port: libc::c_int, bound_port: *mut libc::c_int) -> libc::c_int;
}


/*
void channel_free()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_free(channel: *mut ssh_channel_struct);
}


/*
int channel_get_exit_status()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_get_exit_status(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
ssh_session channel_get_session() [struct ssh_session_struct *]
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_get_session(channel: *mut ssh_channel_struct) -> *mut ssh_session_struct;
}


/*
int channel_is_closed()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_is_closed(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_is_eof()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_is_eof(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_is_open()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_is_open(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
ssh_channel channel_new() [struct ssh_channel_struct *]
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn channel_new(session: *mut ssh_session_struct) -> *mut ssh_channel_struct;
}


/*
int channel_open_forward()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) remotehost
	(int) remoteport
	(const char *) sourcehost
	(int) localport
*/
extern "C" {
	pub fn channel_open_forward(channel: *mut ssh_channel_struct, remotehost: *const libc::c_char, remoteport: libc::c_int, sourcehost: *const libc::c_char, localport: libc::c_int) -> libc::c_int;
}


/*
int channel_open_session()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_open_session(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_poll()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) is_stderr
*/
extern "C" {
	pub fn channel_poll(channel: *mut ssh_channel_struct, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int channel_read()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(void *) dest
	(uint32_t) count [unsigned int]
	(int) is_stderr
*/
extern "C" {
	pub fn channel_read(channel: *mut ssh_channel_struct, dest: *mut libc::c_void, count: libc::c_uint, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int channel_read_buffer()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(ssh_buffer) buffer [struct ssh_buffer_struct *]
	(uint32_t) count [unsigned int]
	(int) is_stderr
*/
extern "C" {
	pub fn channel_read_buffer(channel: *mut ssh_channel_struct, buffer: *mut ssh_buffer_struct, count: libc::c_uint, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int channel_read_nonblocking()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(void *) dest
	(uint32_t) count [unsigned int]
	(int) is_stderr
*/
extern "C" {
	pub fn channel_read_nonblocking(channel: *mut ssh_channel_struct, dest: *mut libc::c_void, count: libc::c_uint, is_stderr: libc::c_int) -> libc::c_int;
}


/*
int channel_request_env()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) name
	(const char *) value
*/
extern "C" {
	pub fn channel_request_env(channel: *mut ssh_channel_struct, name: *const libc::c_char, value: *const libc::c_char) -> libc::c_int;
}


/*
int channel_request_exec()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) cmd
*/
extern "C" {
	pub fn channel_request_exec(channel: *mut ssh_channel_struct, cmd: *const libc::c_char) -> libc::c_int;
}


/*
int channel_request_pty()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_request_pty(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_request_pty_size()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) term
	(int) cols
	(int) rows
*/
extern "C" {
	pub fn channel_request_pty_size(channel: *mut ssh_channel_struct, term: *const libc::c_char, cols: libc::c_int, rows: libc::c_int) -> libc::c_int;
}


/*
int channel_request_shell()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_request_shell(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_request_send_signal()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) signum
*/
extern "C" {
	pub fn channel_request_send_signal(channel: *mut ssh_channel_struct, signum: *const libc::c_char) -> libc::c_int;
}


/*
int channel_request_sftp()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_request_sftp(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_request_subsystem()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const char *) subsystem
*/
extern "C" {
	pub fn channel_request_subsystem(channel: *mut ssh_channel_struct, subsystem: *const libc::c_char) -> libc::c_int;
}


/*
int channel_request_x11()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) single_connection
	(const char *) protocol
	(const char *) cookie
	(int) screen_number
*/
extern "C" {
	pub fn channel_request_x11(channel: *mut ssh_channel_struct, single_connection: libc::c_int, protocol: *const libc::c_char, cookie: *const libc::c_char, screen_number: libc::c_int) -> libc::c_int;
}


/*
int channel_send_eof()
	(ssh_channel) channel [struct ssh_channel_struct *]
*/
extern "C" {
	pub fn channel_send_eof(channel: *mut ssh_channel_struct) -> libc::c_int;
}


/*
int channel_select()
	(ssh_channel *) readchans [struct ssh_channel_struct **]
	(ssh_channel *) writechans [struct ssh_channel_struct **]
	(ssh_channel *) exceptchans [struct ssh_channel_struct **]
	(struct timeval *) timeout [struct timeval *]
*/
extern "C" {
	pub fn channel_select(readchans: *mut *mut ssh_channel_struct, writechans: *mut *mut ssh_channel_struct, exceptchans: *mut *mut ssh_channel_struct, timeout: *mut timeval) -> libc::c_int;
}


/*
void channel_set_blocking()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(int) blocking
*/
extern "C" {
	pub fn channel_set_blocking(channel: *mut ssh_channel_struct, blocking: libc::c_int);
}


/*
int channel_write()
	(ssh_channel) channel [struct ssh_channel_struct *]
	(const void *) data
	(uint32_t) len [unsigned int]
*/
extern "C" {
	pub fn channel_write(channel: *mut ssh_channel_struct, data: *const libc::c_void, len: libc::c_uint) -> libc::c_int;
}


/*
void privatekey_free()
	(ssh_private_key) prv [struct ssh_private_key_struct *]
*/
extern "C" {
	pub fn privatekey_free(prv: *mut ssh_private_key_struct);
}


/*
ssh_private_key privatekey_from_file() [struct ssh_private_key_struct *]
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) filename
	(int) type
	(const char *) passphrase
*/
extern "C" {
	pub fn privatekey_from_file(session: *mut ssh_session_struct, filename: *const libc::c_char, type_: libc::c_int, passphrase: *const libc::c_char) -> *mut ssh_private_key_struct;
}


/*
void publickey_free()
	(ssh_public_key) key [struct ssh_public_key_struct *]
*/
extern "C" {
	pub fn publickey_free(key: *mut ssh_public_key_struct);
}


/*
int ssh_publickey_to_file()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) file
	(ssh_string) pubkey [struct ssh_string_struct *]
	(int) type
*/
extern "C" {
	pub fn ssh_publickey_to_file(session: *mut ssh_session_struct, file: *const libc::c_char, pubkey: *mut ssh_string_struct, type_: libc::c_int) -> libc::c_int;
}


/*
ssh_string publickey_from_file() [struct ssh_string_struct *]
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) filename
	(int *) type
*/
extern "C" {
	pub fn publickey_from_file(session: *mut ssh_session_struct, filename: *const libc::c_char, type_: *mut libc::c_int) -> *mut ssh_string_struct;
}


/*
ssh_public_key publickey_from_privatekey() [struct ssh_public_key_struct *]
	(ssh_private_key) prv [struct ssh_private_key_struct *]
*/
extern "C" {
	pub fn publickey_from_privatekey(prv: *mut ssh_private_key_struct) -> *mut ssh_public_key_struct;
}


/*
ssh_string publickey_to_string() [struct ssh_string_struct *]
	(ssh_public_key) key [struct ssh_public_key_struct *]
*/
extern "C" {
	pub fn publickey_to_string(key: *mut ssh_public_key_struct) -> *mut ssh_string_struct;
}


/*
int ssh_try_publickey_from_file()
	(ssh_session) session [struct ssh_session_struct *]
	(const char *) keyfile
	(ssh_string *) publickey [struct ssh_string_struct **]
	(int *) type
*/
extern "C" {
	pub fn ssh_try_publickey_from_file(session: *mut ssh_session_struct, keyfile: *const libc::c_char, publickey: *mut *mut ssh_string_struct, type_: *mut libc::c_int) -> libc::c_int;
}


/*
enum ssh_keytypes_e ssh_privatekey_type() [enum ssh_keytypes_e]
	(ssh_private_key) privatekey [struct ssh_private_key_struct *]
*/
extern "C" {
	pub fn ssh_privatekey_type(privatekey: *mut ssh_private_key_struct) -> libc::c_uint;
}


/*
ssh_string ssh_get_pubkey() [struct ssh_string_struct *]
	(ssh_session) session [struct ssh_session_struct *]
*/
extern "C" {
	pub fn ssh_get_pubkey(session: *mut ssh_session_struct) -> *mut ssh_string_struct;
}


/*
ssh_message ssh_message_retrieve() [struct ssh_message_struct *]
	(ssh_session) session [struct ssh_session_struct *]
	(uint32_t) packettype [unsigned int]
*/
extern "C" {
	pub fn ssh_message_retrieve(session: *mut ssh_session_struct, packettype: libc::c_uint) -> *mut ssh_message_struct;
}


/*
ssh_public_key ssh_message_auth_publickey() [struct ssh_public_key_struct *]
	(ssh_message) msg [struct ssh_message_struct *]
*/
extern "C" {
	pub fn ssh_message_auth_publickey(msg: *mut ssh_message_struct) -> *mut ssh_public_key_struct;
}


/*
void string_burn()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn string_burn(str: *mut ssh_string_struct);
}


/*
ssh_string string_copy() [struct ssh_string_struct *]
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn string_copy(str: *mut ssh_string_struct) -> *mut ssh_string_struct;
}


/*
void * string_data()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn string_data(str: *mut ssh_string_struct) -> *mut libc::c_void;
}


/*
int string_fill()
	(ssh_string) str [struct ssh_string_struct *]
	(const void *) data
	(size_t) len [unsigned long]
*/
extern "C" {
	pub fn string_fill(str: *mut ssh_string_struct, data: *const libc::c_void, len: libc::c_ulong) -> libc::c_int;
}


/*
void string_free()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn string_free(str: *mut ssh_string_struct);
}


/*
ssh_string string_from_char() [struct ssh_string_struct *]
	(const char *) what
*/
extern "C" {
	pub fn string_from_char(what: *const libc::c_char) -> *mut ssh_string_struct;
}


/*
size_t string_len() [unsigned long]
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn string_len(str: *mut ssh_string_struct) -> libc::c_ulong;
}


/*
ssh_string string_new() [struct ssh_string_struct *]
	(size_t) size [unsigned long]
*/
extern "C" {
	pub fn string_new(size: libc::c_ulong) -> *mut ssh_string_struct;
}


/*
char * string_to_char()
	(ssh_string) str [struct ssh_string_struct *]
*/
extern "C" {
	pub fn string_to_char(str: *mut ssh_string_struct) -> *mut libc::c_char;
}


/*
struct ssh_agent_struct
*/
#[repr(C)]
pub struct ssh_agent_struct;

/*
struct ssh_buffer_struct
*/
#[repr(C)]
pub struct ssh_buffer_struct;

/*
struct ssh_channel_struct
*/
#[repr(C)]
pub struct ssh_channel_struct;

/*
struct ssh_message_struct
*/
#[repr(C)]
pub struct ssh_message_struct;

/*
struct ssh_pcap_file_struct
*/
#[repr(C)]
pub struct ssh_pcap_file_struct;

/*
struct ssh_key_struct
*/
#[repr(C)]
pub struct ssh_key_struct;

/*
struct ssh_scp_struct
*/
#[repr(C)]
pub struct ssh_scp_struct;

/*
struct ssh_session_struct
*/
#[repr(C)]
pub struct ssh_session_struct;

/*
struct ssh_string_struct
*/
#[repr(C)]
pub struct ssh_string_struct;

/*
struct ssh_event_struct
*/
#[repr(C)]
pub struct ssh_event_struct;

/*
struct ssh_private_key_struct
*/
#[repr(C)]
pub struct ssh_private_key_struct;

/*
struct ssh_public_key_struct
*/
#[repr(C)]
pub struct ssh_public_key_struct;

/*
struct None
*/
#[repr(C)]
pub struct None;

/*
struct timeval
		(__time_t) tv_sec [long]
		(__suseconds_t) tv_usec [long]
*/
#[repr(C)]
pub struct timeval {
	tv_sec: libc::c_long,
	tv_usec: libc::c_long,
}

/*
struct fd_set
		(__fd_mask [16]) __fds_bits [long [16]]
*/
#[repr(C)]
pub struct fd_set {
	__fds_bits: [libc::c_long, ..16],
}

/*
enum ssh_kex_types_e {
	SSH_KEX =	0x00000000 (0)
	SSH_HOSTKEYS =	0x00000001 (1)
	SSH_CRYPT_C_S =	0x00000002 (2)
	SSH_CRYPT_S_C =	0x00000003 (3)
	SSH_MAC_C_S =	0x00000004 (4)
	SSH_MAC_S_C =	0x00000005 (5)
	SSH_COMP_C_S =	0x00000006 (6)
	SSH_COMP_S_C =	0x00000007 (7)
	SSH_LANG_C_S =	0x00000008 (8)
	SSH_LANG_S_C =	0x00000009 (9)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_kex_types_e {
	SSH_KEX =	0,
	SSH_HOSTKEYS =	1,
	SSH_CRYPT_C_S =	2,
	SSH_CRYPT_S_C =	3,
	SSH_MAC_C_S =	4,
	SSH_MAC_S_C =	5,
	SSH_COMP_C_S =	6,
	SSH_COMP_S_C =	7,
	SSH_LANG_C_S =	8,
	SSH_LANG_S_C =	9,
}

impl ssh_kex_types_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_kex_types_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_auth_e {
	SSH_AUTH_SUCCESS =	0x00000000 (0)
	SSH_AUTH_DENIED =	0x00000001 (1)
	SSH_AUTH_PARTIAL =	0x00000002 (2)
	SSH_AUTH_INFO =	0x00000003 (3)
	SSH_AUTH_AGAIN =	0x00000004 (4)
	SSH_AUTH_ERROR =	0x-0000001 (-1)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(i32)]
pub enum ssh_auth_e {
	SSH_AUTH_SUCCESS =	0,
	SSH_AUTH_DENIED =	1,
	SSH_AUTH_PARTIAL =	2,
	SSH_AUTH_INFO =	3,
	SSH_AUTH_AGAIN =	4,
	SSH_AUTH_ERROR =	-1,
}

impl ssh_auth_e {
	pub fn to_i32(&self) -> libc::c_int {
		*self as libc::c_int
	}

	pub fn from_i32(v: libc::c_int) -> ssh_auth_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_requests_e {
	SSH_REQUEST_AUTH =	0x00000001 (1)
	SSH_REQUEST_CHANNEL_OPEN =	0x00000002 (2)
	SSH_REQUEST_CHANNEL =	0x00000003 (3)
	SSH_REQUEST_SERVICE =	0x00000004 (4)
	SSH_REQUEST_GLOBAL =	0x00000005 (5)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_requests_e {
	SSH_REQUEST_AUTH =	1,
	SSH_REQUEST_CHANNEL_OPEN =	2,
	SSH_REQUEST_CHANNEL =	3,
	SSH_REQUEST_SERVICE =	4,
	SSH_REQUEST_GLOBAL =	5,
}

impl ssh_requests_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_requests_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_channel_type_e {
	SSH_CHANNEL_UNKNOWN =	0x00000000 (0)
	SSH_CHANNEL_SESSION =	0x00000001 (1)
	SSH_CHANNEL_DIRECT_TCPIP =	0x00000002 (2)
	SSH_CHANNEL_FORWARDED_TCPIP =	0x00000003 (3)
	SSH_CHANNEL_X11 =	0x00000004 (4)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_channel_type_e {
	SSH_CHANNEL_UNKNOWN =	0,
	SSH_CHANNEL_SESSION =	1,
	SSH_CHANNEL_DIRECT_TCPIP =	2,
	SSH_CHANNEL_FORWARDED_TCPIP =	3,
	SSH_CHANNEL_X11 =	4,
}

impl ssh_channel_type_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_channel_type_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_channel_requests_e {
	SSH_CHANNEL_REQUEST_UNKNOWN =	0x00000000 (0)
	SSH_CHANNEL_REQUEST_PTY =	0x00000001 (1)
	SSH_CHANNEL_REQUEST_EXEC =	0x00000002 (2)
	SSH_CHANNEL_REQUEST_SHELL =	0x00000003 (3)
	SSH_CHANNEL_REQUEST_ENV =	0x00000004 (4)
	SSH_CHANNEL_REQUEST_SUBSYSTEM =	0x00000005 (5)
	SSH_CHANNEL_REQUEST_WINDOW_CHANGE =	0x00000006 (6)
	SSH_CHANNEL_REQUEST_X11 =	0x00000007 (7)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_channel_requests_e {
	SSH_CHANNEL_REQUEST_UNKNOWN =	0,
	SSH_CHANNEL_REQUEST_PTY =	1,
	SSH_CHANNEL_REQUEST_EXEC =	2,
	SSH_CHANNEL_REQUEST_SHELL =	3,
	SSH_CHANNEL_REQUEST_ENV =	4,
	SSH_CHANNEL_REQUEST_SUBSYSTEM =	5,
	SSH_CHANNEL_REQUEST_WINDOW_CHANGE =	6,
	SSH_CHANNEL_REQUEST_X11 =	7,
}

impl ssh_channel_requests_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_channel_requests_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_global_requests_e {
	SSH_GLOBAL_REQUEST_UNKNOWN =	0x00000000 (0)
	SSH_GLOBAL_REQUEST_TCPIP_FORWARD =	0x00000001 (1)
	SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD =	0x00000002 (2)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_global_requests_e {
	SSH_GLOBAL_REQUEST_UNKNOWN =	0,
	SSH_GLOBAL_REQUEST_TCPIP_FORWARD =	1,
	SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD =	2,
}

impl ssh_global_requests_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_global_requests_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_publickey_state_e {
	SSH_PUBLICKEY_STATE_ERROR =	0x-0000001 (-1)
	SSH_PUBLICKEY_STATE_NONE =	0x00000000 (0)
	SSH_PUBLICKEY_STATE_VALID =	0x00000001 (1)
	SSH_PUBLICKEY_STATE_WRONG =	0x00000002 (2)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(i32)]
pub enum ssh_publickey_state_e {
	SSH_PUBLICKEY_STATE_ERROR =	-1,
	SSH_PUBLICKEY_STATE_NONE =	0,
	SSH_PUBLICKEY_STATE_VALID =	1,
	SSH_PUBLICKEY_STATE_WRONG =	2,
}

impl ssh_publickey_state_e {
	pub fn to_i32(&self) -> libc::c_int {
		*self as libc::c_int
	}

	pub fn from_i32(v: libc::c_int) -> ssh_publickey_state_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_server_known_e {
	SSH_SERVER_ERROR =	0x-0000001 (-1)
	SSH_SERVER_NOT_KNOWN =	0x00000000 (0)
	SSH_SERVER_KNOWN_OK =	0x00000001 (1)
	SSH_SERVER_KNOWN_CHANGED =	0x00000002 (2)
	SSH_SERVER_FOUND_OTHER =	0x00000003 (3)
	SSH_SERVER_FILE_NOT_FOUND =	0x00000004 (4)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(i32)]
pub enum ssh_server_known_e {
	SSH_SERVER_ERROR =	-1,
	SSH_SERVER_NOT_KNOWN =	0,
	SSH_SERVER_KNOWN_OK =	1,
	SSH_SERVER_KNOWN_CHANGED =	2,
	SSH_SERVER_FOUND_OTHER =	3,
	SSH_SERVER_FILE_NOT_FOUND =	4,
}

impl ssh_server_known_e {
	pub fn to_i32(&self) -> libc::c_int {
		*self as libc::c_int
	}

	pub fn from_i32(v: libc::c_int) -> ssh_server_known_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_error_types_e {
	SSH_NO_ERROR =	0x00000000 (0)
	SSH_REQUEST_DENIED =	0x00000001 (1)
	SSH_FATAL =	0x00000002 (2)
	SSH_EINTR =	0x00000003 (3)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_error_types_e {
	SSH_NO_ERROR =	0,
	SSH_REQUEST_DENIED =	1,
	SSH_FATAL =	2,
	SSH_EINTR =	3,
}

impl ssh_error_types_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_error_types_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_keytypes_e {
	SSH_KEYTYPE_UNKNOWN =	0x00000000 (0)
	SSH_KEYTYPE_DSS =	0x00000001 (1)
	SSH_KEYTYPE_RSA =	0x00000002 (2)
	SSH_KEYTYPE_RSA1 =	0x00000003 (3)
	SSH_KEYTYPE_ECDSA =	0x00000004 (4)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_keytypes_e {
	SSH_KEYTYPE_UNKNOWN =	0,
	SSH_KEYTYPE_DSS =	1,
	SSH_KEYTYPE_RSA =	2,
	SSH_KEYTYPE_RSA1 =	3,
	SSH_KEYTYPE_ECDSA =	4,
}

impl ssh_keytypes_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_keytypes_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_keycmp_e {
	SSH_KEY_CMP_PUBLIC =	0x00000000 (0)
	SSH_KEY_CMP_PRIVATE =	0x00000001 (1)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_keycmp_e {
	SSH_KEY_CMP_PUBLIC =	0,
	SSH_KEY_CMP_PRIVATE =	1,
}

impl ssh_keycmp_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_keycmp_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum  {
	SSH_LOG_NOLOG =	0x00000000 (0)
	SSH_LOG_WARNING =	0x00000001 (1)
	SSH_LOG_PROTOCOL =	0x00000002 (2)
	SSH_LOG_PACKET =	0x00000003 (3)
	SSH_LOG_FUNCTIONS =	0x00000004 (4)
}
*/
pub const SSH_LOG_NOLOG: i32 = 0;
pub const SSH_LOG_WARNING: i32 = 1;
pub const SSH_LOG_PROTOCOL: i32 = 2;
pub const SSH_LOG_PACKET: i32 = 3;
pub const SSH_LOG_FUNCTIONS: i32 = 4;

/*
enum ssh_options_e {
	SSH_OPTIONS_HOST =	0x00000000 (0)
	SSH_OPTIONS_PORT =	0x00000001 (1)
	SSH_OPTIONS_PORT_STR =	0x00000002 (2)
	SSH_OPTIONS_FD =	0x00000003 (3)
	SSH_OPTIONS_USER =	0x00000004 (4)
	SSH_OPTIONS_SSH_DIR =	0x00000005 (5)
	SSH_OPTIONS_IDENTITY =	0x00000006 (6)
	SSH_OPTIONS_ADD_IDENTITY =	0x00000007 (7)
	SSH_OPTIONS_KNOWNHOSTS =	0x00000008 (8)
	SSH_OPTIONS_TIMEOUT =	0x00000009 (9)
	SSH_OPTIONS_TIMEOUT_USEC =	0x0000000A (10)
	SSH_OPTIONS_SSH1 =	0x0000000B (11)
	SSH_OPTIONS_SSH2 =	0x0000000C (12)
	SSH_OPTIONS_LOG_VERBOSITY =	0x0000000D (13)
	SSH_OPTIONS_LOG_VERBOSITY_STR =	0x0000000E (14)
	SSH_OPTIONS_CIPHERS_C_S =	0x0000000F (15)
	SSH_OPTIONS_CIPHERS_S_C =	0x00000010 (16)
	SSH_OPTIONS_COMPRESSION_C_S =	0x00000011 (17)
	SSH_OPTIONS_COMPRESSION_S_C =	0x00000012 (18)
	SSH_OPTIONS_PROXYCOMMAND =	0x00000013 (19)
	SSH_OPTIONS_BINDADDR =	0x00000014 (20)
	SSH_OPTIONS_STRICTHOSTKEYCHECK =	0x00000015 (21)
	SSH_OPTIONS_COMPRESSION =	0x00000016 (22)
	SSH_OPTIONS_COMPRESSION_LEVEL =	0x00000017 (23)
	SSH_OPTIONS_KEY_EXCHANGE =	0x00000018 (24)
	SSH_OPTIONS_HOSTKEYS =	0x00000019 (25)
	SSH_OPTIONS_GSSAPI_SERVER_IDENTITY =	0x0000001A (26)
	SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY =	0x0000001B (27)
	SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS =	0x0000001C (28)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_options_e {
	SSH_OPTIONS_HOST =	0,
	SSH_OPTIONS_PORT =	1,
	SSH_OPTIONS_PORT_STR =	2,
	SSH_OPTIONS_FD =	3,
	SSH_OPTIONS_USER =	4,
	SSH_OPTIONS_SSH_DIR =	5,
	SSH_OPTIONS_IDENTITY =	6,
	SSH_OPTIONS_ADD_IDENTITY =	7,
	SSH_OPTIONS_KNOWNHOSTS =	8,
	SSH_OPTIONS_TIMEOUT =	9,
	SSH_OPTIONS_TIMEOUT_USEC =	10,
	SSH_OPTIONS_SSH1 =	11,
	SSH_OPTIONS_SSH2 =	12,
	SSH_OPTIONS_LOG_VERBOSITY =	13,
	SSH_OPTIONS_LOG_VERBOSITY_STR =	14,
	SSH_OPTIONS_CIPHERS_C_S =	15,
	SSH_OPTIONS_CIPHERS_S_C =	16,
	SSH_OPTIONS_COMPRESSION_C_S =	17,
	SSH_OPTIONS_COMPRESSION_S_C =	18,
	SSH_OPTIONS_PROXYCOMMAND =	19,
	SSH_OPTIONS_BINDADDR =	20,
	SSH_OPTIONS_STRICTHOSTKEYCHECK =	21,
	SSH_OPTIONS_COMPRESSION =	22,
	SSH_OPTIONS_COMPRESSION_LEVEL =	23,
	SSH_OPTIONS_KEY_EXCHANGE =	24,
	SSH_OPTIONS_HOSTKEYS =	25,
	SSH_OPTIONS_GSSAPI_SERVER_IDENTITY =	26,
	SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY =	27,
	SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS =	28,
}

impl ssh_options_e {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_options_e {
		unsafe { mem::transmute(v) }
	}
}


/*
enum  {
	SSH_SCP_WRITE =	0x00000000 (0)
	SSH_SCP_READ =	0x00000001 (1)
	SSH_SCP_RECURSIVE =	0x00000010 (16)
}
*/
pub const SSH_SCP_WRITE: i32 = 0;
pub const SSH_SCP_READ: i32 = 1;
pub const SSH_SCP_RECURSIVE: i32 = 16;

/*
enum ssh_scp_request_types {
	SSH_SCP_REQUEST_NEWDIR =	0x00000001 (1)
	SSH_SCP_REQUEST_NEWFILE =	0x00000002 (2)
	SSH_SCP_REQUEST_EOF =	0x00000003 (3)
	SSH_SCP_REQUEST_ENDDIR =	0x00000004 (4)
	SSH_SCP_REQUEST_WARNING =	0x00000005 (5)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_scp_request_types {
	SSH_SCP_REQUEST_NEWDIR =	1,
	SSH_SCP_REQUEST_NEWFILE =	2,
	SSH_SCP_REQUEST_EOF =	3,
	SSH_SCP_REQUEST_ENDDIR =	4,
	SSH_SCP_REQUEST_WARNING =	5,
}

impl ssh_scp_request_types {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_scp_request_types {
		unsafe { mem::transmute(v) }
	}
}


/*
enum ssh_publickey_hash_type {
	SSH_PUBLICKEY_HASH_SHA1 =	0x00000000 (0)
	SSH_PUBLICKEY_HASH_MD5 =	0x00000001 (1)
}
*/
#[deriving(Copy, PartialEq, Show)]
#[repr(u32)]
pub enum ssh_publickey_hash_type {
	SSH_PUBLICKEY_HASH_SHA1 =	0,
	SSH_PUBLICKEY_HASH_MD5 =	1,
}

impl ssh_publickey_hash_type {
	pub fn to_u32(&self) -> libc::c_uint {
		*self as libc::c_uint
	}

	pub fn from_u32(v: libc::c_uint) -> ssh_publickey_hash_type {
		unsafe { mem::transmute(v) }
	}
}


/* _LIBSSH_H # */

/* LIBSSH_API __attribute__ ( ( visibility ( "default" ) ) ) # */

/* SSH_STRINGIFY ( s ) SSH_TOSTRING ( s ) # */

/* SSH_TOSTRING ( s ) # s /* libssh version macros */ */

/* SSH_VERSION_INT ( a , b , c ) ( ( a ) << 16 | ( b ) << 8 | ( c ) ) # */

/* SSH_VERSION_DOT ( a , b , c ) a ## . ## b ## . ## c # */

/* SSH_VERSION ( a , b , c ) SSH_VERSION_DOT ( a , b , c ) /* libssh version */ */

/* LIBSSH_VERSION_MAJOR 0 # */
pub const LIBSSH_VERSION_MAJOR: i32 = 0;

/* LIBSSH_VERSION_MINOR 6 # */
pub const LIBSSH_VERSION_MINOR: i32 = 6;

/* LIBSSH_VERSION_MICRO 3 # */
pub const LIBSSH_VERSION_MICRO: i32 = 3;

/* LIBSSH_VERSION_INT SSH_VERSION_INT ( LIBSSH_VERSION_MAJOR , LIBSSH_VERSION_MINOR , LIBSSH_VERSION_MICRO ) # */

/* LIBSSH_VERSION SSH_VERSION ( LIBSSH_VERSION_MAJOR , LIBSSH_VERSION_MINOR , LIBSSH_VERSION_MICRO ) /* GCC have printf type attribute check.  */ */

/* PRINTF_ATTRIBUTE ( a , b ) __attribute__ ( ( __format__ ( __printf__ , a , b ) ) ) # */

/* SSH_DEPRECATED __attribute__ ( ( deprecated ) ) # */

/* SSH_INVALID_SOCKET ( ( socket_t ) - 1 ) /* the offsets of methods */ */

/* SSH_CRYPT 2 # */
pub const SSH_CRYPT: i32 = 2;

/* SSH_MAC 3 # */
pub const SSH_MAC: i32 = 3;

/* SSH_COMP 4 # */
pub const SSH_COMP: i32 = 4;

/* SSH_LANG 5 enum */
pub const SSH_LANG: i32 = 5;

/* SSH_AUTH_METHOD_UNKNOWN 0 # */
pub const SSH_AUTH_METHOD_UNKNOWN: i32 = 0;

/* SSH_AUTH_METHOD_NONE 0x0001 # */
pub const SSH_AUTH_METHOD_NONE: i32 = 1;

/* SSH_AUTH_METHOD_PASSWORD 0x0002 # */
pub const SSH_AUTH_METHOD_PASSWORD: i32 = 2;

/* SSH_AUTH_METHOD_PUBLICKEY 0x0004 # */
pub const SSH_AUTH_METHOD_PUBLICKEY: i32 = 4;

/* SSH_AUTH_METHOD_HOSTBASED 0x0008 # */
pub const SSH_AUTH_METHOD_HOSTBASED: i32 = 8;

/* SSH_AUTH_METHOD_INTERACTIVE 0x0010 # */
pub const SSH_AUTH_METHOD_INTERACTIVE: i32 = 16;

/* SSH_AUTH_METHOD_GSSAPI_MIC 0x0020 /* messages */ */
pub const SSH_AUTH_METHOD_GSSAPI_MIC: i32 = 32;

/* SSH_CLOSED 0x01 /** Reading to socket won't block */ */
pub const SSH_CLOSED: i32 = 1;

/* SSH_READ_PENDING 0x02 /** Session was closed due to an error */ */
pub const SSH_READ_PENDING: i32 = 2;

/* SSH_CLOSED_ERROR 0x04 /** Output buffer not empty */ */
pub const SSH_CLOSED_ERROR: i32 = 4;

/* SSH_WRITE_PENDING 0x08 enum */
pub const SSH_WRITE_PENDING: i32 = 8;

/* MD5_DIGEST_LEN 16 # */
pub const MD5_DIGEST_LEN: i32 = 16;

/* SSH_OK 0 /* No error */ */
pub const SSH_OK: i32 = 0;

/* SSH_ERROR - 1 /* Error of some kind */ */
pub const SSH_ERROR: i32 = -1;

/* SSH_AGAIN - 2 /* The nonblocking call must be repeated */ */
pub const SSH_AGAIN: i32 = -2;

/* SSH_EOF - 127 /* We have already a eof */ */
pub const SSH_EOF: i32 = -127;

/* SSH_LOG_RARE SSH_LOG_WARNING /**
 * @name Logging levels
 *
 * @brief Debug levels for logging.
 * @{
 */ */

/* SSH_LOG_NONE 0 /** Show only warnings */ */
pub const SSH_LOG_NONE: i32 = 0;

/* SSH_LOG_WARN 1 /** Get some information what's going on */ */
pub const SSH_LOG_WARN: i32 = 1;

/* SSH_LOG_INFO 2 /** Get detailed debuging information **/ */
pub const SSH_LOG_INFO: i32 = 2;

/* SSH_LOG_DEBUG 3 /** Get trace output, packet information, ... */ */
pub const SSH_LOG_DEBUG: i32 = 3;

/* SSH_LOG_TRACE 4 /** @} */ */
pub const SSH_LOG_TRACE: i32 = 4;

/* LEGACY_H_ typedef */

