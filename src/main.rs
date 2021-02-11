use std::fs;
use std::fs::File;
use std::io;
use std::io::{Write, Read};
use std::time::SystemTime;
use std::path::{PathBuf};
use directories::{ProjectDirs};
use rpassword::read_password;
#[macro_use] extern crate serde_derive;
use rustyline::Editor;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use progress_bar::progress_bar::ProgressBar;

//"\u{1b}]31mFFFFF\u{1b}]0m" 

//Color formatting codes
#[cfg(target_os = "macos")]
mod constants {
	pub const ENV_USER: &str = env!("USER");

	pub const RED: &str = "\x1b[31mERR: ";
	pub const GRN: &str = "\x1b[32mSCSS: ";
	pub const ORG: &str = "\x1b[33mWARN: ";
	pub const BLD: &str = "\x1b[1mINF: ";
	pub const MAG: &str = "\x1b[35m";
	pub const CYN: &str = "\x1b[36m";
	pub const RES: &str = "\x1b[0m";
	pub const CTB: &str = "\x1b[100H";
}

#[cfg(target_os = "windows")]
mod constants {
	pub const ENV_USER: &str = env!("USERNAME");

	pub const RED: &str = "";
	pub const GRN: &str = "";
	pub const ORG: &str = "";
	pub const BLD: &str = "";
	pub const MAG: &str = "";
	pub const CYN: &str = "";
	pub const RES: &str = "";
	pub const CTB: &str = "\x1b[100H";
}
use crate::constants::*;

const CHECKSEED: &'static str = "ZENIT345";

#[derive(Serialize, Deserialize, Debug)]
struct ConfigFile {
	since: u64,
	default_dir: String,
	data: Vec<u8>
}
#[derive(Serialize, Deserialize, Debug)]
struct EncryptedFile {
	since: u64,
	user: String,
	formal_name: String,
	data: Vec<u8>
}
#[derive(Debug)]
struct Lifecycle {
	dir: String,
	default_dir: String,
	key: Vec<u8>,
	iv: Vec<u8>
}
#[derive(Debug)]
struct OperationOutcome {
	total: usize,
	ok: usize,
	skip: usize,
	fail: usize
}
#[derive(Debug)]
enum OperationStepResult {
	Ok,
	Skip,
	Fail
}
#[derive(Debug)]
struct DirectoryCondition{
	total: usize,
	encrypted: usize,
	decrypted: usize,
	other: usize,
	condition: DirectoryConditionLabel
}
#[derive(Debug)]
enum DirectoryConditionLabel{
	FullyEncrypted,
	FullyDecrypted,
	Empty,
	Other
}

fn main() {
	let configdir: PathBuf;
	let mut configfile: PathBuf;
	let mut readline_editor = Editor::<()>::new();
	let mut lifecycle: Lifecycle;

	println!("Welcome to Hide v{}\n", env!("CARGO_PKG_VERSION"));

	//Checking if config file exists using env vars lib
	if let Some(proj_dirs) = ProjectDirs::from("com", "Fetch", "Hide") {
		configdir = proj_dirs.config_dir().to_owned();
		configfile = configdir.clone();
		configfile.push("conf.fetch")
	}
	else {
		panic("Couldn't access configuration directory");
	}

	if configfile.exists() {
		let p = request_password(Some("Password #1: >"));
		let iv = fill_byte_arr(p.as_bytes(), 0, 16).to_owned();
		let o = request_password(Some("Password #2: >"));
		let key = fill_byte_arr(o.as_bytes(), 0, 32);

		let filecontent: String = string_from_file(&configfile).unwrap();
		let decrypted: ConfigFile; 

		match serde_json::from_str::<ConfigFile>(&filecontent){
			Ok(result) => decrypted = result,
			Err(error) => panic(&error.to_string())
		}
		match decrypt_data(&decrypted.data, &key, &iv){
			Ok(result) => {
				if String::from_utf8_lossy(&result) == CHECKSEED {
					println!("{}Access granted{}", GRN, RES);
					let z = decrypted.default_dir;
					lifecycle = Lifecycle{default_dir: z.clone(), dir: z, key: key.to_vec(), iv: iv.to_vec()};
					let a = (get_now() - decrypted.since) / 86400;
					if a > 365{
						println!("{}It's {} days since the password changed{}", ORG, a, RES)
					}
				} else {
					panic("Access restricted (1)")
				}
			},
			Err(_) => panic("Access restricted (2)")
		}
	}
	//Creating new password
	else {
		println!("{}Couldn't find config file, will create new.{}", BLD, RES);
		println!("Encryption bases on a pair of password.\nFirst one of up to 16 numbers, and second one of up to 32.");
		fs::create_dir_all(configdir).expect("Couldn't create directory");
		let encrypted_data: Vec<u8>;
		let mut iv = vec!();
		let mut key = vec!();
		'outer: loop {
			for i in 1..=2{
				let password = request_password(if i == 2 { Some("Now enter second password (up to 32 digits) >") } else { Some("Now enter first password (up to 16 digits) >") });
				match password.as_bytes().len(){
					6..=16 => (),
					n @ _ => { println!("Password of length {}; expected one of value between 6 and 16", n); continue 'outer }
				}
				println!("Now confirm");
				if request_password(None) != password {
					println!("{}Passwords did not match{}", RED, RES);
					continue 'outer
				}
				if i == 2 { key = fill_byte_arr(password.as_bytes(), 0, 32) } else { iv = fill_byte_arr(password.as_bytes(), 0, 16) }
			}
			match encrypt_data(CHECKSEED.as_bytes(), &key, &iv){
				Ok(result) => { encrypted_data = result; break }
				Err(error) => println!("{}{:?}{}", RED, error, RES)
			}
		}
		
		loop{
			println!("Now provide a default encryption directory (full path like /a/b/c)");
			let dir = readline_editor.readline("> ").expect("Stdin error");
			match fs::read_dir(&dir){
				Ok(_) => {
					lifecycle = Lifecycle{default_dir: dir.clone(), dir: dir.clone(), iv: iv.to_vec(), key: key.to_vec()};
					let json: String;
					match serde_json::to_string(&prepare_config(encrypted_data, dir)){
						Ok(result) => json = result,
						Err(error) => panic(&error.to_string())
					}
					write_to_file(&configfile, json);
					println!("{}Configuration saved{}", GRN, RES);
					println!("{}Consider using [help] command{}", BLD, RES);
					break;
				},
				Err(error) => println!("{}Unreachable dir: {}{}", RED, error, RES)
			}
		}
	}

//**********************************
//********* Main lifecycle *********
//**********************************
	let user = ENV_USER;
	loop {
		match &(readline_editor.readline(&format!("{}{}@Hide {} > {}", MAG, user, &lifecycle.dir.split("/").collect::<Vec<&str>>().last().unwrap_or(&"~"), RES)).expect("Stdin error")) as &str{
			"kill" | "exit" => exit(),
			"ld" | "ls" => {
				println!("{}:", lifecycle.dir);
				let mut dirst = DirectoryCondition{total: 0, encrypted: 0, decrypted: 0, other: 0, condition: DirectoryConditionLabel::Other};
				match walk_through_dir(false, &lifecycle.dir, &mut|i: usize, path: &fs::DirEntry| { 
							println!("{}.{} {}", i + 1, 
								if path.file_type().unwrap().is_dir() { 
									dirst.other += 1;
									format!("{} [FLDR]{}", CYN, RES) 
								} else if path.file_type().unwrap().is_symlink() {
									dirst.other += 1;
									format!("{} [SYML]{}", CYN, RES)
								} else if path.path().extension().is_none() { 
									dirst.other += 1;
									format!("{} [NOEX]{}", CYN, RES)
								} else if path.file_name().into_string().unwrap_or(String::new()).contains(".crpt") {
									dirst.encrypted += 1;
									format!("{} [CRPT]{}", CYN, RES)
								} else { 
									dirst.decrypted += 1;
									String::new()
								}, 
								path.file_name().into_string().unwrap());
							dirst.total += 1;
							OperationStepResult::Ok
						}
					) {
						Err(_) => println!("{}Empty/unreachable dir{}", RED, RES),
						Ok(_) => {
							dirst.define_condition();
							match dirst.condition {
								DirectoryConditionLabel::Empty => println!("{} is empty", lifecycle.dir),
								DirectoryConditionLabel::FullyEncrypted => println!("{} is fully encrypted", lifecycle.dir),
								DirectoryConditionLabel::FullyDecrypted => println!("{} is fully decrypted", lifecycle.dir),
								DirectoryConditionLabel::Other => { 
									println!("{}: {} encrypted, {} decrypted, {} other with total of {} files", lifecycle.dir, dirst.encrypted, dirst.decrypted, dirst.other, dirst.total)
								}
							}
						}
				}
			},
			"cd" => { lifecycle.dir = lifecycle.default_dir.clone(); println!("{}Directory set to default{}", GRN, RES) },
			cd if cd.contains("cd") => {
				let dir = cd.replace("cd ","");
				match fs::read_dir(&dir){
					Ok(_) => {
						lifecycle.dir = dir;
						println!("{}Directory changed{}", GRN, RES);
					},
					Err(error) => println!("{}Unreachable dir: {}{}", RED, error, RES)
				}
			},
			"st" => {
				let mut dirst = DirectoryCondition{total: 0, encrypted: 0, decrypted: 0, other: 0, condition: DirectoryConditionLabel::Other};
				match walk_through_dir(false, &lifecycle.dir, &mut|_i: usize, path: &fs::DirEntry, | {
								if path.file_type().unwrap().is_dir() { 
									dirst.other += 1;
								} else if path.file_type().unwrap().is_symlink() {
									dirst.other += 1;
								} else if path.path().extension().is_none() { 
									dirst.other += 1;
								} else if path.file_name().into_string().unwrap_or(String::new()).contains(".crpt") {
									dirst.encrypted += 1;
								} else { 
									dirst.decrypted += 1;
								}
								dirst.total += 1;
								OperationStepResult::Ok
							}
						) {
						Err(_) => println!("{}Empty/unreachable dir{}", RED, RES),
						Ok(_) => {
							dirst.define_condition();
							match dirst.condition {
								DirectoryConditionLabel::Empty => println!("{} is empty", lifecycle.dir),
								DirectoryConditionLabel::FullyEncrypted => println!("{} is fully encrypted", lifecycle.dir),
								DirectoryConditionLabel::FullyDecrypted => println!("{} is fully decrypted", lifecycle.dir),
								DirectoryConditionLabel::Other => { 
									println!("{}: {} encrypted, {} decrypted, {} other with total of {} files", lifecycle.dir, dirst.encrypted, dirst.decrypted, dirst.other, dirst.total)
								}
							}
						}
					}
			}
			"en" => {
					println!("Encrypting {}...", &lifecycle.dir);
					match walk_through_dir(true, &lifecycle.dir, &mut|i: usize, path: &fs::DirEntry| {
								encrypt(path, &lifecycle.dir, i)
							}
						) {
						Err(_) => println!("{}Empty/unreachable dir{}", RED, RES),
						Ok(result) => println!("\nOperation totals: {} encrypted, {} skipped, {} errors, {} total", result.ok, result.skip, result.fail, result.total)
					}
			},
			en if en.contains("en") => {
				let mode = en.replace("en", "");
				match &mode as &str {
					"" => (),
					_ => ()
				}
			},
			"de" => {
				println!("Decrypting {}...", &lifecycle.dir);
				match walk_through_dir(true, &lifecycle.dir, &mut|_i: usize, path: &fs::DirEntry| {
							decrypt(path)
						}
					){
					Err(_) => println!("{}Empty/unreachable dir{}", RED, RES),
					Ok(result) => println!("\nOperation totals: {} decrypted, {} skipped, {} errors", result.ok, result.skip, result.fail)
				}
			},
			"revoke" => {
				println!("{}All settings and password data will be lost. This action can't be undone.{}", ORG, RES);
				if readline_editor.readline("Type 'delete data' to proceed: > ").expect("Stdin error") == "delete data"{
					fs::remove_file(configfile).expect("Couldn't delete");
					println!("{}Configuration deleted{}", GRN, RES);
					std::process::exit(-1)
				}
				else{
					println!("Cancelled");
				}
			}
			_ => println!("Unknown command")
		}
	}
}

//Functions of data handling
fn encrypt_data(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
	let mut encryptor = aes::cbc_encryptor(
			aes::KeySize::KeySize256,
			key,
			iv,
			blockmodes::PkcsPadding);
	let mut final_result = Vec::<u8>::new();
	let mut read_buffer = buffer::RefReadBuffer::new(data);
	let mut buffer = [0; 4096];
	let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
	loop {
		let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
		final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

		match result {
			BufferResult::BufferUnderflow => break,
			BufferResult::BufferOverflow => { }
		}
	}

	Ok(final_result)
}

fn decrypt_data(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
	let mut decryptor = aes::cbc_decryptor(
			aes::KeySize::KeySize256,
			key,
			iv,
			blockmodes::PkcsPadding);

	let mut final_result = Vec::<u8>::new();
	let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
	let mut buffer = [0; 4096];
	let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

	loop {
		let result: crypto::buffer::BufferResult;
		match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true){
			Ok(res) => result = res,
			Err(_) => (return Err(symmetriccipher::SymmetricCipherError::InvalidPadding))
		}
		final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
		match result {
			BufferResult::BufferUnderflow => break,
			BufferResult::BufferOverflow => { }
		}
	}

	Ok(final_result)
}

//Function of defining directory condition
impl DirectoryCondition{
	fn define_condition(&mut self){
		if self.total == self.encrypted + self.other && self.encrypted > 0 {
			self.condition = DirectoryConditionLabel::FullyEncrypted
		} else if self.total == self.decrypted + self.other && self.decrypted > 0 {
			self.condition = DirectoryConditionLabel::FullyDecrypted
		} else if self.total == 0 {
			self.condition = DirectoryConditionLabel::Empty
		} else {
			self.condition = DirectoryConditionLabel::Other
		}
	}
}
//Function of smart exiting
fn exit() -> ! {
	std::process::exit(-1)
}

//Function of walking through dir
fn walk_through_dir(progress_bar: bool, dir: &str, foreach: &mut dyn FnMut(usize, &fs::DirEntry) -> OperationStepResult) -> Result<OperationOutcome, io::Error> {
	match fs::read_dir(dir){
		Ok(result) => {
			let mut map: Vec<_> = result.map(|r| r.unwrap()).collect();
			map.sort_by_key(|dir| dir.file_name());
			let mut bar = ProgressBar::new(map.len());
			let mut oks = 0;
			let mut skips = 0;
			let mut fails = 0;
			for (i, path) in map.iter().enumerate() {
				match foreach(i, path){
					OperationStepResult::Ok => oks += 1,
					OperationStepResult::Skip => skips += 1,
					OperationStepResult::Fail => fails += 1,
				}
				if progress_bar { bar.inc() }
			}
			return Ok(OperationOutcome{total: map.len(), ok: oks, skip: skips, fail: fails})
		},
		Err(error) => return Err(error)
	}
}

//Function of filling an array
fn fill_byte_arr(vec: &[u8], with: u8, until: usize) -> Vec<u8>{
	let mut v = vec.to_vec();
	while v.len() < until{	
		v.push(with);
	}
	v
}

//Function of getting timestamp
fn get_now() -> u64{
	let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
	let a: u64;
	match now {
		Ok(n) => a = n.as_secs(),
		Err(_) => panic("SystemTime set wrong"),
	}
	a
}

//Function of handling decryption
fn decrypt(path: &fs::DirEntry) -> OperationStepResult{
	let name = path.file_name().into_string().unwrap_or(String::new());
	if !name.contains(".crpt"){
			return OperationStepResult::Skip
	} else {
		let json: EncryptedFile;
		let filecontent: String;
		match string_from_file(&path.path()){
			Ok(result) => filecontent = result,
			Err(_) => { println!("\n{}Couldn't read {}{}", RED, name, RES); return OperationStepResult::Fail }
		}
		match serde_json::from_str::<EncryptedFile>(&filecontent){
			Ok(result) => json = result,
			Err(error) => { println!("\n{}{} ({}){}", RED, error, name, RES); return OperationStepResult::Fail }
		}

		let key: [u8; 32] = [0; 32];
		let iv: [u8; 16] = [0; 16];
		let de: Vec<u8>;
		match decrypt_data(&json.data, &key, &iv){
			Ok(result) => (de = result),
			Err(_) => { println!("\n{}Couldn't decrypt {}{}", RED, name, RES); return OperationStepResult::Fail }
		}
		match fs::write(path.path(), de){
			Ok(_) => (),
			Err(error) => { println!("\n{}{} ({}) {}", RED, error, name, RES); return OperationStepResult::Fail }
		}
		fs::rename(path.path(), json.formal_name).unwrap();
		OperationStepResult::Ok
	}
}

//Function of handling encryption
fn encrypt(path: &fs::DirEntry, in_dir: &String, index: usize) -> OperationStepResult {
	let name = path.file_name().into_string().unwrap_or(String::new());
	if name.contains(".crpt") || path.file_type().unwrap().is_dir() || path.file_type().unwrap().is_symlink() || path.path().extension().is_none(){
		return OperationStepResult::Skip
	} else {
		//print(&format!("{} being encrypted... ", name));
		let fpath = path.path();
		let mut f: File;
		match File::open(fpath.clone()){
			Ok(result) => f = result,
			Err(error) => { println!("\n{}{} ({}){}", RED, error, name, RES); return OperationStepResult::Fail }
		}
		let mut buffer = Vec::new();
		match f.read_to_end(&mut buffer){
			Ok(_) => (),
			Err(error) => { println!("\n{}{} ({}){}", RED, error, name, RES); return OperationStepResult::Fail }
		}
		let key: [u8; 32] = [0; 32];
		let iv: [u8; 16] = [0; 16];

		let encrypted_data = encrypt_data(&buffer, &key, &iv).ok().unwrap();
		let to_write = prepare_data(encrypted_data, fpath.to_str().unwrap());
		let json: String;
		match serde_json::to_string(&to_write){
			Ok(result) => json = result,
			Err(error) => { println!("\n{}{} ({}){}", RED, error, name, RES); return OperationStepResult::Fail }
		}
		write_to_file(&fpath, json);
		fs::rename(fpath, format!("{}/{}.crpt", in_dir, index + 1)).unwrap();
		OperationStepResult::Ok
	}
}
//Function of panicking in style
fn panic(error: &str) -> !{
	println!("{}[FATAL] {}{}", RED, error, RES);
	pause();
	std::process::exit(-1)
}

//Function of writing String to file
fn write_to_file(path: &PathBuf, data: String){
	let mut file: File;
	match File::create(path){
		Ok(result) => file = result, 
		Err(error) => panic(&error.to_string())
	}
	match write!(file, "{}", data){
		Ok(_) => (),
		Err(error) => panic(&error.to_string())
	}
}

//Functions of reading from file
fn string_from_file(path: &PathBuf) -> Result<String, io::Error>{
	let mut file: File;
	let mut filecontent: String = String::from("");
	match File::open(path){
		Ok(result) => file = result,
		Err(error) => return Err(error)
	}
	match file.read_to_string(&mut filecontent) {
		Ok(_) => (),
		Err(error) => return Err(error)
	}
	Ok(filecontent)
}

//Functions of preparing data
fn prepare_data(data: Vec<u8>, formal_name: &str) -> EncryptedFile {
	EncryptedFile{
		since: get_now(), user: ENV_USER.to_string(), formal_name: formal_name.to_string(), data: data
	}
}
fn prepare_config(data: Vec<u8>, dir: String) -> ConfigFile {
	ConfigFile{
		since: get_now(),
		default_dir: dir,
		data: data
	}
}

//Function of requesting password
fn request_password(prompt: Option<&str>) -> String{
	match prompt{
		Some(p) => print(p),
		None => print("Password: >")
	}
	match read_password() {
		Ok(result) => return result,
		Err(_) => panic("Couldn't read password")
	}
}

//Function of printing
fn print(string: &str){
	print!("{}", string);
	io::stdout().flush().expect("Couldn't flush");
}

//Function of waiting for key before quitting
fn pause() {
	let mut stdin = io::stdin();
	let mut stdout = io::stdout();
	write!(stdout, "Press any key to continue...").unwrap();
	stdout.flush().unwrap();
	if cfg!(windows) {
		stdin.read(&mut [0]).unwrap();
	}
	loop{
		match stdin.read(&mut [0u8]){
			Ok(_res) => break,
			Err(_err) => ()
		}
	}
}
