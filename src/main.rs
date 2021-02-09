use std::fs;
use std::fs::File;
use std::io;
use std::io::{Write, Read};
//use std::ffi::OsStr;
use std::time::SystemTime;
use std::path::{PathBuf};
extern crate directories;
use directories::{ProjectDirs};
extern crate rpassword;
use rpassword::read_password;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate rustyline;
use rustyline::Editor;

//help me
extern crate crypto;

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
//aaaa

//Color formatting codes
const RED: &str = "\x1b[31mERR: ";
const GRN: &str = "\x1b[32mSCSS: ";
const ORG: &str = "\x1b[33mWARN: ";
const BLD: &str = "\x1b[1mINF: ";
const MAG: &str = "\x1b[35m";
const CYN: &str = "\x1b[36m";
const RES: &str = "\x1b[0m";

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
		match qdecrypt(&decrypted.data, &key, &iv){
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
			match qencrypt(CHECKSEED.as_bytes(), &key, &iv){
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
	let user = env!("USER");
	loop {
		match &(readline_editor.readline(&format!("{}{}@Hide> {}", MAG, user, RES)).expect("Stdin error")) as &str{
			"kill" | "exit" => exit(),
			"ld" | "ls" => {
				println!("{}:", lifecycle.dir);
				walk_through_dir(&lifecycle.dir, &|i: usize, path: &fs::DirEntry| { 
						println!("{}.{} {}", i + 1, 
							if path.file_type().unwrap().is_dir() { 
								format!("{} [FLDR]{}", CYN, RES) 
							} else if path.file_type().unwrap().is_symlink() { 
								format!("{} [SYML]{}", CYN, RES) 
							} else if path.path().extension().is_none() { 
								format!("{} [NOEX]{}", CYN, RES) 
							} else if path.file_name().into_string().unwrap_or(String::new()).contains(".crpt") {
								format!("{} [CRPT]{}", CYN, RES)
							} else { 
								String::new()
							}, 
							path.file_name().into_string().unwrap());
						true
					}
				);
			},
			"cd" => { lifecycle.dir = lifecycle.default_dir.clone(); println!("{}Changed to default{}", GRN, RES) },
			cd if cd.contains("cd") => {
				let dir = cd.replace("cd ","");
				match fs::read_dir(&dir){
					Ok(_) => {
						lifecycle.dir = dir;
						println!("{}Changed{}", GRN, RES);
					},
					Err(error) => println!("{}Unreachable dir: {}{}", RED, error, RES)
				}
			},
			"en" => {
					walk_through_dir(&lifecycle.dir, &|i: usize, path: &fs::DirEntry| {
						encrypt(path, &lifecycle.dir, i)
					}
				);
			},
			en if en.contains("en") => {
				let mode = en.replace("en", "");
				match &mode as &str {
					"" => (),
					_ => ()
				}
			},
			"de" => {
				walk_through_dir(&lifecycle.dir, &|_i: usize, path: &fs::DirEntry| {
					decrypt(path)
					}
				);
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

//***********************************************************
fn qencrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
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

fn qdecrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
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
//***********************************************************


//Function of smart exiting
fn exit() -> ! {
	std::process::exit(-1)
}

//Function of walking through dir
fn walk_through_dir(dir: &str, foreach: &dyn Fn(usize, &fs::DirEntry) -> bool) -> usize{
	match fs::read_dir(dir){
		Ok(result) => {
			let mut map: Vec<_> = result.map(|r| r.unwrap()).collect();
			map.sort_by_key(|dir| dir.file_name());
			let mut a: usize = 0;
			for (i, path) in map.iter().enumerate() {
				foreach(i, path);
				a = i;
			}
			return a
		},
		Err(_) => { println!("{}Empty/unreachable dir{}", RED, RES); return 0 }
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
fn decrypt(path: &fs::DirEntry) -> bool{
let name = path.file_name().into_string().unwrap_or(String::new());
	if !name.contains(".crpt"){
			println!("{} was skipped ", name);
			return false
	} else {
		print(&format!("{} being decrypted... ", name));
		let json: EncryptedFile;
		let filecontent: String;
		match string_from_file(&path.path()){
			Ok(result) => filecontent = result,
			Err(_) => { println!("{}Couldn't read{}", RED, RES); return false }
		}
		match serde_json::from_str::<EncryptedFile>(&filecontent){
			Ok(result) => json = result,
			Err(error) => { println!("{}{}{}", RED, error, RES); return false }
		}

		let key: [u8; 32] = [0; 32];
		let iv: [u8; 16] = [0; 16];
		let de: Vec<u8>;
		match qdecrypt(&json.data, &key, &iv){
			Ok(result) => (de = result),
			Err(_) => { return false }
		}
		match fs::write(path.path(), de){
			Ok(_) => (),
			Err(error) => { println!("{}{}{}", RED, error, RES); return false }
		}
		fs::rename(path.path(), json.formal_name).unwrap();
		println!("OK");
		true
	}
}

//Function of handling encryption
fn encrypt(path: &fs::DirEntry, in_dir: &String, index: usize) -> bool {
	let name = path.file_name().into_string().unwrap_or(String::new());
	if name.contains(".crpt") || path.file_type().unwrap().is_dir() || path.file_type().unwrap().is_symlink() || path.path().extension().is_none(){
		println!("{} was skipped ", name);
		return false
	} else {
		print(&format!("{} being encrypted... ", name));
		let fpath = path.path();
		let mut f: File;
		match File::open(fpath.clone()){
			Ok(result) => f = result,
			Err(error) => { println!("{}{}{}", RED, error, RES); return false }
		}
		let mut buffer = Vec::new();
		match f.read_to_end(&mut buffer){
			Ok(_) => (),
			Err(error) => { println!("{}{}{}", RED, error, RES); return false }
		}
		let key: [u8; 32] = [0; 32];
		let iv: [u8; 16] = [0; 16];

		let encrypted_data = qencrypt(&buffer, &key, &iv).ok().unwrap();
		let to_write = prepare_data(encrypted_data, fpath.to_str().unwrap());
		let json: String;
		match serde_json::to_string(&to_write){
			Ok(result) => json = result,
			Err(error) => { println!("{}{}{}", RED, error, RES); return false }
		}
		write_to_file(&fpath, json);
		fs::rename(fpath, format!("{}/{}.crpt", in_dir, index)).unwrap();
	 	println!("OK");
	 	true
	}
}
//Function of panicking in style
fn panic(error: &str) -> !{
	println!("{}{}{}", RED, error, RES);
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
		since: get_now(), user: env!("USER").to_string(), formal_name: formal_name.to_string(), data: data
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
	//MARK: UNCOMMENT IF COMPILING FOR WINDOWS
	//stdin.read(&mut [0]);
	loop{
		match stdin.read(&mut [0u8]){
			Ok(_res) => break,
			Err(_err) => ()
		}
	}
}
