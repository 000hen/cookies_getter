use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct OsCrypt {
    pub encrypted_key: String
}

#[derive(Deserialize)]
pub struct KeyFileData {
    pub os_crypt: OsCrypt
}

pub struct Database {
    pub host_key: String,
    pub name: String,
    pub value: String,
    pub encrypted_value: Option<Vec<u8>>
}

#[derive(Deserialize, Serialize)]
pub struct DataStorage {
    pub host: String,
    pub name: String,
    pub value: String
}

#[derive(Deserialize, Serialize)]
pub struct DataSave {
    pub timestamp: u64,
    pub cookies: Vec<DataStorage>
}