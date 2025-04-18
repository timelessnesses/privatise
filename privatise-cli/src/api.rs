use std::{ffi::OsStr, io::Read};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{AeadMutInPlace, OsRng},
};
use base64::Engine;
use reqwest;
use serde::{Deserialize, Deserializer};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid file path ({0})")]
    /// Invalid file path
    InvalidFilePath(#[from] std::io::Error),
    #[error("Failed to parse JSON ({0})")]
    /// Failed to parse JSON
    JsonFailed(reqwest::Error),
    #[error("Server failed to process request ({0})")]
    /// Server failed to process request (take a look at response)
    ServerFailed(reqwest::Error),
    #[error("No key provided")]
    /// User error: no key provided
    NoKeyProvided,
    #[error("No nonce provided")]
    /// User error: no nonce provided
    NoNonceProvided,
    #[error("Failed to encrypt ({0})")]
    /// Failed to encrypt (out of memory(?))
    FailedToEncrypt(aes_gcm::aead::Error),
    #[error("Failed to decrypt ({0})")]
    /// Failed to decrypt (out of memory(?))
    FailedToDecrypt(aes_gcm::aead::Error),
}

/// API URL
pub const API_URL: std::sync::LazyLock<url::Url> = std::sync::LazyLock::new(|| {
    url::Url::parse("https://privatise-cf.timelessnesses.workers.dev/").unwrap()
});

// handy dandy :) (and self-advertising)
static CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::ClientBuilder::new()
        .user_agent("privatise-cli-rs")
        .build()
        .unwrap()
});

/// [`File`] struct is a wrapper around the API, you can either use [`File::new`] to get the existing file or [`File::upload`], [`File::upload_encrypt_client_side`], [`File::upload_buffer`] or [`File::upload_buffer_encrypt_client_side`] to upload a new file
/// You can also check for file's existence before creating new instance with [`File::validate_file`] or gain information about the file with [`File::get_info`]
#[derive(serde::Serialize, serde::Deserialize, Clone, Default, Debug)]
pub struct File {
    pub id: String,
    pub expires_at: Option<chrono::DateTime<chrono::Local>>,
    pub file_name: Option<String>,
    pub file_ext: Option<String>,
    pub key: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl std::fmt::Display for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "File ID: {}\nExpires at: {:?}\nFile name: {}\nFile extension: {}\nKey: {}\nNonce: {}",
            self.id,
            self.expires_at,
            self.file_name.as_ref().unwrap_or(&"None".to_string()),
            self.file_ext.as_ref().unwrap_or(&"None".to_string()),
            self.key
                .as_ref()
                .map(|i| base64::engine::general_purpose::STANDARD.encode(i))
                .unwrap_or("None".to_string()),
            self.nonce
                .as_ref()
                .map(|i| base64::engine::general_purpose::STANDARD.encode(i))
                .unwrap_or("None".to_string())
        )
    }
}

impl File {
    /// Creates a new [`File`] instance (without checks)
    pub fn new(id: String) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    /// Validates if a file exists (better than [`File::new`] if you want certainty, of course)
    pub async fn validate_file(id: &str) -> Result<Self, Error> {
        let response = Self::info(&id).await?;
        Ok(Self {
            id: response.id,
            expires_at: Some(response.expires_at.with_timezone(&chrono::Local)),
            file_name: Some(response.name),
            file_ext: Some(response.original_file_extension),
            ..Default::default()
        })
    }

    /// Uploads a buffer to API (encrypting on client side)
    pub async fn upload_buffer_encrypt_client_side(
        mut buffer: Vec<u8>,
        file_name: String,
        file_ext: String,
        expires_at: chrono::TimeDelta,
    ) -> Result<Self, Error> {
        let mut encrypted_buffer = Vec::new();
        let (key, nonce) = encrypt_buffer(&mut buffer, &mut encrypted_buffer)?;
        let response = CLIENT
            .post(API_URL.join("/upload").unwrap())
            .multipart(
                reqwest::multipart::Form::new()
                    .part(
                        "file",
                        reqwest::multipart::Part::bytes(encrypted_buffer)
                            .file_name(file_name.clone()),
                    )
                    .text("expires_at", expires_at.num_seconds().to_string())
                    .text("name", file_name.clone())
                    .text("file_ext", file_ext.clone()),
            )
            .send()
            .await
            .map_err(Error::ServerFailed)?
            .text()
            .await
            .map_err(Error::ServerFailed)?;
        dbg!(&response);
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        /* .error_for_status()
        .map_err(Error::ServerFailed)?
        .json()
        .await
        .map_err(|a| Error::JsonFailed(a))?; */

        let id = response["id"].as_str().unwrap().to_string();
        return Ok(Self {
            id,
            expires_at: Some(chrono::Local::now() + expires_at),
            key: Some(key.to_vec()),
            nonce: Some(nonce.to_vec()),
            file_name: Some(file_name),
            file_ext: Some(file_ext),
            ..Default::default()
        });
    }

    /// Uploads a buffer to API (encrypting on server side)
    pub async fn upload_buffer(
        // this is a requirement (multipart doesn't like something not owned or 'static :( )
        buffer: Vec<u8>,
        file_name: String,
        file_ext: String,
        expires_at: chrono::TimeDelta,
    ) -> Result<Self, Error> {
        let response: serde_json::Value = CLIENT
            .post(API_URL.join("/upload_encrypt_serverside").unwrap())
            .multipart(
                reqwest::multipart::Form::new()
                    .text("expires_at", expires_at.num_seconds().to_string())
                    .text("file_ext", file_ext.clone())
                    .text("name", file_name.clone())
                    .part(
                        "file",
                        reqwest::multipart::Part::bytes(buffer).file_name(file_name.clone()),
                    ),
            )
            .send()
            .await
            .map_err(Error::ServerFailed)?
            .error_for_status()
            .map_err(Error::ServerFailed)?
            .json()
            .await
            .map_err(Error::JsonFailed)?;
        let id = response["id"].as_str().unwrap().to_string();
        return Ok(Self {
            id,
            expires_at: Some(chrono::Local::now() + expires_at),
            key: response["encryption_info"]["key"]
                .as_str()
                .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap()),
            nonce: response["encryption_info"]["nonce"]
                .as_str()
                .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap()),
            file_name: Some(file_name),
            file_ext: Some(file_ext),
            ..Default::default()
        });
    }

    /// Uploads a file ([`std::path::Path`]) to API (encrypting on client side)
    pub async fn upload_encrypt_client_side(
        path: &std::path::Path,
        expires_at: chrono::TimeDelta,
    ) -> Result<Self, Error> {
        let mut file = std::fs::File::open(&path).map_err(Error::InvalidFilePath)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(Error::InvalidFilePath)?;
        let mut encrypted_buffer = Vec::new();
        let (key, nonce) = encrypt_buffer(&mut buffer, &mut encrypted_buffer)?;
        let response = CLIENT
            .post(API_URL.join("/upload").unwrap())
            .multipart(
                reqwest::multipart::Form::new()
                    .part(
                        "file",
                        reqwest::multipart::Part::bytes(encrypted_buffer)
                            .mime_str("application/octet-stream")
                            .unwrap()
                            .file_name(path.file_name().unwrap().to_string_lossy().to_string()),
                    )
                    .text("expires_at", expires_at.num_seconds().to_string())
                    .text(
                        "name",
                        path.file_name().unwrap().to_string_lossy().to_string(),
                    )
                    .text(
                        "file_ext",
                        path.extension().unwrap().to_string_lossy().to_string(),
                    ),
            )
            .send()
            .await
            .map_err(Error::ServerFailed)?;
		let response = response.text().await.map_err(Error::ServerFailed)?;
		dbg!(&response);
		let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        let id = response["id"].as_str().unwrap().to_string();
        return Ok(Self {
            id,
            expires_at: Some(chrono::Local::now() + expires_at),
            key: Some(key.to_vec()),
            nonce: Some(nonce.to_vec()),
            file_name: Some(prefixery(&path)),
            file_ext: Some(path.extension().unwrap().to_string_lossy().to_string()),
            ..Default::default()
        });
    }

    /// Uploads a file ([`std::path::Path`]) to API (encrypting on server side)
    pub async fn upload(
        path: &std::path::Path,
        expires_at: chrono::TimeDelta,
    ) -> Result<Self, Error> {
        let response: serde_json::Value = CLIENT
            .post(API_URL.join("/upload_encrypt_serverside").unwrap())
            .multipart(
                reqwest::multipart::Form::new()
                    .text("expires_at", expires_at.num_seconds().to_string())
                    .text(
                        "file_ext",
                        path.extension().unwrap().to_string_lossy().to_string(),
                    )
                    .text(
                        "name",
                        path.file_name().unwrap().to_string_lossy().to_string(),
                    )
                    .file("file", path)
                    .await
                    .map_err(Error::InvalidFilePath)?,
            )
            .send()
            .await
            .map_err(Error::ServerFailed)?
            .error_for_status()
            .map_err(Error::ServerFailed)?
            .json()
            .await
            .map_err(Error::JsonFailed)?;
        let id = response["id"].as_str().unwrap().to_string();
        return Ok(Self {
            id,
            expires_at: Some(chrono::Local::now() + expires_at),
            key: response["encryption_info"]["key"]
                .as_str()
                .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap()),
            nonce: response["encryption_info"]["nonce"]
                .as_str()
                .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap()),
            file_name: Some(prefixery(&path)),
            file_ext: Some(path.extension().unwrap().to_string_lossy().to_string()),
            ..Default::default()
        });
    }

    // im just tired okay man
    fn get_key_nonce_thingy<'a>(
        &'a self,
        key: Option<&'a [u8]>,
        nonce: Option<&'a [u8]>,
    ) -> Result<(&'a [u8], &'a [u8]), Error> {
        let actual_key = key
            .or(self.key.as_ref().map(|i| i.as_slice()))
            .ok_or(Error::NoKeyProvided)?;
        let actual_nonce = nonce
            .or(self.nonce.as_ref().map(|i| i.as_slice()))
            .ok_or(Error::NoNonceProvided)?;
        Ok((actual_key, actual_nonce))
    }

    /// Reads the file (decrypting on client side)
    pub async fn read(&self, key: Option<&[u8]>, nonce: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let mut url = API_URL.join("/read").unwrap();
        url.query_pairs_mut().append_pair("file_name", &self.id);
        let (actual_key, actual_nonce) = self.get_key_nonce_thingy(key, nonce)?;
        /* url.query_pairs_mut().append_pair(
            "key",
            &base64::engine::general_purpose::STANDARD.encode(actual_key),
        );
        url.query_pairs_mut().append_pair(
            "nonce",
            &base64::engine::general_purpose::STANDARD.encode(actual_nonce),
        ); */
        let response = CLIENT
            .get(url)
            .send()
            .await
            .map_err(Error::ServerFailed)?
            .error_for_status()
            .map_err(Error::ServerFailed)?
            .bytes()
            .await
            .map_err(Error::ServerFailed)?;
        let mut decrypted_buffer = Vec::new();
        decrypt_buffer(
            &mut response.to_vec(),
            &mut decrypted_buffer,
            actual_nonce,
            actual_key,
        )?;
        Ok(decrypted_buffer)
    }

    /// Reads the file (decrypting on server side)
    pub async fn read_server_side(
        &self,
        key: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut url = API_URL.join("/read_serverside").unwrap();
        url.query_pairs_mut().append_pair("file_name", &self.id);
        url.query_pairs_mut().append_pair(
            "key",
            &base64::engine::general_purpose::STANDARD.encode(key.unwrap()),
        );
        url.query_pairs_mut().append_pair(
            "nonce",
            &base64::engine::general_purpose::STANDARD.encode(nonce.unwrap()),
        );
        let response = CLIENT
            .get(url)
            .send()
            .await
            .map_err(Error::ServerFailed)?
            .error_for_status()
            .map_err(Error::ServerFailed)?
            .bytes()
            .await
            .map_err(Error::ServerFailed)?;
        Ok(response.to_vec())
    }

    /// Deletes the file (requires key and nonce for verification of ownership)
    pub async fn delete(&self, key: Option<&[u8]>, nonce: Option<&[u8]>) -> Result<(), Error> {
        let mut url = API_URL.join("/delete").unwrap();
        url.query_pairs_mut().append_pair("file_name", &self.id);
        let (actual_key, actual_nonce) = self.get_key_nonce_thingy(key, nonce)?;
        url.query_pairs_mut().append_pair(
            "key",
            &base64::engine::general_purpose::STANDARD.encode(actual_key),
        );
        url.query_pairs_mut().append_pair(
            "nonce",
            &base64::engine::general_purpose::STANDARD.encode(actual_nonce),
        );
        CLIENT
            .delete(url)
            .send()
            .await
            .map_err(Error::ServerFailed)?
            .error_for_status()
            .map_err(Error::ServerFailed)?;
        Ok(())
    }

    /// Gets information about the file
    pub async fn info(id: &str) -> Result<FileInfo, Error> {
        let mut url = API_URL.join("/info").unwrap();
        url.query_pairs_mut().append_pair("file_name", id);
        let response: FileInfo = CLIENT
            .get(url)
            .send()
            .await
            .map_err(Error::ServerFailed)?
            .error_for_status()
            .map_err(Error::ServerFailed)?
            .json()
            .await
            .map_err(Error::JsonFailed)?;
        Ok(response)
    }

    /// Gets information about the current instance of [`File`]
    pub async fn get_info(&self) -> Result<FileInfo, Error> {
        Ok(Self::info(&self.id).await?)
    }
}

/// This is closely related to [`File`] but it's only for containing information (without any encryption data) and you will guranteed to have data
#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct FileInfo {
    pub id: String,
    #[serde(deserialize_with = "timestamp_to_datetime")]
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub original_file_extension: String,
    pub name: String,
    #[serde(deserialize_with = "timestamp_to_datetime")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// custom thingy
fn timestamp_to_datetime<'de, D>(deserializer: D) -> Result<chrono::DateTime<chrono::Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let timestamp = i64::deserialize(deserializer)?;
    Ok(
        chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
            .ok_or(serde::de::Error::custom("Invalid timestamp"))?,
    )
}

// helper function for encryption
fn encrypt_buffer(
    buffer: &mut Vec<u8>,
    encrypted_buffer: &mut Vec<u8>,
) -> Result<([u8; 32], [u8; 12]), Error> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher
        .encrypt_in_place(&nonce, buffer, encrypted_buffer)
        .map_err(Error::FailedToEncrypt)?;
    Ok((
        key.as_slice().try_into().unwrap(),
        nonce.as_slice().try_into().unwrap(),
    ))
}

// helper function for decryption
fn decrypt_buffer(
    buffer: &mut Vec<u8>,
    decrypted_buffer: &mut Vec<u8>,
    nonce: &[u8],
    key: &[u8],
) -> Result<(), Error> {
    let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key);
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    cipher
        .decrypt_in_place(&nonce, buffer, decrypted_buffer)
        .map_err(Error::FailedToDecrypt)?;
    Ok(())
}

fn prefixery(p: &std::path::Path) -> String {
    p.file_name()
        .map(split_file_at_dot)
        .and_then(|(before, _after)| Some(before))
        .unwrap()
        .to_string_lossy()
        .to_string()
}

fn split_file_at_dot(file: &OsStr) -> (&OsStr, Option<&OsStr>) {
    let slice = file.as_encoded_bytes();
    if slice == b".." {
        return (file, None);
    }

    // The unsafety here stems from converting between &OsStr and &[u8]
    // and back. This is safe to do because (1) we only look at ASCII
    // contents of the encoding and (2) new &OsStr values are produced
    // only from ASCII-bounded slices of existing &OsStr values.
    let i = match slice[1..].iter().position(|b| *b == b'.') {
        Some(i) => i + 1,
        None => return (file, None),
    };
    let before = &slice[..i];
    let after = &slice[i + 1..];
    unsafe {
        (
            OsStr::from_encoded_bytes_unchecked(before),
            Some(OsStr::from_encoded_bytes_unchecked(after)),
        )
    }
}

// [`prefixery`] and [`split_file_at_dot`] is stolen from https://doc.rust-lang.org/src/std/path.rs.html#2643-2645
