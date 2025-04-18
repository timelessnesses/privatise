use base64::Engine;
use clap::Parser;
use regex::bytes;
use std::{
    io::{Read, Write},
    path::PathBuf,
};
pub mod api;

#[cfg(test)]
pub mod tests;

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    subcommand: Subcommands,
    #[arg(global = true, default_value_t = true)]
    client_side_encrypt_decrypt: bool,
    #[arg(global = true, default_value_t = false)]
    output_json: bool,
}

#[derive(clap::Parser)]
enum Subcommands {
    CreateStdin {
        /// File name
        #[arg(short, long)]
        file_name: String,
        /// File duration (in seconds, RFC3339 format or Xs, Xm, Xh and Xw)
        #[arg(short, long, value_parser = parse_datetime)]
        expires_at: chrono::TimeDelta,
    },
    Create {
        /// File name
        #[arg(short, long)]
        file_name: String,
        /// Content of the note
        #[arg(short, long)]
        content: String,
        /// File duration (in seconds, RFC3339 format or Xs, Xm, Xh and Xw)
        #[arg(short, long, value_parser = parse_datetime)]
        expires_at: chrono::TimeDelta,
    },
    Upload {
        /// Path
        #[arg(short, long)]
        path: PathBuf,
        /// File duration (in seconds, RFC3339 format or Xs, Xm, Xh and Xw)
        #[arg(short, long, value_parser = parse_datetime)]
        expires_at: chrono::TimeDelta,
    },
    Delete {
        /// Key used to encrypt the note
        /// This is the key you used to encrypt the note
        /// You can get this key from the output of the create command
        #[arg(short, long, value_parser = parse_bytes_from_b64)]
        input_key: Vec<u8>,
        /// Nonce used to encrypt the note
        /// This is the nonce you used to encrypt the note
        /// You can get this nonce from the output of the create command
        #[arg(short, long, value_parser = parse_bytes_from_b64)]
        nonce: Vec<u8>,
        /// ID of the note
        #[arg(short, long)]
        id: String,
    },
    Read {
        /// Key used to encrypt the note
        /// This is the key you used to encrypt the note
        /// You can get this key from the output of the create command
        #[arg(short, long, value_parser = parse_bytes_from_b64)]
        input_key: Vec<u8>,
        /// Nonce used to encrypt the note
        /// This is the nonce you used to encrypt the note
        /// You can get this nonce from the output of the create command
        #[arg(short, long, value_parser = parse_bytes_from_b64)]
        nonce: Vec<u8>,
        /// ID of the note
        #[arg(short, long)]
        id: String,
        /// Custom output file name
        #[arg(short, long)]
        output_file_name: Option<String>,
        /// Force writing to file even if its not a printable file
        #[arg(short, long)]
        force: Option<Forcing>,
    },
    Info {
        /// ID of the note
        #[arg(short, long)]
        id: String,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum Forcing {
    Write,
    Print,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(
        "Unparsable datetime format (use s, m, h, w at the end of the number for seconds, minutes, hours, weeks respectively)"
    )]
    UnparsableDatetimeFormat,
    #[error("Invalid base64 string")]
    InvalidBase64String,
}

fn parse_bytes_from_b64(s: &str) -> Result<Vec<u8>, Error> {
    Ok(base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| Error::InvalidBase64String)?)
}

static REGEX_PARSE_THINGY: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?:(\d+)([hmsw]))(?:\s+|$)").unwrap());

fn parse_datetime(s: &str) -> Result<chrono::TimeDelta, Error> {
    match chrono::DateTime::parse_from_rfc3339(s) {
        Ok(dt) => Ok(chrono::TimeDelta::seconds(
            chrono::Local::now().signed_duration_since(dt).num_seconds() as i64,
        )),
        Err(e) => {
            let seconds = e.to_string().parse::<u64>();
            match seconds {
                Ok(seconds) => Ok(chrono::TimeDelta::seconds(seconds as i64)),
                // we also supports Xs, Xm, Xh and Xw (regex :( )
                Err(_) => {
                    let matches = REGEX_PARSE_THINGY.captures_iter(s);
                    let mut seconds = 0;
                    for m in matches {
                        let num = m.get(0).unwrap().as_str().parse::<u64>().unwrap();
                        let unit = m.get(1).unwrap().as_str();
                        match unit {
                            "s" => seconds += num,
                            "m" => seconds += num * 60,
                            "h" => seconds += num * 60 * 60,
                            "w" => seconds += num * 60 * 60 * 24 * 7,
                            _ => return Err(Error::UnparsableDatetimeFormat),
                        }
                    }

                    return Ok(chrono::TimeDelta::seconds(seconds as i64));
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    better_panic::Settings::new()
        .lineno_suffix(true)
        .verbosity(better_panic::Verbosity::Full)
        .install();

    let cli = Cli::parse();
    match cli.subcommand {
        Subcommands::Create {
            file_name,
            content,
            expires_at,
        } => {
            let f;
            if cli.client_side_encrypt_decrypt {
                // i trust in my better_panic :))))))))
                f = api::File::upload_buffer_encrypt_client_side(
                    content.into_bytes(),
                    file_name,
                    ".txt".to_string(),
                    expires_at,
                )
                .await
                .unwrap();
            } else {
                f = api::File::upload_buffer(
                    content.into_bytes(),
                    file_name,
                    ".txt".to_string(),
                    expires_at,
                )
                .await
                .unwrap();
            }
            if cli.output_json {
                println!("{}", serde_json::to_string(&f).unwrap());
            } else {
                println!("{}", f);
            }
        }
        Subcommands::CreateStdin {
            file_name,
            expires_at,
        } => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).unwrap();
            let f;
            if cli.client_side_encrypt_decrypt {
                // i trust in my better_panic :))))))))
                f = api::File::upload_buffer_encrypt_client_side(
                    buffer,
                    file_name,
                    ".txt".to_string(),
                    expires_at,
                )
                .await
                .unwrap();
            } else {
                f = api::File::upload_buffer(buffer, file_name, ".txt".to_string(), expires_at)
                    .await
                    .unwrap();
            }
            if cli.output_json {
                println!("{}", serde_json::to_string(&f).unwrap());
            } else {
                println!("{}", f);
            }
        }
        Subcommands::Upload { path, expires_at } => {
            let f;
            if cli.client_side_encrypt_decrypt {
                f = api::File::upload_encrypt_client_side(&path, expires_at)
                    .await
                    .unwrap();
            } else {
                f = api::File::upload(&path, expires_at).await.unwrap();
            }
            if cli.output_json {
                println!("{}", serde_json::to_string(&f).unwrap());
            } else {
                println!("{}", f);
            }
        }
        Subcommands::Read {
            input_key,
            nonce,
            id,
            output_file_name,
            force,
        } => {
            let f = api::File::validate_file(&id).await.unwrap();
            let data;

            if cli.client_side_encrypt_decrypt {
                data = f.read(Some(&input_key), Some(&nonce)).await.unwrap();
            } else {
                data = f
                    .read_server_side(Some(&input_key), Some(&nonce))
                    .await
                    .unwrap();
            }

            let file_name = output_file_name
                .unwrap_or(f.file_name.clone().unwrap() + "." + &f.file_ext.unwrap());

            let printability = mostly_printable(&data) > 0.8;
            match (force, printability) {
                (Some(Forcing::Write), _) => {
                    let mut file = std::fs::File::create(&file_name).unwrap();
                    file.write_all(&data).unwrap();
                }
                (Some(Forcing::Print), _) => {
                    println!("{}", String::from_utf8_lossy(&data));
                }
                (None, false) => {
                    let mut file = std::fs::File::create(&file_name).unwrap();
                    file.write_all(&data).unwrap();
                }
                _ => {
                    println!("{}", String::from_utf8_lossy(&data));
                }
            }
        }
        Subcommands::Delete {
            id,
            input_key,
            nonce,
        } => {
            let f = api::File::validate_file(&id).await.unwrap();
            f.delete(Some(&input_key), Some(&nonce)).await.unwrap();
            if cli.output_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "deleted": true,
                        "id": id
                    })
                )
            } else {
                println!("File deleted");
            }
        }
        Subcommands::Info { id } => {
            let f = api::File::validate_file(&id).await.unwrap();
            println!("{}", f);
        }
    }
}

fn mostly_printable(bytes: &[u8]) -> f64 {
    bytes.iter().filter(|x| **x >= 32 && **x < 127).count() as f64 / bytes.len() as f64
}
