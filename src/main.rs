// lint me harder
#![forbid(non_ascii_idents)]
#![forbid(unsafe_code)]
#![deny(
    future_incompatible,
    keyword_idents,
    elided_lifetimes_in_paths,
    meta_variable_misuse,
    noop_method_call,
    unused_lifetimes,
    clippy::wildcard_dependencies,
    clippy::debug_assert_with_mut_call,
    clippy::empty_line_after_outer_attr,
    clippy::panic,
    clippy::unwrap_used,
    clippy::redundant_field_names,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::unneeded_field_pattern,
    clippy::useless_let_if_seq
)]
#![warn(clippy::pedantic)]

use std::{
    fmt, fs,
    io::{self, Read as _, Write as _},
    ops::Deref,
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    aead::{Aead as _, Key, Nonce},
    AeadCore, KeyInit as _, XChaCha20Poly1305 as Cipher,
};
use clap::{CommandFactory as _, Parser, Subcommand};
use color_eyre::eyre::{self, eyre, WrapErr as _};
use indexmap::IndexMap;
use itertools::Itertools as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::config::{Config, FileDesc};

mod config;
mod keyarmor;

#[derive(Subcommand)]
enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl From<Shell> for clap_complete::Shell {
    fn from(this: Shell) -> Self {
        match this {
            Shell::Bash => Self::Bash,
            Shell::Zsh => Self::Zsh,
            Shell::Fish => Self::Fish,
        }
    }
}

#[allow(clippy::doc_markdown)]
/// Simple encryption tool intended for use with NixOS
#[derive(Parser)]
enum Command {
    /// Generate a new encryption key and print it to stdout
    #[clap(display_order = 1)]
    GenKey,
    /// Encrypt file or stdin with given encryption key and print result to stdout (armored as
    /// base64)
    #[clap(display_order = 2)]
    Encrypt {
        /// Path to the key file
        #[clap(short, long)]
        key: PathBuf,
        /// File to encrypt, stdin if absent
        file: Option<PathBuf>,
    },
    #[clap(display_order = 3)]
    /// Decrypt file that was previously encrypted with `encrypt` and print result to stdout
    Decrypt {
        /// Path to the key file
        #[clap(short, long)]
        key: PathBuf,
        /// File to decrypt, stdin if absent
        file: Option<PathBuf>,
    },
    #[clap(display_order = 4)]
    /// Decrypt multiple files to their target directories, according to JSON/TOML config
    Batch {
        /// Config file, stdin if absent
        config: Option<PathBuf>,
    },
    #[clap(display_order = 5)]
    /// Generate shell completions
    #[clap(subcommand)]
    Completions(Shell),
}

fn trim_newline(mut x: &[u8]) -> &[u8] {
    while let Some((b'\n', start)) = x.split_last() {
        x = start;
    }
    x
}

fn maybe_stdin(file: Option<&Path>) -> eyre::Result<Vec<u8>> {
    if let Some(file) = file {
        fs::read(file).wrap_err("failed to read input file")
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .wrap_err("failed to read stdin")?;
        Ok(buf)
    }
}

fn decrypt(filename: impl fmt::Debug, cipher: &Cipher, armored: &[u8]) -> eyre::Result<Vec<u8>> {
    let encrypted_bytes =
        base64::decode(trim_newline(armored)).wrap_err("failed to unarmor encrypted file")?;
    let encrypted: Encrypted = serde_cbor::from_slice(&encrypted_bytes)
        .wrap_err("failed to deserialize encrypted file")?;
    cipher
        .decrypt(&encrypted.nonce, &*encrypted.bytes)
        .map_err(|_| eyre!("failed to decrypt {filename:?}"))
}

#[derive(Deserialize, Serialize)]
struct Encrypted {
    nonce: Nonce<Cipher>,
    bytes: Vec<u8>,
}

struct ArmoredKey {
    inner: Key<Cipher>,
}

impl fmt::Display for ArmoredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            keyarmor::Words::new(self.inner.into()).words().format(" ")
        )
    }
}

impl ArmoredKey {
    fn new(inner: Key<Cipher>) -> Self {
        Self { inner }
    }

    fn from_file(path: &Path) -> eyre::Result<Self> {
        let armored = fs::read_to_string(path).wrap_err("failed to read key file")?;
        let words: Vec<_> = armored.split_whitespace().collect();
        let bytes = keyarmor::Words::from_words(
            &words
                .try_into()
                .map_err(|v: Vec<_>| eyre!("wrong number of words: {} instead of 24", v.len()))?,
        )
        .wrap_err("failed to decode key")?
        .bytes();
        Ok(Self {
            inner: Key::<Cipher>::from(bytes),
        })
    }
}

impl Deref for ArmoredKey {
    type Target = Key<Cipher>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for ArmoredKey {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let mut rng = rand::thread_rng();
    match Command::parse() {
        Command::GenKey => {
            let key = ArmoredKey::new(Cipher::generate_key(rng));
            println!("{key}");
        }
        Command::Encrypt { key, file } => {
            let cipher = Cipher::new(&*ArmoredKey::from_file(&key)?);
            let nonce = Cipher::generate_nonce(&mut rng);
            let mut plaintext = maybe_stdin(file.as_deref())?;
            let bytes = cipher
                .encrypt(&nonce, plaintext.as_slice())
                .map_err(|_| eyre!("failed to encrypt"))?;
            let encrypted = Encrypted { nonce, bytes };
            let cbor = serde_cbor::to_vec(&encrypted)?;
            let mut out = io::stdout().lock();
            out.write_all(base64::encode(cbor.as_slice()).as_bytes())?;
            out.write_all(b"\n")?;
            plaintext.zeroize();
        }
        Command::Decrypt { key, file } => {
            let cipher = Cipher::new(&*ArmoredKey::from_file(&key)?);
            let armored = maybe_stdin(file.as_deref())?;
            let mut decrypted = decrypt(
                file.as_deref().unwrap_or_else(|| "-".as_ref()),
                &cipher,
                &armored,
            )?;
            io::stdout().write_all(&decrypted)?;
            decrypted.zeroize();
        }
        Command::Batch { config } => {
            let config = Config::parse(&maybe_stdin(config.as_deref())?)?;
            let keys: IndexMap<&str, Cipher> = config
                .keys
                .iter()
                .map(|(name, path)| {
                    Ok((
                        name.as_str(),
                        Cipher::new(&*ArmoredKey::from_file(path.as_ref())?),
                    ))
                })
                .collect::<eyre::Result<_>>()?;

            let decrypted: Vec<(&FileDesc, &str, Vec<u8>)> = config
                .files
                .iter()
                .map(|(name, file)| {
                    let cipher = match &file.key {
                        Some(key) => keys
                            .get(key.as_str())
                            .ok_or_else(|| eyre!("key {key:?} is not configured"))?,
                        None => keys.first().ok_or_else(|| eyre!("no keys specified"))?.1,
                    };
                    let decrypted = decrypt(
                        &file.encrypted,
                        cipher,
                        &maybe_stdin(Some(&file.encrypted))?,
                    )?;
                    Ok((file, name.as_str(), decrypted))
                })
                .collect::<eyre::Result<_>>()?;

            for (file, name, mut contents) in decrypted {
                let path = config.target_dir.join(name);
                file.create(&path, &contents)?;
                contents.zeroize();
            }
        }
        Command::Completions(shell) => {
            clap_complete::generate(
                clap_complete::Shell::from(shell),
                &mut Command::command(),
                "classified",
                &mut io::stdout().lock(),
            );
        }
    }

    Ok(())
}
