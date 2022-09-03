use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    mem,
    os::unix::{fs::OpenOptionsExt as _, io::AsRawFd as _},
    path::{Path, PathBuf},
};

use color_eyre::eyre::{self, bail, eyre, WrapErr as _};
use either::Either;
use indexmap::IndexMap;
use nix::{
    sys::stat::{fchmod, Mode},
    unistd::{fchown, Gid, Group, Uid, User},
};
use serde::{de::Error as _, Deserialize, Deserializer};

fn default_mode() -> u32 {
    0o400
}

fn default_user() -> Either<u32, String> {
    Either::Left(Uid::current().as_raw())
}

fn default_group() -> Either<u32, String> {
    Either::Left(Gid::current().as_raw())
}

fn deserialize_mode<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Helper<'a> {
        Num(u32),
        String(&'a str),
    }

    match Helper::deserialize(deserializer)? {
        Helper::Num(num) => Ok(num),
        Helper::String(s) => match u32::from_str_radix(s, 8) {
            Ok(num) => Ok(num),
            Err(_) => Err(D::Error::invalid_value(
                serde::de::Unexpected::Str(s),
                &"an octal number",
            )),
        },
    }
}

#[derive(Debug, Deserialize)]
pub struct FileDesc {
    pub key: Option<String>,
    #[serde(default)]
    pub encrypted: PathBuf,
    #[serde(default = "default_mode", deserialize_with = "deserialize_mode")]
    pub mode: u32,
    #[serde(with = "either::serde_untagged", default = "default_user")]
    pub user: Either<u32, String>,
    #[serde(with = "either::serde_untagged", default = "default_group")]
    pub group: Either<u32, String>,
}

struct Defer<F: FnMut()>(F);

impl<F: FnMut()> Defer<F> {
    fn defuse(self) {
        mem::forget(self);
    }
}

impl<F: FnMut()> Drop for Defer<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

impl FileDesc {
    fn uid(&self) -> eyre::Result<Uid> {
        match &self.user {
            Either::Left(uid) => Ok(Uid::from_raw(*uid)),
            Either::Right(name) => {
                let user =
                    User::from_name(name)?.ok_or_else(|| eyre!("user {name} does not exist"))?;
                Ok(user.uid)
            }
        }
    }

    fn gid(&self) -> eyre::Result<Gid> {
        match &self.group {
            Either::Left(gid) => Ok(Gid::from_raw(*gid)),
            Either::Right(name) => {
                let group =
                    Group::from_name(name)?.ok_or_else(|| eyre!("group {name} does not exist"))?;
                Ok(group.gid)
            }
        }
    }

    #[allow(clippy::similar_names)]
    pub fn create(&self, path: &Path, contents: &[u8]) -> eyre::Result<()> {
        let uid = self.uid()?;
        let gid = self.gid()?;

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o200)
            .open(path)
            .wrap_err("failed to open decrypted file")?;
        let guard = Defer(|| drop(fs::remove_file(path)));

        file.write_all(contents)
            .wrap_err("failed to write to decrypted file")?;

        let fd = file.as_raw_fd();
        fchmod(fd, Mode::empty()).wrap_err("failed to chmod file")?;
        fchown(fd, Some(uid), Some(gid)).wrap_err("failed to chown file")?;
        fchmod(fd, Mode::from_bits_truncate(self.mode)).wrap_err("failed to chmod file")?;

        guard.defuse();
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(alias = "targetDir")]
    pub target_dir: PathBuf,
    pub keys: IndexMap<String, PathBuf>,
    #[serde(default)]
    pub files: HashMap<String, FileDesc>,
}

impl Config {
    pub fn parse(contents: &[u8]) -> eyre::Result<Self> {
        let mb_json = serde_json::from_slice(contents);
        let mb_toml = toml::from_slice(contents);
        match (mb_json, mb_toml) {
            (Ok(json), Ok(_)) => {
                eprintln!("Your config is somehow valid in both JSON or TOML, that's weird");
                eprintln!("Assuming JSON");
                Ok(json)
            }
            (Ok(json), _) => Ok(json),
            (_, Ok(toml)) => Ok(toml),
            (Err(json), Err(toml)) => {
                bail!("Your config is both invalid JSON:\n{json}\n\nAnd TOML:\n{toml}");
            }
        }
    }
}
