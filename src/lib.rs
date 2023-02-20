#[doc = include_str!("../README.md")]
use std::{fmt::Write, num::ParseIntError};

use getrandom::getrandom;
use rand_core::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use sha2::{Digest, Sha512};

pub fn decode_hex(s: &String) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(feature = "serde")]
use {
    serde::{ser::SerializeMap, Serialize},
    std::{fmt::Display, fs::File, io::Read, path::Path},
};

fn get_rand() -> Result<[u8; 32], getrandom::Error> {
    let mut data = [0u8; 32];

    let mut errors = 0;
    while let Err(e) = getrandom(&mut data) {
        if errors == 8 {
            return Err(e);
        }

        errors += 1;
    }

    Ok(data)
}

fn xor<T: Into<Vec<u8>>>(x: T, y: &String) -> Vec<u8> {
    let x: Vec<u8> = x.into();
    let mut y = y.as_bytes().to_vec();

    let mut hasher = Sha512::new();
    y.reverse();
    hasher.update(y.clone());
    y.reverse();
    let seed: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();

    let mut rng = Hc128Rng::from_seed(seed);

    while y.len() < x.len() {
        let mut fill = [0u8; 8];
        rng.fill_bytes(fill.as_mut_slice());
        y.append(&mut Vec::from(fill));
    }

    x.into_iter().zip(y).map(|(a, b)| a ^ b).collect()
}

/// A passkey you can use to verify/store a password.
///
/// The salt for hashed passwords comes from the system random source.
///
/// Can be a hash of a password, a plaintext password, or an encrypted password.
/// Encryption is an xor with a key, using rand::Hc128Rng to generate pseudorandom filler (seeded by the key).
/// ***Using a long, random encryption key is stongly advised!***
///
/// ```
/// # use auther_lib::*;
/// let pass = Passkey::Plain("abc123".to_string());
///
/// // hashes the password; use `hashed_pass.salt()`
/// // to retrieve the salt later
/// let hash = pass.hash(None, None).unwrap();
///
/// // encrypts the password
/// let key = "qwertyuiop".to_string();
/// let encrypted = pass.encrypt(&key).unwrap();
///
/// // you can check against a plaintext password...
/// assert!(
///     pass.check(
///         &Passkey::Plain(
///             "abc123".to_string()
///         ), None).unwrap()
/// );
///
/// // ...or against a hash...
/// assert!(
///     pass.check(&hash, None).unwrap()
/// );
///
/// // ...or against an encrypted passkey
/// assert!(
///     pass.check(&encrypted, Some(&key)).unwrap()
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Passkey {
    Hash(String, [u8; 64]),
    Plain(String),
    Encrypted(Vec<u8>),
}

impl Default for Passkey {
    fn default() -> Self {
        Self::Plain(String::new())
    }
}

impl Passkey {
    /// Checks against another passkey.
    ///
    /// If one key is encrypted and the other isn't, requires a key to decrypt with.
    pub fn check(&self, other: &Passkey, key: Option<&String>) -> Option<bool> {
        Some(match self {
            Self::Hash(_, salt) => match other {
                Self::Hash(..) => self == other,
                Self::Plain(_) => self == &other.hash(Some(*salt), None)?,
                Self::Encrypted(_) => {
                    let pass = other.decrypt(key?);
                    if pass.is_none() {
                        false
                    } else {
                        self.check(&pass.unwrap(), None)?
                    }
                }
            },
            Self::Plain(pass) => match other {
                Self::Hash(..) => other.check(self, key)?,
                Self::Plain(other) => pass == other,
                Self::Encrypted(..) => {
                    let pass = other.decrypt(key?);
                    if pass.is_none() {
                        false
                    } else {
                        self.check(&pass.unwrap(), None)?
                    }
                }
            },
            Self::Encrypted(ctext) => match other {
                Self::Encrypted(other) => ctext == other,
                _ => {
                    let pass = self.decrypt(key?);
                    if pass.is_none() {
                        false
                    } else {
                        other.check(&pass.unwrap(), None)?
                    }
                }
            },
        })
    }

    /// Returns a Passkey::Hash of the password, using sha512. Uses the system rng to salt the password.
    ///
    /// If the password is encrypted, requires a key to decrypt with.
    pub fn hash(&self, salt: Option<[u8; 64]>, key: Option<&String>) -> Option<Passkey> {
        let hash;
        let mut salt_raw = salt.unwrap_or([0u8; 64]);
        match self {
            Self::Hash(h, s) => {
                hash = h.clone();
                salt_raw = *s;
            }
            Self::Plain(pass) => {
                if salt.is_none() {
                    let mut rng = Hc128Rng::from_seed(get_rand().ok()?);
                    rng.fill_bytes(&mut salt_raw);
                }

                let mut hasher = Sha512::new();
                hasher.update(pass);
                hasher.update(salt_raw);
                hash = format!("{:02x}", hasher.finalize());
            }
            Self::Encrypted(_) => {
                let pass = self.decrypt(key?)?;

                if salt.is_none() {
                    let mut rng = Hc128Rng::from_seed(get_rand().ok()?);
                    rng.fill_bytes(&mut salt_raw);
                }

                let mut hasher = Sha512::new();

                let bytes = match pass {
                    Self::Plain(pass) => pass.into_bytes(),
                    Self::Hash(hash, _) => decode_hex(&hash).unwrap(),
                    Self::Encrypted(ctext) => ctext,
                };

                hasher.update(bytes);
                hasher.update(salt_raw);
                hash = format!("{:02x}", hasher.finalize());
            }
        }

        Some(Self::Hash(hash, salt_raw))
    }

    /// Returns the salt, if self is Passkey::Hash.
    pub fn salt(&self) -> Option<[u8; 64]> {
        if let Self::Hash(_, salt) = self {
            Some(*salt)
        } else {
            None
        }
    }

    /// Encrypts the password. Cannot encrypt a hash.
    ///
    /// Does nothing if the password is already encrypted.
    pub fn encrypt(&self, key: &String) -> Option<Passkey> {
        Some(match self {
            Self::Hash(..) => None?,
            Self::Plain(pass) => Passkey::Encrypted(xor(pass.clone(), key)),
            Self::Encrypted(_) => self.clone(),
        })
    }

    /// Encrypts the password. Cannot decrypt a hash.
    ///
    /// Does nothing if the password is already decrypted.
    pub fn decrypt(&self, key: &String) -> Option<Passkey> {
        Some(match self {
            Self::Hash(..) => None?,
            Self::Encrypted(ctext) => {
                Passkey::Plain(String::from_utf8(xor(ctext.clone(), key)).ok()?)
            }
            Self::Plain(_) => self.clone(),
        })
    }
}

/// Password data.
///
/// ```
/// # use auther_lib::*;
/// let data = Data::all(
///     "example.com".to_string(),
///     "user@example.com".to_string(),
///     "user".to_string()
/// );
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Data {
    pub location: String,
    pub email: Option<String>,
    pub username: Option<String>,
}

#[cfg(feature = "serde")]
impl Serialize for Data {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(None)?;

        state.serialize_entry("name", &self.location)?;

        if let Some(email) = &self.email {
            state.serialize_entry("email", email)?;
        }

        if let Some(username) = &self.username {
            state.serialize_entry("username", username)?;
        }

        state.end()
    }
}

impl Data {
    /// Creates a Data with just a location.
    pub fn location(location: String) -> Self {
        Self {
            location,
            ..Default::default()
        }
    }

    /// Creates a Data with a location and email.
    pub fn email(location: String, email: String) -> Self {
        Self {
            location,
            email: Some(email),
            username: None,
        }
    }

    /// Creates a Data with a location and username.
    pub fn username(location: String, username: String) -> Self {
        Self {
            location,
            email: None,
            username: Some(username),
        }
    }

    /// Creates a Data with a location, email, and username.
    pub fn all(location: String, email: String, username: String) -> Self {
        Self {
            location,
            email: Some(email),
            username: Some(username),
        }
    }
}

/// A Passkey with associated information (Data).
///
/// ```
/// # use auther_lib::*;
/// let mut pass = Password::plain("abc123".to_string());
///
/// pass.add_email("example.com".to_string(), "user@example.com".to_string());
/// pass.add_username("website.net".to_string(), "user".to_string());
///
/// assert_eq!(pass.email()[0], "user@example.com".to_string());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Password {
    pub pass: Passkey,
    data: Vec<Data>,
}

#[cfg(feature = "serde")]
impl Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(None)?;

        match &self.pass {
            Passkey::Plain(pass) => {
                state.serialize_entry("type", "plain")?;
                state.serialize_entry("pass", &pass)?;
            }
            Passkey::Hash(hash, salt) => {
                state.serialize_entry("type", "hash")?;
                state.serialize_entry("pass", &hash)?;
                state.serialize_entry("salt", &encode_hex(salt))?;
            }
            Passkey::Encrypted(ctext) => {
                state.serialize_entry("type", "encrypted")?;
                state.serialize_entry("pass", &encode_hex(ctext))?;
            }
        }

        if !self.data.is_empty() {
            state.serialize_entry("location", &self.data)?;
        }

        state.end()
    }
}

impl Password {
    /// Creates a new password.
    pub fn new(pass: Passkey) -> Self {
        Self {
            pass,
            data: Vec::new(),
        }
    }

    /// Creates a new plaintext password.
    pub fn plain(pass: String) -> Self {
        Self::new(Passkey::Plain(pass))
    }

    /// Creates a new hashed password.
    pub fn hash(hash: String, salt: [u8; 64]) -> Self {
        Self::new(Passkey::Hash(hash, salt))
    }

    pub fn encrypted(pass: Vec<u8>) -> Self {
        Self::new(Passkey::Encrypted(pass))
    }

    /// Checks against a passkey.
    ///
    /// If the key is encrypted, and `other` is not, requires a key to decrypt with.
    pub fn check(&self, other: &Passkey, key: Option<&String>) -> Option<bool> {
        self.pass.check(other, key)
    }

    /// Returns all associated emails.
    pub fn email(&self) -> Vec<String> {
        self.data.iter().filter_map(|d| d.email.clone()).collect()
    }

    /// Returns all associated usernames.
    pub fn username(&self) -> Vec<String> {
        self.data
            .iter()
            .filter_map(|d| d.username.clone())
            .collect()
    }

    /// Returns all associated locations.
    pub fn location(&self) -> Vec<String> {
        self.data.iter().map(|d| d.location.clone()).collect()
    }

    /// Returns all associated Data.
    pub fn data(&self) -> Vec<Data> {
        self.data.clone()
    }

    /// Adds a location with an email.
    pub fn add_email(&mut self, location: String, email: String) {
        self.add(Data::email(location, email));
    }

    /// Adds  location with a username.
    pub fn add_username(&mut self, location: String, username: String) {
        self.add(Data::username(location, username));
    }

    /// Adds a location without a username or email.
    pub fn add_location(&mut self, location: String) {
        self.add(Data::location(location));
    }

    /// Adds a location.
    pub fn add(&mut self, data: Data) {
        self.data.push(data);
    }

    /// Removes a location.
    pub fn remove_location(&mut self, location: String) {
        self.data = self
            .data
            .clone()
            .into_iter()
            .filter(|d| d.location != location)
            .collect();
    }

    /// Removes all locations with a given email.
    pub fn remove_email(&mut self, email: String) {
        self.data = self
            .data
            .clone()
            .into_iter()
            .filter(|d| d.email != Some(email.clone()))
            .collect();
    }

    /// Removes all locations with a given username.
    pub fn remove_username(&mut self, username: String) {
        self.data = self
            .data
            .clone()
            .into_iter()
            .filter(|d| d.username != Some(username.clone()))
            .collect();
    }
}

#[cfg(feature = "serde")]
#[derive(Debug)]
pub enum LoadPasswordsError {
    InvalidSyntax(toml::de::Error),
    InvalidStructure(&'static str),
    InvalidPassType(String),
    InvalidPass,

    FileError(std::io::Error),
}

#[cfg(feature = "serde")]
impl Display for LoadPasswordsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSyntax(e) => write!(f, "Syntax error: {e}")?,
            Self::InvalidStructure(e) => write!(f, "Structure error: {e}")?,

            Self::InvalidPassType(t) => write!(f, "Invalid password type: {t}")?,
            Self::InvalidPass => write!(f, "Invalid password (somewhere)")?,

            Self::FileError(e) => write!(f, "File error: {e}")?,
        }

        Ok(())
    }
}

/// A password manager.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PassManager {
    passwords: Vec<Password>,
}

#[cfg(feature = "serde")]
impl Serialize for PassManager {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(Some(1))?;

        state.serialize_entry("passwords", &self.passwords)?;

        state.end()
    }
}

#[cfg(feature = "serde")]
impl TryFrom<String> for PassManager {
    type Error = LoadPasswordsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut manager = PassManager::new();

        let parsed = value
            .parse::<toml::Table>()
            .map_err(LoadPasswordsError::InvalidSyntax)?;

        if let Some(toml::Value::Array(passwords)) = &parsed.get("passwords") {
            for password in passwords {
                if let Some(toml::Value::String(ty)) = password.get("type") {
                    match ty.as_str() {
                        "plain" => {
                            if let Some(toml::Value::String(pass)) = password.get("pass") {
                                let mut pass = Password::plain(pass.clone());

                                if let Some(toml::Value::Array(locations)) =
                                    password.get("location")
                                {
                                    let mut locations = locations.iter();
                                    while let Some(toml::Value::Table(location)) = locations.next()
                                    {
                                        let mut data = Data::default();

                                        if let Some(toml::Value::String(name)) =
                                            &location.get("name")
                                        {
                                            data.location = name.clone();
                                        } else {
                                            return Err(LoadPasswordsError::InvalidStructure(
                                                "must provide a location name",
                                            ));
                                        }

                                        if let Some(toml::Value::String(email)) =
                                            &location.get("email")
                                        {
                                            data.email = Some(email.clone());
                                        }

                                        if let Some(toml::Value::String(username)) =
                                            &location.get("username")
                                        {
                                            data.username = Some(username.clone());
                                        }

                                        pass.add(data);
                                    }
                                }

                                manager.add_password(pass);
                            } else {
                                return Err(LoadPasswordsError::InvalidStructure(
                                    "must provide a pass",
                                ));
                            }
                        }
                        "hash" => {
                            if let Some(toml::Value::String(pass)) = password.get("pass") {
                                let salt =
                                    if let Some(toml::Value::String(salt)) = password.get("salt") {
                                        let salt = decode_hex(salt)
                                            .map_err(|_| LoadPasswordsError::InvalidPass)?;

                                        if salt.len() != 64 {
                                            return Err(LoadPasswordsError::InvalidPass);
                                        }

                                        salt.try_into().unwrap()
                                    } else {
                                        return Err(LoadPasswordsError::InvalidPass);
                                    };

                                let mut pass = Password::hash(pass.clone(), salt);

                                if let Some(toml::Value::Array(locations)) =
                                    password.get("location")
                                {
                                    let mut locations = locations.iter();
                                    while let Some(toml::Value::Table(location)) = locations.next()
                                    {
                                        let mut data = Data::default();

                                        if let Some(toml::Value::String(name)) =
                                            &location.get("name")
                                        {
                                            data.location = name.clone();
                                        } else {
                                            return Err(LoadPasswordsError::InvalidStructure(
                                                "must provide a location name",
                                            ));
                                        }

                                        if let Some(toml::Value::String(email)) =
                                            &location.get("email")
                                        {
                                            data.email = Some(email.clone());
                                        }

                                        if let Some(toml::Value::String(username)) =
                                            &location.get("username")
                                        {
                                            data.username = Some(username.clone());
                                        }

                                        pass.add(data);
                                    }
                                }

                                manager.add_password(pass);
                            } else {
                                return Err(LoadPasswordsError::InvalidStructure(
                                    "must provide a pass",
                                ));
                            }
                        }
                        "encrypted" => {
                            if let Some(toml::Value::String(pass)) = password.get("pass") {
                                let bytes = decode_hex(pass)
                                    .map_err(|_| LoadPasswordsError::InvalidPass)?;
                                let mut pass = Password::encrypted(bytes);

                                if let Some(toml::Value::Array(locations)) =
                                    password.get("location")
                                {
                                    let mut locations = locations.iter();
                                    while let Some(toml::Value::Table(location)) = locations.next()
                                    {
                                        let mut data = Data::default();

                                        if let Some(toml::Value::String(name)) =
                                            &location.get("name")
                                        {
                                            data.location = name.clone();
                                        } else {
                                            return Err(LoadPasswordsError::InvalidStructure(
                                                "must provide a location name",
                                            ));
                                        }

                                        if let Some(toml::Value::String(email)) =
                                            &location.get("email")
                                        {
                                            data.email = Some(email.clone());
                                        }

                                        if let Some(toml::Value::String(username)) =
                                            &location.get("username")
                                        {
                                            data.username = Some(username.clone());
                                        }

                                        pass.add(data);
                                    }
                                }

                                manager.add_password(pass);
                            } else {
                                return Err(LoadPasswordsError::InvalidStructure(
                                    "must provide a pass",
                                ));
                            }
                        }
                        ty => return Err(LoadPasswordsError::InvalidPassType(ty.to_owned())),
                    }
                } else {
                    return Err(LoadPasswordsError::InvalidStructure(
                        "must provide a pass type",
                    ));
                }
            }
        } else {
            return Err(LoadPasswordsError::InvalidStructure(
                "must provide a password list",
            ));
        }

        Ok(manager)
    }
}

#[cfg(feature = "serde")]
impl TryFrom<&Path> for PassManager {
    type Error = LoadPasswordsError;
    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let mut file = File::open(path).map_err(LoadPasswordsError::FileError)?;

        let mut data = String::new();
        file.read_to_string(&mut data)
            .map_err(LoadPasswordsError::FileError)?;

        data.try_into()
    }
}

impl PassManager {
    /// Creates a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn passwords(&self) -> Vec<Password> {
        self.passwords.clone()
    }

    /// Adds a password.
    ///
    /// If the passwords are identical (not matching), updates the information instead.
    pub fn add_password(&mut self, mut password: Password) {
        if let Some(pass) = self.passwords.iter_mut().find(|p| p == &&password) {
            pass.data.append(&mut password.data);
        } else {
            self.passwords.push(password);
        }
    }

    /// Retrieves a password by passkey.
    ///
    /// If multiple passwords share a passkey, returns the first occurence.
    pub fn get_passkey(&self, pass: Passkey) -> Option<Password> {
        self.passwords.iter().find(|p| p.pass == pass).cloned()
    }

    /// Retrieves a password by location.
    ///
    /// If multiple passwords share a location, returns the first occurence.
    pub fn get_location(&self, location: String) -> Option<Password> {
        self.get_data(Data::location(location))
    }

    /// Retrieves a password by location and email.
    ///
    /// If multiple passwords share a location and email, returns the first occurence.
    pub fn get_email(&self, location: String, email: String) -> Option<Password> {
        self.get_data(Data::email(location, email))
    }

    /// Retrieves a password by location and username.
    ///
    /// If multiple passwords share a location and username, returns the first occurence.
    pub fn get_username(&self, location: String, username: String) -> Option<Password> {
        self.get_data(Data::username(location, username))
    }

    /// Retrieves a password by data.
    ///
    /// Ignores empty fields in `data`.
    pub fn get_data(&self, data: Data) -> Option<Password> {
        self.passwords
            .iter()
            .find(|d| {
                d.location().contains(&data.location)
                    && (data.email.is_none() || d.email().contains((data.email).as_ref().unwrap()))
                    && (data.username.is_none()
                        || d.username().contains((data.username).as_ref().unwrap()))
            })
            .cloned()
    }

    /// Removes a password.
    /// 
    /// The passkey must be identical.
    pub fn remove(&mut self, pass: Passkey) {
        self.passwords.retain(|p| p.pass != pass);
    }

    /// Removes a password by data.
    /// 
    /// Ignores empty fields in `data`.
    pub fn remove_by_data(&mut self, data: Data) {
        self.passwords.retain(|pass| {
            !(pass.location().contains(&data.location)
                    && (data.email.is_none() || pass.email().contains((data.email).as_ref().unwrap()))
                    && (data.username.is_none()
                        || pass.username().contains((data.username).as_ref().unwrap())))
        });
    }

    /// Removes a password by location.
    /// 
    /// If multiple passwords match, removes them all.
    pub fn remove_by_location(&mut self, location: String) {
        self.remove_by_data(Data::location(location))
    }

    /// Removes a password by location and email.
    /// 
    /// If multiple passwords match, removes them all.
    pub fn remove_by_email(&mut self, location: String, email: String) {
        self.remove_by_data(Data::email(location, email))
    }

    /// Removes a password by location and username.
    /// 
    /// If multiple passwords match, removes them all.
    pub fn remove_by_username(&mut self, location: String, username: String) {
        self.remove_by_data(Data::username(location, username))
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[cfg(feature = "serde")]
    const EXAMPLE: &str = r#"[[passwords]]
type = "plain"
pass = "abc123"

[[passwords.location]]
name = "example.com"
email = "user@example.com"
username = "user"

[[passwords]]
type = "encrypted"
pass = "10150643464a"

[[passwords]]
type = "hash"
pass = "95f6dbe5b0c7b7feb458eae5d9bb3c8314d0d8cce1c192fa59127480bb4448541a2872fd69e8d823c0fdc054e93d88ce21eeeafc7c3480e679f2135614a88611"
salt = "5c5a1916d307fc0bc7b116398b2fd15efd05d654d0ffe0f762339c88f694d0dc737ff4a1e2c7fa251b0bec00058eec4b9cb9073712ab308197d62692b19fd851"

[[passwords.location]]
name = "example.net"
username = "user""#;

    macro_rules! s {
        ( $string:expr ) => {
            String::from($string)
        };
    }

    #[test]
    fn plain_verif() {
        let pass1 = Passkey::Plain(s!("Hello, World! 0123456789"));
        let pass2 = Passkey::Plain(s!("Hello, World! 0123456788"));

        let hash1 = pass1.hash(None, None).unwrap();
        let hash2 = pass2.hash(None, None).unwrap();

        assert_eq!(pass1.check(&pass1, None), Some(true));
        assert_eq!(pass1.check(&hash1, None), Some(true));

        assert_eq!(pass1.check(&pass2, None), Some(false));
        assert_eq!(pass1.check(&hash2, None), Some(false));

        assert_eq!(pass2.check(&pass2, None), Some(true));
        assert_eq!(pass2.check(&hash2, None), Some(true));

        assert_eq!(pass2.check(&pass1, None), Some(false));
        assert_eq!(pass2.check(&hash1, None), Some(false));
    }

    #[test]
    fn encrypted_verif() {
        let pass1 = Passkey::Plain(s!("Hello, World! 0123456789"));
        let pass2 = Passkey::Plain(s!("Hello, World! 0123456788"));

        let hash1 = pass1.hash(None, None).unwrap();
        let hash2 = pass2.hash(None, None).unwrap();

        let key1 = s!("abc123");
        let key2 = s!("abc122");

        let enc1 = pass1.encrypt(&key1).unwrap();
        let enc2 = pass2.encrypt(&key2).unwrap();

        assert_eq!(pass1, enc1.decrypt(&key1).unwrap());
        assert_eq!(pass2, enc2.decrypt(&key2).unwrap());

        assert_eq!(
            hash1,
            enc1.hash(Some(hash1.salt().unwrap()), Some(&key1)).unwrap()
        );
        assert_eq!(
            hash2,
            enc2.hash(Some(hash2.salt().unwrap()), Some(&key2)).unwrap()
        );

        assert_eq!(enc1.check(&enc1, None), Some(true));
        assert_eq!(enc1.check(&pass1, Some(&key1)), Some(true));
        assert_eq!(enc1.check(&hash1, Some(&key1)), Some(true));

        assert_eq!(enc1.check(&pass1, Some(&key2)), Some(false));
        assert_eq!(enc1.check(&pass2, Some(&key1)), Some(false));
        assert_eq!(enc1.check(&pass2, Some(&key2)), Some(false));

        assert_eq!(enc1.check(&hash1, Some(&key2)), Some(false));
        assert_eq!(enc1.check(&hash2, Some(&key1)), Some(false));
        assert_eq!(enc1.check(&hash2, Some(&key2)), Some(false));

        assert_eq!(enc2.check(&enc2, None), Some(true));
        assert_eq!(enc2.check(&pass2, Some(&key2)), Some(true));
        assert_eq!(enc2.check(&hash2, Some(&key2)), Some(true));

        assert_eq!(enc2.check(&pass2, Some(&key1)), Some(false));
        assert_eq!(enc2.check(&pass1, Some(&key2)), Some(false));
        assert_eq!(enc2.check(&pass1, Some(&key1)), Some(false));

        assert_eq!(enc2.check(&hash2, Some(&key1)), Some(false));
        assert_eq!(enc2.check(&hash1, Some(&key2)), Some(false));
        assert_eq!(enc2.check(&hash1, Some(&key1)), Some(false));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn parse_from_toml() {
        let text = s!(EXAMPLE);

        let manager: PassManager = text.try_into().expect("Failed to parse toml");

        assert_eq!(
            manager
                .get_email(s!("example.com"), s!("user@example.com"))
                .expect("Failed to get plain password")
                .check(&Passkey::Plain(s!("abc123")), None),
            Some(true)
        );

        assert_eq!(
            manager
                .get_username(s!("example.net"), s!("user"))
                .expect("Failed to get hashed password")
                .check(&Passkey::Plain(s!("def456")), None),
            Some(true)
        );

        assert_eq!(
            manager
                .get_passkey(Passkey::Encrypted(vec![16, 21, 6, 67, 70, 74]))
                .expect("Failed to get encrypted password")
                .check(&Passkey::Plain(s!("abc123")), Some(&s!("qwerty"))),
            Some(true)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize() {
        let text = s!(EXAMPLE);

        let manager1: PassManager = text.clone().try_into().expect("Failed to parse toml");

        let out = toml::to_string_pretty(&manager1).unwrap();

        println!("{manager1:#?}\n\n{out}");

        let manager2 = out.try_into().unwrap();

        assert_eq!(manager1, manager2);
    }
}
