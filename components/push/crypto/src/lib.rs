/* Handles cryptographic functions.
 * Depending on platform, this may call various libraries or have other dependencies.
 *
 * This uses prime256v1 EC encryption that should come from internal crypto calls. The "application-services"
 * module compiles openssl, however, so might be enough to tie into that.
 */
#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;

use ece;
use hkdf::Hkdf;
use openssl;
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use sha2::Sha256;

mod error;

const SER_AUTH_LENGTH:usize = 16;

/* build the key off of the OpenSSL key implementation.
 * Much of this is taken from rust_ece/crypto/openssl/lib.rs
 */

lazy_static! {
    static ref GROUP_P256: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
}

pub struct CryptoError;

pub struct Key {
    pub private: EcKey<Private>,
    pub public: Vec<u8>,
    pub auth: Vec<u8>,
}

impl Key {
    /*
    reinstantiating the private key from a vector looks to be overly complex.
    use the serialize/deserialize instead

    pub fn private_raw(&self) -> error::Result<Vec<u8>> {
        // Extract the private key and convert to a byte vector.
        Ok(self.private.private_key().to_vec())
    }

    pub fn private_from_raw(&self, raw &vec<u8>) -> error::Result<Self> {
        let private = BigNum::from_slice(raw)?;
    }
    */

    //TODO: Make these real serde functions
    pub fn serialize(&mut self) -> error::Result<Vec<u8>> {
        let mut result:Vec<u8> = Vec::new();
        let mut ser_private = self.private.private_key_to_der()?;
        let len = self.auth.len() + ser_private.len();
        result.append(&mut self.auth);
        result.append(&mut ser_private);
        result.truncate(len);
        Ok(result)
    }

    pub fn deserialize(&mut self, raw: Vec<u8>) -> error::Result<Key> {
        // fetch out the auth
        let auth = &raw[0..SER_AUTH_LENGTH];
        let mut bn_ctx = BigNumContext::new()?;
        let private = EcKey::private_key_from_der(&raw[SER_AUTH_LENGTH..])?;
        Ok(Key{
            private: private.clone(),
            public: private.public_key().to_bytes(&GROUP_P256, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)?,
            auth: auth.to_vec()
        })
    }
}

pub trait Cryptography {
    /// generate a new local EC p256 key
    fn generate_key() -> error::Result<Key>;

    // General decrypt function. Calls to decrypt_aesgcm or decrypt_aes128gcm as needed.
    // (sigh, can't use notifier::Notification because of circular dependencies.)
    fn decrypt(
        key: &Key,
        body: Vec<u8>,
        encoding: &str,
        salt: Option<Vec<u8>>,
        dh: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoError>;
    // IIUC: objects created on one side of FFI can't be freed on the other side, so we have to use references (or clone)
    fn decrypt_aesgcm(
        key: &Key,
        content: &Vec<u8>,
        auth_key: &str,
        salt: &Vec<u8>,
        crypto_key: &Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError>;
    fn decrypt_aes128gcm(
        key: &Key,
        content: &Vec<u8>,
        auth_key: &Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError>;
}

pub struct Crypto {
    key: Key,
}

impl Cryptography for Crypto {
    fn generate_key() -> error::Result<Key> {
        let key = EcKey::generate(&GROUP_P256)?;
        let mut bn_ctx = BigNumContext::new()?;
        let mut auth = vec![0u8; 16];
        rand_bytes(auth.as_mut_slice())?;
        Ok(Key {
            private: key.clone(),
            public: key.public_key().to_bytes(
                &GROUP_P256,
                PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )?,
            auth: auth,
        })
    }

    // General decrypt function. Calls to decrypt_aesgcm or decrypt_aes128gcm as needed.
    // (sigh, can't use notifier::Notification because of circular dependencies.)
    fn decrypt(
        key: &Key,
        _body: Vec<u8>,
        _encoding: &str,
        _salt: Option<Vec<u8>>,
        _dh: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError)
    }

    // IIUC: objects created on one side of FFI can't be freed on the other side, so we have to use references (or clone)
    fn decrypt_aesgcm(
        key: &Key,
        _content: &Vec<u8>,
        _auth_key: &str,
        _salt: &Vec<u8>,
        _crypto_key: &Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError)
    }

    fn decrypt_aes128gcm(
        key: &Key,
        _content: &Vec<u8>,
        _auth_key: &Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError)
    }
}
