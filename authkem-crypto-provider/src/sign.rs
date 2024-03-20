use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use der::Decode;
use hpke::aead::ExportOnlyAead;
use hpke::kdf::HkdfSha256;
use pkcs8::PrivateKeyInfo;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use hpke::{Kem, Serializable};
use hpke::Deserializable;
use hpke::kem::X25519HkdfSha256;

use crate::verify::DHKEM_X25519_SHA256;

#[derive(Clone)]
pub struct DhkemX25519Sha256 {
    secret_key: Arc::<<X25519HkdfSha256 as Kem>::PrivateKey>,
    scheme: SignatureScheme,
}

impl core::fmt::Debug for DhkemX25519Sha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DhkemX25519Sha256").field("secret_key", &self.secret_key.to_bytes()).field("scheme", &self.scheme).finish()
    }
}

impl TryFrom<PrivateKeyDer<'_>> for DhkemX25519Sha256 {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let key = PrivateKeyInfo::try_from(der.secret_pkcs8_der()).expect("Parse pki");
                let algid = spki::ObjectIdentifier::from_der(DHKEM_X25519_SHA256.public_key_alg_id().as_ref()).unwrap();
                if key.algorithm.oid != algid {
                    return Err(pkcs8::Error::ParametersMalformed);
                }
                Ok(Self {
                    secret_key: Arc::new(<X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&key.private_key[2..]).unwrap()),
                    scheme: SignatureScheme::DHKEM_X25519_SHA256,
                })
            },
            _ => panic!("Unsupported"),
        }
    }
}

impl SigningKey for DhkemX25519Sha256 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0xFE)
    }
}

impl Signer for DhkemX25519Sha256 {
    fn sign(&self, _messge: &[u8])-> Result<Vec<u8>, rustls::Error> {
        panic!("Should never call this!")
    }

    fn decapsulate(&self, ciphertext: &[u8], context_info: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let ciphertext = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(ciphertext).unwrap();
        let setup_info = b"tls13 auth-kem";
        let receiver = hpke::setup_receiver::<ExportOnlyAead, HkdfSha256, X25519HkdfSha256>(&hpke::OpModeR::Base, &*self.secret_key, &ciphertext, setup_info).unwrap();
        let mut outvec = vec![0; 32];
        receiver.export(context_info, outvec.as_mut()).map_err(|_| rustls::Error::DecryptError)?;
        Ok(outvec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

