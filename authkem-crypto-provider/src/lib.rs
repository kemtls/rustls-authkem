#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;

use rustls::crypto::ring;

mod sign;
mod verify;


pub fn provider() -> CryptoProvider {
    CryptoProvider {
        signature_verification_algorithms: verify::SUPPORTED_SIG_ALGS,
        key_provider: &Provider,
        ..ring::default_provider()
    }
}

#[derive(Debug)]
struct Provider;


impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let kem = sign::DhkemX25519Sha256::try_from(key_der.clone_key());
        if kem.is_ok() {
            Ok(Arc::new(kem.unwrap()))
        } else {
            rustls::crypto::ring::sign::any_supported_type(&key_der)
        }
    }
}