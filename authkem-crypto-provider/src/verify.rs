
use rand_core::OsRng;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki;

use hpke::aead::ExportOnlyAead;
use hpke::kdf::HkdfSha256;
use hpke::{Kem, Serializable};
use hpke::Deserializable;
use hpke::kem::X25519HkdfSha256;

use alloc::vec;
use alloc::vec::Vec;


/// A `WebPkiSupportedAlgorithms` value that reflects webpki's capabilities when
/// compiled against *ring*.
pub(crate) static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P256_SHA384,
        webpki::ring::ECDSA_P384_SHA256,
        webpki::ring::ECDSA_P384_SHA384,
        webpki::ring::ED25519,
        webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        webpki::ring::RSA_PKCS1_2048_8192_SHA384,
        webpki::ring::RSA_PKCS1_2048_8192_SHA512,
        webpki::ring::RSA_PKCS1_3072_8192_SHA384,
        DHKEM_X25519_SHA256,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki::ring::ECDSA_P384_SHA384,
                webpki::ring::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki::ring::ECDSA_P256_SHA256,
                webpki::ring::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki::ring::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki::ring::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki::ring::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki::ring::RSA_PKCS1_2048_8192_SHA256],
        ),
        (
            SignatureScheme::DHKEM_X25519_SHA256,
            &[DHKEM_X25519_SHA256],
        )
    ],
};

pub(super) static DHKEM_X25519_SHA256: &dyn SignatureVerificationAlgorithm = &DhkemX25519Sha256;


#[derive(Debug)]
struct DhkemX25519Sha256;

impl SignatureVerificationAlgorithm for DhkemX25519Sha256 {
    fn verify_signature(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        panic!("not supported")
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        // https://www.rfc-editor.org/rfc/rfc8410 id-X25519
        AlgorithmIdentifier::from_slice(&[
            0x06, 0x03, 0x2b, 0x65, 0x6e
        ])
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        panic!("Not allowed")
    }

    fn fips(&self) -> bool {
        false
    }

    fn authkem(&self) -> bool {
        // default algorithms don't support this (they're all signatures)
        true
    }

    fn encapsulate(&self, public_key: &[u8], context_info: &[u8]) -> Result<(Vec<u8>, Vec<u8>), InvalidSignature> {
        let mut rng = OsRng;
        let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(public_key).unwrap();
        let (ciphertext, context) = hpke::setup_sender::<ExportOnlyAead, HkdfSha256, X25519HkdfSha256, _>(&hpke::OpModeS::Base, &public_key, b"tls13 auth-kem", &mut rng).unwrap();
        let mut ss = vec![0; 32];
        context.export(context_info, &mut ss).unwrap();
        Ok((ciphertext.to_bytes().to_vec(), ss))
    }
}