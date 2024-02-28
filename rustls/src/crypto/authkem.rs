use spki::{SubjectPublicKeyInfoRef, ObjectIdentifier};
use crate::pki_types::SignatureVerificationAlgorithm;
use crate::pki_types::CertificateDer;

use crate::Error;

use alloc::vec::Vec;

fn select_algorithm<'a>(spki: &SubjectPublicKeyInfoRef, algorithms: &[&'a dyn SignatureVerificationAlgorithm]) -> Result<Option<&'a dyn SignatureVerificationAlgorithm>, Error> {
    for alg in algorithms {
        if !alg.authkem() {
            continue;
        }
        let expected_oid = ObjectIdentifier::from_bytes(alg.public_key_alg_id().as_ref()).unwrap();
        if expected_oid == spki.algorithm.oid {
            return Ok(Some(*alg));
        }
    }
    Ok(None)
}

pub(crate) fn is_authkem_certificate(cert: &CertificateDer<'_>, algorithms: &[&dyn SignatureVerificationAlgorithm]) -> Result<bool, Error> {
    let spki = SubjectPublicKeyInfoRef::try_from(cert.as_ref()).unwrap();
    Ok(select_algorithm(&spki, algorithms)?.is_some())
}

pub(crate) fn encapsulate(cert: &CertificateDer<'_>, algorithms: &[&dyn SignatureVerificationAlgorithm], context_info: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let spki = SubjectPublicKeyInfoRef::try_from(cert.as_ref()).unwrap();
    let alg = select_algorithm(&spki, algorithms)?.expect("this should be a valid alg");
    Ok(alg.encapsulate(spki.subject_public_key.as_bytes().unwrap(), context_info).unwrap())
}