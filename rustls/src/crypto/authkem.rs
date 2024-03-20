use spki::der::Decode;
use x509_cert::Certificate;
use spki::SubjectPublicKeyInfo;
use crate::pki_types::SignatureVerificationAlgorithm;
use crate::pki_types::CertificateDer;

use crate::Error;

use alloc::vec::Vec;

fn select_algorithm<'a, 'b, Params, Key>(spki: &SubjectPublicKeyInfo<Params, Key>, algorithms: &[&'a dyn SignatureVerificationAlgorithm]) -> Result<Option<&'a dyn SignatureVerificationAlgorithm>, Error>
    where Params: spki::der::Choice<'static> + spki::der::EncodeValue
{
    for alg in algorithms {
        if !alg.authkem() {
            continue;
        }
        let algid = alg.public_key_alg_id();
        let expected_alginfo = spki::ObjectIdentifier::from_der(algid.as_ref());
        if expected_alginfo.is_err() {
            panic!("invalid oid for alg {:?}", alg);
        }
        if expected_alginfo.unwrap() == spki.algorithm.oid {
            return Ok(Some(*alg));
        }
    }
    Ok(None)
}

pub(crate) fn is_authkem_certificate(cert: &CertificateDer<'_>, algorithms: &[&dyn SignatureVerificationAlgorithm]) -> Result<bool, Error> {
    //this don't work
    let certificate = Certificate::from_der(cert.as_ref()).unwrap();
    let spki = certificate.tbs_certificate.subject_public_key_info;
    Ok(select_algorithm(&spki, algorithms)?.is_some())
}

pub(crate) fn encapsulate(cert: &CertificateDer<'_>, algorithms: &[&dyn SignatureVerificationAlgorithm], context_info: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let certificate = Certificate::from_der(cert.as_ref()).unwrap();
    let spki = certificate.tbs_certificate.subject_public_key_info;
    let alg = select_algorithm(&spki, algorithms)?.expect("this should be a valid alg");
    Ok(alg.encapsulate(spki.subject_public_key.as_bytes().unwrap(), context_info).unwrap())
}