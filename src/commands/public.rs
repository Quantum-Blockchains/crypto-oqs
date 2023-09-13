use super::asc1_dilithium::SubjectPublicKeyInfoBorrowed;
use super::utils;
use crate::commands::arg_enums::Format;
use crate::commands::asc1_dilithium::{
    AlgorithmIdentifier, OneAsymmetricKeyBorrowed, OneAsymmetricKeyOwned, OID_DILITHIUM2,
    OID_DILITHIUM3, OID_DILITHIUM5,
};
use crate::commands::error::CryptoError;
use clap::Parser;
use der::asn1::OctetString;
use der::pem::LineEnding;
use der::{Decode, DecodePem, Encode, EncodePem};
use oqs::sig;
use std::str;

#[derive(Debug, Clone, Parser)]
pub struct PublicCmd {
    ///Input format (DER or PEM)
    #[clap(long = "inform", value_name = "PEM|DER", default_value = "PEM")]
    pub inform: Format,
    ///Input key
    #[clap(short = 'i', long = "in", value_name = "FILE")]
    pub in_path: String,
    ///Output format (DER or PEM)
    #[clap(long = "outform", value_name = "PEM|DER", default_value = "PEM")]
    pub outform: Format,
    ///Output file
    #[clap(short = 'o', long = "out", value_name = "FILE")]
    pub out_path: Option<String>,
}

impl PublicCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let bytes = utils::read_file(&self.in_path)?;

        let key: OctetString;
        let algorithm: String;
        if self.inform == Format::DER {
            let one_asymmetric_key = OneAsymmetricKeyBorrowed::from_der(&bytes).unwrap();
            algorithm = one_asymmetric_key
                .private_key_algorithm
                .algorithm
                .to_string();
            key = OctetString::from_der(one_asymmetric_key.private_key).unwrap();
        } else {
            let one_asymmetric_key = OneAsymmetricKeyOwned::from_pem(&bytes).unwrap();
            algorithm = one_asymmetric_key
                .private_key_algorithm
                .algorithm
                .to_string();
            key = OctetString::from_der(one_asymmetric_key.private_key.as_bytes()).unwrap();
        }

        let bytes_keypair = key.as_bytes();

        let algorithm_str: &str = &algorithm;
        match algorithm_str {
            OID_DILITHIUM2 => {
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium2) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let public_key = sigalg
                    .public_key_from_bytes(&bytes_keypair[sigalg.length_secret_key()..])
                    .unwrap();
                let bytes_public_key = public_key.to_vec();

                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM2.parse().unwrap(),
                };

                let der_public_key: SubjectPublicKeyInfoBorrowed = SubjectPublicKeyInfoBorrowed {
                    algorithm: algorithm_identifier,
                    subject_public_key: &bytes_public_key,
                };

                if self.outform == Format::DER {
                    let der = der_public_key.to_der().unwrap();
                    utils::output(&der, &self.out_path);
                } else {
                    let pem = der_public_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.out_path);
                }
            }
            OID_DILITHIUM3 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM3.parse().unwrap(),
                };
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium3) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let public_key = sigalg
                    .public_key_from_bytes(&bytes_keypair[sigalg.length_secret_key()..])
                    .unwrap();

                let bytes_public_key = public_key.to_vec();

                let der_public_key: SubjectPublicKeyInfoBorrowed = SubjectPublicKeyInfoBorrowed {
                    algorithm: algorithm_identifier,
                    subject_public_key: &bytes_public_key,
                };

                if self.outform == Format::DER {
                    let der = der_public_key.to_der().unwrap();
                    utils::output(&der, &self.out_path);
                } else {
                    let pem = der_public_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.out_path);
                }
            }
            OID_DILITHIUM5 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM5.parse().unwrap(),
                };

                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium5) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let public_key = sigalg
                    .public_key_from_bytes(&bytes_keypair[sigalg.length_secret_key()..])
                    .unwrap();
                let bytes_public_key = public_key.to_vec();

                let der_public_key: SubjectPublicKeyInfoBorrowed = SubjectPublicKeyInfoBorrowed {
                    algorithm: algorithm_identifier,
                    subject_public_key: &bytes_public_key,
                };

                if self.outform == Format::DER {
                    let der = der_public_key.to_der().unwrap();
                    utils::output(&der, &self.out_path);
                } else {
                    let pem = der_public_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.out_path);
                }
            }
            _ => {
                panic!("ERROR length keypair.");
            }
        }
        Ok(())
    }
}
