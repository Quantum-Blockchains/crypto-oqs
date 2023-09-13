use std::{fs::File, io::Read};

use clap::Parser;
use super::{arg_enums::Format, utils};
use crate::commands::{
    asc1_dilithium::{
        SubjectPublicKeyInfoBorrowed, SubjectPublicKeyInfoOwned, OID_DILITHIUM2, OID_DILITHIUM3,
        OID_DILITHIUM5,
    },
    error::CryptoError,
};
use der::{asn1::BitString, Decode, DecodePem};
use oqs::sig;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Parser)]
#[clap(name = "verify", about = "Message verification")]
pub struct VerifyCmd {
    ///Input format (DER or PEM)
    #[clap(long = "inform", value_name = "PEM|DER", default_value = "PEM")]
    pub inform: Format,
    ///Input public key
    #[clap(long = "pub", value_name = "FILE")]
    pub pub_path: String,
    ///Input signature
    #[clap(long = "sig", value_name = "FILE")]
    pub sig_path: String,
    ///Input file for verification
    #[clap(long = "file", value_name = "FILE")]
    pub file_path: String,
}

impl VerifyCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let bytes = utils::read_file(&self.pub_path)?;
        let sig_bytes = utils::read_file(&self.sig_path)?;

        let key: BitString;
        let algorithm: String;
        if self.inform == Format::DER {
            let public_key = SubjectPublicKeyInfoBorrowed::from_der(&bytes).unwrap();
            algorithm = public_key.algorithm.algorithm.to_string();
            key = BitString::from_der(public_key.subject_public_key).unwrap();
        } else {
            let public_key = SubjectPublicKeyInfoOwned::from_pem(&bytes).unwrap();
            algorithm = public_key.algorithm.algorithm.to_string();
            key = public_key.subject_public_key;
        }

        let bytes_public_key = key.as_bytes().unwrap();

        let algorithm_str: &str = &algorithm;

        let mut file = File::open(&self.file_path)?;

        let mut hasher = Sha256::new();
        let mut buffer = [0; 4096];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let message_hash = hasher.finalize();

        match algorithm_str {
            OID_DILITHIUM2 => {
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium2) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                if bytes_public_key.len() != sigalg.length_public_key() {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        sigalg.length_public_key(),
                        sigalg.length_signature(),
                    )));
                }

                let public_key = sigalg.public_key_from_bytes(&bytes_public_key).unwrap();
                let signature = sigalg.signature_from_bytes(&sig_bytes).unwrap();
                match sigalg.verify(&message_hash, signature, public_key) {
                    Ok(()) => println!("Verification: OK"),
                    Err(_err) => println!("Verification: FAILED"),
                }
            }
            OID_DILITHIUM3 => {
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium3) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                if bytes_public_key.len() != sigalg.length_public_key() {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        sigalg.length_public_key(),
                        sigalg.length_signature(),
                    )));
                }

                let public_key = sigalg.public_key_from_bytes(&bytes_public_key).unwrap();
                let signature = sigalg.signature_from_bytes(&sig_bytes).unwrap();
                match sigalg.verify(&message_hash, signature, public_key) {
                    Ok(()) => println!("Verification: OK"),
                    Err(_err) => println!("Verification: FAILED"),
                }
            }
            OID_DILITHIUM5 => {
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium5) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                if bytes_public_key.len() != sigalg.length_public_key() {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        sigalg.length_public_key(),
                        sigalg.length_signature(),
                    )));
                }

                let public_key = sigalg.public_key_from_bytes(&bytes_public_key).unwrap();
                let signature = sigalg.signature_from_bytes(&sig_bytes).unwrap();
                match sigalg.verify(&message_hash, signature, public_key) {
                    Ok(()) => println!("Verification: OK"),
                    Err(_err) => println!("Verification: FAILED"),
                }
            }
            _ => return Err(CryptoError::InvalidLengthSignature(sig_bytes.len())),
        };
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::commands::{GenerateCmd, PublicCmd, SignCmd};
    use std::fs;

    #[test]
    fn verify_message() {
        let test_sec_file = "sec_test";
        let test_pub_file = "pub_test";
        let test_sig_file = "sig_test";
        let generate =
            GenerateCmd::parse_from(&["generate", "--algorithm", "dil2", "--out", test_sec_file]);

        let public =
            PublicCmd::parse_from(&["public", "--in", test_sec_file, "--out", test_pub_file]);

        let sign = SignCmd::parse_from(&[
            "sign",
            "--sec",
            test_sec_file,
            "--out",
            test_sig_file,
            "--file",
            test_pub_file,
        ]);

        let verify = VerifyCmd::parse_from(&[
            "verify",
            "--sig",
            test_sig_file,
            "--pub",
            test_pub_file,
            "--file",
            test_pub_file,
        ]);

        assert!(generate.run().is_ok());
        assert!(public.run().is_ok());
        assert!(sign.run().is_ok());
        assert!(verify.run().is_ok());

        fs::remove_file(test_pub_file).unwrap();
        fs::remove_file(test_sec_file).unwrap();
        fs::remove_file(test_sig_file).unwrap();
    }
}
