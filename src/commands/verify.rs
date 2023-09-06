use std::{fs::File, io::Read};

use clap::Parser;
// use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
use der::{asn1::BitString, Decode, DecodePem};
use sha2::{Sha256, Digest};
use crate::commands::{error::CryptoError, asc1_dilithium::{SubjectPublicKeyInfoBorrowed, SubjectPublicKeyInfoOwned, OID_DILITHIUM2, OID_DILITHIUM3, OID_DILITHIUM5}};
use super::{utils, arg_enums::Format};
use oqs::sig;


#[derive(Debug, Clone, Parser)]
#[clap(name = "verify", about = "Message verification")]
pub struct VerifyCmd {
    ///A message to be verified
    // #[clap(short = 'm', long)]
    // message: String,
    ///Input format (DER or PEM)
    #[clap(long = "inform", value_name = "PEM|DER", default_value = "PEM")]
    pub inform: Format,
    ///The public key that will be used to verify the message
    #[clap(long="pub")]
    pub pub_path: String,
    ///The signature that will be used to verify the message
    #[clap(long="sig")]
    pub sig_path: String,
    ///Path for writing the signature to the file
    #[clap(long="file")]
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
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium2){
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string()))
                };
                if bytes_public_key.len() != sigalg.length_public_key() {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        sigalg.length_public_key(),
                        sigalg.length_signature(),
                    )))
                }
                // let public = dilithium2::PublicKey::from_bytes(bytes_public_key);
                // public.verify(&message_hash, &sig_bytes)


                let public_key = sigalg.public_key_from_bytes(&bytes_public_key).unwrap();
                let signature = sigalg.signature_from_bytes(&sig_bytes).unwrap();
                match sigalg.verify(&message_hash, signature, public_key) {
                    Ok(()) => println!("Verification: OK"),
                    Err(_err) => println!("Verification: FAILED")
                }


            }
            OID_DILITHIUM3 => {
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium3){
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string()))
                };
                if bytes_public_key.len() != sigalg.length_public_key() {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        sigalg.length_public_key(),
                        sigalg.length_signature(),
                    )))
                }
                // let public = dilithium3::PublicKey::from_bytes(bytes_public_key);
                // public.verify(&message_hash, &sig_bytes)

                let public_key = sigalg.public_key_from_bytes(&bytes_public_key).unwrap();
                let signature = sigalg.signature_from_bytes(&sig_bytes).unwrap();
                match sigalg.verify(&message_hash, signature, public_key) {
                    Ok(()) => println!("Verification: OK"),
                    Err(_err) => println!("Verification: FAILED")
                }
            }
            OID_DILITHIUM5 => {
                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium5){
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string()))
                };
                if bytes_public_key.len() != sigalg.length_public_key() {
                    return Err(CryptoError::InvalidLengthPublicKey(format!(
                        "A public key of length {:?} is expected a signature of length {:?}",
                        sigalg.length_public_key(),
                        sigalg.length_signature(),
                    )))
                }
                // let public = dilithium5::PublicKey::from_bytes(bytes_public_key);
                // public.verify(&message_hash, &sig_bytes)

                let public_key = sigalg.public_key_from_bytes(&bytes_public_key).unwrap();
                let signature = sigalg.signature_from_bytes(&sig_bytes).unwrap();
                match sigalg.verify(&message_hash, signature, public_key) {
                    Ok(()) => println!("Verification: OK"),
                    Err(_err) => println!("Verification: FAILED")
                }
            }
            _ => {
                return Err(CryptoError::InvalidLengthSignature(sig_bytes.len()))
            }
        };
        // println!("Verification: {:?}", ver);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use crate::commands::{GenerateCmd, SignCmd};
    use super::*;

    #[test]
    fn verify_message() {
        let test_sec_file = "sec_test";
        let test_pub_file = "pub_test";
        let test_sig_file = "sig_test";
        let generate = GenerateCmd::parse_from(&[
            "generate",
            "--algorithm",
            "dil5",
            "--sec",
            test_sec_file,
            "--pub",
            test_pub_file,
        ]);

        let sign = SignCmd::parse_from(&[
            "sign",
            "-m",
            "test message",
            "--sec",
            test_sec_file,
            "--out",
            test_sig_file,
        ]);

        let verify = VerifyCmd::parse_from(&[
            "verify",
            "-m",
            "test message",
            "--sig",
            test_sig_file,
            "--pub",
            test_pub_file,
        ]);

        assert!(generate.run().is_ok());
        assert!(sign.run().is_ok());
        assert!(verify.run().is_ok());

        fs::remove_file(test_pub_file).unwrap();
        fs::remove_file(test_sec_file).unwrap();
        fs::remove_file(test_sig_file).unwrap();
    }
}
