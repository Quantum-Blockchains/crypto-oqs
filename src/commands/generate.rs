use super::{
    arg_enums::{Algorithm, Format},
    asc1_dilithium::{
        AlgorithmIdentifier, OneAsymmetricKeyBorrowed, OID_DILITHIUM2, OID_DILITHIUM3,
        OID_DILITHIUM5,
    },
    error::CryptoError,
    utils,
};
use clap::Parser;
use der::{pem::LineEnding, Encode, EncodePem};
use oqs::sig;
use rand::*;

#[derive(Debug, Clone, Parser)]
#[clap(name = "generate", about = "Generate key pair")]
pub struct GenerateCmd {
    ///Algorithm for key pair generation (dilithium2 or dil2, dilithium3 or dil3, dilithium5 or dil5)
    #[clap(short = 'a', long = "algorithm")]
    pub algorithm: Algorithm,
    ///Output format (DER or PEM)
    #[clap(long = "outform", value_name = "PEM|DER", default_value = "PEM")]
    pub outform: Format,
    ///Output file
    #[clap(long = "out", value_name = "FILE")]
    pub secret_output_path: Option<String>,
}

impl GenerateCmd {
    pub fn run(&self) -> Result<(), CryptoError> {
        let mut seed = [0u8; 32];
        thread_rng().fill_bytes(&mut seed[..]);

        let mut vector_bytes_private_key: Vec<u8> = Vec::new();
        vector_bytes_private_key.push(0x04);
        vector_bytes_private_key.push(0x82);
        match self.algorithm {
            Algorithm::Dilithium2 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM2.parse().unwrap(),
                };

                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium2) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let (a_sig_pk, a_sig_sk) = match sigalg.keypair() {
                    Ok((pk, sk)) => (pk, sk),
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let mut vec1 = a_sig_sk.into_vec();
                let mut vec2 = a_sig_pk.into_vec();

                vector_bytes_private_key.push(0x0F);
                vector_bytes_private_key.push(0x00);
                vector_bytes_private_key.append(&mut vec1);
                vector_bytes_private_key.append(&mut vec2);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::DER {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path);
                }
            }
            Algorithm::Dilithium3 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM3.parse().unwrap(),
                };

                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium3) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let (a_sig_pk, a_sig_sk) = match sigalg.keypair() {
                    Ok((pk, sk)) => (pk, sk),
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let mut vec1 = a_sig_sk.into_vec();
                let mut vec2 = a_sig_pk.into_vec();

                vector_bytes_private_key.push(0x17);
                vector_bytes_private_key.push(0x40);

                vector_bytes_private_key.append(&mut vec1);
                vector_bytes_private_key.append(&mut vec2);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::DER {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path);
                }
            }
            Algorithm::Dilithium5 => {
                let algorithm_identifier = AlgorithmIdentifier {
                    algorithm: OID_DILITHIUM5.parse().unwrap(),
                };

                let sigalg = match sig::Sig::new(sig::Algorithm::Dilithium5) {
                    Ok(s) => s,
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let (a_sig_pk, a_sig_sk) = match sigalg.keypair() {
                    Ok((pk, sk)) => (pk, sk),
                    Err(err) => return Err(CryptoError::GenerateKeys(err.to_string())),
                };
                let mut vec1 = a_sig_sk.into_vec();
                let mut vec2 = a_sig_pk.into_vec();

                vector_bytes_private_key.push(0x1D);
                vector_bytes_private_key.push(0x20);

                vector_bytes_private_key.append(&mut vec1);
                vector_bytes_private_key.append(&mut vec2);

                let der_private_key: OneAsymmetricKeyBorrowed = OneAsymmetricKeyBorrowed {
                    version: 0,
                    private_key_algorithm: algorithm_identifier,
                    private_key: &vector_bytes_private_key,
                };

                if self.outform == Format::DER {
                    let der = der_private_key.to_der().unwrap();
                    utils::output(&der, &self.secret_output_path);
                } else {
                    let pem = der_private_key.to_pem(LineEnding::LF).unwrap();
                    utils::output(pem.as_bytes(), &self.secret_output_path);
                }
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn generate_dilithium2() {
        let generate = GenerateCmd::parse_from(&["generate", "-a", "dil2"]);
        assert!(generate.run().is_ok())
    }

    #[test]
    fn generate_dilithium3() {
        let generate = GenerateCmd::parse_from(&["generate", "-a", "dil3"]);
        assert!(generate.run().is_ok())
    }

    #[test]
    fn generate_dilithium5() {
        let generate = GenerateCmd::parse_from(&["generate", "-a", "dil5"]);
        assert!(generate.run().is_ok())
    }

    #[test]
    fn generate_dilithium2_and_write_keys_to_files() {
        let test_out_file = "out_test";
        let generate =
            GenerateCmd::parse_from(&["generate", "--algorithm", "dil5", "--out", test_out_file]);
        assert!(generate.run().is_ok());
        let path_sec = Path::new(test_out_file);
        if path_sec.exists() {
            fs::remove_file(test_out_file).unwrap();
            assert!(true);
        } else {
            assert!(false);
        }
    }
}
