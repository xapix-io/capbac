// #[cfg(feature = "with-serde")]
// extern crate serde;
// #[cfg(feature = "with-serde")]
// #[macro_use]
// extern crate serde_derive;
// #[cfg(feature = "with-serde")]
// extern crate serde_json;

use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::pkey::{Private, Public};
use protobuf::{Message};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub mod proto;

pub trait Pubs {
    fn get(&self, id: &Url) -> Option<&EcKey<Public>>;
}

pub trait TrustChecker {
    fn is_trusted(&self, id: &Url) -> bool;
}

pub struct CertificateBlueprint {
    pub subject: Url,
    pub capability: Vec<u8>,
    pub exp: Option<u64>,
}

#[derive(Error, Debug)]
pub enum ForgeError {
    #[error("Unexpected OpenSSL error. Invalid private key?")]
    CryptoError {
        #[from]
        source: ErrorStack,
    },
}

#[derive(Error, Debug)]
pub enum InvokeError {}

pub struct Holder<'a> {
    me: Url,
    sk: &'a EcKey<Private>,
}

impl<'a> Holder<'a> {
    pub fn new(me: Url, sk: &'a EcKey<Private>) -> Self {
        Holder { me, sk }
    }

    pub fn forge(&self, options: CertificateBlueprint) -> Result<proto::Certificate, ForgeError> {
        let mut proto_payload = proto::Certificate_Payload::new();
        proto_payload.set_capability(options.capability);
        match options.exp {
            Some(x) => proto_payload.set_expiration(x),
            _ => {}
        }
        proto_payload.set_issuer(self.me.clone().into_string());
        proto_payload.set_subject(options.subject.to_string());
        let bytes = proto_payload
            .write_to_bytes()
            .expect("Protobuf internal error");

        let mut proto = proto::Certificate::new();
        proto.set_signature(self.sign(&bytes)?);
        proto.set_payload(bytes);
        Ok(proto)
    }

    // pub fn delegate(&self, cert: proto::Certificate, options: CertificateBlueprint) -> Result<proto::Certificate, InvokeError> {

    // }

    // pub fn invoke(&self, )

    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, ForgeError> {
        let mut hasher = Sha256::new();
        hasher.input(msg);
        let hash = hasher.result();
        Ok(EcdsaSig::sign(&hash, &self.sk)?.to_der()?)
    }
}

#[derive(Error, Debug)]
pub enum ValidateError {
    #[error("Malformed protobuf message")]
    Malformed {
        #[from]
        source: protobuf::ProtobufError,
    },
    #[error("Untrusted issuer {issuer}")]
    Untrusted { issuer: Url },
    #[error("Can't parse URL {url}")]
    BadURL { url: String },
    #[error("Unknown pub key for {url}")]
    UnknownPub { url: Url },
    #[error("Issuer {issuer} doesn't match subject {subject}")]
    BadIssuer { subject: Url, issuer: Url },
    #[error("Expired item")]
    Expired,
    #[error("Bad signature")]
    BadSign,
}
pub struct Validator<'a> {
    trust_checker: &'a dyn TrustChecker,
    pubs: &'a dyn Pubs,
}

impl<'a> Validator<'a> {
    pub fn new(trust_checker: &'a dyn TrustChecker, pubs: &'a dyn Pubs) -> Self {
        Validator {
            trust_checker,
            pubs,
        }
    }

    pub fn validate_cert(&self, cert: &proto::Certificate, now: u64) -> Result<(), ValidateError> {
        self.validate_cert2(None, cert, now)
    }

    fn validate_cert2(
        &self,
        next_issuer: Option<&Url>,
        cert: &proto::Certificate,
        now: u64,
    ) -> Result<(), ValidateError> {
        let mut payload = proto::Certificate_Payload::new();
        payload.merge_from_bytes(cert.get_payload())?;
        if payload.get_expiration() != 0 && payload.get_expiration() < now {
            return Err(ValidateError::Expired);
        }

        let issuer = Url::parse(payload.get_issuer()).map_err(|_| ValidateError::BadURL {
            url: payload.get_issuer().to_string(),
        })?;

        let subject = Url::parse(payload.get_subject()).map_err(|_| ValidateError::BadURL {
            url: payload.get_issuer().to_string(),
        })?;

        match next_issuer {
            Some(issuer) => {
                if issuer != &subject {
                    return Err(ValidateError::BadIssuer {
                        issuer: issuer.clone(),
                        subject,
                    });
                }
            }
            None => {}
        }

        if payload.has_parent() {
            self.validate_cert2(Some(&issuer), payload.get_parent(), now)?
        } else {
            if !self.trust_checker.is_trusted(&issuer) {
                return Err(ValidateError::Untrusted { issuer });
            }
        }

        let issuer_pub = match self.pubs.get(&issuer) {
            Some(x) => x,
            None => return Err(ValidateError::UnknownPub { url: issuer }),
        };

        self.verify(cert.get_payload(), cert.get_signature(), issuer_pub)?;
        Ok(())
    }

    fn verify(&self, msg: &[u8], sign: &[u8], pk: &EcKey<Public>) -> Result<(), ValidateError> {
        let mut hasher = Sha256::new();
        hasher.input(msg);
        let hash = hasher.result();
        if !EcdsaSig::from_der(sign)
            .map_err(|_| ValidateError::BadSign)?
            .verify(&hash, pk)
            .map_err(|_| ValidateError::BadSign)?
        {
            return Err(ValidateError::BadSign);
        }
        Ok(())
    }
}
