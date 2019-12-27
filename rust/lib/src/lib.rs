use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::pkey::{Private, Public};
use protobuf::{CodedInputStream, Message};
use sha2::{Digest, Sha256, Sha512};
use std::rc::Rc;
use thiserror::Error;
use url::Url;

pub mod proto;

// mod cert {
//     use super::holder;
//     use super::proto;
//     use protobuf::Message;
//     use protobuf::ProtobufError;
//     use std::cell::RefCell;
//     use thiserror::Error;

//     #[derive(Error, Debug)]
//     pub enum Error {
//         #[error("Malformed protobuf message")]
//         Malformed {
//             #[from]
//             source: ProtobufError,
//         },
//     }

//     pub struct NestedCertificate<'a> {
//         proto: &'a proto::Certificate,
//         payload: proto::Certificate_Payload,
//         parent: RefCell<Option<Box<NestedCertificate<'a>>>>,
//     }

//     pub struct RootCertificate<'a> {
//         proto: proto::Certificate,
//         payload: proto::Certificate_Payload,
//         parent: Option<NestedCertificate<'a>>,
//     }

//     pub trait Certificate<'a> {
//         fn getProto(&self) -> &'a proto::Certificate;
//         fn getPayload<'b: 'a>(&'b self) -> &'b proto::Certificate_Payload;
//         fn getParent(&self) -> Option<&'a NestedCertificate<'a>>;
//     }

//     impl<'a> NestedCertificate<'a> {
//         fn new(proto: &'a proto::Certificate) -> Result<NestedCertificate<'a>, Error> {
//             let mut payload = proto::Certificate_Payload::new();
//             payload.merge_from_bytes(proto.get_payload())?;
//             let me = NestedCertificate {
//                 proto,
//                 payload,
//                 parent: RefCell::new(None),
//             };
//             let parent;
//             if payload.has_parent() {
//                 parent = Some(Box::new(Self::new(&payload.get_parent())?))
//             } else {
//                 parent = None;
//             }
//             Ok(me)
//         }
//     }

//     impl<'a> Certificate<'a> for NestedCertificate<'a> {
//         fn getParent(&self) -> Option<&'a NestedCertificate<'a>> {
//             self.parent.borrow().map(|x| x.as_ref())
//         }
//         fn getProto(&self) -> &'a proto::Certificate {
//             self.proto
//         }
//         fn getPayload<'b: 'a>(&'b self) -> &'b proto::Certificate_Payload {
//             &self.payload
//         }
//     }

//     impl<'a> RootCertificate<'a> {
//         pub(crate) fn root(
//             payload: proto::Certificate_Payload,
//             holder: &holder::Holder,
//         ) -> Result<RootCertificate<'a>, holder::Error> {
//             let mut proto = proto::Certificate::new();

//             let bytes = payload.write_to_bytes().expect("Protobuf internal error");

//             proto.set_signature(holder.sign(&bytes)?);
//             proto.set_payload(bytes);

//             Ok(RootCertificate {
//                 proto,
//                 payload,
//                 parent: None,
//             })
//         }

//         pub fn new(bytes: &[u8]) -> Result<RootCertificate, Error> {
//             let mut proto = proto::Certificate::new();
//             proto.merge_from_bytes(bytes)?;
//             let mut payload = proto::Certificate_Payload::new();
//             payload.merge_from_bytes(proto.get_payload())?;

//             let parent;
//             if payload.has_parent() {
//                 parent = Some(NestedCertificate::new(&payload.get_parent())?)
//             } else {
//                 parent = None;
//             }
//             Ok(RootCertificate {
//                 proto,
//                 payload,
//                 parent,
//             })
//         }
//     }

//     pub struct CertificateChain<'a> {
//         current: Option<&'a dyn Certificate<'a>>,
//     }

//     impl<'a> Iterator for CertificateChain<'a> {
//         type Item = &'a dyn Certificate<'a>;
//         fn next(&mut self) -> Option<Self::Item> {
//             match self.current {
//                 Some(cert) => {
//                     self.current = cert.getParent().map(|x| x as &'a dyn Certificate<'a>);
//                     Some(cert)
//                 }
//                 None => None,
//             }
//         }
//     }
// }

// struct Invocation {}

// pub mod holder {
//     use super::cert;
//     use super::proto;
//     use openssl::ec::EcKey;
//     use openssl::ecdsa::EcdsaSig;
//     use openssl::error::ErrorStack;
//     use openssl::pkey::Private;
//     use protobuf::Message;
//     use thiserror::Error;
//     use url::Url;

//     type Result<T> = std::result::Result<T, Error>;
//     pub struct Holder<'a> {
//         me: Url,
//         sk: &'a EcKey<Private>,
//     }
// }

// pub mod validator {
//     use thiserror::Error;
//     #[derive(Error, Debug)]
//     pub enum Error {
//         #[error("Item is expired. Expiration caveat is {exp}, now is {now}")]
//         Expired { now: u64, exp: u64 },
//     }

//     type Result<T> = std::result::Result<T, Error>;

// }

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
