use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::{Private, Public};
use protobuf::{CodedInputStream, Message};
use std::rc::Rc;
use url::Url;

mod proto;

mod cert {
    use super::holder;
    use super::proto;
    use protobuf::Message;
    use protobuf::ProtobufError;
    use std::cell::RefCell;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Malformed protobuf message")]
        Malformed {
            #[from]
            source: ProtobufError,
        },
    }

    pub struct NestedCertificate<'a> {
        proto: &'a proto::Certificate,
        payload: proto::Certificate_Payload,
        parent: RefCell<Option<Box<NestedCertificate<'a>>>>,
    }

    pub struct RootCertificate<'a> {
        proto: proto::Certificate,
        payload: proto::Certificate_Payload,
        parent: Option<NestedCertificate<'a>>,
    }

    pub trait Certificate<'a> {
        fn getProto(&self) -> &'a proto::Certificate;
        fn getPayload<'b: 'a>(&'b self) -> &'b proto::Certificate_Payload;
        fn getParent(&self) -> Option<&'a NestedCertificate<'a>>;
    }

    impl<'a> NestedCertificate<'a> {
        fn new(proto: &'a proto::Certificate) -> Result<NestedCertificate<'a>, Error> {
            let mut payload = proto::Certificate_Payload::new();
            payload.merge_from_bytes(proto.get_payload())?;
            let me = NestedCertificate {
                proto,
                payload,
                parent: RefCell::new(None),
            };
            let parent;
            if payload.has_parent() {
                parent = Some(Box::new(Self::new(&payload.get_parent())?))
            } else {
                parent = None;
            }
            Ok(me)
        }
    }

    impl<'a> Certificate<'a> for NestedCertificate<'a> {
        fn getParent(&self) -> Option<&'a NestedCertificate<'a>> {
            self.parent.borrow().map(|x| x.as_ref())
        }
        fn getProto(&self) -> &'a proto::Certificate {
            self.proto
        }
        fn getPayload<'b: 'a>(&'b self) -> &'b proto::Certificate_Payload {
            &self.payload
        }
    }

    impl<'a> RootCertificate<'a> {
        pub(crate) fn root(
            payload: proto::Certificate_Payload,
            holder: &holder::Holder,
        ) -> Result<RootCertificate<'a>, holder::Error> {
            let mut proto = proto::Certificate::new();

            let bytes = payload.write_to_bytes().expect("Protobuf internal error");

            proto.set_signature(holder.sign(&bytes)?);
            proto.set_payload(bytes);

            Ok(RootCertificate {
                proto,
                payload,
                parent: None,
            })
        }

        pub fn new(bytes: &[u8]) -> Result<RootCertificate, Error> {
            let mut proto = proto::Certificate::new();
            proto.merge_from_bytes(bytes)?;
            let mut payload = proto::Certificate_Payload::new();
            payload.merge_from_bytes(proto.get_payload())?;

            let parent;
            if payload.has_parent() {
                parent = Some(NestedCertificate::new(&payload.get_parent())?)
            } else {
                parent = None;
            }
            Ok(RootCertificate {
                proto,
                payload,
                parent,
            })
        }
    }

    pub struct CertificateChain<'a> {
        current: Option<&'a dyn Certificate<'a>>,
    }

    impl<'a> Iterator for CertificateChain<'a> {
        type Item = &'a dyn Certificate<'a>;
        fn next(&mut self) -> Option<Self::Item> {
            match self.current {
                Some(cert) => {
                    self.current = cert.getParent().map(|x| x as &'a dyn Certificate<'a>);
                    Some(cert)
                }
                None => None,
            }
        }
    }
}

struct Invocation {}

pub mod holder {
    use super::cert;
    use super::proto;
    use openssl::ec::EcKey;
    use openssl::ecdsa::EcdsaSig;
    use openssl::error::ErrorStack;
    use openssl::pkey::Private;
    use protobuf::Message;
    use thiserror::Error;
    use url::Url;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Unexpected OpenSSL error. Invalid private key?")]
        CryptoError {
            #[from]
            source: ErrorStack,
        },
    }

    type Result<T> = std::result::Result<T, Error>;
    pub struct Holder<'a> {
        me: Url,
        sk: &'a EcKey<Private>,
    }

    pub struct CertificateBlueprint {
        subject: Url,
        capability: Vec<u8>,
        exp: Option<u64>,
    }
    impl<'a> Holder<'a> {
        pub fn forge(&self, options: CertificateBlueprint) -> Result<cert::RootCertificate> {
            let mut proto_payload = proto::Certificate_Payload::new();
            proto_payload.set_capability(options.capability);
            match options.exp {
                Some(x) => proto_payload.set_expiration(x),
                _ => {}
            }
            proto_payload.set_issuer(self.me.clone().into_string());
            proto_payload.set_subject(options.subject.to_string());
            cert::RootCertificate::root(proto_payload, self)
        }

        pub(crate) fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>> {
            Ok(EcdsaSig::sign(&msg, &self.sk)?.to_der()?)
        }
    }
    pub fn new<'a>(me: Url, sk: &'a EcKey<Private>) -> Holder<'a> {
        Holder { me, sk }
    }
}

pub mod validator {
    use thiserror::Error;
    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Item is expired. Expiration caveat is {exp}, now is {now}")]
        Expired { now: u64, exp: u64 },
    }

    type Result<T> = std::result::Result<T, Error>;
    pub struct Validator<'a> {
        trust_checker: &'a super::TrustChecker,
        pubs: &'a super::Pubs,
    }

    impl<'a> Validator<'a> {
        pub fn validate_cert(now: u64) -> Result<()> {
            Ok(())
        }
    }
}

trait Pubs {
    fn get(&self, id: &Url) -> Option<&EcKey<Public>>;
}

trait TrustChecker {
    fn is_trusted(&self, id: &Url) -> bool;
}
