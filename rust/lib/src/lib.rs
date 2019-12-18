use protobuf::{CodedInputStream, Message};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, UnparsedPublicKey};
use std::rc::Rc;
use url::Url;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

mod error {
    use protobuf::ProtobufError;

    pub enum Malformed {
        ProtobufError(protobuf::ProtobufError),
    }

    pub struct BadID {}

    impl From<ProtobufError> for Malformed {
        fn from(x: protobuf::ProtobufError) -> Self {
            Malformed::ProtobufError(x)
        }
    }
}

mod proto;

pub struct Certificate {
    pub proto: proto::Certificate,
}

impl Certificate {
    pub fn parse(bytes: &[u8]) -> Result<Certificate, error::Malformed> {
        let mut cert_proto = proto::Certificate::new();
        cert_proto.merge_from_bytes(bytes)?;
        Ok(Certificate { proto: cert_proto })
    }
}

struct Invocation {}

pub struct CapBAC {
    keypairs: Box<dyn Keypairs>,
    resolver: Box<dyn Resolver>,
}

impl CapBAC {
    pub fn new(keypairs: Box<dyn Keypairs>, resolver: Box<dyn Resolver>) -> Self {
        CapBAC { keypairs, resolver }
    }
}

pub struct Holder {
    me: Url,
    capbac: Rc<CapBAC>,
    random: SystemRandom,
}

pub struct CertificateBlueprint {
    subject: Url,
    capability: Vec<u8>,
    exp: Option<u64>,
}

impl Holder {
    pub fn new(me: Url, capbac: Rc<CapBAC>) -> Self {
        Holder {
            me,
            capbac,
            random: SystemRandom::new(),
        }
    }

    pub fn forge(&self, options: CertificateBlueprint) -> Result<Certificate, error::BadID> {
        let mut proto = proto::Certificate::new();
        let mut proto_payload = proto::Certificate_Payload::new();
        proto_payload.set_capability(options.capability);
        match options.exp {
            Some(x) => proto_payload.set_expiration(x),
            _ => {}
        }
        proto_payload.set_issuer(self.me.clone().into_string());
        proto_payload.set_subject(options.subject.to_string());
        let bytes = proto_payload.write_to_bytes().unwrap();
        proto.set_signature(self.make_signature(options.subject, &bytes)?);
        proto.set_payload(bytes);
        Ok(Certificate { proto })
    }

    fn make_signature(&self, subject: Url, bytes: &Vec<u8>) -> Result<Vec<u8>, error::BadID> {
        let subject_key = self
            .capbac
            .resolver
            .resolve(&subject)
            .ok_or(error::BadID {})?;
        let key_pair = self.capbac.keypairs.get(&self.me).unwrap();
        let message = {
            let mut r = subject_key.to_vec();
            r.extend_from_slice(&bytes);
            r
        };
        Ok(key_pair
            .sign(&self.random, message.as_ref())
            .unwrap()
            .as_ref()
            .to_vec())
    }
}

pub trait Keypairs {
    fn get(&self, id: &Url) -> Option<&EcdsaKeyPair>;
}

trait Resolver {
    fn resolve(&self, id: &Url) -> Option<&[u8]>;
}
