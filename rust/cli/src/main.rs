use capbac::{self, ValidateError};
use openssl::ec::EcKey;
use openssl::pkey::PKey;
use openssl::pkey::{Private, Public};
use protobuf::Message;
use regex::Regex;
use std::error::Error;
use std::fmt::Debug;
use std::io::{stdin, stdout, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use structopt::StructOpt;
use url::Url;
use Result::Err;
use base64;
use serde::{Serialize, Deserialize};

fn parse_id_pair(s: &str) -> Result<(Url, EcKey<Public>), Box<dyn Error>> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    let path: PathBuf = s[pos + 1..].parse()?;
    let der_content = &read_file(&path)?;
    Ok((s[..pos].parse()?, PKey::public_key_from_der(der_content)?.ec_key()?))
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = std::fs::File::open(path)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

fn parse_priv_key(s: &str) -> Result<EcKey<Private>, Box<dyn Error>> {
    let path = Path::new(s);
    let content = &read_file(&path)?;
    Ok(PKey::private_key_from_pkcs8(content)?.ec_key()?)
}

fn parse_cert(s: &str) -> Result<capbac::proto::Certificate, Box<dyn Error>> {
    let path = Path::new(s);
    let content = &read_file(&path)?;
    let mut cert = capbac::proto::Certificate::new();
    cert.merge_from_bytes(&content)?;
    Ok(cert)
}

fn read_from_stdin<T: protobuf::Message>(proto: &mut T) -> &T {
    let mut buf = Vec::new();
    stdin().read_to_end(&mut buf).unwrap();
    proto.merge_from_bytes(&buf).unwrap();
    proto
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonCertificate<'a> {
    payload: &'a str,
    signature: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonCertPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<JsonCertificate<'a>>,
    capability: &'a str,
    issuer: &'a str,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<u64>
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonInvocation<'a> {
    payload: &'a str,
    signature: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonInvocationPayload<'a> {
    certificate: JsonCertificate<'a>,
    invoker: &'a str,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<u64>
}

fn print_cert(cert: &capbac::proto::Certificate) {
    let json_cert = JsonCertificate {
        payload: &base64::encode(cert.get_payload()),
        signature: &base64::encode(cert.get_signature())
    };
    let mut payload = capbac::proto::Certificate_Payload::new();
    payload.merge_from_bytes(cert.get_payload()).unwrap();
    let parent_cert = payload.get_parent();
    let parent_cert = JsonCertificate {
        payload: &base64::encode(parent_cert.get_payload()),
        signature: &base64::encode(parent_cert.get_signature())
    };
    let parent_payload = if payload.has_parent() {
        Some(parent_cert)
    } else {
        None
    };
    let exp = if payload.get_expiration() != 0 {
        Some(payload.get_expiration())
    } else {
        None
    };
    let json_cert_payload = JsonCertPayload {
        parent: parent_payload,
        capability: &base64::encode(payload.get_capability()),
        issuer: payload.get_issuer(),
        subject: payload.get_subject(),
        expiration: exp
    };
    println!("{}", serde_json::to_string_pretty(&json_cert).unwrap());
    println!("{}", serde_json::to_string_pretty(&json_cert_payload).unwrap());
    if payload.has_parent() {
        print_cert(payload.get_parent());
    }
}

fn print_invocation(invocation: &capbac::proto::Invocation) {
    let json_inv = JsonInvocation {
        payload: &base64::encode(invocation.get_payload()),
        signature: &base64::encode(invocation.get_signature())
    };
    let mut payload = capbac::proto::Invocation_Payload::new();
    payload.merge_from_bytes(invocation.get_payload()).unwrap();
    let cert = payload.get_certificate();
    let json_cert = JsonCertificate {
        payload: &base64::encode(cert.get_payload()),
        signature: &base64::encode(cert.get_signature())
    };
    let exp = if payload.get_expiration() != 0 {
        Some(payload.get_expiration())
    } else {
        None
    };
    let json_inv_payload = JsonInvocationPayload {
        certificate: json_cert,
        invoker: payload.get_invoker(),
        action: &base64::encode(payload.get_action()),
        expiration: exp
    };
    println!("{}", serde_json::to_string_pretty(&json_inv).unwrap());
    println!("{}", serde_json::to_string_pretty(&json_inv_payload).unwrap());
    print_cert(cert);
}

#[derive(StructOpt, Debug)]
enum CapBACApp {
    Forge {
        #[structopt(flatten)]
        holder: HolderArgs,
        #[structopt(flatten)]
        cert: CertArgs,
    },

    Delegate {
        #[structopt(flatten)]
        holder: HolderArgs,
        #[structopt(flatten)]
        cert: CertArgs
    },

    Invoke {
        #[structopt(flatten)]
        holder: HolderArgs,
        #[structopt(flatten)]
        invoke: InvokeArgs
    },

    Invocation {

    },

    InvocationValidate {
        #[structopt(flatten)]
        pubs: PubsArgs,
        #[structopt(flatten)]
        validate: ValidateArgs
    },

    Certificate {

    },

    CertificateValidate {
        #[structopt(flatten)]
        pubs: PubsArgs,
        #[structopt(flatten)]
        validate: ValidateArgs
    },
}

#[derive(StructOpt, Debug)]
struct HolderArgs {
    #[structopt(long)]
    me: Url,
    #[structopt(long, parse(try_from_str = parse_priv_key))]
    sk: EcKey<Private>,
}

#[derive(StructOpt, Debug)]
struct CertArgs {
    #[structopt(long)]
    capability: String,
    #[structopt(long)]
    exp: Option<u64>,
    #[structopt(long)]
    subject: Url,
}

#[derive(StructOpt, Debug)]
struct ValidateArgs {
    #[structopt(long)]
    now: u64,
    #[structopt(long)]
    trust_ids: Regex,
}

#[derive(StructOpt, Debug)]
struct InvokeArgs {
    #[structopt(long)]
    action: String,
    #[structopt(long, parse(try_from_str = parse_cert))]
    cert: capbac::proto::Certificate,
    #[structopt(long)]
    exp: Option<u64>,
}

impl capbac::TrustChecker for ValidateArgs {
    fn is_trusted(&self, id: &url::Url) -> bool {
        self.trust_ids.is_match(id.as_str())
    }
}

impl Into<capbac::CertificateBlueprint> for CertArgs {
    fn into(self) -> capbac::CertificateBlueprint {
        capbac::CertificateBlueprint {
            subject: self.subject,
            capability: self.capability.as_bytes().to_vec(),
            exp: self.exp
        }
    }
}

impl Into<capbac::InvokeBlueprint> for InvokeArgs {
    fn into(self) -> capbac::InvokeBlueprint {
        capbac::InvokeBlueprint {
            action: self.action.as_bytes().to_vec(),
            cert: self.cert,
            exp: self.exp
        }
    }
}

#[derive(StructOpt, Debug)]
struct PubsArgs {
    #[structopt(long = "pub", parse(try_from_str = parse_id_pair))]
    pubs: Vec<(Url, EcKey<Public>)>,
}

impl capbac::Pubs for PubsArgs {
    fn get(&self, id: &Url) -> Option<EcKey<Public>> {
        self.pubs.iter().find(|(x, _)| x.eq(id)).map(|(_, x)| x.clone())
    }
}

fn main() {
    use CapBACApp::*;
    let opt = CapBACApp::from_args();
    match opt {
        Forge { holder, cert } => {
            let cert = capbac::Holder::new(holder.me, holder.sk)
                .forge(cert.into())
                .unwrap();
            stdout().write(&cert.write_to_bytes().unwrap()).unwrap();
        }
        Delegate { holder, cert } => {
            let mut parent_cert = capbac::proto::Certificate::new();
            read_from_stdin(&mut parent_cert);
            let cert = capbac::Holder::new(holder.me, holder.sk)
                .delegate(parent_cert, cert.into())
                .unwrap();
            stdout().write(&cert.write_to_bytes().unwrap()).unwrap();
        }
        Invoke { holder, invoke } => {
            let invocation = capbac::Holder::new(holder.me, holder.sk)
                .invoke(invoke.into())
                .unwrap();
            stdout().write(&invocation.write_to_bytes().unwrap()).unwrap();
        }
        Invocation { } => {
            let mut invocation = capbac::proto::Invocation::new();
            read_from_stdin(&mut invocation);
            print_invocation(&invocation);
        }
        Certificate { } => {
            let mut cert = capbac::proto::Certificate::new();
            read_from_stdin(&mut cert);
            print_cert(&cert);
        }
        InvocationValidate { validate, pubs } => {
            let mut invocation = capbac::proto::Invocation::new();
            read_from_stdin(&mut invocation);
            match capbac::Validator::new(&validate, &pubs).validate_invocation(&invocation, validate.now) {
                Result::Ok(_) => (),
                Err(e @ ValidateError::Malformed { .. }) => {
                    println!("{:#?}", e);
                    exit(11)
                }
                Err(e @ ValidateError::BadURL { .. }) => {
                    println!("{:#?}", e);
                    exit(12)
                }
                Err(e @ ValidateError::UnknownPub { .. }) => {
                    println!("{:#?}", e);
                    exit(12)
                }
                Err(e @ ValidateError::BadIssuer { .. }) => {
                    println!("{:#?}", e);
                    exit(13)
                }
                Err(e @ ValidateError::BadInvoker { .. }) => {
                    println!("{:#?}", e);
                    exit(13)
                }
                Err(e @ ValidateError::Untrusted { .. }) => {
                    println!("{:#?}", e);
                    exit(13)
                }
                Err(ValidateError::Expired) => {
                    println!("Expired");
                    exit(14)
                }
                Err(ValidateError::BadSign) => {
                    println!("Bad sign");
                    exit(15)
                }
            }
        }
        CertificateValidate { validate, pubs } => {
            let mut cert = capbac::proto::Certificate::new();
            read_from_stdin(&mut cert);
            match capbac::Validator::new(&validate, &pubs).validate_cert(&cert, validate.now) {
                Result::Ok(_) => (),
                Err(e @ ValidateError::Malformed { .. }) => {
                    println!("{:#?}", e);
                    exit(11)
                }
                Err(e @ ValidateError::BadURL { .. }) => {
                    println!("{:#?}", e);
                    exit(12)
                }
                Err(e @ ValidateError::UnknownPub { .. }) => {
                    println!("{:#?}", e);
                    exit(12)
                }
                Err(e @ ValidateError::BadIssuer { .. }) => {
                    println!("{:#?}", e);
                    exit(13)
                }
                Err(e @ ValidateError::BadInvoker { .. }) => {
                    println!("{:#?}", e);
                    exit(13)
                }
                Err(e @ ValidateError::Untrusted { .. }) => {
                    println!("{:#?}", e);
                    exit(13)
                }
                Err(ValidateError::Expired) => {
                    println!("Expired");
                    exit(14)
                }
                Err(ValidateError::BadSign) => {
                    println!("Bad sign");
                    exit(15)
                }
            };
        }
    }
}
