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

fn read_cert(cert: &mut capbac::proto::Certificate) -> &capbac::proto::Certificate {
    let mut buf = Vec::new();
    stdin().read_to_end(&mut buf).unwrap();
    cert.merge_from_bytes(&buf).unwrap();
    return cert
}

fn print_cert(cert: &capbac::proto::Certificate) {
    let mut payload = capbac::proto::Certificate_Payload::new();
    payload.merge_from_bytes(cert.get_payload()).unwrap();
    println!("-- SIGNATURE   : {:?}", base64::encode(cert.get_signature()));
    println!("-- PAYLOAD     : {:?}", base64::encode(cert.get_payload()));
    println!("--- capability : {:?}", base64::encode(payload.get_capability()));
    println!("--- issuer     : {:?}", payload.get_issuer());
    println!("--- subject    : {:?}", payload.get_subject());
    if payload.get_expiration() > 0 {
        println!("--- exp        : {:?}", payload.get_expiration());
    }
    if payload.has_parent() {
        print_cert(payload.get_parent());
    }
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

#[derive(StructOpt, Debug)]
struct PubsArgs {
    #[structopt(long = "pub", parse(try_from_str = parse_id_pair))]
    pubs: Vec<(Url, EcKey<Public>)>,
}

impl capbac::Pubs for PubsArgs {
    fn get(&self, id: &Url) -> Option<&EcKey<Public>> {
        self.pubs.iter().find(|(x, _)| x.eq(id)).map(|(_, x)| x)
    }
}

fn main() {
    use CapBACApp::*;
    let opt = CapBACApp::from_args();
    match opt {
        Forge { holder, cert } => {
            let cert = capbac::Holder::new(holder.me, &holder.sk)
                .forge(cert.into())
                .unwrap();
            stdout().write(&cert.write_to_bytes().unwrap()).unwrap();
        }
        Delegate { holder, cert } => {
            let mut parent_cert = capbac::proto::Certificate::new();
            read_cert(&mut parent_cert);
            let cert = capbac::Holder::new(holder.me, &holder.sk)
                .delegate(parent_cert, cert.into())
                .unwrap();
            stdout().write(&cert.write_to_bytes().unwrap()).unwrap();
        }
        Invoke { holder, invoke } => {

        }
        Invocation { } => {}
        InvocationValidate { validate, pubs } => {

        }
        Certificate { } => {
            let mut cert = capbac::proto::Certificate::new();
            read_cert(&mut cert);
            print_cert(&cert);
        }
        CertificateValidate { validate, pubs } => {
            let mut cert = capbac::proto::Certificate::new();
            read_cert(&mut cert);
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
