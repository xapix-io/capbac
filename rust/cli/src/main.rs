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

#[derive(StructOpt, Debug)]
enum CapBACApp {
    Forge {
        #[structopt(flatten)]
        holder: HolderArgs,
        #[structopt(flatten)]
        cert: CertArgs,
    },

    CertificateValidate {
        #[structopt(flatten)]
        pubs: PubsArgs,
        #[structopt(flatten)]
        validate: ValidateArgs,
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
            exp: self.exp,
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
        CertificateValidate { validate, pubs } => {
            let mut cert = capbac::proto::Certificate::new();
            let mut buf = Vec::new();
            stdin().read_to_end(&mut buf).unwrap();
            cert.merge_from_bytes(&buf).unwrap();
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

// fn read_sk() -> EcKey<Private> {
//     let path = Path::new("./key-me.pem");
//     let content = &read_file(&path).unwrap();
//     EcKey::private_key_from_pem(&content).unwrap()
// }

// fn read_pk() -> EcKey<Public> {
//     let path = Path::new("./key-me-pub.pem");
//     let pemContent = &read_file(&path).unwrap();

//     let pk = PKey::public_key_from_pem(pemContent).unwrap();
//     pk.ec_key().unwrap()
// }

// fn main() {
//     // let sk = read_sk();
//     // let pk = read_pk();

//     // sk.check_key().unwrap();
//     // pk.check_key().unwrap();
//     // let msg = "hello!".as_bytes();
//     // let sign = EcdsaSig::sign(&msg, &sk).unwrap().to_der().unwrap();
//     // println!("{:?}", sign);

//     // let res = EcdsaSig::from_der(&sign)
//     //     .unwrap()
//     //     .verify(&msg, &pk)
//     //     .unwrap();
//     // println!("{}", res)

//     //    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pem.contents).unwrap();
//     //    use CapBACApp::*;
//     //    let opt = CapBACApp::from_args();
//     //    println!("{:#?}", opt);
//     //    match opt {
//     //        Forge {
//     //            holder,
//     //            cert,
//     //            resolver,
//     //        } => {
//     //            let (id, key) = resolver.id.get(0).unwrap();
//     //            let message = "hoho".as_bytes();
//     //            let sign = holder.sk.sign(&SystemRandom::new(), message).unwrap();
//     //
//     //            let keyFromSK = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, holder.sk.public_key().as_ref());
//     //            println!("Res: {:#?}", keyFromSK.verify(message, sign.as_ref()).unwrap());
//     //            println!("Res: {:#?}", key.unparsed.verify(message, sign.as_ref()).unwrap());
//     //
//     ////            let capbac = CapBAC::new(holder.into(), resolver.into());
//     ////            let holder = Holder::new(holder.me, capbac);
//     //
//     //        }
//     //    }
// }
