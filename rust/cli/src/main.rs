use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::PKey;
use std::error::Error;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use url::Url;

fn parse_id_pair(s: &str) -> Result<(Url, PublicKey), Box<dyn Error>>
where
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    let path: PathBuf = s[pos + 1..].parse()?;
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, read_file(&path)?);
    Ok((s[..pos].parse()?, PublicKey { unparsed: key }))
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, Box<dyn Error>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

fn parse_priv_key(s: &str) -> Result<EcdsaKeyPair, Box<dyn Error>> {
    let path: PathBuf = s.parse()?;
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &read_file(&path)?).unwrap();
    Ok(key)
}

#[derive(StructOpt, Debug)]
enum CapBACApp {
    Forge {
        #[structopt(flatten)]
        holder: HolderArgs,
        #[structopt(flatten)]
        cert: CertArgs,
        #[structopt(flatten)]
        resolver: ResolverArgs,
    },
}

#[derive(StructOpt, Debug)]
struct HolderArgs {
    #[structopt(long)]
    me: Url,
    #[structopt(long, parse(try_from_str = parse_priv_key))]
    sk: EcdsaKeyPair,
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

struct PublicKey {
    unparsed: UnparsedPublicKey<Vec<u8>>,
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "<pub-key>")
    }
}

#[derive(StructOpt, Debug)]
struct ResolverArgs {
    #[structopt(long, parse(try_from_str = parse_id_pair))]
    id: Vec<(Url, PublicKey)>,
}

use capbac::{CapBAC, Holder, Keypairs};
use core::fmt;
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};
use ring::error::KeyRejected;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};
use std::fmt::{Debug, Formatter};

impl Keypairs for HolderArgs {
    fn get(&self, id: &Url) -> Option<&EcdsaKeyPair> {
        if (self.me.eq(id)) {
            return Some(&self.sk);
        } else {
            return None;
        }
    }
}

fn read_sk() -> EcKey<Private> {
    let path = Path::new("./key-me.pem");
    let content = &read_file(&path).unwrap();
    EcKey::private_key_from_pem(&content).unwrap()
}

fn read_pk() -> EcKey<Public> {
    let path = Path::new("./key-me-pub.pem");
    let pemContent = &read_file(&path).unwrap();

    let pk = PKey::public_key_from_pem(pemContent).unwrap();
    pk.ec_key().unwrap()

    //    let public_key: Vec<u8> = vec![];
    //    let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    //    let mut ctx = BigNumContext::new().unwrap();
    //    let point = EcPoint::from_bytes(&group, &public_key, &mut ctx).unwrap();
    //    EcKey::from_public_key(&group, &point).unwrap()
}

fn main() {
    let sk = read_sk();
    let pk = read_pk();

    sk.check_key().unwrap();
    pk.check_key().unwrap();
    let msg = "hello!".as_bytes();
    let sign = EcdsaSig::sign(&msg, &sk).unwrap().to_der().unwrap();
    println!("{:?}", sign);

    let res = EcdsaSig::from_der(&sign)
        .unwrap()
        .verify(&msg, &pk)
        .unwrap();
    println!("{}", res)

    //    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pem.contents).unwrap();
    //    use CapBACApp::*;
    //    let opt = CapBACApp::from_args();
    //    println!("{:#?}", opt);
    //    match opt {
    //        Forge {
    //            holder,
    //            cert,
    //            resolver,
    //        } => {
    //            let (id, key) = resolver.id.get(0).unwrap();
    //            let message = "hoho".as_bytes();
    //            let sign = holder.sk.sign(&SystemRandom::new(), message).unwrap();
    //
    //            let keyFromSK = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, holder.sk.public_key().as_ref());
    //            println!("Res: {:#?}", keyFromSK.verify(message, sign.as_ref()).unwrap());
    //            println!("Res: {:#?}", key.unparsed.verify(message, sign.as_ref()).unwrap());
    //
    ////            let capbac = CapBAC::new(holder.into(), resolver.into());
    ////            let holder = Holder::new(holder.me, capbac);
    //
    //        }
    //    }
}
