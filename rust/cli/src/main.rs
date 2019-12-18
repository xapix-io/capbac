use std::error::Error;
use std::path::{PathBuf, Path};
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
    Ok((s[..pos].parse()?, PublicKey { unparsed: key } ))
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
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &read_file(&path)?).unwrap();
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
    unparsed: UnparsedPublicKey <Vec<u8>>
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

use capbac::{Holder, CapBAC, Keypairs};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, UnparsedPublicKey, KeyPair};
use ring::error::KeyRejected;
use std::fmt::{Debug, Formatter};
use core::fmt;
use ring::rand::SystemRandom;

impl Keypairs for HolderArgs {
    fn get(&self, id: &Url) -> Option<&EcdsaKeyPair> {

        if (self.me.eq(id)) {
            return Some(&self.sk);
        } else {
            return None;
        }
    }
}

fn main() {
    use CapBACApp::*;
    let opt = CapBACApp::from_args();
    println!("{:#?}", opt);
    match opt {
        Forge {
            holder,
            cert,
            resolver,
        } => {
            let (id, key) = resolver.id.get(0).unwrap();
            let message = "hoho".as_bytes();
            let sign = holder.sk.sign(&SystemRandom::new(), message).unwrap();

            let keyFromSK = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, holder.sk.public_key().as_ref());
            println!("Res: {:#?}", keyFromSK.verify(message, sign.as_ref()).unwrap());
            println!("Res: {:#?}", key.unparsed.verify(message, sign.as_ref()).unwrap());

//            let capbac = CapBAC::new(holder.into(), resolver.into());
//            let holder = Holder::new(holder.me, capbac);

        }
    }
}
