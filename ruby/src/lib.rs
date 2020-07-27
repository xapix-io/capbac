#[macro_use]
extern crate rutie;
#[macro_use]
extern crate lazy_static;

use capbac::{CertificateBlueprint, InvokeBlueprint};
use openssl::{
    ec::EcKey,
    pkey::{PKey, Public},
};
use protobuf::Message;
use ring::{
    rand,
    signature::{self, EcdsaKeyPair, KeyPair},
};
use rutie::{
    AnyObject, Boolean, Class, Encoding, Fixnum, Hash, Module, Object, RString, Symbol,
    VerifiedObject, GC, VM, Array,
};
use std::{fmt, str};
use url::Url;

class!(ASCIIRString);

impl VerifiedObject for ASCIIRString {
    fn is_correct_type<T: Object>(object: &T) -> bool {
        object
            .class()
            .ancestors()
            .iter()
            .any(|class| *class == Class::from_existing("String"))
    }

    fn error_message() -> &'static str {
        "Error converting to ASCII String"
    }
}

impl From<ASCIIRString> for Vec<u8> {
    fn from(rstring: ASCIIRString) -> Self {
        let bytes = rstring
            .protect_send("bytes", &[])
            .map_err(VM::raise_ex)
            .unwrap()
            .try_convert_to::<Array>()
            .map_err(VM::raise_ex)
            .unwrap();

        let mut res = Vec::new();

        for n in bytes.into_iter() {
            let n = n.try_convert_to::<Fixnum>()
                .map_err(|e| VM::raise_ex(e))
                .unwrap();

            res.push(n.to_i64() as u8);
        }
        res
    }
}

class!(URI);

impl VerifiedObject for URI {
    fn is_correct_type<T: Object>(object: &T) -> bool {
        object
            .class()
            .ancestors()
            .iter()
            .any(|class| *class == Class::from_existing("URI"))
    }

    fn error_message() -> &'static str {
        "Error converting to URI"
    }
}

impl fmt::Display for URI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self
            .protect_send("to_s", &[])
            .map_err(VM::raise_ex)
            .unwrap()
            .try_convert_to::<RString>()
            .map_err(VM::raise_ex)
            .unwrap()
            .to_string();
        write!(f, "{}", s)
    }
}

impl From<&Url> for URI {
    fn from(url: &Url) -> Self {
        let args = [RString::new_utf8(&url.clone().to_string()).to_any_object()];
        Class::from_existing("URI")
            .protect_send("parse", &args)
            .map_err(VM::raise_ex)
            .unwrap()
            .try_convert_to::<URI>()
            .map_err(VM::raise_ex)
            .unwrap()
    }
}

impl From<URI> for Url {
    fn from(uri: URI) -> Self {
        Url::parse(&uri.to_string())
            .map_err(|_e| {
                VM::raise(
                    Class::from_existing("URI").get_nested_class("InvalidURIError"),
                    &format!("bad URI(is not URI?): {}", uri.to_string()),
                )
            })
            .unwrap()
    }
}

// TODO CertificateBlueprint -> Result<CertificateBlueprint, Error>
fn options_to_cert_blueprint(options: Hash) -> CertificateBlueprint {
    let subject = options
        .at(&Symbol::new("subject"))
        .try_convert_to::<URI>()
        .map_err(VM::raise_ex)
        .unwrap();

    let subject = Url::from(subject);

    let capability = options
        .at(&Symbol::new("capability"))
        .try_convert_to::<RString>()
        .map_err(VM::raise_ex)
        .unwrap()
        .to_string()
        .into_bytes();

    let exp = match options.at(&Symbol::new("exp")).try_convert_to::<Fixnum>() {
        Ok(x) => Some(x.to_i64() as u64),
        _ => None,
    };

    CertificateBlueprint {
        subject,
        capability,
        exp,
    }
}

fn options_to_invoke_blueprint(options: Hash) -> InvokeBlueprint {
    let cert_content = options
        .at(&Symbol::new("cert"))
        .try_convert_to::<ASCIIRString>()
        .map_err(VM::raise_ex)
        .unwrap();

    let mut cert = capbac::proto::Certificate::new();
    cert.merge_from_bytes(&Vec::from(cert_content)).unwrap();

    let action = options
        .at(&Symbol::new("action"))
        .try_convert_to::<RString>()
        .map_err(VM::raise_ex)
        .unwrap()
        .to_string()
        .into_bytes();

    let exp = match options.at(&Symbol::new("exp")).try_convert_to::<Fixnum>() {
        Ok(x) => Some(x.to_i64() as u64),
        _ => None,
    };

    InvokeBlueprint { cert, action, exp }
}

wrappable_struct!(capbac::Holder, HolderWrapper, HOLDER_WRAPPER);

class!(Holder);

methods!(
    Holder,
    itself,

    fn ruby_holder_new(me: URI, sk: RString) -> AnyObject {
        let ruby_me = me.map_err(VM::raise_ex).unwrap().to_string();

        let ruby_sk = sk
            .map_err(VM::raise_ex)
            .unwrap()
            .to_string_unchecked();

        let me = Url::parse(&ruby_me)
            .map_err(|e| VM::raise(Class::from_existing("ArgumentError"), &e.to_string()))
            .unwrap();
        let sk = PKey::private_key_from_pkcs8(&ruby_sk.as_bytes())
            .map_err(|e| {
                VM::raise(
                    Class::from_existing("ArgumentError"),
                    &format!("Wrong secret key formar (not pkcs8?) ({})", e.to_string()),
                )
            })
            .unwrap()
            .ec_key()
            .map_err(|e| {
                VM::raise(
                    Class::from_existing("ArgumentError"),
                    &format!("Can't extract EC key ({})", e.to_string()),
                )
            })
            .unwrap();

        let holder = capbac::Holder::new(me, sk);

        Class::from_existing("CapBAC")
            .get_nested_class("Holder")
            .wrap_data(holder, &*HOLDER_WRAPPER)
    }

    fn ruby_holder_forge(options: Hash) -> RString {
        let ruby_options = options.map_err(VM::raise_ex).unwrap();
        let options = options_to_cert_blueprint(ruby_options);
        let holder = itself.get_data(&*HOLDER_WRAPPER);

        let cert = holder.forge(options).unwrap();

        RString::from_bytes(&cert.write_to_bytes().unwrap(), &Encoding::us_ascii())
    }

    fn ruby_holder_delegate(cert: ASCIIRString, options: Hash) -> RString {
        let ruby_options = options.map_err(VM::raise_ex).unwrap();
        let options = options_to_cert_blueprint(ruby_options);
        let holder = itself.get_data(&*HOLDER_WRAPPER);

        let cert_content = Vec::from(cert.map_err(VM::raise_ex).unwrap());

        let mut cert = capbac::proto::Certificate::new();
        cert.merge_from_bytes(&cert_content).unwrap();

        let cert = holder.delegate(cert, options).unwrap();

        RString::from_bytes(&cert.write_to_bytes().unwrap(), &Encoding::us_ascii())
    }

    fn ruby_holder_invoke(options: Hash) -> RString {
        let ruby_options = options.map_err(VM::raise_ex).unwrap();
        let options = options_to_invoke_blueprint(ruby_options);
        let holder = itself.get_data(&*HOLDER_WRAPPER);

        let invocation = holder.invoke(options).unwrap();

        RString::from_bytes(&invocation.write_to_bytes().unwrap(), &Encoding::us_ascii())
    }
);

pub struct IntValidator {
    trust_checker: AnyObject,
    pubs: AnyObject,
}

impl IntValidator {
    fn new(trust_checker: AnyObject, pubs: AnyObject) -> Self {
        IntValidator {
            trust_checker,
            pubs,
        }
    }
}

impl capbac::TrustChecker for IntValidator {
    fn is_trusted(&self, id: &Url) -> bool {
        let args = vec![URI::from(id).to_any_object()];
        self.trust_checker
            .protect_send("trusted?", &args)
            .map_err(VM::raise_ex)
            .unwrap()
            .try_convert_to::<Boolean>()
            .unwrap_or_else(|_| Boolean::new(false))
            .to_bool()
    }
}

impl capbac::Pubs for IntValidator {
    fn get(&self, id: &Url) -> Option<EcKey<Public>> {
        let args = [URI::from(id).to_any_object()];
        let res = self
            .pubs
            .protect_send("get", &args)
            .map_err(VM::raise_ex)
            .unwrap()
            .try_convert_to::<RString>();

        match res {
            Ok(pk) => {
                Some(
                    PKey::public_key_from_der(&pk.to_string_unchecked().as_bytes())
                        .unwrap()
                        .ec_key()
                        .unwrap(),
                )
            }
            Err(_) => None
        }
    }
}

wrappable_struct!(IntValidator, IntValidatorWrapper, INT_VALIDATOR_WRAPPER, mark(data) {
    GC::mark(&data.trust_checker);
    GC::mark(&data.pubs);
});

class!(Validator);

methods!(
    Validator,
    itself,

    fn ruby_validator_new(trust_checker: AnyObject, pubs: AnyObject) -> AnyObject {
        let validator = IntValidator::new(trust_checker.unwrap(), pubs.unwrap());

        Class::from_existing("CapBAC")
            .get_nested_class("Validator")
            .wrap_data(validator, &*INT_VALIDATOR_WRAPPER)
    }

    fn ruby_validator_validate_cert(cert: RString, now: Fixnum) -> Boolean {
        let ruby_cert = cert
            .map_err(VM::raise_ex)
            .unwrap()
            .to_string_unchecked();

        let mut cert = capbac::proto::Certificate::new();
        cert.merge_from_bytes(&ruby_cert.as_bytes()).unwrap();

        let now = now.map_err(VM::raise_ex).unwrap().to_i64() as u64;

        let x = itself.get_data(&*INT_VALIDATOR_WRAPPER);
        let validator = capbac::Validator::new(x, x);

        match validator.validate_cert(&cert, now) {
            Result::Ok(_) => Boolean::new(true),
            Err(x) => {
                let capbac_class = Class::from_existing("CapBAC");
                match x {
                    capbac::ValidateError::Malformed { .. } => VM::raise(
                        capbac_class.get_nested_class("Malformed"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::BadURL { .. } => {
                        VM::raise(capbac_class.get_nested_class("BadURL"), &format!("{}", x))
                    }
                    capbac::ValidateError::UnknownPub { .. } => VM::raise(
                        capbac_class.get_nested_class("UnknownPub"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::BadIssuer { .. } => VM::raise(
                        capbac_class.get_nested_class("BadIssuer"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::BadInvoker { .. } => VM::raise(
                        capbac_class.get_nested_class("BadInvoker"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::Untrusted { .. } => VM::raise(
                        capbac_class.get_nested_class("Untrusted"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::Expired => {
                        VM::raise(capbac_class.get_nested_class("Expired"), &format!("{}", x))
                    }
                    capbac::ValidateError::BadSign => {
                        VM::raise(capbac_class.get_nested_class("BadSign"), &format!("{}", x))
                    }
                }
                Boolean::new(false)
            }
        }
    }

    fn ruby_validator_validate_invocation(invocation: RString, now: Fixnum) -> Boolean {
        let ruby_invocation = invocation
            .map_err(VM::raise_ex)
            .unwrap()
            .to_string_unchecked();

        let mut invocation = capbac::proto::Invocation::new();
        invocation
            .merge_from_bytes(&ruby_invocation.as_bytes())
            .unwrap();

        let now = now.map_err(VM::raise_ex).unwrap().to_i64() as u64;

        let x = itself.get_data(&*INT_VALIDATOR_WRAPPER);
        let validator = capbac::Validator::new(x, x);

        match validator.validate_invocation(&invocation, now) {
            Result::Ok(_) => Boolean::new(true),
            Err(x) => {
                let capbac_class = Class::from_existing("CapBAC");
                match x {
                    capbac::ValidateError::Malformed { .. } => VM::raise(
                        capbac_class.get_nested_class("Malformed"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::BadURL { .. } => {
                        VM::raise(capbac_class.get_nested_class("BadURL"), &format!("{}", x))
                    }
                    capbac::ValidateError::UnknownPub { .. } => VM::raise(
                        capbac_class.get_nested_class("UnknownPub"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::BadIssuer { .. } => VM::raise(
                        capbac_class.get_nested_class("BadIssuer"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::BadInvoker { .. } => VM::raise(
                        capbac_class.get_nested_class("BadInvoker"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::Untrusted { .. } => VM::raise(
                        capbac_class.get_nested_class("Untrusted"),
                        &format!("{}", x),
                    ),
                    capbac::ValidateError::Expired => {
                        VM::raise(capbac_class.get_nested_class("Expired"), &format!("{}", x))
                    }
                    capbac::ValidateError::BadSign => {
                        VM::raise(capbac_class.get_nested_class("BadSign"), &format!("{}", x))
                    }
                }
                Boolean::new(false)
            }
        }
    }
);

class!(KeyGen);

methods!(
    KeyGen,
    itself,

    fn ruby_generate_keypair() -> Hash {
        let rng = rand::SystemRandom::new();

        let key_pair =
            EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();
        let sk = key_pair.as_ref();

        let key_pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &key_pair.as_ref(),
        )
        .unwrap();
        let pk = key_pair.public_key().as_ref();

        let mut res = Hash::new();
        res.store(
            Symbol::new("sk"),
            RString::from_bytes(&sk, &Encoding::us_ascii()),
        );
        res.store(
            Symbol::new("pk"),
            RString::from_bytes(&pk, &Encoding::us_ascii()),
        );
        res
    }
);

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Init_capbac() {
    Module::from_existing("CapBAC").define(|itself| {
        itself.define_nested_class("Holder", None).define(|itself| {
            itself.def_self("new", ruby_holder_new);
            itself.def("forge", ruby_holder_forge);
            itself.def("delegate", ruby_holder_delegate);
            itself.def("invoke", ruby_holder_invoke);
        });

        itself
            .define_nested_class("Validator", None)
            .define(|itself| {
                itself.def_self("new", ruby_validator_new);
                itself.def("validate_cert", ruby_validator_validate_cert);
                itself.def("validate_invocation", ruby_validator_validate_invocation);
            });

        itself
            .define_nested_class("KeyPair", None)
            .define(|itself| {
                itself.def("generate!", ruby_generate_keypair);
            });
    });
}
