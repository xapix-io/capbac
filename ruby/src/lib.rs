#[macro_use] extern crate ruru;
#[macro_use] extern crate lazy_static;

use ruru::{Class, RString, Object, AnyObject, Array, Fixnum, Hash, Symbol, VM, Boolean, GC, VerifiedObject};
use capbac::{CertificateBlueprint};
use url::Url;
use openssl::pkey::{PKey, Public};
use openssl::ec::EcKey;
use protobuf::{Message};
use std::fmt;

class!(URI);

impl VerifiedObject for URI {
    fn is_correct_type<T: Object>(object: &T) -> bool {
        object.class().ancestors().iter()
            .any(|class| *class == Class::from_existing("URI"))
    }

    fn error_message() -> &'static str {
        "Error converting to URI"
    }
}

impl fmt::Display for URI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self.send("to_s", vec![]).try_convert_to::<RString>().unwrap().to_string();
        write!(f, "{}", s)
    }
}

impl From<&Url> for URI {
    fn from(url: &Url) -> Self {
        Class::from_existing("URI").send("parse", vec![RString::new(&url.clone().to_string()).to_any_object()]).try_convert_to::<URI>().unwrap()
    }
}

impl From<URI> for Url {
    fn from(uri: URI) -> Self {
        Url::parse(&uri.to_string()).unwrap()
    }
}

wrappable_struct!(capbac::Holder, HolderWrapper, HOLDER_WRAPPER);

class!(Holder);

methods!(
    Holder,
    itself,

    fn ruby_holder_new(me: URI, sk: Array) -> AnyObject {
        if let Err(ref error) = me {
            VM::raise(error.to_exception(), &error.to_string());
        }

        if let Err(ref error) = sk {
            VM::raise(error.to_exception(), &error.to_string());
        }

        let me = Url::parse(&me.unwrap().to_string());

        if let Err(ref error) = me {
            VM::raise(Class::from_existing("ArgumentError"), &error.to_string())
        }

        let mut sk_content: Vec<u8> = Vec::new();
        for n in sk.unwrap().into_iter() {
            let n = n.try_convert_to::<Fixnum>();

            if let Err(ref error) = n {
                VM::raise(error.to_exception(), &error.to_string());
            }

            sk_content.push(n.unwrap().to_i64() as u8);
        }

        let holder = capbac::Holder::new(me.unwrap(), PKey::private_key_from_pkcs8(&sk_content).unwrap().ec_key().unwrap());

        Class::from_existing("CapBAC")
            .get_nested_class("Holder")
            .wrap_data(holder, &*HOLDER_WRAPPER)
    }

    fn ruby_holder_forge(options: Hash) -> Array {
        // TODO check everything before unwrap!
        let options = options.unwrap();
        let subject = Url::from(
            options
                .at(Symbol::new("subject"))
                .try_convert_to::<URI>()
                .unwrap()
        );
        let capability = options
            .at(Symbol::new("capability"))
            .try_convert_to::<RString>()
            .unwrap().to_string()
            .into_bytes();

        let exp = match options.at(Symbol::new("exp")).try_convert_to::<Fixnum>() {
            Ok(x) => Some(x.to_i64() as u64),
            _ => None
        };

        let options = CertificateBlueprint {
            subject,
            capability,
            exp
        };

        let holder = itself.get_data(&*HOLDER_WRAPPER);
        let cert = holder.forge(options).unwrap();

        let mut res = Array::new();
        for item in cert.write_to_bytes().unwrap().iter() {
            res.push(Fixnum::new(i64::from(*item)));
        };
        res
    }

    fn ruby_holder_delegate(cert: Array, options: Hash) -> Array {
        Array::new()
    }

    fn ruby_holder_invoke(options: Hash) -> Array {
        Array::new()
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
            pubs
        }
    }
}

impl capbac::TrustChecker for IntValidator {
    fn is_trusted(&self, id: &Url) -> bool {
        let args = vec![URI::from(id).to_any_object()];
        self.trust_checker
            .send("trusted?", args)
            .try_convert_to::<Boolean>()
            .unwrap()
            .to_bool()
    }
}

impl capbac::Pubs for IntValidator {
    fn get(&self, id: &Url) -> Option<EcKey<Public>> {
        let res = self.pubs.send("get", vec![URI::from(id).to_any_object()]);
        let ok_res = res.try_convert_to::<Array>().unwrap();
        let mut pk_content: Vec<u8> = Vec::new();
        for n in ok_res.into_iter() {
            let n = n.try_convert_to::<Fixnum>();

            if let Err(ref error) = n {
                VM::raise(error.to_exception(), &error.to_string());
            }

            pk_content.push(n.unwrap().to_i64() as u8);
        }
        Some(PKey::public_key_from_der(&pk_content).unwrap().ec_key().unwrap())
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

    // TODO define exception classes!
    // TODO rethrow exception!
    fn ruby_validator_validate_cert(cert: Array, now: Fixnum) -> Boolean {
        if let Err(ref error) = cert {
            VM::raise(error.to_exception(), &error.to_string());
        }

        if let Err(ref error) = now {
            VM::raise(error.to_exception(), &error.to_string());
        }

        let mut cert_content: Vec<u8> = Vec::new();
        for n in cert.unwrap().into_iter() {
            let n = n.try_convert_to::<Fixnum>();

            if let Err(ref error) = n {
                VM::raise(error.to_exception(), &error.to_string());
            }

            cert_content.push(n.unwrap().to_i64() as u8);
        }
        let mut cert = capbac::proto::Certificate::new();
        cert.merge_from_bytes(&cert_content).unwrap();

        let now = now.unwrap().to_i64() as u64;

        let x = itself.get_data(&*INT_VALIDATOR_WRAPPER);
        let validator = capbac::Validator::new(x, x);

        match validator.validate_cert(&cert, now) {
            Result::Ok(_) => Boolean::new(true),
            Err(x) =>  {
                println!("{}", x);
                Boolean::new(false)
            }
        }
    }

    fn ruby_validator_validate_invocation(invocation: Array, now: Fixnum) -> Boolean {
        Boolean::new(false)
    }
);

#[no_mangle]
pub extern fn init_capbac() {
    Class::from_existing("CapBAC").define(|itself| {
        itself.define_nested_class("Holder", None).define(|itself| {
            itself.def_self("new", ruby_holder_new);
            itself.def("forge", ruby_holder_forge);
            itself.def("delegate", ruby_holder_delegate);
            itself.def("invoke", ruby_holder_invoke);
        });

        itself.define_nested_class("Validator", None).define(|itself| {
            itself.def_self("new", ruby_validator_new);
            itself.def("validate_cert", ruby_validator_validate_cert);
            itself.def("validate_invocation", ruby_validator_validate_invocation);
        });
    });
}
