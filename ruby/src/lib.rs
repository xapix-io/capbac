#[macro_use] extern crate ruru;
#[macro_use] extern crate lazy_static;

use ruru::{Class, RString, Object, AnyObject, Array, Fixnum, Hash, Symbol, VM, Boolean, NilClass};
use capbac::{CertificateBlueprint};
use url::Url;
use openssl::pkey::{PKey, Private, Public};
use openssl::ec::EcKey;
use protobuf::{Message};

pub struct RustHolder {
    me: Url,
    sk_content: Vec<u8>
}

impl RustHolder {
    fn new(me: Url, sk_content: Vec<u8>) -> Self {
        RustHolder {
            me,
            sk_content
        }
    }
}

wrappable_struct!(RustHolder, RustHolderWrapper, RUST_HOLDER_WRAPPER);

class!(Holder);

methods!(
    Holder,
    itself,

    fn ruby_holder_new(me: RString, sk: Array) -> AnyObject {
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

        let rust_holder = RustHolder::new(me.unwrap(), sk_content);

        Class::from_existing("CapBAC")
            .get_nested_class("Holder")
            .wrap_data(rust_holder, &*RUST_HOLDER_WRAPPER)
    }

    fn ruby_holder_forge(options: Hash) -> Array {
        // TODO check everything before unwrap!
        let options = options.unwrap();
        let subject = Url::parse(
            &options
                .at(Symbol::new("subject"))
                .try_convert_to::<RString>()
                .unwrap().to_string()
        ).unwrap();
        let mut capability: Vec<u8> = Vec::new();
        for n in options.at(Symbol::new("capability")).try_convert_to::<Array>().unwrap().into_iter() {
            capability.push(n.try_convert_to::<Fixnum>().unwrap().to_i64() as u8);
        }

        let exp = match options.at(Symbol::new("exp")).try_convert_to::<Fixnum>() {
            Ok(x) => Some(x.to_i64() as u64),
            _ => None
        };

        let options = CertificateBlueprint {
            subject,
            capability,
            exp
        };

        let sk_content = &itself.get_data(&*RUST_HOLDER_WRAPPER).sk_content;
        let me = itself.get_data(&*RUST_HOLDER_WRAPPER).me.clone();
        let sk: EcKey<Private> = PKey::private_key_from_pkcs8(&sk_content).unwrap().ec_key().unwrap();
        let holder = capbac::Holder::new(me, &sk);
        let cert = holder.forge(options).unwrap();

        let mut res = Array::new();
        for item in cert.write_to_bytes().unwrap().iter() {
            res.push(Fixnum::new(i64::from(*item)));
        };
        res
    }

    // fn delegate(options: Hash) -> Array {
    //     Array::new()
    // }
);

pub struct RustTrustChecker {
    trust_checker: AnyObject
}

impl capbac::TrustChecker for RustTrustChecker {
    fn is_trusted(&self, id: &Url) -> bool {
        self.trust_checker
            .send("is_trusted", vec![RString::new(&id.clone().to_string()).to_any_object()])
            .try_convert_to::<Boolean>()
            .unwrap()
            .to_bool()
    }
}

pub struct RustPubs {
    pubs: AnyObject
}

impl capbac::Pubs for RustPubs {
    fn get(&self, id: &Url) -> Option<&EcKey<Public>> {
        // let res = self.pubs.send("get", vec![RString::new(&id.clone().to_string()).to_any_object()]);
        // let ok_res = res.try_convert_to::<Array>();

        // if let Err(ref _error) = ok_res {
        //     None
        // } else {
        //     let ok_res = ok_res.unwrap();
        //     let mut pk_content: Vec<u8> = Vec::new();
        //     for n in ok_res.into_iter() {
        //         let n = n.try_convert_to::<Fixnum>();

        //         if let Err(ref error) = n {
        //             VM::raise(error.to_exception(), &error.to_string());
        //         }

        //         pk_content.push(n.unwrap().to_i64() as u8);
        //     }
        //     Some(&PKey::public_key_from_der(&[1,2,3]).unwrap().ec_key().unwrap())
        // }
        None
    }
}

pub struct RustValidator {
    trust_checker: RustTrustChecker,
    pubs: AnyObject
}

impl RustValidator {
    fn new(trust_checker: RustTrustChecker, pubs: AnyObject) -> Self {
        RustValidator {
            trust_checker,
            pubs
        }
    }

    fn validate_cert() {

    }
}

wrappable_struct!(RustValidator, RustValidatorWrapper, RUST_VALIDATOR_WRAPPER);

class!(Validator);

methods!(
    Validator,
    itself,

    fn ruby_validator_new(trust_checker: AnyObject, pubs: AnyObject) -> AnyObject {
        let rust_validator = RustValidator::new(
            RustTrustChecker {
                trust_checker: trust_checker.unwrap()
            },
            pubs.unwrap()
        );

        Class::from_existing("CapBAC")
            .get_nested_class("Validator")
            .wrap_data(rust_validator, &*RUST_VALIDATOR_WRAPPER)
    }
);

#[no_mangle]
pub extern fn init_capbac() {
    Class::new("CapBAC", None).define(|itself| {
        itself.define_nested_class("Holder", None).define(|itself| {
            itself.def_self("new", ruby_holder_new);
            itself.def("forge", ruby_holder_forge);
        });

        itself.define_nested_class("Validator", None).define(|itself| {
            itself.def_self("new", ruby_validator_new);
            // itself.def("validate_cert", ruby_validator_validate_cert);
        });
    });
}
