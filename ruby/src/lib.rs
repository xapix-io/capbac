#[macro_use] extern crate ruru;
#[macro_use] extern crate lazy_static;

use ruru::{Class, RString, Object, AnyObject, Array, Fixnum, Hash, Symbol};
use capbac::{Holder, CertificateBlueprint};
use url::Url;
use openssl::ec::EcKey;
use openssl::pkey::{Private, PKey};
use base64;
use protobuf::{Message};
use std::convert;

// class!(Greeter);

// methods!(
//     Greeter,
//     itself,

//     fn anonymous_greeting() -> RString {
//         RString::new("Hello stranger!")
//     }

//     fn friendly_greeting(name: RString) -> RString {
//         let name = name
//             .map(|name| name.to_string())
//             .unwrap_or("Anonymous".to_string());

//         let greeting = format!("Hello dear {}!", name);

//         RString::new(&greeting)
//     }
// );

wrappable_struct!(Holder<'static>, HolderWrapper, HOLDER_WRAPPER);

class!(RubyHolder);

methods!(
    RubyHolder,
    itself,

    fn ruby_holder_new(me: RString, sk: Array) -> AnyObject {
        let me = Url::parse(&me.unwrap().to_string()).unwrap();
        let mut sk_content: Vec<u8> = Vec::new();
        for item in sk.unwrap().into_iter() {
            sk_content.push(item.try_convert_to::<Fixnum>().unwrap().to_i64() as u8);
        }
        let sk = PKey::private_key_from_pkcs8(&sk_content).unwrap().ec_key().unwrap();
        let holder = Holder::new(me, &sk);
        Class::from_existing("RubyHolder").wrap_data(holder, &*HOLDER_WRAPPER)
    }

    fn ruby_holder_forge(options: Hash) -> Array {
        let options = options.unwrap();
        let holder = itself.get_data(&*HOLDER_WRAPPER);
        let subject = options.at(Symbol::new("subject")).try_convert_to::<RString>().unwrap().to_string();
        let capability = options.at(Symbol::new("capability")).try_convert_to::<Array>().unwrap();
        let mut capability_content = Vec::new();
        for item in capability.into_iter() {
            capability_content.push(item.try_convert_to::<Fixnum>().unwrap().to_i64() as u8);
        }
        let exp = options.at(Symbol::new("exp")).try_convert_to::<Fixnum>().unwrap().to_i64() as u64;

        println!("subject: {}, capability: {:?}, exp: {}", subject, &capability_content, exp);

        let options = CertificateBlueprint {
            subject: Url::parse(&subject).unwrap(),
            capability: capability_content,
            exp: Some(exp)
        };

        let cert = holder.forge(options).unwrap();
        let mut res = Array::new();
        for item in cert.write_to_bytes().unwrap().iter() {
            res.push(Fixnum::new(i64::from(*item)));
        };
        res
    }
);

#[no_mangle]
pub extern fn init_greater() {
    // Class::new("Greeter", None).define(|itself| {
    //     itself.def("anonymous_greeting", anonymous_greeting);
    //     itself.def("friendly_greeting", friendly_greeting);
    // });
    Class::new("RubyHolder", None).define(|itself| {
        itself.def_self("new", ruby_holder_new);

        itself.def("forge", ruby_holder_forge);
    });
}
