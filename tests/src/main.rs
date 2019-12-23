mod support;
use crate::support::*;

fn basic_cert_validation(ctx: Ctx) -> Ctx {
    let service = &ctx.system.service;
    let alice = &ctx.system.alice;
    let (ctx, cert) = ctx.service().forge("everything", alice, None).ok();
    ctx.service().cert_validate(&cert, vec![&service]).ok().
        alice().cert_validate(&cert, vec![&service]).ok()
}

fn no_pub_cert_validation(ctx: Ctx) -> Ctx {
    let service = &ctx.system.service;
    let alice = &ctx.system.alice;
    let (ctx, cert) = ctx.service().forge("everything", alice, None).ok();
    ctx.service().cert_validate(&cert, vec![]).doit(12)
}

fn wrong_cert_sign(ctx: Ctx) -> Ctx {
    let alice = &ctx.system.alice;
    let bad_alice = &ctx.system.bad_alice;
    let (ctx, cert) = ctx.alice().forge("everything", alice, None).ok();
    ctx.alice().cert_validate(&cert, vec![&alice]).ok().
        alice().cert_validate(&cert, vec![&bad_alice]).doit(15)
}

fn main() {
    let suite: &[fn(Ctx) -> Ctx] = &[
//        basic_cert_validation,
//        no_pub_cert_validation,
        wrong_cert_sign
    ];
    run(suite)
}

//struct A {}
//
//struct B<'a> {
//    a: &'a A
//}
//
//struct C<'a> {
//    b: B<'a>
//}
//
//impl <'a> B<'a> {
//    fn foo(self) -> C<'a> {
//        C { b: self }
//    }
//
//    fn bar(self) {
//
//    }
//}
//
//
//fn main() {
//    let a = A {
//    };
//
//    {
//        let mut b = B { a: &a };
//
//        let b = b.foo().b;
//        b.bar();
//    }
//
//
//}