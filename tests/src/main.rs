use std::fs::File;
use std::rc::Rc;
mod support;
use crate::support::*;

fn service_self_validation(ctx: Ctx) -> Ctx {
    let service = &ctx.system.service;
    let alice = &ctx.system.alice;
    let (ctx, cert) = ctx.service().forge("everything", alice, None).ok();
    ctx.service().cert_validate(&cert, vec![&service]).ok()
}

fn main() {
    let suite: &[fn(Ctx) -> Ctx] = &[
        service_self_validation
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