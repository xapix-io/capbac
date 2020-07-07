mod support;
use crate::support::*;

fn basic_cert_validation(ctx: Ctx) -> Ctx {
    let service = &ctx.system.service;
    let alice = &ctx.system.alice;
    let (ctx, cert) = ctx.service().forge("everything", alice, None).ok();
    ctx.service()
        .cert_validate(&cert, vec![&service])
        .ok()
        .alice()
        .cert_validate(&cert, vec![&service])
        .ok()
}

fn no_pub_cert_validation(ctx: Ctx) -> Ctx {
    let alice = &ctx.system.alice;
    let (ctx, cert) = ctx.service().forge("everything", alice, None).ok();
    ctx.service().cert_validate(&cert, vec![]).doit(12)
}

fn wrong_cert_sign(ctx: Ctx) -> Ctx {
    let alice = &ctx.system.alice;
    let bad_alice = &ctx.system.bad_alice;
    let (ctx, cert) = ctx.alice().forge("everything", alice, None).ok();
    ctx.alice()
        .cert_validate(&cert, vec![&alice])
        .ok()
        .alice()
        .cert_validate(&cert, vec![&bad_alice])
        .doit(15)
}

fn cert_delegate_validation(ctx: Ctx) -> Ctx {
    let service = &ctx.system.service;
    let alice = &ctx.system.alice;
    let (ctx, cert) = ctx.service().forge("everything", service, None).ok();
    let (ctx, cert) = ctx.service().delegate(&cert, "not everything", alice, None).ok();
    ctx.alice()
        .cert_validate(&cert, vec![&service])
        .ok()
        .alice()
        .cert_validate(&cert, vec![])
        .doit(12)
}

fn broken_chain(ctx: Ctx) -> Ctx {
    let service = &ctx.system.service;
    let alice = &ctx.system.alice;
    let bob = &ctx.system.bob;
    let (ctx, cert) = ctx.service().forge("everything", service, None).ok();
    let (ctx, cert) = ctx.service().delegate(&cert, "not everything", alice, None).ok();
    let (ctx, cert) = ctx.bob().delegate(&cert, "everything", bob, None).ok();
    ctx.bob()
        .cert_validate(&cert, vec![&service, &alice])
        .doit(13)
}

fn main() {
    let suite: Suite = &[
        basic_cert_validation,
        no_pub_cert_validation,
        wrong_cert_sign,
        cert_delegate_validation,
        broken_chain
    ];
    run(suite)
}
