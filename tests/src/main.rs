use std::fs::File;
mod support;
use crate::support::*;

fn service_to_alice_forge(ctx: &mut Ctx, System { alice, bob, service }: &System) {
    ctx.forge(&service, "everything", &alice, None);
}

fn main() {
    let suite: &[fn(&mut Ctx, &System)] = &[
        service_to_alice_forge
    ];
    run(suite)
}
