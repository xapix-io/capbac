use ansi_term::Colour::{Green, Red};
use duct;
use itertools::Itertools;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

struct Impl {
    cmd: String,
    args: Vec<String>,
}

impl Impl {
    fn cmd(
        &self,
        stdin: Option<Rc<Container>>,
        args: &[&str],
        stdout: Option<Rc<Container>>,
        expected_exit_code: i32,
    ) -> Cmd {
        let mut cmd_args = self.args.clone();
        for arg in args {
            cmd_args.push(arg.to_string());
        }
        Cmd {
            stdin: stdin,
            stdout: stdout,
            cmd: self.cmd.clone(),
            args: cmd_args,
            expected_exit_code,
        }
    }
}

pub struct ActorImpl<'a> {
    actor: &'a Actor,
    implementation: &'a Impl,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub name: String,
    pub id: String,
    pub sk_path: String,
    pub pk_path: String,
    pub pk_mapping: String,
}

impl Actor {
    fn new(name: &str) -> Actor {
        let id = format!("http://{}.local/", name);
        let sk_path = format!("./keys/{}.pem", name);
        let pk_path = format!("./keys/{}-pub.pem", name);
        let pk_mapping = format!("{}={}", id, pk_path);
        Actor {
            name: name.to_string(),
            id,
            sk_path,
            pk_path,
            pk_mapping,
        }
    }

    fn bad_new(name: &str, pk_path: &str) -> Actor {
        let id = format!("http://{}.local/", name);
        let sk_path = format!("./keys/{}.pem", name);
        let pk_mapping = format!("{}={}", id, pk_path);
        Actor {
            name: name.to_string(),
            id,
            sk_path,
            pk_path: pk_path.to_string(),
            pk_mapping,
        }
    }
}

#[derive(Debug)]
pub struct Container {
    name: String,
}

#[derive(Debug)]
struct Cmd {
    stdin: Option<Rc<Container>>,
    stdout: Option<Rc<Container>>,
    cmd: String,
    args: Vec<String>,
    expected_exit_code: i32,
}

#[derive(Debug, Snafu)]
enum CmdError<'a> {
    #[snafu(display("Error while executing {}: {}", command.as_shell(), source))]
    ExecError { command: &'a Cmd, source: io::Error },
    #[snafu(display("Unexpected exit code for command {}. {} was expected, actual is {}", command.as_shell(), expected, actual))]
    UnexpectedExitCode {
        command: &'a Cmd,
        expected: i32,
        actual: i32,
    },
}

impl Cmd {
    fn as_shell(&self) -> String {
        let args = self.args.iter().map(|x| format!("'{}'", x)).join(" ");

        let mut cmd = String::new();

        if let Some(ref c) = self.stdin {
            cmd += "cat ";
            cmd += &c.name;
            cmd += " | "
        }

        cmd += &format!("{} {}", self.cmd, args);

        if let Some(ref c) = self.stdout {
            cmd += " > ";
            cmd += &c.name;
        }
        cmd
    }

    fn to_duct(&self, data: &HashMap<String, Vec<u8>>) -> duct::Expression {
        let mut cmd = duct::cmd(&self.cmd, &self.args).unchecked();

        if let Some(ref c) = self.stdin {
            cmd = cmd.stdin_bytes(data.get(&c.name).unwrap().clone());
        }
        cmd = cmd.stdout_capture();
        cmd = cmd.stderr_capture();

        return cmd;
    }

    fn exec(&self, data: &mut HashMap<String, Vec<u8>>) -> Result<(), CmdError> {
        let res = self
            .to_duct(data)
            .run()
            .context(ExecError { command: self })?;
        if let Some(ref c) = self.stdout {
            data.insert(c.name.clone(), res.stdout);
        }
        let code = res.status.code().unwrap();
        if code != self.expected_exit_code {
            Err(CmdError::UnexpectedExitCode {
                expected: self.expected_exit_code,
                actual: code,
                command: self,
            })
        } else {
            Ok(())
        }
    }
}

pub struct System<'a> {
    pub alice: ActorImpl<'a>,
    pub bob: ActorImpl<'a>,
    pub service: ActorImpl<'a>,
    pub bad_alice: ActorImpl<'a>,
}

pub struct Ctx<'a> {
    pub system: &'a System<'a>,
    commands: Vec<Cmd>,
    container_counter: u32,
    now: u64,
}

pub struct ForgeBlueprint<'a> {
    target: TargetBlueprint<'a>,
    capability: &'a str,
    subject: &'a ActorImpl<'a>,
    exp: Option<u64>,
    with_holder_args: bool,
}

impl<'a> ForgeBlueprint<'a> {
    // pub fn without_holder_args(self) -> Self {
    //     Self {
    //         with_holder_args: false,
    //         ..self
    //     }
    // }

    pub fn ok(self) -> (Ctx<'a>, Rc<Container>) {
        let mut args = vec![
            "forge",
            "--capability",
            self.capability,
            "--subject",
            &self.subject.actor.id,
        ];
        let exp_arg;

        if let Some(exp) = self.exp {
            exp_arg = exp.to_string();
            args.push("--exp");
            args.push(&exp_arg)
        }

        if self.with_holder_args {
            args.push("--me");
            args.push(&self.target.actor.actor.id);

            args.push("--sk");
            args.push(&self.target.actor.actor.sk_path)
        }

        let mut ctx = self.target.ctx;

        let cert = ctx.new_container("cert");
        ctx.commands.push(
            self.target
                .actor
                .implementation
                .cmd(None, &args, Some(cert.clone()), 0),
        );

        (ctx, cert)
    }
}

pub struct DelegateBlueprint<'a> {
    target: TargetBlueprint<'a>,
    cert: Rc<Container>,
    capability: &'a str,
    subject: &'a ActorImpl<'a>,
    exp: Option<u64>,
    with_holder_args: bool,
}

impl<'a> DelegateBlueprint<'a> {
    pub fn ok(self) -> (Ctx<'a>, Rc<Container>) {
        let mut args = vec![
            "delegate",
            "--capability",
            self.capability,
            "--subject",
            &self.subject.actor.id
        ];
        let exp_arg;
        if let Some(exp) = self.exp {
            exp_arg = exp.to_string();
            args.push("--exp");
            args.push(&exp_arg)
        }

        if self.with_holder_args {
            args.push("--me");
            args.push(&self.target.actor.actor.id);

            args.push("--sk");
            args.push(&self.target.actor.actor.sk_path)
        }

        let mut ctx = self.target.ctx;

        let cert = ctx.new_container("cert");
        ctx.commands.push(self.target.actor.implementation.cmd(
            Some(self.cert.clone()),
            &args,
            Some(cert.clone()),
            0));

        (ctx, cert)
    }
}

pub struct CertValidateBlueprint<'a> {
    target: TargetBlueprint<'a>,
    cert: Rc<Container>,
    trust_regex: String,
    pubs: Vec<&'a ActorImpl<'a>>,
}

impl<'a> CertValidateBlueprint<'a> {
    pub fn doit(self, exit_code: i32) -> Ctx<'a> {
        let now = self.target.ctx.now.to_string();
        let mut args = vec![
            "certificate-validate",
            "--trust-ids",
            &self.trust_regex,
            "--now",
            &now,
        ];

        for pk in self.pubs {
            args.push("--pub");
            args.push(&pk.actor.pk_mapping);
        }

        let mut ctx = self.target.ctx;
        ctx.commands.push(self.target.actor.implementation.cmd(
            Some(self.cert),
            &args,
            None,
            exit_code,
        ));

        ctx
    }
    pub fn ok(self) -> Ctx<'a> {
        self.doit(0)
    }
}

pub struct TargetBlueprint<'a> {
    ctx: Ctx<'a>,
    actor: &'a ActorImpl<'a>,
}

impl<'a> TargetBlueprint<'a> {
    pub fn forge(
        self,
        capability: &'a str,
        subject: &'a ActorImpl,
        exp: Option<u64>,
    ) -> ForgeBlueprint<'a> {
        ForgeBlueprint {
            target: self,
            capability,
            subject,
            with_holder_args: true,
            exp,
        }
    }
    pub fn delegate(
        self,
        cert: &Rc<Container>,
        capability: &'a str,
        subject: &'a ActorImpl,
        exp: Option<u64>
    ) -> DelegateBlueprint<'a> {
        DelegateBlueprint {
            target: self,
            cert: cert.clone(),
            capability,
            subject,
            with_holder_args: true,
            exp
        }
    }
    pub fn cert_validate(
        self,
        cert: &Rc<Container>,
        pubs: Vec<&'a ActorImpl>,
    ) -> CertValidateBlueprint<'a> {
        CertValidateBlueprint {
            target: self,
            cert: cert.clone(),
            trust_regex: ".*".to_string(),
            pubs: pubs,
        }
    }
}

impl<'a> Ctx<'a> {
    pub fn service(self) -> TargetBlueprint<'a> {
        let actor = &self.system.service;
        TargetBlueprint { ctx: self, actor }
    }

    pub fn alice(self) -> TargetBlueprint<'a> {
        let actor = &self.system.alice;
        TargetBlueprint { ctx: self, actor }
    }

    pub fn bob(self) -> TargetBlueprint<'a> {
        let actor = &self.system.bob;
        TargetBlueprint { ctx: self, actor }
    }

    // pub fn bad_alice(self) -> TargetBlueprint<'a> {
    //     let actor = &self.system.bad_alice;
    //     TargetBlueprint {ctx: self, actor}
    // }

    fn new_container(&mut self, prefix: &str) -> Rc<Container> {
        self.container_counter += 1;
        Rc::new(Container {
            name: format!("{}{}", prefix, self.container_counter),
        })
    }

    fn run(&self) -> Result<(), CmdError> {
        let mut data = HashMap::new();
        for command in &self.commands {
            println!("{}", command.as_shell());
            command.exec(&mut data)?
        }
        Ok(())
    }
}

pub type Suite<'a> = &'a [fn(Ctx) -> Ctx];

fn run_system(suite: &Suite, service_impl: &Impl, alice_impl: &Impl, bob_impl: &Impl) {
    let service_actor = Actor::new("service");
    let alice_actor = Actor::new("alice");
    let bob_actor = Actor::new("bob");
    let service = ActorImpl {
        actor: &service_actor,
        implementation: service_impl,
    };
    let alice = ActorImpl {
        actor: &alice_actor,
        implementation: alice_impl,
    };
    let bob = ActorImpl {
        actor: &bob_actor,
        implementation: bob_impl,
    };

    let bad_alice_actor = Actor::bad_new("alice", &bob_actor.pk_path);

    let system = System {
        service,
        alice,
        bob,
        bad_alice: ActorImpl {
            actor: &bad_alice_actor,
            implementation: alice_impl,
        },
    };

    for case in *suite {
        let ctx = Ctx {
            system: &system,
            commands: vec![],
            container_counter: 0,
            now: 0,
        };

        let ctx = case(ctx);
        match ctx.run() {
            Ok(()) => println!("[{}]", Green.paint("SUCESS")),
            Err(err) => println!("[{}]: {}", Red.paint("ERROR"), err),
        }
    }
}

pub fn run(suite: Suite) {
    let impls = [
        Impl {
            cmd: "java".to_string(),
            args: vec![
                "-jar".to_string(),
                "../java/cli/target/capbac-cli-1.0.jar".to_string(),
            ],
        },
        Impl {
            cmd: "../rust/target/debug/capbac-cli".to_string(),
            args: vec![],
        },
        Impl {
            cmd: "../ruby/exe/capbac-cli".to_string(),
            args: vec![],
        }
    ];

    for service_impl in &impls {
        for alice_impl in &impls {
            for bob_impl in &impls {
                run_system(&suite, service_impl, alice_impl, bob_impl)
            }
        }
    }
}
