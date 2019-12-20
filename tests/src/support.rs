use std::path::Path;
use url::Url;
use duct;
use std::rc::Rc;
use itertools::Itertools;

struct Impl {
    cmd: String,
    args: Vec<String>
}

impl Impl {
    fn cmd(&self, stdin: Option<Rc<Container>>, args: &[&str], stdout: Option<Rc<Container>>, expected_exit_code: u32) -> Cmd {
        let mut cmd_args = self.args.clone();
        for arg in args {
            cmd_args.push(arg.to_string());
        }
        Cmd {
            stdin: stdin,
            stdout: stdout,
            cmd: self.cmd.clone(),
            args: cmd_args
        }
    }
}

pub struct ActorImpl<'a> {
    actor: &'a Actor,
    implementation: &'a Impl,
}

pub struct Actor {
    name: String,
    id: String,
    sk_path: String,
    pk_path: String,
    pk_mapping: String,
}

impl Actor {
    fn new(name: &str) -> Actor {
        let id = format!("http://{}.local", name);
        let sk_path = format!("./keys/{}.pem", name);
        let pk_path = format!("./keys/{}-pub.pem", name);
        let pk_mapping = format!("{}={}", id, pk_path);
        Actor {
            name: name.to_string(),
            id,
            sk_path,
            pk_path,
            pk_mapping
        }
    }
}

pub struct Container {
    name: String
}

struct Cmd {
    stdin: Option<Rc<Container>>,
    stdout: Option<Rc<Container>>,
    cmd: String,
    args: Vec<String>
}

impl Cmd {
    fn as_shell(&self) -> String {
        let args = self.args.iter().map(|x|  format!("'{}'", x)).join(" ");

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
}

pub struct System<'a> {
    pub alice: ActorImpl<'a>,
    pub bob: ActorImpl<'a>,
    pub service: ActorImpl<'a>,
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
    with_holder_args: bool
}

impl <'a> ForgeBlueprint<'a> {
    fn without_holder_args(self) -> Self {
        Self { with_holder_args: false, ..self }
    }

    pub fn ok(self) -> (Ctx<'a>, Rc<Container>) {
        let mut args= vec!["forge", "--capability", self.capability, "--subject", &self.subject.actor.id];
        let mut exp_arg;

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
            None,
            &args,
            Some(cert.clone()), 0));

        (ctx, cert)
    }
}

pub struct CertValidateBlueprint<'a> {
    target: TargetBlueprint<'a>,
    cert: Rc<Container>,
    trust_regex: String,
    pubs: Vec<&'a ActorImpl<'a>>
}

impl <'a> CertValidateBlueprint<'a> {
    pub fn doit(self, exit_code: u32) -> Ctx<'a> {
        let now = self.target.ctx.now.to_string();
        let mut args= vec!["certificate-validate", "--trust-ids", &self.trust_regex, "--now", &now];

        for pk in self.pubs {
            args.push("--pub");
            args.push(&pk.actor.pk_mapping);
        }

        let mut ctx = self.target.ctx;
        ctx.commands.push(self.target.actor.implementation.cmd(
            Some(self.cert),
            &args,
            None, 0));

        ctx
    }
    pub fn ok(self) -> Ctx<'a> {
        self.doit(0)
    }
}

pub struct TargetBlueprint<'a> {
    ctx: Ctx<'a>,
    actor: &'a ActorImpl<'a>
}

impl <'a> TargetBlueprint<'a> {
    pub fn forge(self, capability: &'a str, subject: &'a ActorImpl, exp: Option<u64>) -> ForgeBlueprint<'a> {
        ForgeBlueprint {
            target: self,
            capability,
            subject,
            with_holder_args: true,
            exp
        }
    }
    pub fn cert_validate(self, cert: &Rc<Container>, pubs: Vec<&'a ActorImpl>) -> CertValidateBlueprint<'a> {
        CertValidateBlueprint {
            target: self,
            cert: cert.clone(),
            trust_regex: ".*".to_string(),
            pubs: pubs
        }
    }
}

impl<'a> Ctx<'a> {
    pub fn service(self) -> TargetBlueprint<'a> {
        let actor = &self.system.service;
        TargetBlueprint {
            ctx: self,
            actor
        }
    }

    fn new_container(&mut self, prefix: &str) -> Rc<Container> {
        self.container_counter += 1;
        Rc::new(Container {
            name: format!("{}{}", prefix, self.container_counter)
        })
    }

    fn run(&self) {
        for command in &self.commands {
            println!("{}", command.as_shell())
        }
    }
}

pub fn run(suite: &[fn(Ctx) -> Ctx]) {
    let java = Impl {
        cmd: "java".to_string(),
        args: vec!["-jar".to_string(), "../java/cli/target/capbac-cli-1.0-SNAPSHOT.jar".to_string()]
    };
    let service_actor = Actor::new("service");
    let alice_actor = Actor::new("alice");
    let bob_actor = Actor::new("bob");
    let service = ActorImpl {
        actor: &service_actor,
        implementation: &java
    };
    let alice = ActorImpl {
        actor: &alice_actor,
        implementation: &java
    };
    let bob = ActorImpl {
        actor: &bob_actor,
        implementation: &java
    };

    let system = System {
        service, alice, bob
    };

    for case in suite {
        let mut ctx = Ctx {
            system: &system,
            commands: vec![],
            container_counter: 0,
            now: 0
        };

        let ctx = case(ctx);
        ctx.run();
    }
}