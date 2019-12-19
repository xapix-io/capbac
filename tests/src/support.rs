use std::path::Path;
use url::Url;
use duct;
use std::rc::Rc;

struct Impl {
    cmd: String,
    args: Vec<String>
}

impl Impl {
    fn cmd(&self, stdin: Option<Rc<Container>>, args: &[&str], stdout: Option<Rc<Container>>) -> Cmd {
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
    sk_mapping: String,
}

impl Actor {
    fn new(name: &str) -> Actor {
        let id = format!("http://{}.local", name);
        let sk_path = format!("./keys/{}.pem", name);
        let pk_path = format!("./keys/{}.pem", name);
        let sk_mapping = format!("{}={}", id, sk_path);
        Actor {
            name: name.to_string(),
            id,
            sk_path,
            pk_path,
            sk_mapping
        }
    }

    fn holder_args<'a>(&'a self) -> Vec<&'a str> {
        vec!["--me", &self.id, "--sk", &self.sk_mapping]
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
        let args = self.args.join(" ");

        let mut cmd = String::new();

        if let Some(ref c) = self.stdin {
            cmd += &c.name;
            cmd += " > "
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

pub struct Ctx {
    commands: Vec<Cmd>,
    container_counter: u32,
    now: u64,
}

//impl CtxState {
//    fn now(&self) -> u64 {
//        self.now
//    }
//
//    fn advance_time(&mut self, time: u64) {
//        self.now += time;
//    }
//}

impl Ctx {
    pub fn forge<'a>(&mut self, target: &'a ActorImpl, capability: &str, subject: &'a ActorImpl, exp: Option<u64>) -> Rc<Container> {
        let cert = self.new_container("cert");
        let mut exp_arg;
        let mut args= vec!["forge", "--capability", capability, "--subject", &subject.actor.id];
        if let Some(exp) = exp {
            exp_arg = exp.to_string();
            args.push("--exp");
            args.push(&exp_arg)
        }

        for arg in target.actor.holder_args() {
            args.push(arg);
        }
        self.commands.push(target.implementation.cmd(
            None,
            &args,
            Some(cert.clone())));
        cert
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

pub fn run(suite: &[fn(&mut Ctx, &System)]) {
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
            commands: vec![],
            container_counter: 0,
            now: 0
        };
        case(&mut ctx, &system);

        ctx.run();
    }
}