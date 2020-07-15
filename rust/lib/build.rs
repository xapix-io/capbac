use protoc_rust::Customize;

fn main() {
    protoc_rust::Codegen::new()
        .out_dir("src/proto")
        .inputs(&["src/proto/capbac.proto"])
        .includes(&["src/proto"])
        .customize(Customize {
            ..Default::default()
        })
        .run()
        .unwrap();
}
