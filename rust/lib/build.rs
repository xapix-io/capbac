use protoc_rust;
use protoc_rust::Customize;

fn main() {
    protoc_rust::Codegen::new()
        .out_dir("src/proto")
        .inputs(&["src/proto/capbac.proto"])
        .includes(&["src/proto"])
        .customize(Customize {
            // serde_derive: Some(true),
            // generate_accessors: Some(true),
            ..Default::default()
        })
        .run().unwrap();
}
