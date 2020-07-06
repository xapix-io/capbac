extern crate protoc;
extern crate protoc_rust;

fn main() {
    protoc_rust::Codegen::new()
        .out_dir("src/proto")
        .inputs(&["src/proto/capbac.proto"])
        .includes(&["src/proto"])
        .run().unwrap();
}
