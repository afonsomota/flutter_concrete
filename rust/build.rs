fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/concrete-protocol.capnp")
        .run()
        .expect("capnp schema compilation failed");
}
