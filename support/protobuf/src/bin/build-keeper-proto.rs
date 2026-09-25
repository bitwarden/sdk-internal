use std::env;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <proto_dir> <out_dir>", args[0]);
        eprintln!("Example: {} proto/keeper src/importers/keeper/proto", args[0]);
        std::process::exit(1);
    }

    let proto_dir = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);

    if !proto_dir.exists() {
        eprintln!("Error: Proto directory does not exist: {}", proto_dir.display());
        std::process::exit(1);
    }

    // Ensure output directory exists
    std::fs::create_dir_all(&out_dir).expect("Failed to create output directory");

    // Configure prost to generate Rust types from proto files.
    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(
            &[
                proto_dir.join("api-request.proto"),
                proto_dir.join("breachwatch.proto"),
                proto_dir.join("client.proto"),
                proto_dir.join("enterprise.proto"),
                proto_dir.join("graph-sync.proto"),
                proto_dir.join("notification-center.proto"),
                proto_dir.join("push.proto"),
                proto_dir.join("record.proto"),
                proto_dir.join("ssocloud.proto"),
                proto_dir.join("sync-down.proto"),
            ],
            &[proto_dir],
        )
        .expect("Failed to compile protobufs");
}
