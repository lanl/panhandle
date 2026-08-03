use aya_build::{Package, Toolchain::Nightly};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let features = ["all"];
    let ebpf_package = Package {
        name: "panhandle-ebpf",
        root_dir: "../",
        no_default_features: false,
        features: &features[1..1],
    };

    Ok(aya_build::build_ebpf([ebpf_package], Nightly)?)
}
