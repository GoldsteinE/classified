{
  inputs = {
    nixpkgs.url      = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
    naersk.url       = "github:nix-community/naersk";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, naersk }:
    flake-utils.lib.eachDefaultSystem (system:
      let 
        packageName = "INSERT_NAME_HERE";

        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rust = (pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "cargo"
            "rustc"
            "rustfmt"
          ];
        });
        naersk-lib = naersk.lib."${system}".override {
          cargo = rust;
          rustc = rust;
        };
      in rec {
        packages.${packageName} = naersk-lib.buildPackage {
          pname = "${packageName}";
          root = ./.;
        };
        defaultPackage = packages.${packageName};

        apps.${packageName} = packages.${packageName};
        defaultApp = apps.${packageName};

        devShell = pkgs.mkShell {
          buildInputs = [
            rust
            pkgs.rust-analyzer
          ];
        };
      }
    );
}
