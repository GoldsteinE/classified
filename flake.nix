{
  inputs = {
    nixpkgs.url      = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
    naersk.url       = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, naersk }:
    flake-utils.lib.eachDefaultSystem (system:
      let 
        packageName = "classified";
        pkgs = import nixpkgs {
          inherit system;
        };
        naersk-lib = naersk.lib."${system}";
      in rec {
        packages.${packageName} = naersk-lib.buildPackage {
          pname = "${packageName}";
          root = ./.;
          postInstall = ''
            mkdir -p $out/share/{bash-completion/completions,zsh/site-functions,fish/vendor_completions.d}
            $out/bin/classified completions bash > $out/share/bash-completion/completions/classified.bash
            $out/bin/classified completions zsh > $out/share/zsh/site-functions/_classified
            $out/bin/classified completions fish > $out/share/fish/vendor_completions.d/classified.fish
          '';
        };
        defaultPackage = packages.${packageName};

        apps.${packageName} = packages.${packageName};
        defaultApp = apps.${packageName};

        nixosModules.default = import ./module.nix defaultApp;

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer
          ];
        };
      }
    );
}
