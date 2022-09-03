# classified

A simpler NixOS secrets management system.

## Problem

There’re some secrets management systems for NixOS ([agenix], [sops-nix]), but they require kinda complicated setup. In many cases it’s enough to just decrypt all the secrets with root-readable key file present on disk (if someone has root access to your computer, you’re probably already royally fucked).

## Solution

Use a simple encryption program and put the config into a NixOS module. Just like this:

```nix
# flake.nix
{
  inputs = {
    classified = {
	  url = "github:GoldsteinE/classified";
	  # to avoid having one more copy of nixpkgs
	  inputs.nixpkgs.follows = "nixpkgs";
	  # you can also do this with naersk
	};
  };
  outputs = { nixpkgs, classified, ... }: {
    nixosConfigurations.your-hostname = nixpkgs.lib.nixosSystem rec {
	  system = "x86_64-linux";
      modules = [
	    # other modules here
		./configuration.nix
		classified.nixosModules."${system}".default
	  ];
	};
  };
}
```

and then

```nix
# configuration.nix
{
   classified = {
     # Default is `/var/secrets`
	 targetDir = "/var/classfied";
	 keys = {
	   first = "/path/to/first.key";
	   second = "/path/to/second.key";
	 };
	 files = {
	   top-secret = {
	     # You can omit the `key` attribute if you have exactly one key configured
	     key = "first";
		 encrypted = ./encrypted-file;
		 # Default is `400`
		 mode = "440";
		 # Defaults are `root:root`
		 user = "nginx";
		 group = "nogroup";
	   };
	 };
   };
}
```

### Generating keys and encrypting data

```shell
# (as root)
umask 377  # so the key file has the right permissions
classified gen-key > /path/to/key
cat /path/to/key  # key is just 24 words, so you can write it down
umask 022  # it's ok for encrypted data to be world-readable
classified encrypt --key /path/to/key /path/to/secret-data > /path/to/encrypted-data
# if you ever want to manually decrypt it
classified decrypt --key /path/to/key /path/to/encrypted-data
```

### What’s inside?

* `XChaCha20-Poly1305` which is proven secure. The nonce is chosen randomly for every encrypted file.

* A fresh `tmpfs` is created on every decryption, so old secrets are not available.

* No temporary files are written, no Rust unsafe code is used, and the codebase is small and easy to audit yourself.

* It attempts to zeroize any keys and decrypted files before deallocating memory.

### So it’s secure?

I mean...

* It didn’t pass any kind of professional security review.

* Zeroizing memory is hard and should be considered best-effort.

So (as with any cryptography project) — use at your own risk.

[agenix]: https://github.com/ryantm/agenix
[sops-nix]: https://github.com/Mic92/sops-nix
