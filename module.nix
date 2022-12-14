classified: { config, pkgs, ... }:

let
  cfg = config.classified;
  enabled = assert cfg.files != { } -> cfg.keys != { }; cfg.files != { };
  ifEnabled = alt: x: if enabled then x else alt;
  jsonConfig = builtins.toFile "classified.json" (builtins.toJSON cfg);

in
{
  options.classified = with pkgs.lib; {
    targetDir = mkOption {
      type = types.path;
      default = "/var/secrets";
      description = "Directory where tmpfs with decrypted secrets will be created";
    };
    keys = mkOption {
      type = types.attrsOf types.path;
      description = ''
        Where to find encryption keys (generated with `classified gen-key`).

        These files should belong to root:root and have permissions 400 or 600.
      '';
      default = { };
    };
    files = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          key = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              Name of the encryption key to use (as specified in `keys`).

              It's allowed to be null if there's exactly one key configured.
            '';
          };
          encrypted = mkOption {
            type = types.path;
            description = ''
              Path to the encrypted file
            '';
          };
          mode = mkOption {
            type = types.either types.ints.u32 types.str;
            default = "400";
            description = ''
              Mode of the decrypted file as an integer.

              Nix doesn't support octal literals, so you can also specify it as a string, e. g. "0400".
            '';
          };
          user = mkOption {
            type = types.either types.ints.u32 types.str;
            description = ''
              UID or name of the decrypted file owner
            '';
            default = "root";
          };
          group = mkOption {
            type = types.either types.ints.u32 types.str;
            description = ''
              GID or name of the decrypted file group
            '';
            default = "root";
          };
        };
      });
      default = { };
      description = ''
        Files to decrypt. The key is a name of the decrypted file in target-dir '';
    };
  };

  config = {
    environment.systemPackages = [ classified ];
    systemd.services.classified = ifEnabled { } {
      wantedBy = [ "basic.target" ];
      restartTriggers = [ jsonConfig ];
      serviceConfig.Type = "notify";
      script = ''
        ${classified}/bin/classified batch ${jsonConfig}
        ${pkgs.systemd}/bin/systemd-notify --ready
        ${pkgs.coreutils}/bin/sleep inf
      '';
    };
    systemd.mounts = ifEnabled [ ] [{
      what = "tmpfs";
      type = "tmpfs";
      where = cfg.targetDir;
      requiredBy = [ "classified.service" ];
      before = [ "classified.service" ];
      partOf = [ "classified.service" ];
    }];
  };
}
