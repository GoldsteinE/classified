classified: { config, pkgs, lib, ... }:

let
  cfg = config.classified;
  enabled = assert cfg.files != { } -> cfg.keys != { }; cfg.files != { };
  ifEnabled = alt: x: if enabled then x else alt;
  jsonConfig = builtins.toFile "classified.json" (builtins.toJSON cfg);
  singleBefore = lib.concatLists (lib.mapAttrsToList (_: value: value.before) cfg.files);
  mkSystemdConfig = jsonCfg: beforeServices: {
    wantedBy = [ "basic.target" ];
    restartTriggers = [ jsonCfg ];
    serviceConfig.Type = "notify";
    before = beforeServices;
    script = ''
      ${classified}/bin/classified batch ${jsonCfg}
      ${pkgs.systemd}/bin/systemd-notify --ready
      ${pkgs.coreutils}/bin/sleep inf
    '';
  };
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
    multipleServices = mkOption {
      type = types.bool;
      default = false;
      description = "Whether classified should create a separate systemd service for each file";
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
          before = mkOption {
            type = types.listOf types.str;
            description = ''
              If the specified units are started at the same time as this unit, delay them until the file was created.
            '';
            default = [];
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

    systemd.services = if !enabled
      then { }
      else if !cfg.multipleServices
      then { classified = mkSystemdConfig jsonConfig singleBefore; }
      else
        let buildSingleFileService = file: fileConfig:
              let
                localCfg = cfg // {files = { "${file}" = fileConfig; }; };
                localJsonCfg = builtins.toFile "classified-${file}.json" (builtins.toJSON localCfg);
              in
                { "classified-${file}" = mkSystemdConfig localJsonCfg fileConfig.before; };
        in
          lib.concatMapAttrs buildSingleFileService cfg.files;

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
