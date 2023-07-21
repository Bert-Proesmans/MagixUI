{
  description = "Command line interface (CLI) binaries for non-kosher shenanigans.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    inputs.nci = {
        url = "github:yusdacra/nix-cargo-integration";
        inputs.nixpkgs.follows = "nixpkgs";
    };
    inputs.flake-parts = {
        url = "github:hercules-ci/flake-parts";
        inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    flake-parts,
    nci,
    ...
  }:
    parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux"];
      imports = [nci.flakeModule];
      perSystem = {
        pkgs,
        config,
        ...
      }: let
        crateName = "magixui";
        # shorthand for accessing this crate's outputs
        # you can access crate outputs under `config.nci.outputs.<crate name>` (see documentation)
        crateOutputs = config.nci.outputs.${crateName};
      in {
        # declare projects
        # relPath is the relative path of a project to the flake root
        nci.projects.${crateName}.relPath = ".";
        # configure crates
        nci.crates.${crateName} = {
          # export crate (packages and devshell) in flake outputs
          # alternatively you can access the outputs and export them yourself (see below)
          export = true;
          depsOverrides.set-target = {
            # set cargo target to WINDOWS so it compiles correctly
            CARGO_BUILD_TARGET = "x86_64-pc-windows-msvc";
          };
          # compile in release profile, and skip tests
          profiles = {
            release = {
              runTests = false;
              };
          };
        };
        # export the crate devshell as the default devshell
        devShells.default = crateOutputs.devShell;
        # export the release package of the crate as default package
        packages.default = crateOutputs.packages.release;
      };
    };
}