
{
  description = "sdk-internal";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };
  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystemTypes = fn: nixpkgs.lib.genAttrs supportedSystems fn;
  in {
    devShells = forAllSystemTypes (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      default = pkgs.mkShell {
        inputsFrom = with self.devShells.${system}; [
          building
        ];
      };
      building = let
        runBuild = (pkgs.writeScriptBin "run-build" ''
          cargo build
        '');
        runTests = (pkgs.writeScriptBin "run-tests" ''
          cargo test
        '');
      in
      pkgs.mkShell {
        buildInputs = [
          pkgs.rustup
          pkgs.cargo
        ];
        packages = [
          runBuild
          runTests
        ];
        shellHook = ''
          rustup default nightly
        '';
      };
    });
  };
}


