{
  description = "Explain the effective status of automated Nix maintenance";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        rec {
          nix-maintenance-status = pkgs.rustPlatform.buildRustPackage {
            pname = "nix-maintenance-status";
            version = "0.1.0";
            src = pkgs.lib.cleanSource ./.;
            cargoLock.lockFile = ./Cargo.lock;

            meta = {
              description = "Explain the effective status of automated Nix maintenance";
              homepage = "https://github.com/Anionix/nix-maintenance-status";
              license = pkgs.lib.licenses.mit;
              mainProgram = "nix-maintenance-status";
              platforms = pkgs.lib.platforms.darwin;
            };
          };

          default = nix-maintenance-status;
        }
      );

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) nix-maintenance-status;
      });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nix-maintenance-status";
          meta.description = "Explain the effective status of automated Nix maintenance";
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              clippy
              rustc
              rustfmt
            ];
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
