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
      linuxSystem = "x86_64-linux";
      expectedNixpkgsRevision = "6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee";
      expectedSystemdVersion = "261";
      expectedSystemdSourceHash = "sha256-6IB1ZEQqQ0impwBhCaLZAEgMVkVFU61JDVlGotxNzGQ=";
      expectedNixpkgsPatches = [
        "0001-Don-t-try-to-unmount-nix-or-nix-store.patch"
        "0002-Change-usr-share-zoneinfo-to-etc-zoneinfo.patch"
        "0003-add-rootprefix-to-lookup-dir-paths.patch"
        "0004-path-util.h-add-placeholder-for-DEFAULT_PATH_NORMAL.patch"
        "0005-core-don-t-taint-on-unmerged-usr.patch"
        "0006-timesyncd-disable-NSCD-when-DNSSEC-validation-is-dis.patch"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      linuxPkgs = import nixpkgs { system = linuxSystem; };
      actualNixpkgsPatches = map (patch: builtins.baseNameOf (toString patch)) linuxPkgs.systemd.patches;
      systemdVmProbe = linuxPkgs.rustPlatform.buildRustPackage {
        pname = "nix-maintenance-status-systemd-vm-probe";
        version = "0.1.0";
        src = linuxPkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [
          "--bin"
          "nix-maintenance-status-systemd-vm-probe"
          "--features"
          "systemd-vm-probe"
        ];
        installPhase = ''
          mkdir -p $out/bin
          cp target/${linuxPkgs.stdenv.hostPlatform.rust.rustcTarget}/release/nix-maintenance-status-systemd-vm-probe $out/bin/
        '';
      };
      nixosTest = variant:
        linuxPkgs.testers.runNixOSTest (import ./tests/nixos/systemd-gc.nix {
          inherit variant expectedNixpkgsRevision expectedSystemdVersion;
          inherit expectedSystemdSourceHash expectedNixpkgsPatches;
          probePackage = systemdVmProbe;
        });
    in
    assert (nixpkgs.rev or null) == expectedNixpkgsRevision;
    assert linuxPkgs.systemd.version == expectedSystemdVersion;
    assert linuxPkgs.systemd.src.outputHash == expectedSystemdSourceHash;
    assert actualNixpkgsPatches == expectedNixpkgsPatches;
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

      checks = (forAllSystems (system: {
        inherit (self.packages.${system}) nix-maintenance-status;
      })) // {
        ${linuxSystem} = {
          nixos-systemd-official = nixosTest "official";
          nixos-systemd-boundaries = nixosTest "boundaries";
        };
      };

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
