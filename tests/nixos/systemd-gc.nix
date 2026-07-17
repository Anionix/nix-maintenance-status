{ variant
, expectedNixpkgsRevision
, expectedSystemdVersion
, expectedSystemdSourceHash
, expectedNixpkgsPatches
, probePackage
, ...
}:
{ lib, pkgs, ... }:
let
  official = variant == "official";
  futureDate = "2099-01-01 00:00:00 UTC";
in
{
  name = "nix-maintenance-status-systemd-${variant}";
  requiredFeatures.kvm = false;

  # This is a fixture-conformance VM, not the Linux CLI. The Rust transport's
  # malformed-reply and changed-during-read cases remain pure tests because
  # systemd v261 exposes no read-generation property. No authority is inferred
  # from Manager.Version or from these guest observations.
  nodes.machine = { ... }:
    {
      assertions = [
        {
          assertion = pkgs.systemd.version == expectedSystemdVersion;
          message = "the VM must use the pinned systemd ${expectedSystemdVersion}";
        }
      ];
      system.stateVersion = "25.11";
      virtualisation.restrictNetwork = true;
      virtualisation.forwardPorts = [ ];
      virtualisation.writableStore = false;
      virtualisation.qemu.forceAccel = false;

      environment.systemPackages = with pkgs; [
        coreutils
        gnugrep
        systemd
        probePackage
      ];
      environment.etc."nix-maintenance-status/pins".text = ''
        nixpkgs=${expectedNixpkgsRevision}
        systemd=${expectedSystemdVersion}
        systemd-source=${expectedSystemdSourceHash}
        nixpkgs-patches=${lib.concatStringsSep "," expectedNixpkgsPatches}
      '';

      users.users.alice = {
        uid = 1000;
        isNormalUser = true;
        linger = true;
      };
      users.users.bob = {
        uid = 1001;
        isNormalUser = true;
        linger = false;
      };

      # Keep the generated wrapper present without enabling the timer. The VM
      # never starts nix-gc.service and never invokes garbage collection.
      nix.gc = {
        automatic = false;
        dates = futureDate;
        options = "--delete-old";
      };

      systemd.services.nix-gc = if official then { } else {
        script = lib.mkForce "exec ${pkgs.coreutils}/bin/true";
      };
      systemd.timers.nix-gc = if official then {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = futureDate;
          Persistent = false;
        };
      } else {
        wantedBy = [ "timers.target" ];
        timerConfig.OnCalendar = futureDate;
      };
    };

  nodes.noJob = { ... }:
    {
      system.stateVersion = "25.11";
      virtualisation.restrictNetwork = true;
      virtualisation.forwardPorts = [ ];
      virtualisation.writableStore = false;
      virtualisation.qemu.forceAccel = false;
      environment.systemPackages = [ probePackage ];
    };

  nodes.unloaded = { ... }:
    {
      system.stateVersion = "25.11";
      virtualisation.restrictNetwork = true;
      virtualisation.forwardPorts = [ ];
      virtualisation.writableStore = false;
      virtualisation.qemu.forceAccel = false;
      environment.systemPackages = [ probePackage ];
      systemd.services.nix-gc.script = "exec ${pkgs.coreutils}/bin/true";
      systemd.timers.nix-gc.timerConfig.OnCalendar = futureDate;
    };

  testScript = if official then ''
    machine.wait_for_unit("nix-gc.timer")
    machine.succeed("test \"$(systemctl is-enabled nix-gc.timer)\" = enabled")
    machine.succeed("test \"$(systemctl is-active nix-gc.service)\" = inactive")
    machine.succeed("systemctl show nix-gc.service -p ExecStart | grep -F '/nix/store/'")
    machine.succeed("systemctl cat nix-gc.service | grep -F 'unit-script-nix-gc-start'")
    machine.succeed("wrapper=$(systemctl show nix-gc.service -p ExecStart | sed -n 's/.*path=\\([^; ]*\\).*/\\1/p'); test -x \"$wrapper\"; grep -F 'nix-collect-garbage' \"$wrapper\"")
    machine.succeed("systemctl --version | grep -F 'systemd ${expectedSystemdVersion}'")
    machine.succeed("grep -Fx 'nixpkgs=${expectedNixpkgsRevision}' /etc/nix-maintenance-status/pins")
    machine.succeed("grep -Fx 'systemd-source=${expectedSystemdSourceHash}' /etc/nix-maintenance-status/pins")
    machine.succeed("grep -Fx 'nixpkgs-patches=${lib.concatStringsSep "," expectedNixpkgsPatches}' /etc/nix-maintenance-status/pins")
    machine.succeed("test -S /run/dbus/system_bus_socket")
    machine.wait_for_unit("user@1000.service")
    machine.succeed("test -S /run/user/1000/bus")
    machine.succeed("runuser -u alice -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user --no-pager list-unit-files")
    machine.succeed("nix-maintenance-status-systemd-vm-probe --system | grep -Fx 'scope=system command=present observations=4'")
    machine.succeed("runuser -u alice -- env UID=1000 nix-maintenance-status-systemd-vm-probe --current-user | grep -Fx 'scope=current-user command=not-applicable observations=3'")
    machine.fail("test -S /run/user/1001/bus")
    machine.succeed("test \"$(systemctl show nix-gc.service -p ActiveState --value)\" = inactive")
  '' else ''
    machine.wait_for_unit("nix-gc.timer")
    machine.succeed("test \"$(systemctl show nix-gc.timer -p LoadState --value)\" = loaded")
    machine.wait_for_unit("user@1000.service")
    machine.succeed("test -S /run/user/1000/bus")
    machine.succeed("wrapper=$(systemctl show nix-gc.service -p ExecStart | sed -n 's/.*path=\\([^; ]*\\).*/\\1/p'); test -x \"$wrapper\"; grep -F '/bin/true' \"$wrapper\"")
    machine.succeed("test \"$(systemctl show nix-gc.service -p ActiveState --value)\" = inactive")
    machine.succeed("systemctl show nix-gc.timer -p LoadState --value | grep -Fx loaded")
    machine.succeed("runuser -u alice -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user --no-pager list-unit-files")
    machine.succeed("nix-maintenance-status-systemd-vm-probe --system | grep -Fx 'scope=system command=unknown observations=4'")
    machine.succeed("runuser -u alice -- env UID=1000 nix-maintenance-status-systemd-vm-probe --current-user | grep -Fx 'scope=current-user command=not-applicable observations=3'")
    machine.fail("test -S /run/user/1001/bus")
    machine.fail("systemctl --user --machine=bob@ list-units nix-gc.timer")
    machine.succeed("test -S /run/dbus/system_bus_socket")
    noJob.fail("systemctl show nix-gc.timer")
    noJob.succeed("nix-maintenance-status-systemd-vm-probe --system | grep -Fx 'scope=system command=unknown observations=4'")
    unloaded.succeed("systemctl list-unit-files --no-legend nix-gc.timer | grep -F nix-gc.timer")
    unloaded.fail("systemctl list-units --all --no-legend nix-gc.timer | grep -F nix-gc.timer")
    unloaded.succeed("nix-maintenance-status-systemd-vm-probe --system | grep -Fx 'scope=system command=unknown observations=4'")
  '';
}
