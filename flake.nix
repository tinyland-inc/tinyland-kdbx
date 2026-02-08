{
  description = "tinyland-kdbx: Native KeePassXC KDBX reader with base58 transport";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in {
      packages = forAllSystems (system:
        let pkgs = pkgsFor system;
        in {
          default = pkgs.python312.pkgs.buildPythonApplication {
            pname = "tinyland-kdbx";
            version = "0.1.0";
            pyproject = true;
            src = ./.;

            build-system = with pkgs.python312.pkgs; [
              setuptools
              wheel
            ];

            dependencies = with pkgs.python312.pkgs; [
              pykeepass
              pycryptodome
            ];

            nativeCheckInputs = with pkgs.python312.pkgs; [
              pytestCheckHook
            ];

            preCheck = ''
              export PYTHONDONTWRITEBYTECODE=1
            '';

            disabledTests = [
              "test_get_missing_database"
              "test_get_missing_password"
              "test_list_missing_database"
              "test_sudo_pipe_missing_database"
              "test_missing_env_exits"
              "test_missing_env_var_exits_3"
            ];

            pytestFlagsArray = [
              "tinyland_kdbx/tests/"
            ];

            pythonImportsCheck = [
              "tinyland_kdbx"
              "tinyland_kdbx.reader"
              "tinyland_kdbx.base58"
              "tinyland_kdbx.cli"
            ];

            meta = with pkgs.lib; {
              description = "Native KeePassXC KDBX reader with base58 transport for Tinyland infrastructure";
              license = licenses.mit;
              platforms = platforms.unix;
              mainProgram = "tinyland-kdbx";
            };
          };
        });

      overlays.default = final: prev: {
        tinyland-kdbx = self.packages.${final.system}.default;
      };
    };
}
