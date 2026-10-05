{
  description = "Buck2 probe toolchain: same nixpkgs pin and Rust toolchain as the round-2 tools, plus buck2";
  inputs.nixpkgs.url = "https://api.flakehub.com/f/pinned/DeterminateSystems/nixpkgs-weekly/0.1.1077143%2Brev-44a91898084f46797b5fac650c7e8c9ac38c43d4/01a0ebad-51ce-7451-8dd8-3e80d608beae/source.tar.gz";
  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      cli = with pkgs; [ rustc cargo stdenv.cc bash coreutils findutils gnugrep gnused gnutar gzip xz bzip2 unzip time git cacert curl python3 buck2 binutils gnumake cmake pkg-config rsync procps ];
      env = pkgs.writeShellScriptBin "buck-env" ''
        export PATH=${pkgs.lib.makeBinPath cli}
        export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
        exec "$@"
      '';
      tools = pkgs.buildEnv { name = "buck2-probe-tools"; paths = [ env ] ++ cli; ignoreCollisions = true; };
    in { packages.${system}.tools = tools; };
}
