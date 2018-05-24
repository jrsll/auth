{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc822" }:

let

  inherit (nixpkgs) pkgs;

  hpkgs = pkgs.haskell.packages.${compiler}.extend (
    self: super: {
      ghc =
        super.ghc // { withPackages = super.ghc.withHoogle; };
      ghcWithPackages =
        self.ghc.withPackages;
    }
  ); 

  drv = pkgs.haskell.lib.addBuildTool (
    hpkgs.callPackage (import ./default.nix) {}
  ) [ hpkgs.hlint
      hpkgs.stylish-haskell
      hpkgs.ghcid ];

in

  if pkgs.lib.inNixShell then drv.env else drv