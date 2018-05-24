{ mkDerivation, aeson, base, base64-bytestring, bytestring
, cryptonite, entropy, HUnit, stdenv, time
}:
mkDerivation {
  pname = "auth";
  version = "0.1.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base base64-bytestring bytestring cryptonite entropy time
  ];
  testHaskellDepends = [
    aeson base bytestring cryptonite HUnit time
  ];
  license = stdenv.lib.licenses.bsd3;
}
