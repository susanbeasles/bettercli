# shellcheck shell=bash
# The seal: a signed manifest that ships inside the bundle and is verified on every
# invocation.
#
# WHY THIS EXISTS
#
# A signed installer package proves the bytes were authentic in transit. It proves
# nothing afterwards: the signature is checked once by the installer and discarded,
# and what remains on disk is a directory of scripts with no cryptographic protection
# at all. Anyone who can write that directory owns the tool from then on.
#
# `cf integrity pin` does not fix that. The pin is trust-on-first-use, and it lives in
# the invoking user's own config directory — whoever can modify the bundle can re-pin
# it in the same breath.
#
# So a release carries three files that stay on disk:
#
#   lib/RELEASE.manifest       sha256 + mode + path for every file in the bundle
#   lib/RELEASE.manifest.asc   detached signature over that manifest
#   lib/RELEASE.pubkey.asc     the public key the signature must verify against
#
# and `cf` refuses to run a sealed bundle whose seal does not verify. Forging that
# requires the release private key, which is not on the machine.
#
# WHAT THIS CANNOT DO
#
# Self-verification cannot defend against someone who can rewrite the verifier. An
# attacker with write access to lib/core/seal.sh can delete the check. The seal makes
# every OTHER file tamper-evident and forces the attacker to modify the verifier
# specifically — which a root-owned 0755 install prevents for a non-root attacker, and
# which `cf seal --expect <fingerprint>` from a known-good copy detects for a root one.
#
# The fingerprint is compiled into this file rather than read from the bundle, so
# swapping in an attacker's key requires editing the verifier too.

# Fingerprint of the release signing key. Replaced at build time from the key that
# actually signs; the placeholder means "unsealed development tree".
SEAL_EXPECT_FINGERPRINT="${CFDNS_SEAL_FINGERPRINT:-@RELEASE_KEY_FINGERPRINT@}"

seal_manifest_path()   { printf '%s/RELEASE.manifest' "$CFDNS_LIB"; }
seal_signature_path()  { printf '%s/RELEASE.manifest.asc' "$CFDNS_LIB"; }
seal_pubkey_path()     { printf '%s/RELEASE.pubkey.asc' "$CFDNS_LIB"; }

# A bundle is sealed if it carries a manifest. A sealed bundle missing its signature is
# not "unsealed" — it is a broken seal, and treated as such.
seal_present() { [ -f "$(seal_manifest_path)" ]; }

seal_fingerprint_pinned() {
  case "$SEAL_EXPECT_FINGERPRINT" in
    ''|@RELEASE_KEY_FINGERPRINT@) return 1 ;;
    *) return 0 ;;
  esac
}

# seal_verify_signature -> 0 if the manifest carries a valid signature from the pinned
# key. Uses a throwaway keyring so the user's own trust database is irrelevant: a key
# the operator happens to trust locally must not make an unrelated signature acceptable.
seal_verify_signature() {
  local manifest sig pubkey home fpr
  manifest="$(seal_manifest_path)"
  sig="$(seal_signature_path)"
  pubkey="$(seal_pubkey_path)"

  [ -f "$sig" ]    || { seal_fail "the manifest has no signature ($sig is missing)"; return 1; }
  [ -f "$pubkey" ] || { seal_fail "the release public key is missing ($pubkey)"; return 1; }
  command -v gpg >/dev/null 2>&1 || { seal_fail "gpg is required to verify the seal"; return 1; }

  home="$(mktemp -d)" || return 1
  chmod 700 "$home"
  if ! GNUPGHOME="$home" gpg --batch --quiet --import "$pubkey" 2>/dev/null; then
    rm -rf "$home"; seal_fail "the bundled public key could not be imported"; return 1
  fi

  fpr="$(GNUPGHOME="$home" gpg --batch --with-colons --fingerprint 2>/dev/null \
         | awk -F: '/^fpr:/{print $10; exit}')"
  if [ "$fpr" != "$SEAL_EXPECT_FINGERPRINT" ]; then
    rm -rf "$home"
    seal_fail "the bundle is signed by an unexpected key.
    expected  $SEAL_EXPECT_FINGERPRINT
    bundled   ${fpr:-<none>}
  A bundled key that does not match the fingerprint compiled into this tool means the
  key was replaced. Reinstall from a source you trust."
    return 1
  fi

  if ! GNUPGHOME="$home" gpg --batch --verify "$sig" "$manifest" >/dev/null 2>&1; then
    rm -rf "$home"
    seal_fail "the manifest signature is not valid — the seal is broken"
    return 1
  fi
  rm -rf "$home"
  return 0
}

# seal_verify_contents <computed-manifest> -> 0 if every file matches the signed
# manifest. The computed manifest comes from bundle_manifest, which the integrity
# check already produces, so this costs no extra hashing.
seal_verify_contents() {
  local computed="$1" signed differences
  signed="$(seal_manifest_path)"

  # The seal files themselves cannot appear in a manifest they are part of.
  differences="$(diff <(seal_manifest_expected "$signed") \
                      <(seal_manifest_expected <(printf '%s\n' "$computed")) 2>/dev/null)" || true
  [ -z "$differences" ] && return 0

  seal_fail "the files on disk do not match the signed manifest"
  printf '%s\n' "$differences" | sed 's/^/    /' >&2
  return 1
}

# Normalise a manifest for comparison: drop the seal's own files and sort.
seal_manifest_expected() {
  grep -vE ' \./lib/RELEASE\.(manifest|manifest\.asc|pubkey\.asc)$' "$1" 2>/dev/null \
    | LC_ALL=C sort -k3
}

seal_fail() {
  SEAL_ERROR="$1"
  return 0
}

# seal_check <computed-manifest> -> SEAL_STATE in SEALED|BROKEN|UNSEALED
#
# Fails closed: a bundle that claims to be sealed and is not verifiable must not run.
# An unsealed bundle (a development checkout) runs with a warning, because refusing
# would make the tool undevelopable.
seal_check() {
  local computed="$1"
  SEAL_ERROR=""

  if ! seal_present; then SEAL_STATE=UNSEALED; return 0; fi
  if ! seal_fingerprint_pinned; then
    SEAL_STATE=BROKEN
    SEAL_ERROR="this bundle carries a manifest but no key fingerprint was compiled in"
    return 0
  fi
  if ! seal_verify_signature; then SEAL_STATE=BROKEN; return 0; fi
  if ! seal_verify_contents "$computed"; then SEAL_STATE=BROKEN; return 0; fi

  SEAL_STATE=SEALED
  return 0
}
