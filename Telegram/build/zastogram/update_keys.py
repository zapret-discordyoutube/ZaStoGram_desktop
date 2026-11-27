#!/usr/bin/env python3
"""Trust data of the ZaStoGram v2 update envelope (the fork's own key chain).

The client verifies every update package against data compiled into it
(Telegram/Resources/update: root-public.pem, manifest.min.json, manifest.sig,
embedded by Telegram/cmake/update_keys_header.cmake). Telegram's own root key
does not trust the fork's signatures, so the fork has its own chain:

  root key     Ed25519, signs ONLY the manifest. Private half never leaves
               the build host (KEYS_DIR, mode 700/600) and is never copied to
               the Windows VM.
  release key  Ed25519, signs every update package (Packer -local-key). Its
               private half is also copied to the VM, see `install-vm-key`
               in the release skill. Listed in the manifest for the stable
               and beta channels as the single group [[release-id]].

Commands (private keys are never printed):

  update_keys.py init [--keys-dir D] [--out Resources/update]
      Creates the root and release keys if they are missing (never
      overwrites), then writes root-public.pem, manifest.min.json and
      manifest.sig.
  update_keys.py manifest [--keys-dir D] [--out ...] [--manifest-version N]
      Re-issues the manifest from the existing keys (rotation, expiry).
      manifest_version must grow, a client keeps the newest one it has seen.
  update_keys.py check [--out ...]
      Verifies manifest.sig against root-public.pem and the manifest shape.
  update_keys.py install-vm [--keys-dir D] [--host win10]
      Copies ONLY the release private key to the Windows build VM
      (C:/TBuild/DesktopPrivate/update-release-private.pem, access limited to
      the SSH user and SYSTEM). The root key is never copied.
  update_keys.py backup [--keys-dir D] [--backup-dir ~/DesktopPrivate/update-v2]
      Copies both private keys to the host backup folder (mode 700/600).
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time

DEFAULT_KEYS_DIR = os.path.expanduser('~/.config/zastogram-signing/update-v2')
DEFAULT_RELEASE_ID = 'zsg-rel-2026a'
CHANNELS = ('stable', 'beta')
FIVE_YEARS = 5 * 365 * 24 * 3600


def run_openssl(*args, data=None):
    result = subprocess.run(
        ['openssl', *args], input=data, capture_output=True)
    if result.returncode != 0:
        # openssl stderr never contains key material for these commands.
        raise SystemExit('openssl %s failed: %s' % (
            args[0], result.stderr.decode(errors='replace').strip()))
    return result.stdout


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def generate_private(path):
    if os.path.exists(path):
        return False
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    run_openssl('genpkey', '-algorithm', 'ed25519', '-out', path)
    os.chmod(path, 0o600)
    return True


def public_pem(private_path):
    return run_openssl('pkey', '-in', private_path, '-pubout')


def raw_public(private_path):
    der = run_openssl('pkey', '-in', private_path, '-pubout', '-outform', 'DER')
    # SubjectPublicKeyInfo of Ed25519: a 12-byte prefix, then the raw 32 bytes.
    if len(der) != 44:
        raise SystemExit('unexpected Ed25519 public key encoding')
    return der[-32:]


def sign_raw(private_path, message):
    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, 'm')
        target = os.path.join(tmp, 's')
        with open(source, 'wb') as f:
            f.write(message)
        run_openssl(
            'pkeyutl', '-sign', '-inkey', private_path, '-rawin',
            '-in', source, '-out', target)
        with open(target, 'rb') as f:
            return f.read()


def verify_raw(public_pem_path, message, signature):
    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, 'm')
        sig = os.path.join(tmp, 's')
        with open(source, 'wb') as f:
            f.write(message)
        with open(sig, 'wb') as f:
            f.write(signature)
        result = subprocess.run(
            ['openssl', 'pkeyutl', '-verify', '-pubin',
             '-inkey', public_pem_path, '-rawin', '-in', source,
             '-sigfile', sig],
            capture_output=True)
        return result.returncode == 0


def build_manifest(release_public, release_id, version, issued):
    document = {
        'format': 1,
        'manifest_version': version,
        'issued': issued,
        'expires': issued + FIVE_YEARS,
        'keys': [{
            'id': release_id,
            'alg': 'Ed25519',
            'x': b64url(release_public),
        }],
        'channels': {name: [[release_id]] for name in CHANNELS},
        'revoked': [],
    }
    return json.dumps(document, separators=(',', ':')).encode('ascii')


def write_file(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def cmd_issue(args, create):
    keys_dir = os.path.expanduser(args.keys_dir)
    os.makedirs(keys_dir, mode=0o700, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    root_path = os.path.join(keys_dir, 'root-private.pem')
    release_path = os.path.join(keys_dir, 'release-private.pem')
    if create:
        made = [generate_private(root_path), generate_private(release_path)]
        print('keys: root %s, release %s' % tuple(
            'created' if m else 'kept' for m in made))
    for path in (root_path, release_path):
        if not os.path.isfile(path):
            raise SystemExit('missing key file (run init): ' + path)
        if os.stat(path).st_mode & 0o077:
            raise SystemExit('key file must be mode 600: ' + path)

    out = args.out
    os.makedirs(out, exist_ok=True)
    version = args.manifest_version
    if version is None:
        try:
            with open(os.path.join(out, 'manifest.min.json'), 'rb') as f:
                version = json.load(f)['manifest_version'] + (
                    0 if create else 1)
        except (OSError, ValueError, KeyError):
            version = 1
    issued = int(time.time()) if args.issued is None else args.issued
    manifest = build_manifest(
        raw_public(release_path), args.release_id, version, issued)
    signature = sign_raw(root_path, manifest)
    write_file(os.path.join(out, 'root-public.pem'), public_pem(root_path))
    write_file(os.path.join(out, 'manifest.min.json'), manifest)
    write_file(os.path.join(out, 'manifest.sig'), signature)
    print('manifest_version %d, release key id %s, written to %s' % (
        version, args.release_id, out))
    return cmd_check(args)


def cmd_check(args):
    out = args.out
    manifest_path = os.path.join(out, 'manifest.min.json')
    with open(manifest_path, 'rb') as f:
        manifest = f.read()
    with open(os.path.join(out, 'manifest.sig'), 'rb') as f:
        signature = f.read()
    if len(signature) != 64:
        raise SystemExit('manifest.sig must be a raw 64-byte Ed25519 signature')
    if not verify_raw(os.path.join(out, 'root-public.pem'), manifest, signature):
        raise SystemExit('manifest.sig does NOT verify against root-public.pem')
    document = json.loads(manifest)
    ids = {key['id'] for key in document['keys']}
    for name, groups in document['channels'].items():
        for group in groups:
            for key_id in group:
                if key_id not in ids:
                    raise SystemExit(
                        'channel %s names unknown key %s' % (name, key_id))
    print('OK: manifest_version %d, keys %s, channels %s' % (
        document['manifest_version'],
        sorted(ids),
        sorted(document['channels'])))
    return 0


VM_KEY_PATH = 'C:/TBuild/DesktopPrivate/update-release-private.pem'


def cmd_install_vm(args):
    release_path = os.path.join(
        os.path.expanduser(args.keys_dir), 'release-private.pem')
    if not os.path.isfile(release_path):
        raise SystemExit('missing key file (run init): ' + release_path)
    subprocess.run(
        ['scp', '-q', release_path, '%s:%s' % (args.host, VM_KEY_PATH)],
        check=True)
    # The file is created with the folder ACL, narrow it to this account.
    acl = ('icacls "%s" /inheritance:r /grant:r "%%USERNAME%%:(R,W)" '
           '"SYSTEM:(F)"' % VM_KEY_PATH.replace('/', '\\'))
    subprocess.run(['ssh', args.host, acl], check=True,
                   stdout=subprocess.DEVNULL)
    print('release key installed on %s: %s' % (args.host, VM_KEY_PATH))
    return 0


def cmd_backup(args):
    keys_dir = os.path.expanduser(args.keys_dir)
    target = os.path.expanduser(args.backup_dir)
    os.makedirs(target, mode=0o700, exist_ok=True)
    os.chmod(target, 0o700)
    for name in ('root-private.pem', 'release-private.pem'):
        source = os.path.join(keys_dir, name)
        if not os.path.isfile(source):
            raise SystemExit('missing key file (run init): ' + source)
        destination = os.path.join(target, name)
        if os.path.exists(destination):
            print('backup kept: ' + name)
            continue
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out, open(source, 'rb') as src:
            out.write(src.read())
        print('backup written: ' + name)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    install = sub.add_parser('install-vm')
    install.add_argument('--keys-dir', default=DEFAULT_KEYS_DIR)
    install.add_argument('--host', default='win10')
    backup = sub.add_parser('backup')
    backup.add_argument('--keys-dir', default=DEFAULT_KEYS_DIR)
    backup.add_argument(
        '--backup-dir', default=os.path.expanduser('~/DesktopPrivate/update-v2'))
    for name in ('init', 'manifest', 'check'):
        p = sub.add_parser(name)
        p.add_argument('--out', default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', '..', 'Resources', 'update'))
        if name != 'check':
            p.add_argument('--keys-dir', default=DEFAULT_KEYS_DIR)
            p.add_argument('--release-id', default=DEFAULT_RELEASE_ID)
            p.add_argument('--manifest-version', type=int)
            p.add_argument('--issued', type=int, help='unix time, for tests')
    args = parser.parse_args()
    if args.command == 'check':
        return cmd_check(args)
    if args.command == 'install-vm':
        return cmd_install_vm(args)
    if args.command == 'backup':
        return cmd_backup(args)
    return cmd_issue(args, create=(args.command == 'init'))


if __name__ == '__main__':
    sys.exit(main())
