import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from contextlib import suppress
from shutil import which
from typing import List
from zipfile import ZipFile, ZipInfo

class Packager:
    def __init__(self, src=None, pkg=None, key=None, crt=None, self_signed=False, openssl=None):
        self.pkg = pkg
        self.src = src
        self.key = key
        self.crt = crt
        self.self_signed = self_signed

        self.setup_path = src and os.path.join(self.src, "setup.py")
        self.openssl_path = openssl or which("openssl")
        self.made_setup = False

    @classmethod
    def from_args(cls, argv):
        args = cls.parse_args(argv)
        return Packager(src=args.src, pkg=args.pkg,
                        key=args.key, crt=args.crt,
                        self_signed=args.self_signed, openssl=args.openssl)

    @staticmethod
    def parse_args(argv):
        parser = argparse.ArgumentParser(description="Atakama plugin packaging helper", epilog="""

        An atakama plugin package consists of a python installable package, and an openssl signature file.

        These two files are located in the same zip.


        It is installed by installing the package into the plugins folder.

        The python package can be:

            - a simple zip of sources
            - a binary wheel
            - a certificate file (CRT), proving authority

        This tool simply shells out to openssl as needed to produce the signature.
        """)

        parser.add_argument("--src", help="Package source root folder.")
        parser.add_argument("--pkg", help="Package file path (wheel, for example)")
        parser.add_argument("--key", help="Openssl private key file", required=True)
        parser.add_argument("--crt", help="Openssl certificate file", required=True)
        parser.add_argument("--openssl", help="Location of openssl binary", default=which("openssl"))
        parser.add_argument("--self-signed", help="Allow a self-signed cert", action="store_true")
        args = parser.parse_args(argv)
        if not args.src and not args.pkg:
            raise ValueError("Nothing to do: must specify --src or --pkg")
        return args

    def run_setup(self):
        from distutils.core import run_setup
        wd = os.getcwd()
        try:
            os.chdir(os.path.dirname(self.src))
            dist = run_setup(self.setup_path, script_args=["bdist_wheel"], stop_after='run')
            for typ, ver, path in getattr(dist, "dist_files"):
                if typ == "bdist_wheel":
                    self.pkg = os.path.abspath(path)
                    return
            raise ValueError("Expected package not created")
        finally:
            os.chdir(wd)

    def has_setup(self):
        return os.path.exists(self.setup_path)

    def make_setup(self):
        self.made_setup = True
        with open(self.setup_path, "w") as f:
            f.write(textwrap.dedent("""
        from setuptools import setup
        setup(
            name="{plug_name}",
            version="1.0",
            description="{plug_name}",
            packages=["{plug_name}"],
            setup_requires=["wheel"],
        )
            """.format(src=self.src, plug_name=os.path.basename(self.src))))

    def remove_setup(self):
        os.remove(self.setup_path)

    def openssl(self, cmd, **kws) -> subprocess.CompletedProcess:
        print("+ openssl", " ".join(cmd), file=sys.stderr)
        cmd = [self.openssl_path] + cmd
        return subprocess.run(cmd, **kws)

    def sign_package(self):
        key = self.key
        crt = self.crt
        pkg = self.pkg

        sig = pkg + ".sig"
        self.openssl(["dgst", "-sha256", "-sign", key, "-out", sig, pkg], check=True)
        self.verify_signature(crt, pkg, sig)

    @staticmethod
    def verify_certificate(crt):
        from certvalidator import CertificateValidator
        with open(crt, 'rb') as f:
            end_entity_cert = f.read()
        validator = CertificateValidator(end_entity_cert)
        validator.validate_usage({'digital_signature'})

    def zip_package(self):
        crt = self.crt
        pkg = self.pkg
        sig = pkg + ".sig"
        final = pkg + ".apkg"
        with ZipFile(final, 'w') as myzip:
            myzip.write(pkg, arcname=os.path.basename(pkg))
            myzip.write(sig, arcname=os.path.basename(sig))
            myzip.write(crt, arcname="cert")
        print("wrote package", final, file=sys.stderr)
        return final

    @classmethod
    def unpack_plugin(cls, path, dest_dir, self_signed=False):
        with ZipFile(path) as zip:
            ent: ZipInfo
            wheels: List[ZipInfo] = []
            for ent in zip.infolist():
                if ent.filename.endswith(".whl"):
                    wheels += [ent]

            tmpdir = tempfile.mkdtemp("-apkg")
            try:
                crt = zip.getinfo("cert")
                crt = zip.extract(crt, tmpdir)

                if not self_signed:
                    cls.verify_certificate(crt)

                for whl in wheels:
                    sig = whl.filename + ".sig"
                    whl = zip.extract(whl, tmpdir)
                    sig = zip.extract(sig, tmpdir)
                    cls.verify_signature(crt, whl, sig)

                    with ZipFile(whl) as wzip:
                        wzip.extractall(dest_dir)
            finally:
                shutil.rmtree(tmpdir)

    @staticmethod
    def verify_signature(crt, whl, sig):
        from oscrypto.asymmetric import load_certificate, rsa_pkcs1v15_verify

        cert_obj = load_certificate(crt)

        # Load the payload contents and the signature.
        with open(whl, 'rb') as f:
            payload_contents = f.read()

        with open(sig, 'rb') as f:
            signature = f.read()

        rsa_pkcs1v15_verify(cert_obj, signature, payload_contents, "sha256")

def main():
    try:
        p = Packager.from_args(sys.argv[1:])

        if not p.self_signed:
            p.verify_certificate(p.crt)

        if p.src:
            if not p.has_setup():
                p.make_setup()
            try:
                p.run_setup()
            finally:
                if p.made_setup:
                    p.remove_setup()

        if p.pkg:
            p.sign_package()
            p.zip_package()

    except subprocess.CalledProcessError as ex:
        print(ex)
        sys.exit(1)


if __name__ == "__main__":
    main()
