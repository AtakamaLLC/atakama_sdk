import subprocess

from atakama import DetectorPlugin

class SubprocDetector(DetectorPlugin):
    def __init__(self, args):
        super().__init__(args)
        self.cmd = args["cmd"]
        assert "{path}" in self.cmd

    @staticmethod
    def name():
        return "subprocess-detector"

    def needs_encryption(self, path):
        cmd = self.cmd.replace("{path}", path)
        ret = subprocess.run(cmd, shell=True)
        return ret.returncode == 0
