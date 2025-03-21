"""
Augeas  Configuration Editor.

Augeas, "augtool" is a configuration editing tool. That contains numerous "lenses" to safely edit
common Linux files. Instead of ADHOC methods like "sed" and "awk".

Stock Lenses: https://augeas.net/stock_lenses.html
"""

from __future__ import annotations

import re
import os.path

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.utils.fs import LinuxFileSystem


class AugeasUtils(MultihostUtility):
    """
    Management of common Linux files.

    ...code-block: python
        :caption: Example usage in
        
        # Use this class to extend other classes 

        class KRB5Utils()
        
        def __init__()
            AugeasUtils("/etc/krb5.conf", lense="Krb5")
            
    .. code-block: python
        :caption: Example usage in test
        import KRB5Utils as krb5

        krb5.config["param", "value"]
    """
    def __init__(self, host: MultihostHost, fs: LinuxFileSystem, file: str, lense: str | None = None) -> None:
        """

        :param host:
        :param fs:
        :param file:
        """
        super().__init__(host)

        self.fs: LinuxFileSystem = fs
        self.file: str = file
        self.aug_path: str = os.path.join("/files", file)
        self.config: AugeasUtils = self

        if lense is not None:
            self.aug_args = f'--noautoload --transform  "{lense}" incl {self.file}'
        else:
            self.aug_args = f'--transform  {self.file}'

    def setup(self) -> None:
        super().setup()
        self.fs.backup(self.file)

    def teardown(self) -> None:
        self.fs.restore(self.file)
        return super().teardown()
    
    def config_apply(self):

    def config_dump(self):

    @property
    def config(self):

    @config.setter
    def config(self, value: dict[list[str, str]]):

    @config.deleter
    def config(self) -> None:

    def __get(self):

    def __set(self) -> None:

    def __del(self) -> None:




