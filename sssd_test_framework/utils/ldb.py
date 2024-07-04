from __future__ import annotations

from enum import Enum

from pytest_mh import MultihostHost, MultihostUtility

from sssd_test_framework.misc import parse_ldif


class LDBUtils(MultihostUtility[MultihostHost]):
    """
    LDB Tools wrappper.
    """

    class Scope(Enum):
        """
        Search scope to use.
        """

        ONE_LEVEL = "one"
        SUBTREE = "sub"
        BASE = "base"

    def search(
        self,
        path: str,
        basedn: str | None = None,
        scope: Scope = Scope.SUBTREE,
        filter: str | None = None,
        args: list[str] | None = None,
    ) -> dict[str, dict[str, list[str]]]:
        """
        Run ``ldbsearch -H path`` command and transform the data to ``dictionary``.

        Can be called with additional arguments.

        :param path: Path to .ldb file.
        :type path: str
        :param basedn: Base DN which is searched by ldbsearch. Defaults to None.
        :type basedn: str | None
        :param scope: Scope of search. Defaults to Scope.SUBTREE.
        :type scope: Scope
        :param filter: Filter to be used for searching. Defaults to None.
        :type filter: str | None
        :param args: Additional arguments. Defaults to None.
        :type args: str | None
        :return: Searched data. In format: dict[dn, dict[attribute, list[attrvalue]]].
        :rtype: dict[str, dict[str, list[str]]
        """
        if args is None:
            args = []

        additional = ["-s", scope.value]

        if basedn is not None:
            additional += ["-b", basedn]

        if filter is not None:
            additional.append(filter)

        result = self.host.conn.exec(["ldbsearch", *args, "-H", path, *additional])
        return parse_ldif(result.stdout)
