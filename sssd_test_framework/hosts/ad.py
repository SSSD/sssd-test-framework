"""Active Directory multihost host."""

from __future__ import annotations

from .base import BaseDomainHost

__all__ = [
    "ADHost",
]


class ADHost(BaseDomainHost):
    """
    Active Directory host object.

    Provides features specific to Active Directory domain controller.

    .. warning::

        Backup and restore functionality of a domain controller is quite limited
        when compared to other backends. Unfortunately, a full backup and
        restore of a domain controller is not possible without a complete system
        backup and reboot which takes too long time and is not suitable for
        setting an exact state for each test. Therefore a limited backup and
        restore is provided which only deletes all added objects. It works well
        if a test does not modify any existing data but only uses new
        objects like newly added users and groups.

        If the test modifies existing data, it needs to make sure to revert
        the modifications manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None

        # Additional client configuration
        self.client.setdefault("id_provider", "ad")
        self.client.setdefault("access_provider", "ad")
        self.client.setdefault("ad_server", self.hostname)
        self.client.setdefault("dyndns_update", False)

        # Use different default for domain
        if "domain" not in self.config and "ad_domain" in self.client:
            self.domain = self.client["ad_domain"]

        # Use different default for realm
        if "realm" not in self.config:
            self.realm = self.domain.upper()

        # Lazy properties
        self.__naming_context: str | None = None

        # GPO policy file location
        self._backup_gpo_location: str | None = None

        # Computers file location
        self._backup_computers_location: str | None = None

    @property
    def features(self) -> dict[str, bool]:
        """
        Features supported by the host.
        """
        if self._features is not None:
            return self._features

        self.logger.info(f"Detecting features on {self.hostname}")

        # Set default values
        self._features = {
            "passkey": True,
        }

        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    @property
    def naming_context(self) -> str:
        """
        Default naming context.

        :raises ValueError: If default naming context can not be obtained.
        :rtype: str
        """
        if not self.__naming_context:
            result = self.ssh.run("Write-Host (Get-ADRootDSE).rootDomainNamingContext")
            nc = result.stdout.strip()
            if not nc:
                raise ValueError("Unable to find default naming context")

            self.__naming_context = nc

        return self.__naming_context

    def disconnect(self) -> None:
        return

    def backup(self) -> None:
        """
        Perform limited backup of the domain controller data. Content under
        ``$default_naming_context``. Site, groupPolicyContainer and computer
        objects are explicitly exported so GPO setup can be undone. These
        operations are usually very fast.
        """
        self.ssh.run(
            rf"""
                $backup = "C:\\multihost_backup.txt"
                if (Test-Path $backup) {{
                    Remove-Item $backup
                }}
                $result = Get-ADObject -SearchBase "{self.naming_context}" -Filter "*"
                foreach ($r in $result) {{
                    $r.DistinguishedName | Add-Content -Path $backup
                }}
            """
        )
        self._backup_location = "C:\\multihost_backup.txt"

        self.ssh.run(
            rf"""
                $backup = "C:\\multihost_gpo_backup.txt"
                if (Test-Path $backup) {{
                    Remove-Item $backup
                }}
                $filter = "objectClass=GroupPolicyContainer"
                $result = Get-ADObject -SearchBase "{self.naming_context}" -LDAPFilter ($filter)
                foreach ($r in $result) {{
                    $r.DistinguishedName | Add-Content -Path $backup
                }}
            """
        )
        self._backup_gpo_location = "C:\\multihost_gpo_backup.txt"

        self.ssh.run(
            rf"""
                $backup = "C:\\multihost_computers_backup.txt"
                $basedn = '{self.naming_context}'
                $computersdn = "cn=computers,$basedn"
                if (Test-Path $backup) {{
                    Remove-Item $backup
                }}
                $filter = "objectClass=computer"
                $result = Get-ADObject -SearchBase "$computersdn" -LDAPFilter ($filter)
                foreach ($r in $result) {{
                    $r.DistinguishedName | Add-Content -Path $backup
                }}
            """
        )
        self._backup_computers_location = "C:\\multihost_computers_backup.txt"

    def restore(self) -> None:
        """
        Perform limited restoration of the domain controller state.

        This is done by removing all records under ``$default_naming_context``
        and that are not present in the original state.

        If GPOs are found, some additional steps are performed. The policy directory
        located at 'C:\\Windows\\SYSVOL\\domain\\Policies\\{{GUID}}' is deleted.
        Before removing the GPO, the GPO needs to be unlinked from the target object.
        There is logic to run through the GPOs that were not present, unlink them and
        then removed.

        The client computer object may move to a different location during a test.
        There is a check to ensure that the object is in 'cn=computers' otherwise
        the object will be deleted when attempting to restore the computer state.
        """
        if self._backup_computers_location:
            self.ssh.run(
                rf"""
                    $basedn = '{self.naming_context}'
                    $backup = Get-Content '{self._backup_computers_location}'
                    $result = Get-ADObject -SearchBase $basedn -Filter "*"
                    $computersdn = "cn=computers,$basedn"
                    foreach ($b in $backup) {{
                        if ($b -Like "*$computersdn*") {{
                            $cn = $b.split(",")[0].split("=")[1].ToUpper()
                            $computer = (Get-ADComputer $cn).DistinguishedName
                            if ($computer -NotLike "*$computersdn*") {{
                                Write-Host Moving: $computer : $computersdn
                                Move-ADObject -Identity "$computer" -TargetPath "$computersdn" -Confirm:$false
                            }}
                        }}
                    }}
                    Exit 0
                """
            )

        if self._backup_gpo_location:
            self.ssh.run(
                rf"""
                    $basedn = '{self.naming_context}'
                    $sitesdn = "cn=Default-First-Site-Name,cn=sites,cn=configuration,$basedn"
                    $backup = Get-Content '{self._backup_gpo_location}'
                    $filter = ("objectClass=GroupPolicyContainer")
                    $gpo = Get-ADObject -SearchBase $basedn -Properties "*" -LDAPFilter $filter
                    $sites = Get-ADObject -Identity $sitesdn -Properties "*"
                    $link = Get-ADObject -SearchBase $basedn -Properties "*" -LDAPFilter ("gplink=*")
                    foreach ($r in $gpo) {{
                        if (!$backup.contains($r.DistinguishedName)) {{
                            if ($sites.gplink -Like "*$r*") {{
                                Remove-GPLink -GUID $r.Name -Target "Default-First-Site-Name"
                                Write-Host Removing: "*$r*" from Default-First-Site-Name
                            }}
                            foreach ($g in $link) {{
                                if ($g.gplink -Like "*$r*") {{
                                    Remove-GPLink -GUID $r.Name -Target $g
                                    Write-Host Removing: "*$r*" from $g
                                }}
                            }}
                            Remove-GPO -GUID $r.Name
                            $path = Join-Path C:\Windows\SYSVOL\domain\Policies\ $r.Name
                            Remove-Item $path -Recurse -Confirm:$false -Force
                            Write-Host "Deleting directory: $path"
                        }}
                    }}
                    # An extra gplink clear on the sites target.
                    Set-ADObject -Identity $sitesdn -Clear gPLink
                    Exit 0
                """
            )

        if self._backup_location:
            self.ssh.run(
                rf"""
                    $backup = Get-Content '{self._backup_location}'
                    $result = Get-ADObject -SearchBase '{self.naming_context}' -Filter "*"
                    foreach ($r in $result) {{
                        if (!$backup.contains($r.DistinguishedName)) {{
                            Write-Host "Removing: $r"
                            Try {{
                                Remove-ADObject -Identity $r.DistinguishedName -Recursive -Confirm:$false
                            }} Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {{
                                # Ignore not found error as the object may have been deleted by recursion
                            }}
                        }}
                    }}
                    # If we got here, make sure we exit with 0
                    Exit 0
                """
            )
