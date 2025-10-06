"""Active Directory multihost host."""

from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Any

from pytest_mh.conn import ProcessLogLevel

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

        self.adminpw: str = self.config.get("adminpw", "Secret123")
        """Password of the Administrator user, defaults to ``Secret123``."""

        self.adminuser: str = self.config.get("adminuser", "administrator")
        """Administrator user, defaults to ``administrator``."""

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
            result = self.conn.run("Write-Host (Get-ADRootDSE).rootDomainNamingContext")
            nc = result.stdout.strip()
            if not nc:
                raise ValueError("Unable to find default naming context")

            self.__naming_context = nc

        return self.__naming_context

    def disconnect(self) -> None:
        return

    def start(self) -> None:
        raise NotImplementedError("Starting Active Directory service is not implemented.")

    def stop(self) -> None:
        raise NotImplementedError("Stopping Active Directory service is not implemented.")

    def backup(self) -> Any:
        """
        Perform limited backup of the domain controller data. Users, groups, sites, dns zones,
        dns records, groupPolicyContainer and computer objects are explicitly exported so the
        setup can be undone. Most of these operations are done using LDAP, DNS changes are
        reverted using powershell. These operations are usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of Active Directory")

        result = self.conn.run(
            rf"""
            $basedn = '{self.naming_context}'
            $sitesdn = "cn=sites,cn=configuration,$basedn"

            # Create temporary directory to store backups
            $tmpdir = New-TemporaryFile | % {{ Remove-Item $_; New-Item -ItemType Directory -Path $_ }}

            # Backup DC content and sites
            $backup_dc = Join-Path $tmpdir dc.txt
            $result_basedn = Get-ADObject -SearchBase "$basedn" -Filter "*"
            $result_sitesdn = Get-ADObject -SearchBase "$sitesdn" -LDAPFilter "objectClass=site"
            $result = $result_basedn + $result_sitesdn
            foreach ($r in $result) {{ $r.DistinguishedName | Add-Content -Path $backup_dc }}

            # Backup DNS zones
            $backup_zones = Join-Path $tmpdir zones.txt
            $zones = Get-DnsServerZone `
            | Where-Object {{ $_.ZoneType -eq "Primary" -and $_.IsAutoCreated -eq $false }} `
            | Select-Object -ExpandProperty ZoneName
            $zones | Out-File -FilePath $backup_zones -Force

            # Backup global DNS forwarders
            $backup_forwarders = Join-Path $tmpdir forwarders.txt
            $forwarders = Get-DNSServerForwarder
            $forwarders.IPAddress.IPAddressToString | Out-File -FilePath $backup_forwarders -Force

            # Backup primary DNS zone records
            $backup_dns = Join-Path $tmpdir dns.txt
            Get-DnsServerResourceRecord -ZoneName {self.domain} | Export-Csv -Path $backup_dns -NoTypeInformation

            # Backup GPOs
            $backup_gpo = Join-Path $tmpdir gpo.txt
            $result = Get-ADObject -SearchBase "$basedn" -LDAPFilter "(objectClass=GroupPolicyContainer)"
            foreach ($r in $result) {{ $r.DistinguishedName | Add-Content -Path $backup_gpo }}

            # Backup computers
            $backup_computers = Join-Path $tmpdir computers.txt
            $result = Get-ADObject -SearchBase "cn=computers,$basedn" -LDAPFilter "(objectClass=computer)"
            foreach ($r in $result) {{ $r.DistinguishedName | Add-Content -Path $backup_computers }}

            Write-Output $tmpdir.FullName
            """,
            log_level=ProcessLogLevel.Error,
        )

        return PureWindowsPath(result.stdout.strip())

    def restore(self, backup_data: Any | None) -> None:
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

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PureWindowsPath):
            raise TypeError(f"Expected PureWindowsPath, got {type(backup_data)}")

        backup_path = str(backup_data)
        self.logger.info(f"Restoring Active Directory from {backup_path}")

        self.conn.run(
            rf"""
            $basedn = '{self.naming_context}'
            $sitesdn = "cn=sites,cn=configuration,$basedn"
            $tmpdir = '{backup_path}'

            # Restore computers
            $backup_computers = Get-Content $(Join-Path $tmpdir computers.txt)
            $result = Get-ADObject -SearchBase $basedn -Filter "*"
            $computersdn = "cn=computers,$basedn"
            foreach ($b in $backup_computers) {{
                if ($b -Like "*$computersdn*") {{
                    $cn = $b.split(",")[0].split("=")[1].ToUpper()
                    $computer = (Get-ADComputer $cn).DistinguishedName
                    if ($computer -NotLike "*$computersdn*") {{
                        Write-Host Moving: $computer : $computersdn
                        Move-ADObject -Identity "$computer" -TargetPath "$computersdn" -Confirm:$false
                    }}
                }}
            }}

            # Restore GPOs
            $backup_gpo = Get-Content $(Join-Path $tmpdir gpo.txt)
            $gpo = Get-ADObject -SearchBase $basedn -Properties "*" -LDAPFilter "(objectClass=GroupPolicyContainer)"
            $sites = Get-ADObject -Identity "cn=Default-First-Site-Name,$sitesdn" -Properties "*"
            $link = Get-ADObject -SearchBase $basedn -Properties "*" -LDAPFilter "(gplink=*)"
            foreach ($r in $gpo) {{
                if (!$backup_gpo.contains($r.DistinguishedName)) {{
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
            Set-ADObject -Identity "cn=Default-First-Site-Name,$sitesdn" -Clear gPLink

            # Clear and restore forwarders
            $backup_forwarders = Get-Content $(Join-Path $tmpdir forwarders.txt)
            $forwarders = Get-DNSServerForwarder
            $current_forwarders = $forwarders.IPAddress.IPAddressToString
            foreach ($f in $current_forwarders) {{ Remove-DNSServerForwarder $f -Force }}
            foreach ($f in $backup_forwarders) {{ Add-DNSServerForwarder $f  }}

            # Remove any added zones
            $backup_zones = Get-Content -Path $(Join-Path $tmpdir zones.txt) | Where-Object {{ $_ -ne "" }}
            $current_zones = Get-DnsServerZone `
            | Where-Object {{ $_.ZoneType -eq "Primary" -and $_.IsAutoCreated -eq $false }} `
            | Select-Object -ExpandProperty ZoneName

            $zones_diff = Compare-Object -ReferenceObject $backup_zones -DifferenceObject $current_zones `
            | Where-Object {{ $_.SideIndicator -eq "=>" }} `
            | Select-Object -ExpandProperty InputObject

            if ($zones_diff) {{
                foreach ($zone in $zones_diff) {{
                    Remove-DnsServerZone -Name $zone -Force -Confirm:$false
                }}
            }}

            # Restore DNS records in the primary zone
            $backup_dns = Join-Path $tmpdir dns.txt
            $dns_backup = Import-Csv -Path $backup_dns | Select-Object -Property HostName, RecordType, RecordData
            $dns_current = Get-DnsServerResourceRecord -ZoneName {self.domain} | `
                    Select-Object -Property HostName, RecordType, RecordData

            $dns_diff = $dns_current | Where-Object {{
                $c = $_
                -not ($dns_backup | Where-Object {{
                    $_.HostName -eq $c.HostName -and
                    $_.RecordType -eq $c.RecordType -and
                    $_.RecordData -eq $c.RecordData
                }})
            }}

            if ($dns_diff) {{
                foreach ($r in $dns_diff) {{
                    Remove-DnsServerResourceRecord -ZoneName {self.domain} `
                        -Name $r.HostName -RRType $r.RecordType -Force
                          Write-Host "Removing dns record: $($r.HostName) ($($r.RecordType))"
                }}
            }}

            # Restore DC content and site
            $backup_dc = Get-Content $(Join-Path $tmpdir dc.txt)
            $result_basedn = Get-ADObject -SearchBase "$basedn" -Filter "*"
            $result_sitesdn = Get-ADObject -SearchBase "$sitesdn" -LDAPFilter ("objectClass=site")
            $result = $result_basedn + $result_sitesdn
            foreach ($r in $result) {{
                if (!$backup_dc.contains($r.DistinguishedName)) {{
                    Write-Host "Removing: $r"
                    Try {{
                        Remove-ADObject -Identity $r.DistinguishedName -Recursive -Confirm:$false
                    }} Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {{
                        # Ignore not found error as the object may have been deleted by recursion
                    }}
                }}
            }}

            # Clean up certificate directories
            if (Test-Path "C:\pki") {{
                Write-Host "Cleaning up certificate directories in C:\pki"
                Remove-Item "C:\pki" -Recurse -Force -ErrorAction SilentlyContinue
            }}

            # If we got here, make sure we exit with 0
            Exit 0
            """,
            log_level=ProcessLogLevel.Error,
        )
