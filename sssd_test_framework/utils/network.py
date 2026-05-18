"""Network utilities."""

from __future__ import annotations

import re
from typing import Any

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

from ..misc import ip_is_valid, ip_to_ptr
from ..misc.ssh import SSHKillableProcess

__all__ = ["NetworkUtils", "IPUtils"]


def _inject_named_forwarders(fs: LinuxFileSystem, forwarder_ips: list[str]) -> None:
    """
    Add DNS forwarders to local named so 127.0.0.1 can resolve external names.

    :param fs: Remote host file system (/etc/named.conf).
    :type fs: LinuxFileSystem
    :param forwarder_ips: Upstream resolver addresses from the original resolv.conf.
    :type forwarder_ips: list[str]
    """
    if not forwarder_ips:
        return

    named_conf = fs.read("/etc/named.conf")
    if "forwarders" in named_conf:
        return

    forwarders_line = "    forwarders { " + "; ".join(forwarder_ips) + "; };\n"
    new_lines: list[str] = []
    inserted = False
    for line in named_conf.splitlines(keepends=True):
        new_lines.append(line)
        if not inserted and line.strip() == "options {":
            new_lines.append(forwarders_line)
            inserted = True

    if inserted:
        fs.write("/etc/named.conf", "".join(new_lines))


def _inject_named_options_for_local_dns(fs: LinuxFileSystem) -> None:
    """
    Set listen-on 127.0.0.1 and a single dnssec-validation no in named.conf.

    :param fs: Remote host file system (/etc/named.conf).
    :type fs: LinuxFileSystem
    """
    named_conf = fs.read("/etc/named.conf")
    lines = named_conf.splitlines(keepends=True)
    filtered: list[str] = []
    for line in lines:
        if re.match(r"^\s*dnssec-validation\s+", line):
            continue
        filtered.append(line)
    named_conf = "".join(filtered)

    extra_options = "    dnssec-validation no;\n"
    if "listen-on port 53 { 127.0.0.1" not in named_conf:
        extra_options = (
            "    listen-on port 53 { 127.0.0.1; };\n" "    listen-on-v6 port 53 { ::1; };\n"
        ) + extra_options

    new_lines: list[str] = []
    inserted = False
    for line in named_conf.splitlines(keepends=True):
        new_lines.append(line)
        if not inserted and line.strip() == "options {":
            new_lines.append(extra_options)
            inserted = True

    if inserted:
        fs.write("/etc/named.conf", "".join(new_lines))


class NetworkUtils(MultihostUtility[MultihostHost]):

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        :param fs: File system object.
        :type fs: LinuxFileSystem
        """
        super().__init__(host)

        self.fs: LinuxFileSystem = fs

        self.__fs: LinuxFileSystem = fs
        self.__rollback: list[str] = []
        self.__ips: list[IPUtils] = []

    def ip(self, name: str | None = None) -> IPUtils:
        """
        Run ip commands.
        """
        inst = IPUtils(self.host, self.fs, name)
        self.__ips.append(inst)

        return inst

    def tcpdump(self, pcap_path: str, args: list[Any] | None = None) -> SSHKillableProcess:
        """
        Run tcpdump. The packets are captured in ``pcap_path``.

        :param pcap_path: Path to the capture file.
        :type pcap_path: str
        :param args: Arguments to ``tcpdump``, defaults to None
        :type args: list[Any] | None, optional
        :return: Killable process.
        :rtype: SSHKillableProcess
        """
        if args is None:
            args = []

        self.__fs.backup(pcap_path)

        command = SSHKillableProcess(self.host.conn, ["tcpdump", *args, "-w", pcap_path])

        # tcpdump requires some time to process and capture packets
        command.kill_delay = 1

        return command

    def tshark(self, args: list[Any] | None = None) -> ProcessResult:
        """
        Execute tshark command with given arguments.

        :param args: Arguments to ``tshark``, defaults to None
        :type args: list[Any] | None, optional
        :return: SSH Process result
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        return self.host.conn.exec(["tshark", *args])

    def dig(self, address: str, server: str | None = None) -> list[dict] | None:
        """
        Execute and parse dig command.

        This returns a list of dicts with the following keys:
        {name, type, ttl, data, all_data}

        .. code-block:: python
            :caption: Example usage

                # Assert the record exists
                assert client.net.dig(hostname, provider.server)
                assert any(r["data"] == ip for r in client.net.dig(hostname, provider.server))

                # Assert the reverse record exists
                assert client.net.dig(ip, provider.server)
                assert any(r["data"] == hostname for r in client.net.dig(ip, provider.server))

        :param address: Hostname or ip.
        :type address: str
        :param server: DNS server, optional, defaults to ""
        :type server: str = ""
        :return: List of dig results.
        :rtype: list[dict]
        """
        rev = "-x " if ip_is_valid(address) else ""
        if server:
            args = f"+norecurse @{server} {rev}{address}"
        else:
            args = f"+norecurse {rev}{address}"
        if address.startswith("_") and " " not in address:
            args += " SRV"

        try:
            output = self.host.conn.run(f"dig {args}").stdout
            parsed_output = jc.parse("dig", output)
        except Exception:
            return None

        if not isinstance(parsed_output, list) or not parsed_output:
            return None

        result: list[dict] = []
        for section in ("answer", "additional"):
            section_records = parsed_output[0].get(section, [])
            if isinstance(section_records, list):
                result.extend(section_records)

        if not result:
            return None

        required_keys = {"name", "type", "ttl", "data"}
        records = []

        for record in result:
            if not isinstance(record, dict):
                continue
            if not required_keys.issubset(record.keys()):
                continue
            if not isinstance(record["ttl"], int) or record["ttl"] < 0:
                continue

            # Strip trailing dots for easier matching
            _name = record["name"].rstrip(".") if isinstance(record["name"], str) else record["name"]
            _data = record["data"].rstrip(".") if isinstance(record["data"], str) else record["data"]

            records.append(
                {
                    "name": _name,
                    "data": _data,
                    "type": record["type"],
                    "ttl": record["ttl"],
                }
            )

        return records if records else None

    def has_srv_record(self, query: str, server: str | None = None) -> bool:
        """
        Return True if query has at least one SRV record.

        Uses dig() first, then dig +short when jc omits SRV from the parsed answer.

        :param query: SRV query name (e.g. _ldap._tcp.ldap.test).
        :type query: str
        :param server: Optional resolver (@127.0.0.1); default is the system resolver.
        :type server: str | None, optional
        :return: True when at least one SRV record is present.
        :rtype: bool
        """
        records = self.dig(query, server)
        if records and any(r.get("type") == "SRV" for r in records):
            return True

        if server:
            short_cmd = f"dig +norecurse +short @{server} {query} SRV"
        else:
            short_cmd = f"dig +norecurse +short {query} SRV"
        short = self.host.conn.run(short_cmd, raise_on_error=False)
        return short.rc == 0 and bool(short.stdout.strip())

    def _resolve_host_ipv4(self, hostname: str) -> str:
        """
        Return the first IPv4 address for hostname via getent ahostsv4.

        :param hostname: FQDN to resolve on this host.
        :type hostname: str
        :return: IPv4 dotted-quad string.
        :rtype: str
        :raises RuntimeError: if the lookup fails or returns no address.
        """
        lookup = self.host.conn.run(f"getent ahostsv4 {hostname}", raise_on_error=False)
        if lookup.rc != 0 or not lookup.stdout:
            raise RuntimeError(f"Could not resolve {hostname} for DNS SRV setup")
        return lookup.stdout.split()[0]

    def _role_ipv4(self, hostname: str, *, role_host: object | None = None, label: str = "host") -> str:
        """
        Resolve role IPv4 using multihost host.ip when set, else getent ahostsv4.

        :param hostname: FQDN to resolve on this host.
        :type hostname: str
        :param role_host: Optional multihost role host with ip attribute.
        :type role_host: object | None, optional
        :param label: Role name for error messages (e.g. LDAP, KDC).
        :type label: str, optional
        :return: IPv4 dotted-quad string.
        :rtype: str
        :raises RuntimeError: if the lookup fails or returns no address.
        """
        if role_host is not None:
            role_ip = getattr(role_host, "ip", None)
            if role_ip:
                return str(role_ip)
        try:
            return self._resolve_host_ipv4(hostname)
        except RuntimeError as exc:
            raise RuntimeError(
                f"Setup: could not resolve {label} to IPv4 on client " f"({hostname}; need A record or role host IP)"
            ) from exc

    def _pin_discovery_hostnames(
        self,
        *,
        ldap_ip: str,
        ldap_hostname: str,
        kdc_ip: str,
        kdc_hostname: str,
    ) -> None:
        """
        Pin LDAP and KDC FQDNs in /etc/hosts.

        krb5_child uses kdc = host:88 from /etc/krb5.conf, not SSSD krb5_server SRV.

        :param ldap_ip: LDAP server IPv4 address.
        :type ldap_ip: str
        :param ldap_hostname: LDAP server FQDN (e.g. master.ldap.test).
        :type ldap_hostname: str
        :param kdc_ip: KDC IPv4 address.
        :type kdc_ip: str
        :param kdc_hostname: KDC FQDN (e.g. kdc.test).
        :type kdc_hostname: str
        :raises RuntimeError: if both hosts share one IP or pinning does not take effect.
        """
        if ldap_hostname != kdc_hostname and ldap_ip == kdc_ip:
            raise RuntimeError(
                f"{ldap_hostname} and {kdc_hostname} resolved to the same address "
                f"({ldap_ip}); krb5_child cannot reach a KDC on the LDAP host"
            )

        self.fs.backup("/etc/hosts")
        hosts_lines: list[str] = []
        for line in self.fs.read("/etc/hosts").splitlines():
            parts = line.split()
            if len(parts) >= 1 and parts[0] in (ldap_ip, kdc_ip):
                continue
            if len(parts) >= 2 and (ldap_hostname in parts[1:] or kdc_hostname in parts[1:]):
                continue
            hosts_lines.append(line)
        hosts_lines.append(f"{ldap_ip}\t{ldap_hostname}")
        hosts_lines.append(f"{kdc_ip}\t{kdc_hostname}")
        self.fs.write("/etc/hosts", "\n".join(hosts_lines).rstrip() + "\n")
        self.host.conn.run("nscd -i hosts 2>/dev/null || true", raise_on_error=False)

        if self._resolve_host_ipv4(ldap_hostname) != ldap_ip:
            raise RuntimeError(f"{ldap_hostname} does not resolve to {ldap_ip} after pinning")
        if self._resolve_host_ipv4(kdc_hostname) != kdc_ip:
            raise RuntimeError(f"{kdc_hostname} does not resolve to {kdc_ip} after pinning")

    def _probe_kdc_port(self, kdc_ip: str, kdc_hostname: str, port: int) -> None:
        """
        Check that the KDC accepts TCP connections on port.

        :param kdc_ip: KDC IPv4 address (after hosts pinning).
        :type kdc_ip: str
        :param kdc_hostname: KDC FQDN (for error messages).
        :type kdc_hostname: str
        :param port: Kerberos port (usually 88).
        :type port: int
        :raises RuntimeError: if the TCP probe fails.
        """
        probe = self.host.conn.run(
            f"timeout 3 bash -c 'echo > /dev/tcp/{kdc_ip}/{port}'",
            raise_on_error=False,
        )
        if probe.rc != 0:
            raise RuntimeError(f"KDC {kdc_hostname} ({kdc_ip}:{port}) is not reachable from {self.host.hostname}")

    def prepare_ldap_krb5_srv_discovery(
        self,
        *,
        discovery_domain: str,
        ldap_hostname: str,
        kdc_hostname: str,
        client_hostname: str,
        ldap_port: int = 389,
        kdc_port: int = 88,
    ) -> None:
        """
        Prepare DNS for LDAP/Kerberos SRV discovery tests on this host.

        Uses the current resolver, then dns.test, else local named on 127.0.0.1.
        Pins LDAP/KDC in /etc/hosts and verifies KDC port 88 for password auth.

        :param discovery_domain: DNS domain for SRV records (e.g. ldap.test for
            _ldap._tcp / _kerberos._udp).
        :type discovery_domain: str
        :param ldap_hostname: LDAP server FQDN published in SRV and A records.
        :type ldap_hostname: str
        :param kdc_hostname: KDC FQDN published in SRV and /etc/krb5.conf.
        :type kdc_hostname: str
        :param client_hostname: This host FQDN (SOA/NS in a local zone when needed).
        :type client_hostname: str
        :param ldap_port: LDAP port in the SRV record (default 389).
        :type ldap_port: int, optional
        :param kdc_port: Kerberos port in the SRV record and TCP probe (default 88).
        :type kdc_port: int, optional
        :raises RuntimeError: if SRV setup, name pinning, or KDC connectivity fails.
        """
        ldap_srv = f"_ldap._tcp.{discovery_domain}"
        krb_srv = f"_kerberos._udp.{discovery_domain}"

        ldap_ip = self._resolve_host_ipv4(ldap_hostname)
        kdc_ip = self._resolve_host_ipv4(kdc_hostname)
        used_local_named = False

        if not (self.has_srv_record(ldap_srv) and self.has_srv_record(krb_srv)):
            dns_probe = self.host.conn.run("getent hosts dns.test", raise_on_error=False)
            if dns_probe.rc == 0 and dns_probe.stdout:
                dns_ip = dns_probe.stdout.split()[0]
                if self.has_srv_record(ldap_srv, dns_ip) and self.has_srv_record(krb_srv, dns_ip):
                    self.fs.backup("/etc/resolv.conf")
                    self.fs.write(
                        "/etc/resolv.conf",
                        f"search {discovery_domain}\nnameserver {dns_ip}\n",
                    )

            if not (self.has_srv_record(ldap_srv) and self.has_srv_record(krb_srv)):
                used_local_named = True
                if self.host.conn.run("rpm -q bind", raise_on_error=False).rc != 0:
                    self.host.conn.run(
                        "dnf install -y bind bind-utils || yum install -y bind bind-utils",
                        raise_on_error=False,
                    )
                if self.host.conn.run("rpm -q bind", raise_on_error=False).rc != 0:
                    raise RuntimeError("bind package is required (dnf install -y bind bind-utils)")

                ldap_short = ldap_hostname.removesuffix(f".{discovery_domain}").rstrip(".")
                kdc_short = kdc_hostname.removesuffix(f".{discovery_domain}").rstrip(".")
                forward_zone_path = f"/var/named/{discovery_domain}"

                self.fs.backup("/etc/resolv.conf")
                self.fs.backup("/etc/named.conf")
                self.fs.backup(forward_zone_path)

                zone_marker = f'zone "{discovery_domain}"'
                named_conf = self.fs.read("/etc/named.conf")
                if zone_marker not in named_conf:
                    named_conf += (
                        f'zone "{discovery_domain}" {{\n'
                        "    type master;\n"
                        "    check-names ignore;\n"
                        f'    file "{discovery_domain}";\n'
                        "};\n"
                    )
                self.fs.write("/etc/named.conf", named_conf)

                upstream_ips: list[str] = []
                for line in self.fs.read("/etc/resolv.conf").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("nameserver ") and "127.0.0.1" not in stripped:
                        upstream_ips.append(stripped.split()[1])
                _inject_named_forwarders(self.fs, upstream_ips)
                _inject_named_options_for_local_dns(self.fs)

                soa_lines = (
                    "$TTL 604800\n"
                    f"$ORIGIN {discovery_domain}.\n"
                    f"@ IN SOA {client_hostname}. root.{client_hostname}. (\n"
                    "    2010050702 ; serial\n"
                    "    604800 ; refresh\n"
                    "    86400 ; retry\n"
                    "    2419200 ; expire\n"
                    "    10800 ; negative caching time\n"
                    "    )\n"
                    f"@ IN NS {client_hostname}.\n"
                )
                self.fs.write(
                    forward_zone_path,
                    soa_lines
                    + f"{ldap_short} IN A {ldap_ip}\n"
                    + f"{kdc_short} IN A {kdc_ip}\n"
                    + f"{ldap_srv}. IN SRV 0 100 {ldap_port} {ldap_hostname}.\n"
                    + f"{krb_srv}. IN SRV 0 100 {kdc_port} {kdc_hostname}.\n",
                )
                self.host.conn.run(f"restorecon -v {forward_zone_path}", raise_on_error=False)

                zone_check = self.host.conn.run(
                    f"named-checkzone {discovery_domain} {forward_zone_path}",
                    raise_on_error=False,
                )
                if zone_check.rc != 0:
                    raise RuntimeError(
                        f"named-checkzone failed for {forward_zone_path}: "
                        f"{(zone_check.stdout or zone_check.stderr or '').strip()}"
                    )

                conf_check = self.host.conn.run("named-checkconf", raise_on_error=False)
                if conf_check.rc != 0:
                    raise RuntimeError(
                        f"named-checkconf failed: {(conf_check.stdout or conf_check.stderr or '').strip()}"
                    )

                self.host.conn.run("systemctl enable named", raise_on_error=False)
                named_restart = self.host.conn.run("systemctl restart named", raise_on_error=False)
                if named_restart.rc != 0:
                    journal = self.host.conn.run(
                        "journalctl -u named -n 30 --no-pager",
                        raise_on_error=False,
                    )
                    raise RuntimeError(
                        "systemctl restart named failed; "
                        f"journal: {(journal.stdout or journal.stderr or '')[-2000:]}"
                    )

                self.fs.write("/etc/resolv.conf", f"search {discovery_domain}\nnameserver 127.0.0.1\n")
                self.host.conn.run("restorecon -v /etc/resolv.conf", raise_on_error=False)

        self._pin_discovery_hostnames(
            ldap_ip=ldap_ip,
            ldap_hostname=ldap_hostname,
            kdc_ip=kdc_ip,
            kdc_hostname=kdc_hostname,
        )
        self._probe_kdc_port(kdc_ip, kdc_hostname, kdc_port)

        if used_local_named:
            local_dns = "127.0.0.1"
            if not (self.has_srv_record(ldap_srv, local_dns) and self.has_srv_record(krb_srv, local_dns)):
                dig_ldap = self.host.conn.run(
                    f"dig +norecurse @{local_dns} {ldap_srv} SRV",
                    raise_on_error=False,
                )
                dig_krb = self.host.conn.run(
                    f"dig +norecurse @{local_dns} {krb_srv} SRV",
                    raise_on_error=False,
                )
                raise RuntimeError(
                    f"SRV records for {discovery_domain} are not visible on @{local_dns} after "
                    f"local named setup ({ldap_srv}, {krb_srv}); "
                    f"dig ldap: {(dig_ldap.stdout or dig_ldap.stderr or '')[-500:]}; "
                    f"dig krb: {(dig_krb.stdout or dig_krb.stderr or '')[-500:]}"
                )

    def setup_sasl_canonicalize_bogus_ptr(
        self,
        *,
        ldap_hostname: str,
        kdc_hostname: str,
        provider_domain: str,
        client_hostname: str,
        ldap_ip: str | None = None,
        kdc_ip: str | None = None,
        ldap_host: object | None = None,
        kdc_host: object | None = None,
        bogus_label: str = "invalid",
    ) -> tuple[str, str]:
        """
        Configure bogus LDAP PTR and local DNS (ldap_sasl_canonicalize).

        Resolves LDAP and KDC IPv4 on this host when ldap_ip/kdc_ip are omitted
        (multihost host.ip, else getent ahostsv4). Runs named on 127.0.0.1,
        wrong PTR for ldap_ip, forward A for LDAP, and pins KDC in /etc/hosts.

        :param ldap_hostname: Real LDAP FQDN (Kerberos service name / forward A record).
        :type ldap_hostname: str
        :param kdc_hostname: KDC FQDN pinned in /etc/hosts.
        :type kdc_hostname: str
        :param provider_domain: LDAP DNS domain (e.g. ldap.test).
        :type provider_domain: str
        :param client_hostname: This host FQDN (SOA/NS in zone files).
        :type client_hostname: str
        :param ldap_ip: LDAP server IPv4 address; resolved when omitted.
        :type ldap_ip: str | None, optional
        :param kdc_ip: KDC IPv4 address; resolved when omitted.
        :type kdc_ip: str | None, optional
        :param ldap_host: LDAP role host for multihost host.ip lookup.
        :type ldap_host: object | None, optional
        :param kdc_host: KDC role host for multihost host.ip lookup.
        :type kdc_host: object | None, optional
        :param bogus_label: Leftmost PTR label (default invalid -> invalid.ldap.test).
        :type bogus_label: str, optional
        :return: Resolved (ldap_ip, kdc_ip) used for the setup.
        :rtype: tuple[str, str]
        :raises RuntimeError: if resolution, bind install, or DNS lookups fail.
        """
        if ldap_ip is None:
            ldap_ip = self._role_ipv4(ldap_hostname, role_host=ldap_host, label="LDAP host")
        if kdc_ip is None:
            kdc_ip = self._role_ipv4(kdc_hostname, role_host=kdc_host, label="KDC host")
        if self.host.conn.run("rpm -q bind", raise_on_error=False).rc != 0:
            self.host.conn.run(
                "dnf install -y bind bind-utils || yum install -y bind bind-utils",
                raise_on_error=False,
            )
        assert (
            self.host.conn.run("rpm -q bind", raise_on_error=False).rc == 0
        ), "bind package is required (dnf install -y bind bind-utils)"

        bogus_hostname = f"{bogus_label}.{provider_domain}"
        ldap_short = ldap_hostname.removesuffix(f".{provider_domain}").rstrip(".")

        self.fs.backup("/etc/hosts")
        hosts_lines: list[str] = []
        for line in self.fs.read("/etc/hosts").splitlines():
            parts = line.split()
            if len(parts) >= 1 and parts[0] == ldap_ip:
                continue
            if len(parts) >= 2 and (ldap_hostname in parts[1:] or bogus_hostname in parts[1:]):
                continue
            if len(parts) >= 2 and kdc_hostname in parts[1:]:
                continue
            hosts_lines.append(line)
        hosts_lines.append(f"{ldap_ip}\t{bogus_hostname}")
        hosts_lines.append(f"{kdc_ip}\t{kdc_hostname}")
        self.fs.write("/etc/hosts", "\n".join(hosts_lines).rstrip() + "\n")
        self.host.conn.run("nscd -i hosts 2>/dev/null || true", raise_on_error=False)

        reverse_zone = ip_to_ptr(ldap_ip)
        ptr_label = ldap_ip.rsplit(".", maxsplit=1)[-1]
        reverse_zone_path = f"/var/named/{reverse_zone}"
        forward_zone_path = f"/var/named/{provider_domain}"

        self.fs.backup("/etc/resolv.conf")
        self.fs.backup("/etc/named.conf")
        self.fs.backup(reverse_zone_path)
        self.fs.backup(forward_zone_path)

        def zone_block(zone_name: str, zone_file: str) -> str:
            """
            Return a named.conf stanza for a master zone file.

            :param zone_name: Zone name (e.g. ldap.test).
            :type zone_name: str
            :param zone_file: Zone file basename under /var/named/.
            :type zone_file: str
            :return: named.conf zone stanza text.
            :rtype: str
            """
            return (
                f'zone "{zone_name}" {{\n'
                "    type master;\n"
                "    check-names ignore;\n"
                f'    file "{zone_file}";\n'
                "};\n"
            )

        named_conf = self.fs.read("/etc/named.conf")
        for zone_name, zone_file in (
            (reverse_zone, reverse_zone),
            (provider_domain, provider_domain),
        ):
            if zone_name not in named_conf:
                named_conf += zone_block(zone_name, zone_file)
        self.fs.write("/etc/named.conf", named_conf)

        upstream_ips: list[str] = []
        for line in self.fs.read("/etc/resolv.conf").splitlines():
            stripped = line.strip()
            if stripped.startswith("nameserver ") and "127.0.0.1" not in stripped:
                upstream_ips.append(stripped.split()[1])
        _inject_named_forwarders(self.fs, upstream_ips)

        soa_lines = (
            "$TTL 604800\n"
            f"$ORIGIN {provider_domain}.\n"
            f"@ IN SOA {client_hostname}. root.{client_hostname}. (\n"
            "    2010050702 ; serial\n"
            "    604800 ; refresh\n"
            "    86400 ; retry\n"
            "    2419200 ; expire\n"
            "    10800 ; negative caching time\n"
            "    )\n"
            f"@ IN NS {client_hostname}.\n"
        )
        reverse_soa = soa_lines.replace(f"$ORIGIN {provider_domain}.\n", f"$ORIGIN {reverse_zone}.\n")
        self.fs.write(
            reverse_zone_path,
            reverse_soa + f"{ptr_label} IN PTR {bogus_hostname}.\n",
        )
        self.fs.write(
            forward_zone_path,
            soa_lines + f"{ldap_short} IN A {ldap_ip}\n",
        )
        self.host.conn.run(
            f"restorecon -v {reverse_zone_path} {forward_zone_path}",
            raise_on_error=False,
        )

        self.host.conn.run("systemctl enable named", raise_on_error=False)
        named_restart = self.host.conn.run("systemctl restart named", raise_on_error=False)
        if named_restart.rc != 0:
            journal = self.host.conn.run(
                "journalctl -u named -n 30 --no-pager",
                raise_on_error=False,
            )
            assert False, (
                "systemctl restart named failed; " f"journal: {(journal.stdout or journal.stderr or '')[-2000:]}"
            )

        self.fs.write("/etc/resolv.conf", "nameserver 127.0.0.1\n")
        self.host.conn.run("restorecon -v /etc/resolv.conf", raise_on_error=False)
        self.host.conn.run("nscd -i hosts 2>/dev/null || true", raise_on_error=False)

        ptr_result = self.dig(ldap_ip, "127.0.0.1")
        assert ptr_result, f"dig -x {ldap_ip} @127.0.0.1 returned no PTR"
        assert any(
            bogus_hostname in str(record.get("data", "")) for record in ptr_result
        ), f"PTR for {ldap_ip} via 127.0.0.1 is not {bogus_hostname}"

        a_result = self.dig(ldap_hostname, "127.0.0.1")
        assert a_result and any(
            record.get("type") == "A" and str(record.get("data")) == ldap_ip for record in a_result
        ), (f"no local A record for {ldap_hostname} via 127.0.0.1 " f"(zone {provider_domain}, record {ldap_short})")

        rev_nss = self.host.conn.run(f"getent hosts {ldap_ip}", raise_on_error=False)
        rev_out = rev_nss.stdout or ""
        assert (
            ldap_hostname not in rev_out
        ), f"{ldap_ip} must not reverse-resolve to {ldap_hostname}; getent hosts: {rev_out.strip()!r}"
        assert (
            bogus_hostname in rev_out
        ), f"{ldap_ip} must reverse-resolve to {bogus_hostname}; getent hosts: {rev_out.strip()!r}"

        if self._resolve_host_ipv4(ldap_hostname) != ldap_ip:
            raise RuntimeError(f"forward lookup for {ldap_hostname} must return {ldap_ip}")
        if self._resolve_host_ipv4(kdc_hostname) != kdc_ip:
            raise RuntimeError(f"forward lookup for {kdc_hostname} must return {kdc_ip}")

        return ldap_ip, kdc_ip

    def teardown(self):
        """
        Revert all changes.

        :meta private:
        """
        errors = []
        for ip in self.__ips:
            try:
                ip.teardown()
            except Exception as e:
                self.logger.warning("Failed to teardown %s: %s", ip, e)
                errors.append({"ip": ip, "error": e})

        cmd = "\n".join(reversed(self.__rollback))
        if cmd:
            self.host.conn.run(cmd)

        if errors:
            raise ExceptionGroup(errors)
        super().teardown()


class IPUtils(MultihostUtility[MultihostHost]):
    """
    IP  utilities.

    .. code-block:: python
        :caption: Example usage

        # Create dummy interfaces
        client.net.ip(name="dummy0").add_device(ip="172.16.2.40", netmask="255.255.255.0")
        client.net.ip(name="dummy0").add_device(ip="172.16.2.40", netmask="24")
        client.net.ip(name="dummy0").add_device(ip="172.16.2.40")

        # Get default device
        default_device  = client.net.ip().default_device

        # Get default gateway
        gateway_ip = client.net.ip().default_gateway
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem, name: str | None) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        :param fs: File system object.
        :type fs: LinuxFileSystem
        :param name: Name of interface.
        :type name: str | None
        """
        super().__init__(host)

        self._name: str | None = name
        """Device name."""

        self._ifconfig_stdout: Any | None = None
        """Ifconfig output."""

        self.default_device: Any | None = self._get_route()[0]
        """Default device."""

        self.default_gateway: Any | None = self._get_route()[1]
        """Default gateway."""

        self.__fs: LinuxFileSystem = fs
        self.__rollback: list[str] = []

    @property
    def name(self) -> Any | None:
        """Device name."""
        if self._name is not None:
            return self._name
        else:
            self._name = self.default_device
            return self._name

    def _get(self, args: list[str] | None = None) -> dict[str, Any | None]:
        """
        Get and parses ifconfig output.

        :param args: List of keys to return, defaults to None
        :type args: list[str] | None, optional
        :return: Keys and values.
        :rtype: dict[str, Any | None]
        """
        if self._ifconfig_stdout is not None:
            result = self._ifconfig_stdout
        else:
            result = jc.parse("ifconfig", self.host.conn.exec(["ifconfig", "-a"]).stdout)
            self._ifconfig_stdout = result

        parsed_results = {}
        if isinstance(result, list) and len(result) > 0:
            for i in result:
                if isinstance(i, dict) and self.name == i.get("name"):
                    if args is None:
                        return i
                    else:
                        for y in args:
                            parsed_results[y] = i.get(y)

        return parsed_results

    def _get_route(self) -> tuple[Any | None, Any | None]:
        """
        Get default gateway device name and ip.

        :return: Default gateway  device name and ip.
        :rtype: tuple[Any | None, Any | None]
        """
        device_name = None
        device_ip = None

        result = jc.parse("ip-route", self.host.conn.exec(["ip", "route"]).stdout)
        if isinstance(result, list):
            if isinstance(result[0], dict) and result[0]["ip"] == "default":
                device_name = result[0].get("dev")
                device_ip = result[0].get("via")

        return device_name, device_ip

    @property
    def nameservers(self) -> Any | None:
        """Get nameservers."""
        result = jc.parse("resolve-conf", self.host.conn.exec(["cat", "/etc/resolv.conf"]).stdout)
        if not isinstance(result, dict):
            raise TypeError("Nameservers is the wrong type, expecting a dictionary!")
        else:
            nameservers = result.get("nameservers")
            return nameservers

    @property
    def address(self) -> Any | None:
        """Get ipv4 address."""
        return self._get(["ipv4_addr"]).get("ipv4_addr")

    @property
    def addresses(self) -> tuple[Any | None, Any | None]:
        """Get ipv4 and ipv6 addresses."""
        ipv4 = self._get(["ipv4_addr"]).get("ipv4_addr")
        ipv6 = self._get(["ipv6_addr"]).get("ipv6_addr")
        return ipv4, ipv6

    @property
    def netmask(self) -> str | None:
        """Get network mask."""
        netmask = self._get(["ipv4_mask"]).get("ipv4_mask")
        return netmask if netmask is not None else None

    def add_device(self, ip: str, netmask: str = "255.255.255.0") -> IPUtils:
        """
        Add and create a link to a dummy device.This is used by dyndns tests.

        :param ip: IP address.
        :type ip: str
        :param netmask: IP network mask, defaults to 255.255.255.0
        :type netmask: str, optional
        :return: IPUtils object.
        :rtype: IPUtils
        """
        if self.name != self.default_device or self.name is not None:
            self.host.conn.exec(["ip", "link", "add", self.name, "type", "dummy"])
            self.host.conn.exec(["ip", "addr", "add", f"{ip}/{netmask}", "dev", self.name])
            self.__rollback.append(f"ip link del {self.name}")
            return self
        else:
            raise Exception(f"Modifying the default {self.name} will render the system unresponsive!")

    def teardown(self):
        """
        Revert all changes.

        :meta private:
        """
        cmd = "\n".join(reversed(self.__rollback))
        if cmd:
            self.host.conn.run(cmd)

        super().teardown()
