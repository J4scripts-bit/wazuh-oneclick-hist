#!/usr/bin/env python3
"""One-command historical Ubuntu -> Wazuh Indexer evidence collection and import.

Run on your trusted Wazuh Ubuntu/WSL workstation:
    python3 wazuh_oneclick_import.py

Uses ONLY Python's standard library and local OpenSSH.
OpenSSH prompts for USER SSH password once, securely, using the TTY.
If sudo requires a separate password, prompts securely after a failed
non-interactive sudo attempt and sends it through SSH's encrypted stdin.
Indexer credentials are prompted by getpass. Passwords are never saved.

Collects an immutable-ish local copy of /var/log and a journald export;
calculates hashes; unpacks SELECTED files safely; prepares and uploads
Apache access/error, supported Linux system/journald log events, and a catch-all
index for other readable /var/log text records. Binary files remain in original tar
and are inventoried, not silently declared indexed.

WARNING: Bulk indexing does NOT run Wazuh manager detection rules, and
not every log format is parsed. This is an investigation/search foundation.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import datetime as dt
import getpass
import gzip
import hashlib
import ipaddress
import io
import bz2
import lzma
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo

USER = 'USERNAME'
TZ = ZoneInfo('TIMEZONE')
APACHE_ACCESS = re.compile(r'^(?:(?P<vhost>\S+)\s+)?(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>(?:\\.|[^"\\])*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\d+|-)\s*(?:"(?P<ref>(?:\\.|[^"\\])*)"\s+"(?P<ua>(?:\\.|[^"\\])*)")?.*$')
APACHE_ERROR = re.compile(r'^\[(?P<time>[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d(?:\.\d+)?\s+\d{4})\]\s+(?P<details>.*)$')
SYSLOG = re.compile(r'^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)\s+(?P<src>\S+)\s+(?P<msg>.*)$')
DPKG = re.compile(r'^(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)\s+(.*)$')
SYSTEM_NAMES = re.compile(r'^(?:(?:auth|kern|daemon|user|cron|ufw|mail)\.log|(?:syslog|messages|debug))(?:\.\d+)?(?:\.gz)?$|^dpkg\.log(?:\.\d+)?(?:\.gz)?$')
INDEX_MAPPING = {
    'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    'mappings': {'properties': {
        '@timestamp': {'type': 'date'},
        'host': {'properties': {'name': {'type': 'keyword'}}},
        'event': {'properties': {'dataset': {'type': 'keyword'}, 'kind': {'type': 'keyword'}, 'original': {'type': 'text'}}},
        'historical': {'properties': {'imported_offline': {'type': 'boolean'}, 'original_timestamp': {'type': 'date'}, 'timestamp_inferred': {'type': 'boolean'}, 'source_collection': {'type': 'keyword'}}},
        'log': {'properties': {'file': {'properties': {'path': {'type': 'keyword'}}}, 'offset_line': {'type': 'long'}}},
        'source': {'properties': {'ip': {'type': 'keyword'}}},
        'http': {'properties': {'request': {'properties': {'method': {'type': 'keyword'}, 'referrer': {'type': 'text'}}}, 'response': {'properties': {'status_code': {'type': 'integer'}, 'body': {'properties': {'bytes': {'type': 'long'}}}}}}},
        'labels': {'properties': {'virtual_host': {'type': 'keyword'}, 'virtual_host_from_filename': {'type': 'keyword'}}},
        'url': {'properties': {'original': {'type': 'keyword', 'ignore_above': 8191}}},
        'message': {'type': 'text'},
        'raw_bytes_base64': {'type': 'binary'},
        'source_archive': {'type': 'keyword'},
        'journald': {'properties': {'raw_fields_json': {'type': 'text'}}},
        'user_agent': {'properties': {'original': {'type': 'text'}}},
        'process': {'properties': {'name': {'type': 'keyword'}, 'pid': {'type': 'long'}}},
        'systemd': {'properties': {'unit': {'type': 'keyword'}}},
    }}
}


def say(msg):
    print(msg, flush=True)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def prompt_inputs():
    while True:
        host = input('Server name (e.g. SERVER01): ').strip().lower()
        if re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', host):
            break
        say('Invalid server name. Use letters, numbers, dash and underscore.')
    while True:
        addr = input('Server IP address: ').strip()
        if valid_ip(addr):
            break
        say('Please enter a valid IPv4 or IPv6 address.')
    while True:
        choice = input('How far back? Days [30], or "all" for all retained history: ').strip().lower() or '30'
        if choice == 'all':
            start = end = None
            break
        if choice.isdigit() and 1 <= int(choice) <= 3650:
            today = dt.datetime.now(TZ).date()
            start = today - dt.timedelta(days=int(choice)-1)
            end = today + dt.timedelta(days=1)
            break
        say('Enter a positive number of days or all.')
    return host, addr, start, end


class MasterSSH:
    def __init__(self, addr, port):
        self.addr, self.port = addr, port
        self.dir = None
        self.sock = None
        self.target = f'{USER}@{addr}'

    def __enter__(self):
        require(shutil.which('ssh') is not None, 'OpenSSH client not found. Install openssh-client.')
        self.dir = tempfile.TemporaryDirectory(prefix='wzh-ssh-')
        self.sock = str(Path(self.dir.name) / 'control.sock')
        say(f'\nConnecting to {self.target} ...')
        say('OpenSSH will prompt for the SSH password and possibly the host-key fingerprint.')
        args = ['ssh', '-M', '-N', '-f', '-S', self.sock, '-p', str(self.port),
                '-o', 'ControlMaster=yes', '-o', 'ControlPersist=no',
                '-o', 'StrictHostKeyChecking=ask', '-o', 'ConnectTimeout=20',
                self.target]
        result = subprocess.run(args, check=False)
        require(result.returncode == 0, 'SSH login failed. No evidence was collected.')
        check = subprocess.run(['ssh', '-S', self.sock, '-p', str(self.port), '-O', 'check', self.target],
                               capture_output=True, text=True, check=False)
        require(check.returncode == 0, 'SSH multiplexed connection unavailable: ' + check.stderr.strip())
        return self

    def command(self, remote, dest=None, *, input_data=None):
        """Run a remote command. Keep sudo password out of argv/logs/files.

        For large evidence streams, stdout goes to a .partial file which is
        atomically renamed only when the remote command succeeds.
        """
        args = ['ssh', '-T', '-S', self.sock, '-p', str(self.port),
                '-o', 'BatchMode=yes', self.target, remote]
        if dest is None:
            return subprocess.run(args, input=input_data, capture_output=True, check=False)
        partial = dest.with_name(dest.name + '.partial')
        try:
            with partial.open('wb') as out:
                result = subprocess.run(args, input=input_data, stdout=out,
                                        stderr=subprocess.PIPE, check=False)
            if result.returncode == 0 and partial.stat().st_size > 0:
                os.replace(partial, dest)
            elif result.returncode == 0:
                result = subprocess.CompletedProcess(args, 1, stdout=None,
                        stderr=b'Remote command returned empty output')
            return result
        finally:
            partial.unlink(missing_ok=True)

    def sudo_command(self, remote, dest=None):
        """Try sudo -n, and request a sudo password only when required.

        The password goes only over SSH stdin to sudo -S, never into a
        command string, argv, environment variable or evidence file.
        """
        if not hasattr(self, '_sudo_password'):
            self._sudo_password = None

        if self._sudo_password is None:
            result = self.command('sudo -n -- ' + remote, dest)
            if result.returncode == 0:
                return result
            reason = (result.stderr or b'').decode('utf-8', 'replace')
            requires_password = ('password is required' in reason.lower() or
                                 'a terminal is required' in reason.lower() or
                                 'no tty present' in reason.lower())
            require(requires_password,
                    f'Remote sudo command failed (exit {result.returncode}): {reason.strip()[:700]}')
            say('The SSH login succeeded, but this server requires a sudo password.')
            self._sudo_password = getpass.getpass(f'Sudo password for {self.target}: ')
            require(bool(self._sudo_password), 'Sudo password cannot be empty.')

        result = self.command('sudo -S -p \'\' -- ' + remote, dest,
                              input_data=(self._sudo_password + '\n').encode('utf-8'))
        if result.returncode != 0:
            reason = (result.stderr or b'').decode('utf-8', 'replace').strip()
            raise RuntimeError(f'Remote sudo command failed (exit {result.returncode}): {reason[:700]}')
        return result

    def __exit__(self, *_):
        self._sudo_password = None
        if self.sock:
            subprocess.run(['ssh', '-S', self.sock, '-p', str(self.port), '-O', 'exit', self.target],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if self.dir:
            self.dir.cleanup()


def collect(host, addr, port, raw_dir):
    raw_dir.mkdir(parents=True, exist_ok=False)
    with MasterSSH(addr, port) as ssh:
        info = ssh.command('hostname -s; hostname -f; date -u +%FT%TZ; date +%z')
        require(info.returncode == 0, 'Could not read remote hostname.')
        desc = info.stdout.decode('utf-8', 'replace').strip().splitlines()
        remote_host = desc[0].strip().lower() if desc else '?'
        require(remote_host == host,
                f'Remote server identifies as {remote_host!r}, not {host!r}. Aborting to prevent mislabeled evidence.')
        details = 'Target IP: '+addr+'\nSSH user: '+USER+'\nCollection start UTC: '+dt.datetime.now(dt.timezone.utc).isoformat()+'\n'+'\n'.join(desc)+'\n'
        (raw_dir / 'collection-metadata.txt').write_text(details, encoding='utf-8')
        say('Collecting /var/log (including Apache, rotated .gz and OS logs)...')
        ssh.sudo_command('tar -C / -cf - var/log', raw_dir / 'var-log.tar')
        say('Exporting complete available systemd journal...')
        ssh.sudo_command('journalctl --output=export --no-pager', raw_dir / 'journal.export')
        vhost = ssh.sudo_command('apache2ctl -S')
        (raw_dir / 'apache-vhosts.txt').write_bytes(vhost.stdout + b'\n' + vhost.stderr)
    sums = []
    for name in ('var-log.tar', 'journal.export', 'collection-metadata.txt', 'apache-vhosts.txt'):
        file = raw_dir / name
        if file.exists():
            sums.append(f'{sha256(file)}  {name}')
    (raw_dir / 'SHA256SUMS').write_text('\n'.join(sums)+'\n', encoding='utf-8')
    say('Evidence archive saved, with SHA-256 checksums.')


def check_archive(raw_dir):
    import shlex
    sums = raw_dir / 'SHA256SUMS'
    require(sums.exists(), 'Missing SHA256SUMS, cannot safely reuse collection.')
    for line in sums.read_text(encoding='utf-8').splitlines():
        hexhash, name = line.split('  ', 1)
        require(sha256(raw_dir / name) == hexhash, f'Checksum mismatch: {name}')
    require((raw_dir / 'var-log.tar').is_file(), 'Missing var-log.tar')
    require((raw_dir / 'journal.export').is_file(), 'Missing journal.export')
    say('Evidence checksums verified.')


def wanted_member(p):
    parts = p.parts
    if len(parts) < 3 or parts[:2] != ('var','log'):
        return False
    if len(parts) >= 4 and parts[2] == 'apache2':
        return True
    if len(parts) == 3 and SYSTEM_NAMES.fullmatch(parts[2]):
        return True
    return False


def safe_extract(raw_dir, work_dir):
    """Manually extract only regular files we can parse, never archive symlinks."""
    extracted = skipped = 0
    unsupported = []
    root = work_dir / 'var' / 'log'
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(raw_dir / 'var-log.tar', 'r:') as tf:
        for member in tf:
            p = PurePosixPath(member.name)
            if member.isdir():
                continue
            if p.is_absolute() or '..' in p.parts or not wanted_member(p):
                skipped += 1
                if member.isfile():
                    unsupported.append(member.name)
                continue
            if not member.isfile():
                skipped += 1
                continue
            dest = work_dir.joinpath(*p.parts)
            require(dest.resolve().is_relative_to(work_dir.resolve()), 'Unsafe archive path: '+member.name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            require(src is not None, 'Cannot extract '+member.name)
            with src, dest.open('wb') as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)
            os.utime(dest, (member.mtime, member.mtime))
            extracted += 1
    (work_dir / 'unsupported-archive-files.txt').write_text('\n'.join(unsupported) + ('\n' if unsupported else ''), encoding='utf-8')
    say(f'Extracted {extracted} supported log files; {skipped} other archive entries remain preserved in original tar.')
    return root


def iter_lines(file):
    opener = gzip.open if file.name.endswith('.gz') else open
    with opener(file, 'rt', encoding='utf-8', errors='replace') as stream:
        for number, text in enumerate(stream, 1):
            yield number, text.rstrip('\r\n')


def parse_apache(line):
    m = APACHE_ACCESS.match(line)
    if m:
        d = m.groupdict()
        try:
            stamp = dt.datetime.strptime(d['time'], '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            stamp = None
        if stamp and (not d['vhost'] or (':' in d['vhost'] or '.' in d['vhost'])):
            fields = {'source': {'ip': d['ip']}}
            http = {}
            if d['status'].isdigit():
                http['response'] = {'status_code': int(d['status'])}
            req = d['request'].split(' ', 2)
            if len(req) >= 2:
                http['request'] = {'method': req[0]}
                fields['url'] = {'original': req[1]}
            if d['size'].isdigit():
                http.setdefault('response', {})['body'] = {'bytes': int(d['size'])}
            if d['ref'] is not None:
                http.setdefault('request', {})['referrer'] = d['ref']
            if d['ua'] is not None:
                fields['user_agent'] = {'original': d['ua']}
            if d['vhost']:
                fields['labels'] = {'virtual_host': d['vhost']}
            if http:
                fields['http'] = http
            return stamp, 'apache.access', fields
    m = APACHE_ERROR.match(line)
    if m:
        for fmt in ('%a %b %d %H:%M:%S.%f %Y', '%a %b %d %H:%M:%S %Y'):
            try:
                return dt.datetime.strptime(m['time'], fmt).replace(tzinfo=TZ), 'apache.error', {}
            except ValueError:
                continue
    return None


def filename_vhost(name):
    name = re.sub(r'\.\d+(?:\.gz)?$|\.gz$', '', name)
    for suffix in ('-access.log','-error.log','.access.log','.error.log','-access','-error'):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return None


def syslog_timestamp(m, filemtime):
    try:
        clock = dt.datetime.strptime('2000 '+m['mon']+' '+m['day']+' '+m['clock'], '%Y %b %d %H:%M:%S')
        variants = [clock.replace(year=y, tzinfo=TZ) for y in (filemtime.year-1,filemtime.year,filemtime.year+1)]
        return min(variants, key=lambda x: abs((x-filemtime).total_seconds()))
    except (ValueError, OverflowError):
        return None


def records_from_journal_export(path):
    with path.open('rb') as stream:
        attrs, entry_no = {}, 0
        while True:
            line = stream.readline()
            if not line:
                if attrs:
                    yield entry_no+1, attrs
                break
            if line == b'\n':
                if attrs:
                    entry_no += 1
                    yield entry_no, attrs
                    attrs = {}
                continue
            key_line = line.rstrip(b'\n')
            if b'=' in key_line:
                key, val = key_line.split(b'=',1)
            else:
                key = key_line
                length_bytes = stream.read(8)
                require(len(length_bytes) == 8, 'Truncated journal export binary length')
                length = int.from_bytes(length_bytes, 'little')
                require(length <= 100_000_000, 'Oversized journal export field')
                val = stream.read(length)
                require(len(val) == length and stream.read(1) == b'\n', 'Truncated binary journal field')
            attrs[key.decode('utf-8','replace')] = val.decode('utf-8','replace')


def event_writer(root, host, typ, start, end):
    index = f'wazuh-historical-{typ}-{host}'
    outpath = root / f'{host}-{typ}.ndjson'
    unparsed = root / f'{host}-{typ}-unparsed.jsonl'
    stats = Counter({'files': 0, 'lines': 0, 'indexed': 0, 'unparsed': 0, 'outside_window': 0, 'journal_records': 0})

    def in_window(t):
        day = t.astimezone(TZ).date()
        return (start is None or day >= start) and (end is None or day < end)

    with outpath.open('w', encoding='utf-8') as out, unparsed.open('w', encoding='utf-8') as rej:
        def emit(doc, stableid):
            out.write(json.dumps({'index':{'_index':index, '_id':stableid}},ensure_ascii=False)+'\n')
            out.write(json.dumps(doc,ensure_ascii=False)+'\n')
            stats['indexed'] += 1
        def bad(name, no, raw):
            stats['unparsed'] += 1
            rej.write(json.dumps({'host': host, 'file': name, 'line': no, 'event': raw},ensure_ascii=False)+'\n')
        if typ == 'apache':
            apache = root / 'var' / 'log' / 'apache2'
            if not apache.is_dir():
                say('No /var/log/apache2 in archive; Apache import skipped.')
            else:
                for path in sorted(apache.iterdir()):
                    if not path.is_file() or not ('.log' in path.name or path.name.endswith(('.gz','-error','-access'))):
                        continue
                    stats['files'] += 1
                    try:
                        for no, raw in iter_lines(path):
                            stats['lines'] += 1
                            if not raw:
                                continue
                            parsed = parse_apache(raw)
                            if not parsed:
                                bad('/var/log/apache2/'+path.name, no, raw)
                                continue
                            stamp, dataset, fields = parsed
                            if not in_window(stamp):
                                stats['outside_window'] += 1
                                continue
                            source = '/var/log/apache2/'+path.name
                            doc = {'@timestamp': stamp.isoformat(),'host': {'name':host},'event':{'dataset': dataset,'kind':'event','original':raw},'log':{'file':{'path':source},'offset_line':no},'historical':{'imported_offline':True,'original_timestamp':stamp.isoformat()},**fields}
                            if not doc.get('labels',{}).get('virtual_host'):
                                vhost = filename_vhost(path.name)
                                if vhost:
                                    doc.setdefault('labels',{})['virtual_host_from_filename'] = vhost
                            eventid = hashlib.sha256(f'{host}\0{source}\0{no}\0{raw}'.encode()).hexdigest()
                            emit(doc,eventid)
                    except (OSError, EOFError, UnicodeError) as exc:
                        raise RuntimeError(f'Apache log processing failed for {path}: {exc}') from exc
        else:
            journal = root.parent / 'original' / 'journal.export'
            if journal.is_file() and journal.stat().st_size:
                for no, rec in records_from_journal_export(journal):
                    stats['lines'] += 1
                    stats['journal_records'] += 1
                    try:
                        stamp = dt.datetime.fromtimestamp(int(rec['__REALTIME_TIMESTAMP']) / 1_000_000, tz=dt.timezone.utc)
                    except (KeyError, ValueError, OverflowError):
                        bad('journal.export', no, str(rec)[:8000]); continue
                    if not in_window(stamp):
                        stats['outside_window'] += 1; continue
                    msg = rec.get('MESSAGE','')
                    doc = {'@timestamp': stamp.isoformat(), 'host': {'name':host},'event':{'dataset':'linux.journald','kind':'event','original':msg}, 'message':msg,
                           'historical':{'imported_offline':True,'original_timestamp':stamp.isoformat(),'timestamp_inferred':False,'source_collection':'journal.export'},
                           'log':{'file':{'path':'journal.export'},'offset_line':no},
                           'journald': {'raw_fields_json': json.dumps(rec, ensure_ascii=False)}}
                    proc = rec.get('SYSLOG_IDENTIFIER') or rec.get('_COMM')
                    if proc:
                        doc['process']={'name':proc}
                    if (rec.get('_PID') or '').isdigit():
                        doc.setdefault('process',{})['pid']=int(rec['_PID'])
                    if rec.get('_SYSTEMD_UNIT'):
                        doc['systemd']={'unit':rec['_SYSTEMD_UNIT']}
                    sid=hashlib.sha256((host+'\0journald\0'+(rec.get('__CURSOR') or stamp.isoformat()+msg)).encode()).hexdigest()
                    emit(doc,sid)
            log_root = root / 'var' / 'log'
            for path in sorted(log_root.iterdir()):
                if not path.is_file() or not SYSTEM_NAMES.fullmatch(path.name):
                    continue
                stats['files'] += 1
                dataset = 'linux.dpkg' if path.name.startswith('dpkg.log') else 'linux.syslog'
                filemtime = dt.datetime.fromtimestamp(path.stat().st_mtime, TZ)
                source = '/var/log/'+path.name
                try:
                    for no, raw in iter_lines(path):
                        stats['lines'] += 1
                        if not raw: continue
                        fields = {}
                        inferred = True
                        if dataset == 'linux.dpkg':
                            m = DPKG.match(raw)
                            inferred = False
                            try:
                                stamp = dt.datetime.strptime(m.group(1)+' '+m.group(2),'%Y-%m-%d %H:%M:%S').replace(tzinfo=TZ) if m else None
                            except ValueError:
                                stamp = None
                        else:
                            m = SYSLOG.match(raw)
                            stamp = syslog_timestamp(m, filemtime) if m else None
                            if m:
                                fields['message'] = m['msg']
                        if stamp is None:
                            bad(source, no, raw);continue
                        if not in_window(stamp):
                            stats['outside_window'] += 1;continue
                        doc = {'@timestamp':stamp.isoformat(),'host':{'name':host},'event':{'dataset':dataset,'kind':'event','original':raw},
                               'historical':{'imported_offline':True,'original_timestamp':stamp.isoformat(),'timestamp_inferred':inferred,'source_collection':'var-log-text'},
                               'log':{'file':{'path':source},'offset_line':no}, **fields}
                        sid=hashlib.sha256(f'{host}\0{source}\0{no}\0{raw}'.encode()).hexdigest()
                        emit(doc,sid)
                except (OSError, EOFError, UnicodeError) as exc:
                    raise RuntimeError(f'System log processing failed for {path}: {exc}') from exc
    say(f'{typ.upper()}: files={stats["files"]}, input_lines={stats["lines"]}, prepared={stats["indexed"]}, unparsed={stats["unparsed"]}, outside_window={stats["outside_window"]}')
    return outpath, index, dict(stats)


# Catch-all ingestion: the structured writers above cover certain formats.
# To avoid indexing all 2m+ Apache lines twice, this writer indexes every OTHER
# readable text record (including rejected lines from recognized log files).
# The source tar remains the canonical complete evidence archive.

def write_catchall(raw_dir, work_dir, host, start, end, *, everything=False):
    import fnmatch
    index = f'wazuh-historical-raw-{host}'
    output = work_dir / f'{host}-raw.ndjson'
    manifest_path = work_dir / f'{host}-file-coverage.json'
    stats = Counter({'files_seen': 0, 'text_files': 0, 'raw_records': 0,
                     'structured_records': 0, 'outside_window': 0,
                     'empty_lines': 0, 'binary_files': 0, 'symlinks': 0,
                     'decode_replacements': 0})
    manifest = []
    capture_stamp = dt.datetime.now(dt.timezone.utc).isoformat()

    def in_window(stamp):
        day = stamp.astimezone(TZ).date()
        return (start is None or day >= start) and (end is None or day < end)

    def parsed_known(source, raw, modtime):
        # True means another structured index has already received this record,
        # or it was intentionally excluded by the selected investigation dates.
        if source.startswith('/var/log/apache2/'):
            # The structured Apache parser considers these filenames only.
            p = Path(source)
            if '.log' in p.name or p.name.endswith(('.gz', '-error', '-access')):
                parsed = parse_apache(raw)
                if parsed is not None:
                    return ('structured' if in_window(parsed[0]) else 'outside')
        p = Path(source)
        if p.parent.as_posix() == '/var/log' and SYSTEM_NAMES.fullmatch(p.name):
            if p.name.startswith('dpkg.'):
                m = DPKG.match(raw)
                stamp = None
                if m:
                    try:
                        stamp = dt.datetime.strptime(m.group(1)+' '+m.group(2), '%Y-%m-%d %H:%M:%S').replace(tzinfo=TZ)
                    except ValueError:
                        pass
            else:
                m = SYSLOG.match(raw)
                stamp = syslog_timestamp(m, modtime) if m else None
            if stamp is not None:
                return ('structured' if in_window(stamp) else 'outside')
        return 'raw'

    def open_text_stream(src, name):
        if name.endswith('.gz'):
            obj = gzip.GzipFile(fileobj=src, mode='rb')
        elif name.endswith('.bz2'):
            obj = bz2.BZ2File(src, mode='rb')
        elif name.endswith(('.xz', '.lzma')):
            obj = lzma.LZMAFile(src, mode='rb')
        else:
            obj = src
        return io.BufferedReader(obj, buffer_size=128*1024)

    with output.open('w', encoding='utf-8') as out, tarfile.open(raw_dir / 'var-log.tar', 'r:') as tf:
        for member in tf:
            # Tar was created as `tar -C / -cf - var/log`.
            p = PurePosixPath(member.name)
            if p.is_absolute() or '..' in p.parts or p.parts[:2] != ('var', 'log'):
                raise RuntimeError('Unexpected/unsafe archive entry: '+member.name)
            if member.isdir():
                continue
            if member.issym():
                stats['symlinks'] += 1
                manifest.append({'file': '/' + member.name, 'status': 'symlink_archived_not_followed',
                                 'link': member.linkname})
                continue
            if not member.isfile():
                manifest.append({'file': '/' + member.name, 'status': 'non_regular_archived_only'})
                continue
            stats['files_seen'] += 1
            source = '/' + member.name
            record = {'file': source, 'size_bytes': member.size,
                      'mtime_utc': dt.datetime.fromtimestamp(member.mtime, tz=dt.timezone.utc).isoformat()}
            if member.size == 0:
                record['status'] = 'empty_original'
                manifest.append(record)
                continue
            src = tf.extractfile(member)
            require(src is not None, 'Cannot read archived file '+source)
            modtime = dt.datetime.fromtimestamp(member.mtime, tz=dt.timezone.utc).astimezone(TZ)
            try:
                with src, open_text_stream(src, member.name) as stream:
                    sample = stream.peek(8192)[:8192]
                    # NUL bytes usually identify binary, including journal, wtmp and btmp.
                    controls = sum(b < 32 and b not in (9, 10, 13) for b in sample)
                    if not sample or b'\x00' in sample or controls > max(8, len(sample)//20):
                        stats['binary_files'] += 1
                        record['status'] = 'binary_archived_not_indexed'
                        manifest.append(record)
                        continue
                    stats['text_files'] += 1
                    num_raw = num_structured = num_outside = num_empty = 0
                    for no, line in enumerate(stream, 1):
                        # Count each physical text line as one record. A long line is
                        # split into chunks but retains its original line number.
                        raw_bytes = line.rstrip(b'\r\n')
                        if not raw_bytes:
                            stats['empty_lines'] += 1
                            num_empty += 1
                            continue
                        raw_text = raw_bytes.decode('utf-8', errors='replace')
                        if '\ufffd' in raw_text:
                            stats['decode_replacements'] += 1
                        disposition = 'raw' if everything else parsed_known(source, raw_text, modtime)
                        if disposition == 'structured':
                            stats['structured_records'] += 1
                            num_structured += 1
                            continue
                        if disposition == 'outside':
                            stats['outside_window'] += 1
                            num_outside += 1
                            continue
                        # Unknown formats cannot be filtered by event time safely.
                        # @timestamp reflects COLLECTION/IMPORT, never falsely
                        # advertised as the original event occurrence.
                        max_chunk = 96*1024
                        for part_no, offset in enumerate(range(0, len(raw_bytes), max_chunk), 1):
                            part = raw_bytes[offset:offset+max_chunk]
                            textval = part.decode('utf-8', errors='replace')
                            sid = hashlib.sha256(host.encode()+b'\0'+source.encode()+b'\0'+str(no).encode()+b'\0'+str(part_no).encode()+b'\0'+part).hexdigest()
                            doc = {'@timestamp': capture_stamp,
                                   'host': {'name': host},
                                   'event': {'dataset': 'linux.raw', 'kind': 'event', 'original': textval},
                                   'message': textval,
                                   'log': {'file': {'path': source}, 'offset_line': no},
                                   'historical': {'imported_offline': True,
                                                  'timestamp_inferred': True,
                                                  'timestamp_source': 'ingestion_time',
                                                  'source_collection': 'var-log-archive',
                                                  'file_mtime': record['mtime_utc'],
                                                  'part': part_no},
                                   'source_archive': 'var-log.tar'}
                            if '\ufffd' in textval:
                                doc['raw_bytes_base64'] = base64.b64encode(part).decode('ascii')
                            out.write(json.dumps({'index': {'_index': index, '_id': sid}})+'\n')
                            out.write(json.dumps(doc, ensure_ascii=False)+'\n')
                            stats['raw_records'] += 1
                            num_raw += 1
                    record.update(status='processed_text', raw_indexed=num_raw,
                                  structured_indexed=num_structured,
                                  outside_window=num_outside, empty_lines=num_empty)
                    manifest.append(record)
            except (OSError, EOFError, UnicodeError, lzma.LZMAError) as exc:
                record['status'] = 'READ_ERROR_ARCHIVED_ONLY'
                record['error'] = str(exc)[:500]
                manifest.append(record)
                # Fail closed: don't declare an import complete with lost data.
                manifest_path.write_text(json.dumps({'stats': dict(stats), 'files': manifest}, indent=2)+'\n')
                raise RuntimeError(f'Cannot decode {source}; evidence is preserved, see manifest: {exc}') from exc
    manifest_path.write_text(json.dumps({'stats': dict(stats), 'files': manifest}, indent=2)+'\n', encoding='utf-8')
    say('CATCH-ALL: '+', '.join(f'{k}={v}' for k,v in stats.items()))
    say(f'Coverage manifest: {manifest_path}')
    return output, index, dict(stats)


class Indexer:
    def __init__(self, url, name, password, ca_cert=None, insecure_local=False):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'https' and parsed.hostname, 'Indexer URL must be HTTPS')
        require(not insecure_local or parsed.hostname in ('localhost','127.0.0.1','::1'), 'TLS bypass is only permitted for local lab')
        self.root = url.rstrip('/')
        self.ctx = ssl._create_unverified_context() if insecure_local else ssl.create_default_context(cafile=ca_cert)
        self.auth = base64.b64encode(f'{name}:{password}'.encode()).decode()
        self.hostname = parsed.hostname

    def request(self, method, path, data=None, content_type=None):
        headers = {'Authorization':'Basic '+self.auth,'Accept':'application/json'}
        if content_type:
            headers['Content-Type'] = content_type
        req = urllib.request.Request(self.root + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=120) as response:
                value = response.read()
                return json.loads(value) if value else {}
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f'Indexer HTTP {exc.code}: '+exc.read(800).decode('utf-8','replace')) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError('Indexer network/TLS failure: '+str(exc)) from exc

    def ensure_index(self, name):
        dest = '/' + urllib.parse.quote(name, safe='')
        try:
            existing = self.request('GET',dest+'/_mapping')
        except RuntimeError as ex:
            if not str(ex).startswith('Indexer HTTP 404:'):
                raise
            say(f'Creating historical index {name}...')
            self.request('PUT',dest, json.dumps(INDEX_MAPPING).encode(), 'application/json')
            existing = self.request('GET',dest+'/_mapping')
        require(existing[name]['mappings'].get('properties',{}).get('@timestamp',{}).get('type') in ('date','date_nanos'),
                f'Wrong @timestamp mapping in {name}. Aborting import.')
        return dest

    def upload(self, ndjson, name, expected_host, max_docs=2000, max_bytes=4*1024*1024):
        self.ensure_index(name)
        submitted = 0
        batch = bytearray()
        count = 0
        batch_no = 0
        def flush():
            nonlocal submitted,batch,count,batch_no
            if not count:
                return
            res=self.request('POST','/_bulk?refresh=false',bytes(batch),'application/x-ndjson')
            items=res.get('items',[])
            bad=[]
            for item in items:
                op=next(iter(item.values()))
                if op.get('status',0) >= 300 or op.get('error'):
                    bad.append({'status':op.get('status'),'id':op.get('_id'),'error':op.get('error')})
                    if len(bad)==3:
                        break
            require(not res.get('errors') and len(items)==count and not bad,
                    'Indexer partial failure: '+str(bad or f'expected {count} responses, received {len(items)}'))
            submitted += count;batch_no+=1
            say(f'  Batch {batch_no}: {count} accepted (total {submitted})')
            batch.clear();count=0
        with ndjson.open('rb') as file:
            number=0
            while True:
                a=file.readline()
                if not a:break
                b=file.readline();number+=2
                require(b, f'Truncated NDJSON at line {number}')
                action=json.loads(a)
                record=json.loads(b)
                require(list(action)==['index'] and action['index'].get('_index')==name and action['index'].get('_id'), f'Invalid action near line {number}')
                require(record.get('host',{}).get('name')==expected_host and record.get('@timestamp'), f'Wrong host or timestamp near line {number}')
                piece=a+b
                require(len(piece)<=max_bytes,f'Single record too large near {number}')
                if count and (count>=max_docs or len(batch)+len(piece)>max_bytes):
                    flush()
                batch.extend(piece);count+=1
            flush()
        if submitted:
            self.request('POST', '/' + urllib.parse.quote(name, safe='') + '/_refresh', b'', 'application/json')
        total=self.request('GET','/'+urllib.parse.quote(name,safe='')+'/_count').get('count')
        say(f'{name}: submitted {submitted}; current index count {total} (may include earlier imports).')
        return submitted,total


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--indexer-url',default='https://127.0.0.1:9200',help='Wazuh Indexer URL')
    ap.add_argument('--indexer-user',default='admin')
    ap.add_argument('--ca-cert',help='CA certificate for indexer TLS validation')
    ap.add_argument('--ssh-port',type=int,default=22)
    ap.add_argument('--data-dir',type=Path,default=Path.home()/'wazuh-investigation')
    ap.add_argument('--test-only',action='store_true',help='Do not collect over SSH; require an existing capture')
    ap.add_argument('--system-only',action='store_true',help='Resume only Ubuntu system/journal import; skip Apache parsing and upload')
    ap.add_argument('--catchall-only',action='store_true',help='Upload only text logs not covered by known parsers; requires prior successful structured import')
    ap.add_argument('--raw-all',action='store_true',help='Index every readable raw log line too (duplicates known parsed events; uses more storage)')
    ap.add_argument('--reuse-capture',action='store_true',help='Require and reuse latest verified capture for this host/IP (no SSH collection)')
    args=ap.parse_args()
    require(args.ssh_port in range(1,65536), 'Invalid SSH port.')
    os.umask(0o077)
    say('WAZUH HISTORICAL IMPORT — Ubuntu / Apache / system / catch-all text logs (v4)')
    say('This imports searchable events; it does NOT automatically execute Wazuh security rules.')
    host,addr,start,end=prompt_inputs()
    say(f'Source: {host} at {addr} | Window: {start or "all"} to {end or "all"} (exclusive)')
    base=args.data_dir/host
    base.mkdir(parents=True, exist_ok=True)
    require(not (args.catchall_only and args.system_only), 'Choose at most one of --catchall-only and --system-only.')
    require(not args.catchall_only or args.reuse_capture, '--catchall-only needs --reuse-capture to avoid skipping required structured events.')
    # Reuse the most recent VERIFIED capture by default, or create a new capture.
    captures=sorted((base/'captures').glob('*/original/SHA256SUMS')) if (base/'captures').exists() else []
    require(not args.reuse_capture or captures, 'No existing capture found for this server. Cannot resume without a capture.')
    raw=None
    if captures:
        latest=captures[-1].parent
        metadata=(latest/'collection-metadata.txt').read_text(encoding='utf-8')
        original_ip=next((line[11:] for line in metadata.splitlines() if line.startswith('Target IP: ')), None)
        if original_ip is not None and original_ip != addr:
            require(not args.reuse_capture, f'Existing capture IP {original_ip} does not match entered IP {addr}; refusing to reuse.')
            say(f'Previous capture was from IP {original_ip}; will make a new capture instead of reusing it for {addr}.')
        else:
            response = '' if args.reuse_capture else input(f'Existing capture {latest.parent.name} found. Reuse it? [Y/n]: ').strip().lower()
            if response not in ('n','no'):
                raw=latest
                check_archive(raw)
    if raw is None:
        ts=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        cap=base/'captures'/ts
        if cap.exists():
            cap=base/'captures'/(ts+'-'+str(os.getpid()))
        raw=cap/'original'
        if args.test_only or args.reuse_capture:
            raise RuntimeError('Existing capture required for --test-only / --reuse-capture; no SSH collection performed')
        collect(host,addr,args.ssh_port,raw)
        check_archive(raw)
    work=raw.parent/'working'
    say('\nExtracting supported logs into working copy...')
    safe_extract(raw,work)
    say('\nParsing Apache logs and Ubuntu security/system logs...')
    outputs=[]
    if not args.catchall_only:
        for kind in (('system',) if args.system_only else ('apache', 'system')):
            path,index,stats=event_writer(work,host,kind,start,end)
            outputs.append((path,index,stats))
    if not args.system_only:
        path,index,stats=write_catchall(raw,work,host,start,end,everything=args.raw_all)
        outputs.append((path,index,stats))
    say('\nConnecting to Wazuh Indexer...')
    ix_url=urllib.parse.urlsplit(args.indexer_url)
    local_lab=ix_url.hostname in ('localhost','127.0.0.1','::1') and not args.ca_cert
    if local_lab:
        say('LAB WARNING: bypassing certificate verification for loopback only. Use --ca-cert in production.')
    secret=getpass.getpass(f'Wazuh Indexer password for {args.indexer_user}: ')
    idx=Indexer(args.indexer_url,args.indexer_user,secret,args.ca_cert,local_lab)
    del secret
    summary={'host':host,'ip':addr,'capture':str(raw.parent),'date_since':str(start) if start else None,
             'date_until_exclusive':str(end) if end else None,'original_checksums':str(raw/'SHA256SUMS'),'data':{}}
    for path,name,stats in outputs:
        n = stats.get('indexed', stats.get('raw_records', 0))
        if not n:
            say(f'{name}: no new records to index.')
            summary['data'][name]={'prepared':0,'uploaded':0,'unparsed':stats.get('unparsed',0)}
            continue
        say(f'\nUploading {n} events to {name} ...')
        uploaded,count=idx.upload(path,name,host)
        summary['data'][name]={'prepared':n,'uploaded':uploaded,'index_count':count,
                               'unparsed':stats.get('unparsed',0),'source_files':stats.get('files',0)}
    summaryfile=raw.parent/'import-summary.json'
    summaryfile.write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8')
    say('\nIMPORT COMPLETE — searchable in dashboard after creating historical index patterns.')
    say('Apache: wazuh-historical-apache-* | System: wazuh-historical-system-* | Catch-all: wazuh-historical-raw-*')
    say('Summary: '+str(summaryfile))
    say('NOTE: Wazuh detection rules were NOT run; this is historical indexing, not a compromise verdict.')
    say('NOTE: Check the file coverage manifest. Binary archives, symlinks and files outside /var/log may not be indexed.')
    say('NOTE: Raw/unknown-format timestamps are ingest time, NOT historical event time; use log contents for historical dates.')

if __name__=='__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        say('\nCancelled. Evidence already collected was not deleted.')
        sys.exit(130)
    except Exception as exc:
        print(f'ERROR: {exc}',file=sys.stderr)
        sys.exit(1)
