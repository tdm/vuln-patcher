#!/usr/bin/python

import os
import sys
import requests
import base64
import getopt
from xml.etree import ElementTree
import email
import subprocess

cfg = dict()
cfg['dry-run'] = False
cfg['ni'] = False

git_history = dict()

def dequote(s):
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s

def cmd_run(args, stdin=None):
    child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not stdin is None:
        child.stdin.write(stdin)
    (out, err) = child.communicate()
    rc = child.returncode
    return (rc, out.rstrip('\n').split('\n'), err.rstrip('\n').split('\n'))

def get_input(s):
    # https://rosettacode.org/wiki/Keyboard_input/Flush_the_keyboard_buffer#Python
    try:
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getch()
    except ImportError:
        import termios    #for linux/unix
        termios.tcflush(sys.stdin, termios.TCIOFLUSH)
    return raw_input(s)

class Version:
    def __init__(self, ver):
        self._segments = []
        if len(ver) > 0:
            self._segments = ver.split('.')

    def __str__(self):
        return '.'.join(self._segments)

    def __hash__(self):
        return hash(self.__str__())

    def empty(self):
        return len(self._segments) == 0

    def cmp(self, other):
        seg = 0
        while seg < len(self._segments):
            if seg >= len(other._segments):
                return 1
            s1 = int(self._segments[seg])
            s2 = int(other._segments[seg])
            if s1 != s2:
                return s1 - s2
            seg += 1
        if seg < len(other._segments):
            return -1
        return 0

    def __lt__(self, other):
        return self.cmp(other) < 0
    def __le__(self, other):
        return self.cmp(other) <= 0
    def __eq__(self, other):
        return self.cmp(other) == 0
    def __ne__(self, other):
        return self.cmp(other) != 0
    def __gt__(self, other):
        return self.cmp(other) > 0
    def __ge__(self, other):
        return self.cmp(other) >= 0

    def in_range(self, vmin, vmax):
        if not vmin.empty():
            if self < vmin:
                return False
        if not vmax.empty():
            if self > vmax:
                return False
        return True

class Patch:
    def __init__(self, url):
        self._url = url
        self._sha = ''
        self._author = ''
        self._date = ''
        self._subject = ''
        self._files = []

    def _fetch(self):
        if len(self._sha) > 0:
            return
        rs = requests.Session()
        r = rs.get(self._url)
        r.raise_for_status()
        if r.content.startswith('From '):
            self._text = r.content
        else:
            self._text = base64.b64decode(r.content)

        message = email.message_from_string(self._text)
        s = message.get_unixfrom()
        if not s:
            return
        self._sha = s.split(' ', 2)[1]
        self._author = message['From']
        self._date = message['Date']
        self._subject = message['Subject']
        self._subject = self._subject.replace('\n', '')

        s = message.get_payload(decode=True)
        for line in s.rstrip('\n').split('\n'):
            if line.startswith('diff '):
                fields = line.split(' ')
                self._files.append(fields[2][2:])

    def url(self):
        self._fetch()
        return self._url

    def sha(self):
        self._fetch()
        return self._sha

    def subject(self):
        self._fetch()
        return self._subject

    def files(self):
        self._fetch()
        return self._files

    def can_apply(self):
        self._fetch()
        argv = ['patch', '-p1', '--force', '--dry-run']
        (rc, out, err) = cmd_run(argv, self._text)
        return (rc == 0)

    def can_reverse(self):
        self._fetch()
        argv = ['patch', '-p1', '--force', '--dry-run', '--reverse']
        (rc, out, err) = cmd_run(argv, self._text)
        return (rc == 0)

    def apply(self):
        self._fetch()
        argv = ['patch', '-p1', '--force', '--no-backup-if-mismatch']
        (rc, out, err) = cmd_run(argv, self._text)
        if rc != 0:
            raise RuntimeError("Patch failed to apply")

    def reverse(self):
        self._fetch()
        argv = ['patch', '-p1', '--force', '--reverse']
        (rc, out, err) = cmd_run(argv, self._text)
        if rc != 0:
            raise RuntimeError("Patch failed to reverse")

    def in_git_history(self):
        self._fetch()
        found = False
        if self._subject in git_history:
            found = True
            revert_subject = "Revert: %s" % (self._subject)
            if revert_subject in git_history:
                found = False
        return found

    def git_am(self):
        self._fetch()
        argv = ['git', 'am']
        (rc, out, err) = cmd_run(argv, self._text)
        if rc != 0:
            raise RuntimeError("Patch failed to merge")


class Vuln:
    def __init__(self, url):
        self._applied = False
        self._action = 'None'

        rs = requests.Session()
        r = rs.get(url)
        r.raise_for_status()

        # Get the basic info
        root = ElementTree.fromstring(r.content)
        self._name = dequote(root.find('name').text)
        self._version_min = Version(dequote(root.find('version_min').text))
        self._version_max = Version(dequote(root.find('version_max').text))
        self._source = dequote(root.find('source').text)
        self._comments = dequote(root.find('comments').text)

        # Key for sorting
        #  - Lower case for alnum fields.
        #  - 9 digits for numeric fields.
        self._key = ''
        pos = 0
        while pos < len(self._name):
            # Skip non-alnum
            if not self._name[pos].isalnum():
                self._key += self._name[pos]
                pos += 1
                continue
            end = pos
            while end < len(self._name) and self._name[end].isalnum():
                end += 1
            field = self._name[pos:end]
            pos = end
            try:
                i = int(field)
                self._key += "%09d" % (i)
            except ValueError:
                self._key += field.lower()

        self._patches = dict()
        p_root = root.find('patch_list')
        for p in p_root.findall('patch'):
            ver = Version(dequote(p.attrib['version']))
            url = dequote(p.text)
            self._patches[ver] = Patch(url)

    def applied(self, val = None):
        if not val is None:
            self._applied = val
        return self._applied

    def action(self, val = None):
        if not val is None:
            self._action = val
        return self._action

    def name(self):
        return self._name

    def version_min(self):
        return self._version_min

    def version_max(self):
        return self._version_max

    def source(self):
        return self._source

    def patches(self):
        return self._patches

    def process(self, ver):
        patch = self.patches()[ver]
        if patch.can_reverse():
            self.applied(True)
            self.action('Already applied')
            return
        if patch.in_git_history():
            self.applied(True)
            self.action('In git history')
            return
        if cfg['dry-run']:
            if patch.can_apply():
                self.applied(True)
                self.action('Can apply')
            else:
                self.applied(False)
                self.action('Cannot apply')
            return
        if patch.can_apply():
            try:
                patch.git_am()
                self.applied(True)
                self.action('Applied cleanly')
                return
            except RuntimeError:
                if cfg['ni']:
                    self.applied(False)
                    self.action('Skipped')
                    return
                sys.stdout.write(" Failed, patching manually ...\n")
                patch.apply()
                reply = get_input("  Please verify and press enter to continue...")
                argv = ['git', 'add']
                argv.extend(patch.files())
                (rc, out, err) = cmd_run(argv)
                if rc != 0:
                    # Should never happen
                    print "  *** Failed to add git files"
                    reply = get_input("  Please add/remove files and press enter: ")
                argv = ['git', 'am', '--continue']
                (rc, out, err) = cmd_run(argv)
                if rc != 0:
                    # Should never happen
                    print "  *** Failed to continue merge"
                    reply = get_input("  Please complete merge and press enter: ")
                sys.stdout.write("  ")
                self.applied(True)
                self.action('Applied manually')
                return
        self.applied(False)
        self.action('Cannot apply')

def get_kernel_version():
    f = open("Makefile")
    for line in f:
        fields = line.split('=')
        if len(fields) != 2:
            continue
        key = fields[0].strip()
        val = fields[1].strip()
        if key == 'VERSION':
            v_major = int(val)
        if key == 'PATCHLEVEL':
            v_minor = int(val)
    f.close()
    return Version("%d.%d" % (v_major, v_minor))

def get_git_history():
    sys.stdout.write("Reading git history: ")
    sys.stdout.flush()
    argv = ['git', 'log', '--oneline', '--no-merges']
    child = subprocess.Popen(argv, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = 0
    for line in child.stdout:
        (sha, subject) = line.split(' ', 1)
        git_history[subject.strip()] = sha
        lines += 1
        if (lines % 1000) == 0:
            sys.stdout.write('.')
            sys.stdout.flush()
    sys.stdout.write('\n')
    sys.stdout.flush()
    child.wait()
    if child.returncode != 0:
        raise RuntimeError("Failed to read git history")

def get_vuln_list():
    vuln_list = []
    rs = requests.Session()
    sys.stdout.write("Fetching vuln list: ")
    sys.stdout.flush()
    vl_r = rs.get("http://code.nwwn.com/vuln/vuln_list.php?format=xml")
    vl_r.raise_for_status()
    vl_root = ElementTree.fromstring(vl_r.text)
    count = 0
    for vl_elem in vl_root:
        id = dequote(vl_elem.attrib['id'])
        vuln = Vuln("http://code.nwwn.com/vuln/vuln_detail.php?format=xml&id=%s" % (id))
        vuln_list.append(vuln)
        count += 1
        if (count % 10) == 0:
            sys.stdout.write('.')
            sys.stdout.flush()
    sys.stdout.write('\n')
    sys.stdout.flush()
    return sorted(vuln_list, key = lambda x:x._key)

### Begin main code ###

if not sys.stdin.isatty():
    cfg['ni'] = True

optargs, argv = getopt.getopt(sys.argv[1:], '', ['dry-run', 'interactive', 'non-interactive'])
for k, v in optargs:
    if k in ('--dry-run'):
        cfg['dry-run'] = True
    if k in ('--interactive'):
        cfg['ni'] = False
    if k in ('--non-interactive'):
        cfg['ni'] = True

kver = get_kernel_version()

ksources = set()
ksources.add('mainline')
if os.path.exists('drivers/staging/android'):
    ksources.add('android')
if os.path.exists('drivers/misc/qcom'):
    ksources.add('caf')
if os.path.exists('drivers/misk/mediatek'):
    ksources.add('mtk')
if os.path.exists('drivers/staging/prima'):
    ksources.add('prima')
if os.path.exists('drivers/staging/qcacld-2.0'):
    ksources.add('qcacld')
if os.path.exists('drivers/net/wireless/bcmdhd'):
    ksources.add('bcmdhd')
if os.path.exists('drivers/input/touchscreen/synaptics_dsx'):
    ksources.add('synaptics_dsx')
if os.path.exists('drivers/input/misc/vl6180'):
    ksources.add('vl6180')
if os.path.exists('drivers/input/misc/vl53L0'):
    ksources.add('vl53L0')
if os.path.exists('sound/soc/codecs/rt5506.h'):
    ksources.add('rt5506')
if os.path.exists('sound/soc/codecs/rt5677.h'):
    ksources.add('rt5677')
# ...

get_git_history()
vuln_list = get_vuln_list()

for vuln in vuln_list:
    sys.stdout.write("Processing %s" % (vuln.name()))
    vmin = vuln.version_min()
    vmax = vuln.version_max()

    if not kver.in_range(vmin, vmax):
        sys.stdout.write(" ... Not applicable: %s not in [%s,%s]\n" % (kver, vmin, vmax))
        continue

    if vuln.source():
        if not vuln.source() in ksources:
            sys.stdout.write(" ... Not applicable: source %s not found\n" % (vuln.source()))
            continue

    patches = vuln.patches()
    if len(patches) == 0:
        sys.stdout.write(" No patches\n")
        continue

    if kver in patches:
        vuln.process(kver)
        sys.stdout.write(" ... %s" % (vuln.action()))
    else:
        if not vuln.applied():
            # Try forward port
            pver = None
            for k in patches:
                if not k < kver:
                    continue
                if not pver or k > pver:
                    pver = k
            if pver:
                sys.stdout.write(" ... Try %s" % (pver))
                vuln.process(pver)
                sys.stdout.write(" ... %s" % (vuln.action()))

        if not vuln.applied():
            # Try backward port
            pver = ''
            patch = None
            for k in patches:
                if not k > kver:
                    continue
                if not pver or k < pver:
                    pver = k
            if pver:
                sys.stdout.write(" ... Try %s" % (pver))
                vuln.process(pver)
                sys.stdout.write(" ... %s" % (vuln.action()))

    if vuln.applied():
        sys.stdout.write('\n')
    else:
        sys.stdout.write(" ... Paches:\n")
        for k in patches:
            sys.stdout.write("  %s: %s\n" % (k, patches[k].subject()))
            sys.stdout.write("    %s\n" % (patches[k].url()))
        reply = ''
        if cfg['ni']:
            reply = 's'
        while reply != 'a' and reply != 's':
            reply = get_input("  Please apply manually. [S]kip or [A]pplied: ")
            if len(reply) > 0:
                reply = reply[0].lower()
            else:
                reply = 's'
