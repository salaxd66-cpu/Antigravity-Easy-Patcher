"""Identify supported agents and replace their files transactionally."""

from dataclasses import dataclass
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile


@dataclass(frozen=True)
class Recipe:
    platform: str
    length: int
    location: int
    pristine: str
    current: str
    upgrades: frozenset[str]
    version: str = '1.5.5'
    cli_location: int | None = None


RECIPES = (
    Recipe('Windows x64', 226117784, 0x2B78CB7,
           'fe9eb2f3884ca6cd630c57eed117580819341bce4b87d2c40b441ddd01cb8f2a',
           'abf5d822691224b27fce29fa9f1996165e3e99a6f64d62fd3728e4d0298e40d2',
           frozenset({
               'a81253d50f9a974ce01ca32f243537f1fafae8f24b32960b84ab1d1afe061fe0',
               '1c2cd12c1f0a2acef92131fda34aa5822dff975e80125c347dd4db90e6c1aa6d',
           })),
    Recipe('Linux x64', 247853456, 0x9750097,
           '89f16bdb87f62e6d07484c52e6bafe76a81b0fd13d740110c77dc3c3c8d8d8b6',
           'f9032adf1e541f4ab283b03f1848f49acf5630e4a5b2a20ebaa0fd45fc533be6',
           frozenset({
               '0b2315eaf481575f6f4f4189d9fb463e5f6aebdf260a5c79eb213b60fea19d87',
               'b0ad942b21cc91ce3f7e60c7fe89b8d7b99acf814c7c9ea2bbfeacb5507b1511',
           })),
    Recipe('Windows x64', 242141336, 0x28D60D7,
           '1db38dca719bc26743853d28c03b5acd99e617d0bd513ad3956b571756f0f3a9',
           'c7d20bab48c338402b317c419d768f5b271a02c8fdbf7defcef83a8e232e0bd8',
           frozenset({'63e883c31f3ffbffa5b2b75cf5bef2048525207c85f76cc709b34bb3344b8d4c'}),
           version='1.5.6', cli_location=0x3355789),
    Recipe('Windows x64', 243185304, 0x2B20BD7,
           '545b72926b3b8807f0622a36c0ce6a11a242c9e4e0f3ee84cbb0396193c8194c',
           'f96222c11bd242543d0424a71a3e109923b720de9f63c907969867630187b243',
           frozenset(), version='1.5.7', cli_location=0x33A4329),
    Recipe('Linux x64', 280564136, 0x98570F7,
           '5df525a2d6908989c57b897723caea66e00d7c4d2e24411f91ad306989574642',
           '62934bee04d48ee666c48e468be890e8e9f4b426c5c57aead686232fdfd796e7',
           frozenset(), version='1.5.7', cli_location=0xA07D129),
)

# The region error is enum value 3. In the verified free-tier block, resume
# iteration on that value. Keep the original failure handling for other values.
EXPECTED = bytes.fromhex(
    '4d85e4740c498b4c2410498b542418eb0431d231c9488954246848898c24b80000004c89e00f1f4000'
)
REPLACEMENT = bytes.fromhex(
    '41837c2408030f84d5feffff498b4c2410498b542418488954246848898c24b80000004c89e0909090'
)
CLI_EXPECTED = bytes.fromhex('80780800')
CLI_REPLACEMENT = bytes.fromhex('4885c090')
# The jump distances are intentionally wildcarded. The surrounding machine
# instructions must still match exactly, and the result must be unique.
CLI_SIGNATURE = re.compile(
    re.escape(bytes.fromhex('20440f117a30904885c00f84'))
    + b'.{4}' + re.escape(CLI_EXPECTED)
    + re.escape(bytes.fromhex('0f85')) + b'.{4}'
    + re.escape(bytes.fromhex('488b5050')),
    re.DOTALL,
)
CLI_OFFSET_IN_SIGNATURE = 16


class AgentError(Exception):
    pass


@dataclass(frozen=True)
class AgentState:
    kind: str
    checksum: str = ''
    recipe: Recipe | None = None
    backup: str = 'missing'
    detail: str = ''

    @property
    def can_patch(self):
        return (self.kind == 'original' and self.backup in ('missing', 'verified', 'rotatable')) or (
            self.kind == 'upgrade' and self.backup == 'verified'
        )

    @property
    def can_restore(self):
        return self.kind in ('patched', 'upgrade') and self.backup == 'verified'


def fingerprint(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot_path(path):
    return path.parent / (path.name + '.agybak')


def executable_ranges(binary):
    """Return the x64 format and file offsets of executable code."""
    size = len(binary)
    if size >= 64 and binary[:2] == b'MZ':
        header = struct.unpack_from('<I', binary, 0x3c)[0]
        if header + 26 > size or binary[header:header + 4] != b'PE\0\0':
            return None, ()
        machine, count = struct.unpack_from('<HH', binary, header + 4)
        optional_size = struct.unpack_from('<H', binary, header + 20)[0]
        if machine != 0x8664 or not 1 <= count <= 96 or header + 24 + optional_size + 40 * count > size:
            return None, ()
        if struct.unpack_from('<H', binary, header + 24)[0] != 0x20b:
            return None, ()
        sections = header + 24 + optional_size
        ranges = []
        for index in range(count):
            section = sections + 40 * index
            length, start = struct.unpack_from('<II', binary, section + 16)
            flags = struct.unpack_from('<I', binary, section + 36)[0]
            if flags & 0x20000000 and length and start + length <= size:
                ranges.append((start, start + length))
        return 'Windows x64', tuple(ranges)
    if size >= 64 and binary[:4] == b'\x7fELF' and binary[4:6] == b'\x02\x01':
        machine = struct.unpack_from('<H', binary, 18)[0]
        headers = struct.unpack_from('<Q', binary, 32)[0]
        stride, count = struct.unpack_from('<HH', binary, 54)
        if machine != 62 or stride < 56 or not 1 <= count <= 128 or headers + stride * count > size:
            return None, ()
        ranges = []
        for index in range(count):
            entry = headers + stride * index
            segment_type, flags = struct.unpack_from('<II', binary, entry)
            start = struct.unpack_from('<Q', binary, entry + 8)[0]
            length = struct.unpack_from('<Q', binary, entry + 32)[0]
            if segment_type == 1 and flags & 1 and length and start + length <= size:
                ranges.append((start, start + length))
        return 'Linux x64', tuple(ranges)
    return None, ()


def in_code(offset, length, ranges):
    return any(start <= offset and offset + length <= end for start, end in ranges)


def unique_pattern(binary, pattern, ranges):
    found = None
    start = 0
    while (offset := binary.find(pattern, start)) >= 0:
        if in_code(offset, len(pattern), ranges):
            if found is not None:
                return None
            found = offset
        start = offset + 1
    return found


def unique_cli_pattern(binary, ranges):
    found = None
    for match in CLI_SIGNATURE.finditer(binary):
        offset = match.start() + CLI_OFFSET_IN_SIGNATURE
        if in_code(match.start(), match.end() - match.start(), ranges):
            if found is not None:
                return None
            found = offset
    return found


def patched_fingerprint(binary, replacements):
    digest = hashlib.sha256()
    view = memoryview(binary)
    try:
        cursor = 0
        for offset, original, replacement in sorted(replacements):
            if offset < cursor or bytes(view[offset:offset + len(original)]) != original:
                return None
            digest.update(view[cursor:offset])
            digest.update(replacement)
            cursor = offset + len(original)
        digest.update(view[cursor:])
    finally:
        view.release()
    return digest.hexdigest()


def cached_version(path, length):
    """Use the updater's version only when its checksum matches this file."""
    manifest = path.parent / 'agy.version.json'
    try:
        data = json.loads(manifest.read_text(encoding='utf-8'))
        version = data['version']
        if data['size'] != length or not re.fullmatch(r'\d+\.\d+\.\d+', version):
            return 'по сигнатуре'
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha512').hexdigest()
        return version if digest == data['sha512'].lower() else 'по сигнатуре'
    except (OSError, KeyError, ValueError, TypeError):
        return 'по сигнатуре'


def adaptive_recipe(path, digest, length):
    if not 64 * 1024 * 1024 <= length <= 1024 * 1024 * 1024:
        return None
    with path.open('rb') as source:
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as binary:
            platform, ranges = executable_ranges(binary)
            if not platform or not ranges:
                return None
            region = unique_pattern(binary, EXPECTED, ranges)
            cli = unique_cli_pattern(binary, ranges)
            if region is None or cli is None:
                return None
            current = patched_fingerprint(binary, (
                (region, EXPECTED, REPLACEMENT),
                (cli, CLI_EXPECTED, CLI_REPLACEMENT),
            ))
    if current is None:
        return None
    return Recipe(platform, length, region, digest, current, frozenset(),
                  version=cached_version(path, length), cli_location=cli)


def original_recipe(path, digest, length):
    for entry in RECIPES:
        if entry.length == length and entry.pristine == digest:
            return entry
    return adaptive_recipe(path, digest, length)


def backup_status(path, recipe, kind):
    backup = snapshot_path(path)
    if not os.path.lexists(backup):
        return 'missing'
    if backup.is_symlink() or not backup.is_file():
        return 'foreign'
    length = backup.stat().st_size
    digest = fingerprint(backup)
    if length == recipe.length and digest == recipe.pristine:
        return 'verified'
    if kind == 'original' and original_recipe(backup, digest, length) is not None:
        return 'rotatable'
    return 'foreign'


def inspect_agent(path):
    try:
        if path is None or not path.is_file():
            return AgentState('missing')
        length = path.stat().st_size
        digest = fingerprint(path)
        entry = None
        kind = None
        for candidate in RECIPES:
            if candidate.length != length:
                continue
            labels = {candidate.pristine: 'original', candidate.current: 'patched'}
            kind = labels.get(digest, 'upgrade' if digest in candidate.upgrades else None)
            if kind is not None:
                entry = candidate
                break
        if entry is None:
            entry = adaptive_recipe(path, digest, length)
            if entry is not None:
                kind = 'original'
            else:
                backup = snapshot_path(path)
                if backup.is_file() and not backup.is_symlink() and backup.stat().st_size == length:
                    previous = original_recipe(backup, fingerprint(backup), length)
                    if previous is not None and previous.current == digest:
                        entry, kind = previous, 'patched'
        if entry is None:
            return AgentState('unknown', digest, detail=f'Контрольная сумма SHA-256: {digest}')
        return AgentState(kind, digest, entry, backup_status(path, entry, kind))
    except (OSError, ValueError, BufferError, struct.error) as error:
        return AgentState('error', detail=str(error))


def sync_directory(directory):
    if os.name != 'nt':
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def copy_access(source, destination):
    if os.name != 'nt':
        owner = source.stat()
        current = destination.stat()
        if (owner.st_uid, owner.st_gid) != (current.st_uid, current.st_gid):
            os.chown(destination, owner.st_uid, owner.st_gid)
    shutil.copymode(source, destination)


def replace_instructions(stream, offset, original, replacement):
    stream.seek(offset)
    if len(original) != len(replacement) or stream.read(len(original)) != original:
        raise AgentError('Проверка инструкций агента не прошла.')
    stream.seek(offset)
    stream.write(replacement)


def install_agent(path, action):
    if action not in ('patch', 'restore'):
        raise ValueError(action)
    target = path.resolve(strict=True)
    state = inspect_agent(target)
    allowed = state.can_patch if action == 'patch' else state.can_restore
    if not allowed:
        raise AgentError(state.detail or 'Для этого действия нужен совместимый агент и его исходная копия.')
    recipe = state.recipe
    backup = snapshot_path(target)
    original = target if state.kind == 'original' else backup

    with tempfile.TemporaryDirectory(prefix='.antigravity-easy-patcher-', dir=target.parent) as directory:
        stage = Path(directory) / 'agent'
        with original.open('rb') as source, stage.open('xb') as out:
            shutil.copyfileobj(source, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        if fingerprint(stage) != recipe.pristine:
            raise AgentError('Контрольная сумма исходной копии изменилась.')

        if state.kind == 'original' and state.backup in ('missing', 'rotatable'):
            # A separate inode ensures subsequent changes to stage cannot affect the backup.
            pending_backup = Path(directory) / 'backup'
            shutil.copyfile(stage, pending_backup)
            with pending_backup.open('r+b') as stream:
                copy_access(target, pending_backup)
                os.fsync(stream.fileno())
            if fingerprint(target) != state.checksum:
                raise AgentError('Агент был обновлён во время операции. Нажмите «Обновить список».')
            if state.backup == 'rotatable':
                old_digest = fingerprint(backup)
                if original_recipe(backup, old_digest, backup.stat().st_size) is None:
                    raise AgentError('Прежняя исходная копия изменилась во время операции.')
                archived = backup.with_name(backup.name + '-' + old_digest[:12] + '.old')
                if os.path.lexists(archived):
                    if archived.is_symlink() or not archived.is_file() or fingerprint(archived) != old_digest:
                        raise AgentError(f'Имя для прежней копии уже занято: {archived}')
                else:
                    os.link(backup, archived)
                if fingerprint(backup) != old_digest:
                    raise AgentError('Прежняя исходная копия изменилась во время операции.')
                os.replace(pending_backup, backup)
            else:
                os.link(pending_backup, backup)
            sync_directory(target.parent)

        if action == 'patch':
            with stage.open('r+b') as stream:
                replace_instructions(stream, recipe.location, EXPECTED, REPLACEMENT)
                if recipe.cli_location is not None:
                    replace_instructions(stream, recipe.cli_location, CLI_EXPECTED, CLI_REPLACEMENT)
                stream.flush()
                os.fsync(stream.fileno())

        expected = recipe.current if action == 'patch' else recipe.pristine
        if fingerprint(stage) != expected:
            raise AgentError('Контрольная сумма результата не совпала.')
        if fingerprint(target) != state.checksum:
            raise AgentError('Агент был обновлён во время операции. Нажмите «Обновить список».')
        copy_access(target, stage)
        os.replace(stage, target)
        sync_directory(target.parent)
