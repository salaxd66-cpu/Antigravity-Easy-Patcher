"""Identify supported agents and replace their files transactionally."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
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
        return (self.kind == 'original' and self.backup != 'foreign') or (
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


def inspect_agent(path):
    try:
        if path is None or not path.is_file():
            return AgentState('missing')
        lengths = [entry for entry in RECIPES if entry.length == path.stat().st_size]
        if not lengths:
            return AgentState('unknown', detail='Размер файла отличается от поддерживаемых сборок.')
        digest = fingerprint(path)
        for entry in lengths:
            labels = {entry.pristine: 'original', entry.current: 'patched'}
            kind = labels.get(digest, 'upgrade' if digest in entry.upgrades else None)
            if kind is None:
                continue
            backup = snapshot_path(path)
            if not os.path.lexists(backup):
                backup_status = 'missing'
            elif backup.is_file() and backup.stat().st_size == entry.length and fingerprint(backup) == entry.pristine:
                backup_status = 'verified'
            else:
                backup_status = 'foreign'
            return AgentState(kind, digest, entry, backup_status)
        return AgentState('unknown', digest, detail=f'Контрольная сумма SHA-256: {digest}')
    except OSError as error:
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

        if state.kind == 'original' and state.backup == 'missing':
            # A separate inode ensures subsequent changes to stage cannot affect the backup.
            pending_backup = Path(directory) / 'backup'
            shutil.copyfile(stage, pending_backup)
            with pending_backup.open('r+b') as stream:
                copy_access(target, pending_backup)
                os.fsync(stream.fileno())
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
