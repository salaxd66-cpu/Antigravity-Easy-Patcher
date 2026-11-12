"""Find program installations and the agent file each can use."""

from collections import defaultdict
from dataclasses import dataclass
import os
from pathlib import Path
import shutil

from agent_files import AgentState, inspect_agent


PROGRAMS = (
    ('ide', 'Antigravity IDE', 'Редактор'),
    ('cli', 'Antigravity CLI', 'Командная строка'),
    ('vscode', 'Antigravity в VS Code', 'Расширение'),
    ('desktop', 'Antigravity App', 'Приложение'),
)


@dataclass(frozen=True)
class Entry:
    file: Path | None
    installed: bool
    manual: bool = False


@dataclass(frozen=True)
class Report:
    entry: Entry
    state: AgentState
    shared_with: tuple[str, ...]


def existing(*choices):
    for choice in choices:
        if choice is not None and choice.is_file():
            return choice.resolve()
    return None


def packaged_agent(roots, executable):
    return existing(*(root / relative / executable for root in roots for relative in (
        Path('resources/bin'), Path('resources/app/bin'), Path('bin'),
    )))


def scan_installations(overrides):
    home = Path.home()
    win = os.name == 'nt'
    executable = 'agy.exe' if win else 'agy'
    agent_dir = home / '.gemini' / 'bin'
    shared = existing(agent_dir / executable, agent_dir / ('antigravity.exe' if win else 'antigravity'))
    on_path = shutil.which(executable)
    if win:
        local = Path(os.environ.get('LOCALAPPDATA', home / 'AppData' / 'Local'))
        base = local / 'Programs'
        system = Path(os.environ.get('ProgramFiles', 'C:/Program Files'))
        ide = (base / 'Antigravity IDE', system / 'Antigravity IDE')
        desktop = (base / 'Antigravity', system / 'Antigravity')
        cli = existing(local / 'agy/bin/agy.exe', Path(on_path) if on_path else None)
        ide_installed = any((root / 'Antigravity IDE.exe').is_file() for root in ide)
        desktop_installed = any((root / 'Antigravity.exe').is_file() for root in desktop)
    else:
        ide = (Path('/usr/share/antigravity-ide'), Path('/opt/antigravity-ide'))
        desktop = (Path('/usr/share/antigravity'), Path('/opt/antigravity'), Path('/opt/Antigravity'))
        cli = existing(home / '.local/bin/agy', Path(on_path) if on_path else None)
        ide_installed = bool(shutil.which('antigravity-ide')) or any(root.is_dir() for root in ide)
        desktop_installed = any((root / 'Antigravity').is_file() or (root / 'antigravity').is_file() for root in desktop)

    extension_roots = (home / '.vscode/extensions', home / '.vscode-insiders/extensions')
    extensions = [folder for root in extension_roots for folder in root.glob('google.google-antigravity-*')]
    result = {
        'ide': Entry(packaged_agent(ide, executable) or (shared if ide_installed else None), ide_installed),
        'cli': Entry(cli, cli is not None),
        'vscode': Entry(packaged_agent(extensions, executable) or (shared if extensions else None), bool(extensions)),
        'desktop': Entry(packaged_agent(desktop, executable), desktop_installed),
    }
    for key, value in overrides.items():
        if key in result and value:
            result[key] = Entry(Path(value).expanduser().resolve(), result[key].installed, True)
    return result


def make_reports(entries):
    users = defaultdict(list)
    for key, title, _ in PROGRAMS:
        if file := entries[key].file:
            users[file].append((key, title))
    inspected = {file: inspect_agent(file) for file in users}
    return {
        key: Report(entry, inspected.get(entry.file, AgentState('missing')),
                    tuple(title for other, title in users[entry.file] if other != key))
        for key, entry in entries.items()
    }
