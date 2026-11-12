"""Native desktop interface for Antigravity Easy Patcher."""

from pathlib import Path
import sys

from PySide6.QtCore import QObject, QRunnable, QSettings, QThreadPool, Qt, Signal, Slot
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout, QLabel, QMainWindow, QMenu,
    QMessageBox, QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from agent_files import install_agent
from installed_apps import PROGRAMS, make_reports, scan_installations


APP_NAME = 'Antigravity Easy Patcher'
VERSION = '1.0.1'
STYLES = '''
QWidget { background: #000000; color: #f5f5f5; }
QLabel { background: transparent; }
QLabel#heading { font-size: 26px; font-weight: 700; }
QLabel#title { font-size: 15px; font-weight: 650; }
QLabel#secondary, QLabel#path { color: #b3b3b3; font-size: 12px; }
QFrame#card { background: #000000; border: 1px solid #303030; border-radius: 8px; }
QPushButton { background: #111111; border: 1px solid #454545; border-radius: 6px;
              padding: 6px 10px; min-height: 18px; font-size: 13px; font-weight: 600; }
QPushButton:hover { background: #252525; }
QPushButton:focus { border-color: #ffff00; }
QPushButton:disabled { color: #777777; background: #0c0c0c; border-color: #242424; }
QPushButton#primary { background: #ffff00; color: #000000; border-color: #ffff00; }
QPushButton#primary:hover { background: #ffff75; }
QPushButton#primary:focus { border-color: #ffffff; }
QPushButton#primary:disabled { color: #777777; background: #0c0c0c; border-color: #242424; }
QPushButton::menu-indicator { image: none; width: 0; }
QScrollArea { border: none; }
QScrollBar:vertical { background: #000000; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #555555; min-height: 24px; border-radius: 4px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QMenu { background: #111111; border: 1px solid #454545; padding: 4px; }
QMenu::item { padding: 8px 16px; }
QMenu::item:selected { background: #ffff00; color: #000000; }
QMenu::item:disabled { color: #777777; }
'''

PALETTES = {
    'original': ('Оригинал', '#dddddd', '#1a1a1a'),
    'patched': ('Патч установлен', '#ffff00', '#242400'),
    'upgrade': ('Есть обновление', '#ffff00', '#242400'),
    'unknown': ('Не поддерживается', '#dddddd', '#1a1a1a'),
    'missing': ('Нет агента', '#b3b3b3', '#1a1a1a'),
    'error': ('Ошибка чтения', '#ffff00', '#242400'),
}


class WorkerSignals(QObject):
    complete = Signal(object, object)


class Worker(QRunnable):
    def __init__(self, job):
        super().__init__()
        self.job = job
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self.job()
        except Exception as error:
            self.signals.complete.emit(None, str(error))
        else:
            self.signals.complete.emit(result, None)


class FileLabel(QLabel):
    def __init__(self):
        super().__init__()
        self.full = ''
        self.setObjectName('path')
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

    def show_value(self, value):
        self.full = value
        self.setToolTip(value)
        self.setAccessibleName(value)
        self.update_text()

    def update_text(self):
        self.setText(self.fontMetrics().elidedText(self.full, Qt.TextElideMode.ElideMiddle, self.width()))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_text()


def label(text, style=None):
    result = QLabel(text)
    result.setTextFormat(Qt.TextFormat.PlainText)
    if style:
        result.setObjectName(style)
    return result


class ProgramCard(QFrame):
    def __init__(self, window, key, name):
        super().__init__()
        self.setObjectName('card')
        self.name = name
        self.report = None
        body = QVBoxLayout(self)
        body.setContentsMargins(16, 12, 16, 12)
        body.setSpacing(6)

        top = QHBoxLayout()
        top.addWidget(label(name, 'title'))
        top.addStretch()
        self.badge = label('Проверка…')
        top.addWidget(self.badge)
        body.addLayout(top)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.path = FileLabel()
        row.addWidget(self.path, 1)
        self.file_button = QPushButton('Файл…')
        self.file_button.setFixedWidth(72)
        file_menu = QMenu(self.file_button)
        file_menu.addAction('Указать файл агента…', lambda: window.choose(key))
        self.reset_action = file_menu.addAction('Вернуться к автопоиску', lambda: window.reset(key))
        self.file_button.setMenu(file_menu)
        self.file_button.setAccessibleName(f'Выбрать файл для {name}')
        self.patch_button = QPushButton('Пропатчить')
        self.patch_button.setFixedWidth(108)
        self.patch_button.setObjectName('primary')
        self.patch_button.setAccessibleName(f'Пропатчить {name}')
        self.patch_button.clicked.connect(lambda: window.change(key, 'patch'))
        self.restore_button = QPushButton('Восстановить')
        self.restore_button.setFixedWidth(120)
        self.restore_button.setAccessibleName(f'Восстановить {name}')
        self.restore_button.clicked.connect(lambda: window.change(key, 'restore'))
        for button in (self.file_button, self.patch_button, self.restore_button):
            row.addWidget(button)
        body.addLayout(row)

        self.note = label('', 'secondary')
        self.note.setWordWrap(True)
        body.addWidget(self.note)
        self.update_buttons(True)

    def update_report(self, report):
        self.report = report
        entry, state = report.entry, report.state
        name, color, background = PALETTES[state.kind]
        if state.kind == 'missing' and not entry.installed and not entry.manual:
            name = 'Не установлено'
        self.badge.setText(name)
        self.badge.setStyleSheet(f'color:{color};background:{background};border-radius:5px;padding:3px 8px;font-size:12px;font-weight:600;')
        self.path.show_value(str(entry.file) if entry.file else '')
        details = state.detail
        if state.recipe:
            details = f'agy {state.recipe.version} · {state.recipe.platform}'
        self.badge.setToolTip(details)

        notes = []
        if report.shared_with:
            notes.append('Общий файл: ' + ', '.join(report.shared_with))
        if state.kind == 'upgrade' and state.backup != 'verified':
            notes.append('Нужна копия .agybak.')
        elif state.kind == 'patched' and state.backup != 'verified':
            notes.append('Нет копии для отката.')
        elif state.backup == 'foreign':
            notes.append('Копия от другой сборки.')
        self.note.setText('  ·  '.join(notes))
        self.note.setVisible(bool(notes))

    def update_buttons(self, busy):
        self.file_button.setEnabled(not busy)
        self.reset_action.setEnabled(bool(self.report and self.report.entry.manual))
        self.patch_button.setEnabled(bool(not busy and self.report and self.report.state.can_patch))
        self.restore_button.setEnabled(bool(not busy and self.report and self.report.state.can_restore))


class Manager(QMainWindow):
    def __init__(self, settings=None):
        super().__init__()
        self.settings = settings if settings is not None else QSettings(APP_NAME, APP_NAME)
        self.overrides = {key: self.settings.value(f'agent/{key}', '') for key, _, _ in PROGRAMS}
        self.pool = QThreadPool(self)
        self.worker = None
        self.callback = None
        self.setWindowTitle(APP_NAME)
        self.resize(880, 496)
        self.setMinimumSize(680, 380)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        heading.addWidget(label(APP_NAME, 'heading'))
        heading.addStretch()
        self.refresh_button = QPushButton('Обновить')
        self.refresh_button.clicked.connect(self.refresh)
        heading.addWidget(self.refresh_button)
        layout.addLayout(heading)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        listings = QWidget()
        cards = QVBoxLayout(listings)
        cards.setContentsMargins(0, 0, 0, 0)
        cards.setSpacing(8)
        self.cards = {}
        for key, name, _ in PROGRAMS:
            card = ProgramCard(self, key, name)
            self.cards[key] = card
            cards.addWidget(card)
        cards.addStretch()
        scroll.setWidget(listings)
        layout.addWidget(scroll, 1)

        self.message = label('', 'secondary')
        self.message.setWordWrap(True)
        self.message.hide()
        layout.addWidget(self.message)
        self.setCentralWidget(content)
        self.refresh()

    def set_busy(self, busy):
        self.refresh_button.setEnabled(not busy)
        for card in self.cards.values():
            card.update_buttons(busy)

    def show_message(self, text=''):
        self.message.setText(text)
        self.message.setVisible(bool(text))

    def run_task(self, job, callback):
        self.set_busy(True)
        self.worker = Worker(job)
        self.callback = callback
        self.worker.signals.complete.connect(self.finish_task, Qt.ConnectionType.QueuedConnection)
        self.pool.start(self.worker)

    @Slot(object, object)
    def finish_task(self, result, error):
        callback = self.callback
        self.callback = None
        self.worker = None
        self.set_busy(False)
        callback(result, error)

    def refresh(self):
        if self.worker is not None:
            return
        self.show_message()
        paths = self.overrides.copy()

        def scanned(reports, error):
            if error:
                self.show_message(f'Ошибка поиска: {error}')
                return
            for key, report in reports.items():
                self.cards[key].update_report(report)
            self.set_busy(False)

        self.run_task(lambda: make_reports(scan_installations(paths)), scanned)

    def choose(self, key):
        report = self.cards[key].report
        start = str(report.entry.file.parent) if report and report.entry.file else str(Path.home())
        path, _ = QFileDialog.getOpenFileName(self, 'Выберите файл агента agy', start)
        if path:
            self.overrides[key] = path
            self.settings.setValue(f'agent/{key}', path)
            self.refresh()

    def reset(self, key):
        self.overrides[key] = ''
        self.settings.remove(f'agent/{key}')
        self.refresh()

    def change(self, key, action):
        if self.worker is not None:
            return
        card = self.cards[key]
        report = card.report
        if report is None or report.entry.file is None:
            return
        path = report.entry.file
        action_name = 'Применить патч' if action == 'patch' else 'Восстановить оригинал'
        shared = '\n\nЭтот файл также используется: ' + ', '.join(report.shared_with) if report.shared_with else ''
        question = f'{card.name}\n{path}{shared}\n\nЗакройте программу и подтвердите действие.'
        yes = QMessageBox.StandardButton.Yes
        no = QMessageBox.StandardButton.No
        if QMessageBox.question(self, action_name, question, yes | no, no) != yes:
            return
        self.show_message(f'{action_name} · {card.name}…')

        def changed(_, error):
            if error:
                QMessageBox.warning(self, 'Операция не завершилась', error)
            self.refresh()

        self.run_task(lambda: install_agent(path, action), changed)

    def closeEvent(self, event):
        if self.worker is not None:
            self.show_message('Дождитесь окончания операции.')
            event.ignore()
        else:
            super().closeEvent(event)


def style_application(app):
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    font_file = Path(__file__).resolve().parent / 'assets/Inter.ttf'
    font_id = QFontDatabase.addApplicationFont(str(font_file))
    custom = QFontDatabase.applicationFontFamilies(font_id) if font_id != -1 else []
    font = QFont()
    font.setFamilies([*custom, 'Segoe UI', 'DejaVu Sans'])
    font.setPointSize(10)
    app.setFont(font)
    app.setStyle('Fusion')
    app.setStyleSheet(STYLES)


def main():
    app = QApplication(sys.argv)
    style_application(app)
    window = Manager()
    window.show()
    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
