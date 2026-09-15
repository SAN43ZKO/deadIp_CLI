"""Точка входа для PyInstaller и `python -m rkn_diag`.

PyInstaller запускает этот файл как самостоятельный скрипт, поэтому здесь
должны быть ТОЛЬКО абсолютные импорты — относительные не сработают.
"""

from deadip.cli import app

if __name__ == "__main__":
    app()
