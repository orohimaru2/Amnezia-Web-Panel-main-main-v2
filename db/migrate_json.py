"""One-shot CLI: import legacy data.json into PostgreSQL.

Usage:
  python -m db.migrate_json [path/to/data.json]
"""

from __future__ import annotations

import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger('migrate_json')


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    force = '--force' in argv
    paths = [a for a in argv if not a.startswith('-')]

    if getattr(sys, 'frozen', False):
        app_path = os.path.dirname(sys.executable)
    else:
        app_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    data_file = paths[0] if paths else os.path.join(app_path, 'data.json')

    from db.store import import_from_json_file, is_database_empty, load_data

    if not os.path.exists(data_file):
        logger.error('File not found: %s', data_file)
        return 1

    if not is_database_empty():
        logger.warning('Database is not empty — import will overwrite panel tables.')
        if not force:
            logger.error('Re-run with --force to overwrite existing data.')
            return 2

    import_from_json_file(data_file, backup=True)
    data = load_data()
    logger.info(
        'Done. servers=%s users=%s connections=%s tokens=%s',
        len(data['servers']),
        len(data['users']),
        len(data['user_connections']),
        len(data['api_tokens']),
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
