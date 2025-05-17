# nmap_fastmcp_project/backend/__init__.py

# Import và re-export các thành phần cần thiết từ database.py
# Điều này làm cho chúng có sẵn dưới dạng backend.SessionLocal, backend.engine, v.v.
from .database import SessionLocal, engine, Base, get_db, create_db_tables

# Import và re-export các hàm từ crud.py
# Điều này làm cho chúng có sẵn dưới dạng backend.create_scan_session, v.v.
from .crud import (
    create_scan_session,
    update_scan_session_with_results,
    update_scan_session_status,
    get_scan_session_by_id,
    get_scan_history,
)

# (Tùy chọn) Bạn có thể định nghĩa một biến __all__ nếu muốn kiểm soát những gì được import khi dùng "from backend import *"
# __all__ = [
#     "SessionLocal", "engine", "Base", "get_db", "create_db_tables",
#     "create_scan_session", "update_scan_session_with_results",
#     "update_scan_session_status", "get_scan_session_by_id", "get_scan_history"
# ]

import logging

logger = logging.getLogger(__name__)
logger.info("Package 'backend' initialized and submodules (database, crud) imported.")
