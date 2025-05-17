# nmap_fastmcp_project/backend/crud.py

from sqlalchemy.orm import Session
from . import database  # Import model ScanSession và db session từ database.py cùng cấp
from typing import Dict, Any, List
import logging
import json  # Để xử lý trường JSON nếu cần

logger = logging.getLogger(__name__)


def create_scan_session(
    db: Session,
    target: str,
    scan_ip: str | None,
    scan_timestamp_utc: Any,
    status: str = "pending",
) -> database.ScanSession:
    """
    Tạo một bản ghi phiên quét mới trong database.
    """
    logger.info(f"CRUD: Tạo phiên quét mới cho target: {target} với status: {status}")
    db_scan_session = database.ScanSession(
        target=target,
        scan_ip=scan_ip,
        scan_timestamp_utc=scan_timestamp_utc,
        status=status,
        # Các trường khác sẽ được cập nhật sau
    )
    db.add(db_scan_session)
    db.commit()
    db.refresh(db_scan_session)
    logger.info(
        f"CRUD: Đã tạo phiên quét ID: {db_scan_session.id} cho target: {target}"
    )
    return db_scan_session


def update_scan_session_with_results(
    db: Session,
    session_id: int,
    overall_summary: str | None,
    statistics: Dict[str, Any] | None,
    full_analysis: Dict[str, Any] | None,
    status: str,
) -> database.ScanSession | None:
    """
    Cập nhật một phiên quét đã có với kết quả phân tích và trạng thái mới.
    """
    logger.info(
        f"CRUD: Cập nhật kết quả cho phiên quét ID: {session_id} với status: {status}"
    )
    db_scan_session = (
        db.query(database.ScanSession)
        .filter(database.ScanSession.id == session_id)
        .first()
    )
    if db_scan_session:
        db_scan_session.overall_summary_text = overall_summary

        # SQLAlchemy tự động xử lý việc serialize/deserialize cho kiểu JSON
        if statistics is not None:
            db_scan_session.statistics_json = statistics
        if full_analysis is not None:
            db_scan_session.full_analysis_json = full_analysis

        db_scan_session.status = status
        db.commit()
        db.refresh(db_scan_session)
        logger.info(f"CRUD: Đã cập nhật phiên quét ID: {session_id}")
        return db_scan_session
    logger.warning(f"CRUD: Không tìm thấy phiên quét ID: {session_id} để cập nhật.")
    return None


def update_scan_session_status(
    db: Session, session_id: int, status: str
) -> database.ScanSession | None:
    """
    Chỉ cập nhật trạng thái của một phiên quét.
    """
    logger.info(
        f"CRUD: Cập nhật status cho phiên quét ID: {session_id} thành: {status}"
    )
    db_scan_session = (
        db.query(database.ScanSession)
        .filter(database.ScanSession.id == session_id)
        .first()
    )
    if db_scan_session:
        db_scan_session.status = status
        db.commit()
        db.refresh(db_scan_session)
        logger.info(f"CRUD: Đã cập nhật status cho phiên quét ID: {session_id}")
        return db_scan_session
    logger.warning(
        f"CRUD: Không tìm thấy phiên quét ID: {session_id} để cập nhật status."
    )
    return None


def get_scan_session_by_id(db: Session, session_id: int) -> database.ScanSession | None:
    """
    Lấy thông tin chi tiết của một phiên quét dựa theo ID.
    """
    logger.info(f"CRUD: Lấy phiên quét theo ID: {session_id}")
    return (
        db.query(database.ScanSession)
        .filter(database.ScanSession.id == session_id)
        .first()
    )


def get_scan_history(
    db: Session, skip: int = 0, limit: int = 100
) -> List[database.ScanSession]:
    """
    Lấy danh sách lịch sử các phiên quét (tóm tắt).
    Sắp xếp theo thời gian quét mới nhất lên đầu.
    """
    logger.info(f"CRUD: Lấy lịch sử quét, skip: {skip}, limit: {limit}")
    return (
        db.query(database.ScanSession)
        .order_by(database.ScanSession.scan_timestamp_utc.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


# Bạn có thể thêm các hàm CRUD khác nếu cần, ví dụ: xóa một session, tìm theo target, v.v.
