# nmap_fastmcp_project/backend/main.py

from fastapi import FastAPI, HTTPException, Body, status, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
import logging
import os
import sys
from typing import Dict, Any, List
import datetime
import pytz

# Thêm thư mục gốc của dự án vào sys.path để import 'core'
project_root_for_core_import = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if project_root_for_core_import not in sys.path:
    sys.path.insert(0, project_root_for_core_import)

# Khai báo biến để dễ theo dõi
run_nmap_scan = None
analyze_nmap_xml_with_llm = None
cleanup_temp_file = None
NmapExecutionError = None
LLMInteractionError = None

# Biến cho các thành phần từ package 'backend' (sẽ được import từ __init__.py)
be_crud = None
be_database_SessionLocal = None
be_database_engine = None
be_database_Base = None
be_database_get_db = None
be_database_create_db_tables = None


try:
    from core.utils import (
        run_nmap_scan as imported_run_nmap_scan,
        analyze_nmap_xml_with_llm as imported_analyze_nmap_xml_with_llm,
        cleanup_temp_file as imported_cleanup_temp_file,
        NmapExecutionError as imported_NmapExecutionError,
        LLMInteractionError as imported_LLMInteractionError,
    )

    run_nmap_scan = imported_run_nmap_scan
    analyze_nmap_xml_with_llm = imported_analyze_nmap_xml_with_llm
    cleanup_temp_file = imported_cleanup_temp_file
    NmapExecutionError = imported_NmapExecutionError
    LLMInteractionError = imported_LLMInteractionError

    # IMPORT TỪ PACKAGE 'backend' (tức là từ backend/__init__.py)
    # Python sẽ chạy __init__.py của 'backend' trước, nơi các module con được import.
    import backend  # Điều này sẽ thực thi backend/__init__.py

    # Gán các thành phần đã được re-export trong backend/__init__.py
    be_crud = backend  # Module crud giờ là một phần của namespace backend

    # Các thành phần từ database cũng là một phần của namespace backend
    be_database_SessionLocal = backend.SessionLocal
    be_database_engine = backend.engine
    be_database_Base = backend.Base
    be_database_get_db = backend.get_db
    be_database_create_db_tables = backend.create_db_tables


except ImportError as e:
    logging.critical(
        f"Lỗi import module: {e}. Hãy đảm bảo bạn đang chạy uvicorn từ thư mục gốc của dự án "
        f"('NMAP_MCP') và các file __init__.py cần thiết tồn tại và được cấu hình đúng."
    )
    logging.critical(f"sys.path hiện tại: {sys.path}")
    logging.critical(f"Thư mục làm việc hiện tại: {os.getcwd()}")
    sys.exit(1)
except Exception as e_import_generic:
    logging.critical(f"Lỗi không xác định trong quá trình import: {e_import_generic}.")
    sys.exit(1)


# --- Gọi hàm tạo bảng khi ứng dụng khởi động ---
if be_database_Base and be_database_engine:
    try:
        be_database_create_db_tables()  # Gọi hàm đã import
        # Hoặc nếu create_db_tables không được re-export:
        # be_database_Base.metadata.create_all(bind=be_database_engine)
        logging.info(
            "Backend: Đã kiểm tra/tạo các bảng database thành công khi khởi động."
        )
    except Exception as e_db_create:
        logging.error(
            f"Backend: Lỗi khi tạo bảng database lúc khởi động: {e_db_create}"
        )
        logging.error("Vui lòng kiểm tra kết nối database và quyền của user.")
else:
    logging.error(
        "Backend: Không thể tạo bảng database do Base hoặc engine từ 'backend' chưa được import/khởi tạo đúng."
    )

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Nmap FastMCP Backend Service",
    description="API service để thực hiện quét Nmap, phân tích bằng LLM và lưu trữ kết quả.",
    version="0.2.4",  # Tăng version
)


# --- Pydantic Models --- (Giữ nguyên)
class ScanRequest(BaseModel):
    target: str = Field(
        ...,
        example="scanme.nmap.org",
        description="Mục tiêu (domain hoặc IP) cần quét.",
    )


class ScanProcessResponse(BaseModel):
    message: str
    target_scanned: str
    session_id: int | None = None
    status_at_response: str
    analysis_result: Dict[str, Any] | None = None
    error_details: str | None = None


class ScanSessionSummary(BaseModel):
    id: int
    target: str
    scan_ip: str | None
    scan_timestamp_utc: datetime.datetime
    status: str
    critical_vulns: int | None = None
    high_vulns: int | None = None
    medium_vulns: int | None = None
    low_vulns: int | None = None
    open_ports: int | None = None

    class Config:
        orm_mode = True


class ScanSessionDetail(ScanSessionSummary):
    overall_summary_text: str | None
    full_analysis_json: Dict[str, Any] | None

    class Config:
        orm_mode = True


# --- API Endpoints ---
@app.get("/", tags=["General"])
async def root():
    logger.info("Root endpoint được gọi.")
    return {
        "message": "Chào mừng bạn đến với Nmap FastMCP Backend Service (với Database)!"
    }


@app.post(
    "/scan",
    response_model=ScanProcessResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Scanning"],
)
async def process_scan_request(
    request: ScanRequest = Body(...),
    db: Session = Depends(be_database_get_db),  # Sử dụng hàm get_db từ backend
):
    target = request.target
    logger.info(f"Backend: Nhận yêu cầu quét cho mục tiêu: {target}")

    current_utc_time = datetime.datetime.now(pytz.utc)
    db_scan_session = None
    session_id = None

    try:
        # Sử dụng các hàm từ be_crud (là module backend)
        db_scan_session = be_crud.create_scan_session(
            db=db,
            target=target,
            scan_ip=None,
            scan_timestamp_utc=current_utc_time,
            status="processing_nmap",
        )
        session_id = db_scan_session.id
        logger.info(
            f"Backend: Đã tạo ScanSession ID: {session_id} cho target: {target}"
        )

        # ... (Phần logic Nmap, LLM, và cập nhật session giữ nguyên như trước,
        #      chỉ cần đảm bảo bạn gọi các hàm CRUD đúng cách, ví dụ: be_crud.update_scan_session_status)

        xml_file_path = None
        analysis_json_result: Dict[str, Any] | None = None
        final_status = "failed_unknown"

        logger.info(
            f"Backend: Bắt đầu quét Nmap cho session ID: {session_id}, target: {target}"
        )
        xml_file_path, nmap_stdout_data, nmap_stderr_data = run_nmap_scan(
            target=target, output_to_xml=True, timeout_seconds=600
        )

        if not xml_file_path:
            logger.error(
                f"Backend: Nmap không tạo được file XML cho session ID: {session_id}, target: {target}"
            )
            final_status = "failed_nmap_no_xml"
            be_crud.update_scan_session_status(
                db=db, session_id=session_id, status=final_status
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "message": "Nmap không tạo được file XML.",
                    "target_scanned": target,
                    "session_id": session_id,
                    "error_details": nmap_stderr_data
                    or "Nmap XML file was not created or is empty.",
                },
            )

        be_crud.update_scan_session_status(
            db=db, session_id=session_id, status="processing_llm"
        )
        logger.info(
            f"Backend: Nmap scan hoàn tất cho session ID: {session_id}. XML tại: {xml_file_path}"
        )

        xml_content = ""
        try:
            with open(xml_file_path, "r", encoding="utf-8") as f:
                xml_content = f.read()
        except Exception as e_read:
            logger.error(
                f"Backend: Lỗi khi đọc file XML {xml_file_path} cho session ID: {session_id}: {e_read}"
            )
            final_status = "failed_xml_read"
            be_crud.update_scan_session_status(
                db=db, session_id=session_id, status=final_status
            )
            raise HTTPException(
                status_code=500, detail=f"Lỗi đọc file XML: {str(e_read)}"
            )

        logger.info(
            f"Backend: Bắt đầu phân tích XML bằng LLM cho session ID: {session_id}"
        )
        analysis_json_result = analyze_nmap_xml_with_llm(
            nmap_xml_content=xml_content, scan_target_override=target
        )

        final_status = "completed"
        logger.info(f"Backend: Phân tích LLM hoàn tất cho session ID: {session_id}")

        scan_ip_from_llm = analysis_json_result.get("scan_ip")
        overall_summary = analysis_json_result.get("overall_summary_text")
        statistics = analysis_json_result.get("statistics")

        llm_scan_time_str = analysis_json_result.get("scan_timestamp_utc")
        actual_scan_time_to_db = db_scan_session.scan_timestamp_utc
        if llm_scan_time_str:
            try:
                parsed_time = datetime.datetime.fromisoformat(
                    llm_scan_time_str.replace("Z", "+00:00")
                )
                if parsed_time.tzinfo is None:
                    actual_scan_time_to_db = pytz.utc.localize(parsed_time)
                else:
                    actual_scan_time_to_db = parsed_time
            except ValueError:
                logger.warning(
                    f"Backend: Không thể parse scan_timestamp_utc từ LLM: {llm_scan_time_str}."
                )

        current_db_session_for_update = be_crud.get_scan_session_by_id(db, session_id)
        if current_db_session_for_update:
            current_db_session_for_update.scan_ip = scan_ip_from_llm
            current_db_session_for_update.scan_timestamp_utc = actual_scan_time_to_db
            be_crud.update_scan_session_with_results(
                db=db,
                session_id=session_id,
                overall_summary=overall_summary,
                statistics=statistics,
                full_analysis=analysis_json_result,
                status=final_status,
            )
            # db.commit() # update_scan_session_with_results đã commit rồi
            # db.refresh(current_db_session_for_update) # update_scan_session_with_results đã refresh rồi
        else:
            logger.error(
                f"Backend: Không tìm thấy session ID {session_id} để cập nhật kết quả cuối cùng."
            )

        return ScanProcessResponse(
            message="Yêu cầu quét và phân tích đã hoàn tất.",
            target_scanned=target,
            session_id=session_id,
            status_at_response=final_status,
            analysis_result=analysis_json_result,
        )

    except NmapExecutionError as e:
        logger.error(
            f"Backend: Lỗi Nmap cho session ID: {session_id or 'N/A'}, target: {target}: {e.stderr or e}"
        )
        final_status = "failed_nmap_execution"
        if session_id:
            be_crud.update_scan_session_status(
                db=db, session_id=session_id, status=final_status
            )
        raise HTTPException(status_code=500, detail=f"Lỗi thực thi Nmap: {str(e)}")
    except LLMInteractionError as e:
        logger.error(
            f"Backend: Lỗi LLM cho session ID: {session_id or 'N/A'}, target: {target}: {e}"
        )
        final_status = "failed_llm"
        if session_id:
            be_crud.update_scan_session_status(
                db=db, session_id=session_id, status=final_status
            )
        raise HTTPException(status_code=500, detail=f"Lỗi tương tác LLM: {str(e)}")
    except FileNotFoundError:
        logger.error(f"Backend: Nmap executable không tìm thấy khi quét {target}.")
        final_status = "failed_nmap_not_found"
        if session_id:
            be_crud.update_scan_session_status(
                db=db, session_id=session_id, status=final_status
            )
        raise HTTPException(
            status_code=500, detail="Lỗi server: Nmap executable không tìm thấy."
        )
    except Exception as e:
        logger.exception(
            f"Backend: Lỗi không mong muốn cho session ID: {session_id or 'N/A'}, target: {target}: {e}"
        )
        final_status = "failed_unknown_server_error"
        if session_id:
            be_crud.update_scan_session_status(
                db=db, session_id=session_id, status=final_status
            )
        raise HTTPException(
            status_code=500, detail=f"Lỗi server không mong muốn: {str(e)}"
        )
    finally:
        if xml_file_path:
            logger.info(
                f"Backend: Dọn dẹp file XML tạm: {xml_file_path} cho session ID: {session_id or 'N/A'}"
            )
            cleanup_temp_file(xml_file_path)


@app.get(
    "/scans/history", response_model=List[ScanSessionSummary], tags=["Scan History"]
)
async def get_all_scan_history(
    skip: int = 0, limit: int = 20, db: Session = Depends(be_database_get_db)
):
    logger.info(f"Backend: Yêu cầu lấy lịch sử quét, skip: {skip}, limit: {limit}")
    sessions_db = be_crud.get_scan_history(db, skip=skip, limit=limit)

    history_summary_list: List[ScanSessionSummary] = []
    for session in sessions_db:
        stats = (
            session.statistics_json if isinstance(session.statistics_json, dict) else {}
        )
        vuln_by_sev = (
            stats.get("vulnerabilities_by_severity", {})
            if isinstance(stats.get("vulnerabilities_by_severity"), dict)
            else {}
        )

        summary_item = ScanSessionSummary(
            id=session.id,
            target=session.target,
            scan_ip=session.scan_ip,
            scan_timestamp_utc=session.scan_timestamp_utc,
            status=session.status,
            critical_vulns=vuln_by_sev.get("critical"),
            high_vulns=vuln_by_sev.get("high"),
            medium_vulns=vuln_by_sev.get("medium"),
            low_vulns=vuln_by_sev.get("low"),
            open_ports=stats.get("open_ports_count"),
        )
        history_summary_list.append(summary_item)
    return history_summary_list


@app.get("/scans/{scan_id}", response_model=ScanSessionDetail, tags=["Scan History"])
async def get_scan_details_by_id(
    scan_id: int, db: Session = Depends(be_database_get_db)
):
    logger.info(f"Backend: Yêu cầu lấy chi tiết cho scan ID: {scan_id}")
    db_scan = be_crud.get_scan_session_by_id(db, session_id=scan_id)
    if db_scan is None:
        logger.warning(f"Backend: Không tìm thấy scan session với ID: {scan_id}")
        raise HTTPException(
            status_code=404, detail=f"Scan session với ID {scan_id} không tìm thấy."
        )

    stats = db_scan.statistics_json if isinstance(db_scan.statistics_json, dict) else {}
    vuln_by_sev = (
        stats.get("vulnerabilities_by_severity", {})
        if isinstance(stats.get("vulnerabilities_by_severity"), dict)
        else {}
    )

    detailed_session = ScanSessionDetail(
        id=db_scan.id,
        target=db_scan.target,
        scan_ip=db_scan.scan_ip,
        scan_timestamp_utc=db_scan.scan_timestamp_utc,
        status=db_scan.status,
        critical_vulns=vuln_by_sev.get("critical"),
        high_vulns=vuln_by_sev.get("high"),
        medium_vulns=vuln_by_sev.get("medium"),
        low_vulns=vuln_by_sev.get("low"),
        open_ports=stats.get("open_ports_count"),
        overall_summary_text=db_scan.overall_summary_text,
        full_analysis_json=db_scan.full_analysis_json,
    )
    return detailed_session


@app.get("/health", tags=["General"])
async def health_check():
    logger.info("Health check được gọi.")
    return {"status": "ok"}


# Cách chạy:
# 1. cd nmap_fastmcp_project  (Thư mục gốc)
# 2. python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
