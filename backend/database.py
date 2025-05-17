# nmap_fastmcp_project/backend/database.py

from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func
import os
from dotenv import load_dotenv
import logging
import urllib.parse  # << -------- THÊM IMPORT NÀY

logger = logging.getLogger(__name__)

project_root_for_env = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
dotenv_path = os.path.join(project_root_for_env, ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
    logger.info(f"Đã load file .env từ: {dotenv_path}")
else:
    logger.warning(
        f"Không tìm thấy file .env tại: {dotenv_path}. Sử dụng giá trị mặc định nếu có."
    )

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_USER = os.getenv("DB_USER", "your_db_user_default")
DB_PASSWORD_RAW = os.getenv(
    "DB_PASSWORD", "your_db_password_default"
)  # Lấy mật khẩu thô
DB_NAME = os.getenv("DB_NAME", "nmap_mcp_db_default")

# URL Encode mật khẩu để xử lý ký tự đặc biệt
DB_PASSWORD_ENCODED = urllib.parse.quote_plus(DB_PASSWORD_RAW)

# Log giá trị DB_HOST để kiểm tra
logger.info(f"DATABASE_PY: Sử dụng DB_HOST: '{DB_HOST}'")
logger.info(f"DATABASE_PY: Sử dụng DB_USER: '{DB_USER}'")
# Không log mật khẩu, kể cả đã encode

SQLALCHEMY_DATABASE_URL = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD_ENCODED}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
logger.info(
    f"DATABASE_PY: Chuỗi kết nối SQLAlchemy (mật khẩu đã ẩn): mysql+mysqlconnector://{DB_USER}:****@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)


engine = None
SessionLocal = None
Base = declarative_base()

try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info(
        f"Đã cấu hình SQLAlchemy engine và SessionLocal cho database: {DB_NAME} trên {DB_HOST}"
    )

    # Test connection nhẹ nhàng bằng cách thử tạo một session (không thực sự kết nối)
    # Điều này sẽ chỉ thất bại nếu URL có vấn đề cú pháp nghiêm trọng
    # Việc kết nối thực sự sẽ xảy ra khi create_all hoặc get_db được gọi
    logger.info("Khởi tạo SessionLocal thành công.")

except Exception as e:
    logger.error(f"Lỗi khi khởi tạo SQLAlchemy engine hoặc SessionLocal: {e}")
    # Không raise lỗi ở đây


# --- Định nghĩa Models (Schema Bảng) ---
class ScanSession(Base):
    __tablename__ = "scan_sessions"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    target = Column(String(255), index=True, nullable=False)
    scan_ip = Column(String(45), nullable=True)
    scan_timestamp_utc = Column(DateTime(timezone=True), nullable=False)
    overall_summary_text = Column(Text, nullable=True)
    statistics_json = Column(JSON, nullable=True)
    full_analysis_json = Column(JSON, nullable=True)
    status = Column(String(50), nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), onupdate=func.now(), server_default=func.now()
    )


def create_db_tables():
    if not engine:
        logger.error("Engine chưa được khởi tạo. Không thể tạo bảng.")
        return
    logger.info("Đang cố gắng tạo các bảng trong database (nếu chưa tồn tại)...")
    try:
        Base.metadata.create_all(bind=engine)  # Lệnh này sẽ thực sự kết nối đến DB
        logger.info("Các bảng đã được kiểm tra/tạo thành công.")
    except Exception as e:
        logger.error(f"Lỗi khi tạo bảng trong database: {e}")
        logger.error(
            "Hãy đảm bảo kết nối database thành công, database '{DB_NAME}' tồn tại và user có đủ quyền."
        )


def get_db():
    if not SessionLocal:
        logger.error("SessionLocal chưa được khởi tạo. Không thể tạo DB session.")
        raise RuntimeError(
            "SessionLocal is not initialized. Check database connection."
        )
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
