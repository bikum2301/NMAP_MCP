# Hệ thống Quét Mạng và Phân tích Lỗ hổng Nmap tích hợp AI

Dự án này xây dựng một ứng dụng web cho phép người dùng thực hiện các lượt quét mạng bằng Nmap, xem kết quả chi tiết, và nhận phân tích bảo mật thông minh được hỗ trợ bởi Trí tuệ Nhân tạo (DeepSeek API). Hệ thống bao gồm một frontend Flask, một backend FastMCP, Nmap chạy trong Docker container, và cơ sở dữ liệu MySQL để lưu trữ kết quả.

## Mục lục

- [Tính năng chính](#tính-năng-chính)
- [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
- [Công nghệ sử dụng](#công-nghệ-sử-dụng)
- [Yêu cầu cài đặt](#yêu-cầu-cài-đặt)
- [Hướng dẫn cài đặt và chạy dự án](#hướng-dẫn-cài-đặt-và-chạy-dự-án)
  - [Bước 1: Thiết lập Cơ sở dữ liệu MySQL](#bước-1-thiết-lập-cơ-sở-dữ-liệu-mysql)
  - [Bước 2: Cấu hình Biến môi trường (.env)](#bước-2-cấu-hình-biến-môi-trường-env)
  - [Bước 3: Xây dựng Image Docker cho Nmap](#bước-3-xây-dựng-image-docker-cho-nmap)
  - [Bước 4: Thiết lập Môi trường ảo Python và Cài đặt Dependencies](#bước-4-thiết-lập-môi-trường-ảo-python-và-cài-đặt-dependencies)
  - [Bước 5: Chạy Backend (FastMCP Nmap Server)](#bước-5-chạy-backend-fastmcp-nmap-server)
  - [Bước 6: Chạy Frontend (Flask Web Application)](#bước-6-chạy-frontend-flask-web-application)
  - [Bước 7: Truy cập Ứng dụng](#bước-7-truy-cập-ứng-dụng)
- [Cấu trúc thư mục dự án](#cấu-trúc-thư-mục-dự-án)
- [Hướng phát triển](#hướng-phát-triển)

## Tính năng chính

- Giao diện web trực quan để khởi tạo các lượt quét Nmap.
- Hỗ trợ nhiều loại quét Nmap phổ biến: Basic, Aggressive, Stealth, Vulnerability, Service Version, OS Detection.
- Thực thi Nmap trong môi trường Docker container hóa, đảm bảo tính nhất quán và đầy đủ thư viện (bao gồm script Vulners, Vulscan).
- Phân tích kết quả XML từ Nmap và hiển thị thông tin chi tiết (host, port, service, OS, script output).
- Lưu trữ lịch sử các lượt quét và kết quả vào cơ sở dữ liệu MySQL.
- Tích hợp Trí tuệ Nhân tạo (DeepSeek API) để cung cấp phân tích bảo mật, đánh giá rủi ro và khuyến nghị hành động.
- Hiển thị thống kê cơ bản về hoạt động quét.

## Kiến trúc hệ thống

Hệ thống bao gồm các thành phần chính:

1.  **Frontend (Flask Web App - `app.py`):** Giao diện người dùng, gửi yêu cầu quét và hiển thị kết quả.
2.  **Backend (FastMCP Server - `nmap_mcp_server.py`):** Xử lý logic nghiệp vụ, định nghĩa các "Tool" Nmap, thực thi Nmap qua Docker, tương tác với CSDL và AI API.
3.  **Nmap Engine (Docker Container - `Dockerfile`):** Môi trường chứa Nmap và các script NSE cần thiết.
4.  **Parser (`nmap_parser.py`):** Module phân tích cú pháp file XML output của Nmap.
5.  **Cơ sở dữ liệu (MySQL):** Lưu trữ thông tin quét, kết quả phân tích.
6.  **AI Service (DeepSeek API):** Dịch vụ cung cấp phân tích thông minh.

*(Bạn có thể chèn một sơ đồ kiến trúc đơn giản ở đây nếu muốn)*

## Công nghệ sử dụng

- **Ngôn ngữ:** Python 3.12
- **Backend Framework:** FastMCP 2.3.4
- **Frontend Framework:** Flask 3.0.2
- **Quét mạng:** Nmap 7.93 (thông qua Docker)
- **Containerization:** Docker
- **Cơ sở dữ liệu:** MySQL 8.0.36
- **Phân tích AI:** DeepSeek API
- **Thư viện Python chính:**
  - `mysql-connector-python==8.3.0`
  - `python-dotenv==1.0.1`
  - `requests==2.31.0`
  - `markdown==3.6`
  - `shortuuid`
- **Môi trường:** Windows 11 Home (có thể hoạt động trên các HĐH khác hỗ trợ Docker và Python)

## Yêu cầu cài đặt

- Python 3.10+ và pip
- Docker Desktop (hoặc Docker Engine trên Linux)
- MySQL Server
- Git (khuyến nghị)

## Hướng dẫn cài đặt và chạy dự án

### Bước 1: Thiết lập Cơ sở dữ liệu MySQL

1.  Kết nối vào MySQL server với quyền quản trị.
2.  Tạo database và user cho ứng dụng:
    ```sql
    CREATE DATABASE IF NOT EXISTS nmap_scans;
    CREATE USER 'your_db_user'@'localhost' IDENTIFIED BY 'your_db_password';
    GRANT ALL PRIVILEGES ON nmap_scans.* TO 'your_db_user'@'localhost';
    FLUSH PRIVILEGES;
    ```
    Thay `your_db_user` và `your_db_password` bằng thông tin bạn muốn.

### Bước 2: Cấu hình Biến môi trường (`.env`)

Tạo file `.env` ở thư mục gốc của dự án với nội dung sau, thay thế các giá trị placeholder:

```env
# MySQL Database Configuration
LOCALHOST=your_db_user
MYSQLPASSWORD=your_db_password

# DeepSeek AI Configuration
DEEPSEEK_API_KEY=your_deepseek_api_key_here

### Bước 3: Xây dựng Image Docker cho Nmap


Từ thư mục gốc của dự án, chạy lệnh:
docker build -t nmap .

### Bước 4: Thiết lập Môi trường ảo Python và Cài đặt Dependencies


1. Tạo môi trường ảo:
python -m venv venv
2. Kích hoạt môi trường ảo:
  Windows (PowerShell): .\venv\Scripts\activate
  Windows (CMD): venv\Scripts\activate.bat
  macOS/Linux: source venv/bin/activate
  (Lưu ý: Trên PowerShell Windows, bạn có thể cần chạy Set-ExecutionPolicy -    ExecutionPolicy RemoteSigned -Scope Process trong một cửa sổ PowerShell với quyền Admin để cho phép chạy script activate.ps1)
3. Cài đặt các thư viện cần thiết:
pip install Flask fastmcp python-dotenv mysql-connector-python requests markdown shortuuid asyncio

### Bước 5: Chạy Backend (FastMCP Nmap Server)


Mở một cửa sổ terminal/PowerShell mới, điều hướng đến thư mục dự án, kích hoạt môi trường ảo (nếu chưa) và chạy:
python nmap_mcp_server.py
Server backend sẽ khởi chạy, thường là trên http://127.0.0.1:4200/nmap. Giữ cửa sổ này chạy.


### Bước 6: Chạy Frontend (Flask Web Application)


Mở một cửa sổ terminal/PowerShell khác, điều hướng đến thư mục dự án, kích hoạt môi trường ảo (nếu chưa) và chạy:
python app.py
Server frontend Flask sẽ khởi chạy, thường là trên http://127.0.0.1:5000. Giữ cửa sổ này chạy.
