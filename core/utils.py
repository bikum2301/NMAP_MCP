# nmap_fastmcp_project/core/utils.py

import subprocess
import tempfile
import os
import requests
import json
import logging
from dotenv import load_dotenv
import datetime
import pytz
import xml.etree.ElementTree as ET
import re

# Thiết lập logging cơ bản
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load biến môi trường từ file .env
try:
    dotenv_path_core = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(dotenv_path_core):
        load_dotenv(dotenv_path=dotenv_path_core)
        logger.info(f"Core: Đã load file .env từ: {dotenv_path_core}")
    else:
        load_dotenv()
        logger.info(
            f"Core: Thử load .env từ thư mục làm việc hiện tại hoặc thư mục script."
        )
except Exception as e_dotenv:
    logger.warning(
        f"Core: Không thể load file .env. Lỗi: {e_dotenv}. Sử dụng giá trị mặc định nếu có."
    )

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_URL = os.getenv(
    "DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions"
)
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
NMAP_EXECUTABLE = os.getenv("NMAP_PATH", "nmap")

# GIỚI HẠN SỐ LƯỢNG FINDINGS TỪ VULNERS CHO MỖI PORT ĐỂ TRÁNH VƯỢT CONTEXT LENGTH CỦA LLM
# Bạn có thể điều chỉnh giá trị này.
MAX_VULNERS_FINDINGS_PER_PORT = 10


class NmapExecutionError(Exception):
    def __init__(self, message, stdout=None, stderr=None):
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


class LLMInteractionError(Exception):
    pass


def run_nmap_scan(
    target: str,
    nmap_args: list = None,
    output_to_xml: bool = True,
    timeout_seconds: int = 300,  # Thời gian quét Nmap mặc định
) -> tuple[str | None, str, str]:
    if nmap_args is None:
        nmap_args = ["-sV", "--script", "vulners"]  # Lệnh Nmap cố định

    xml_output_file = None
    nmap_command = [NMAP_EXECUTABLE] + nmap_args

    if output_to_xml:
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".xml", mode="w", encoding="utf-8"
            ) as tmp_file:
                xml_output_file = tmp_file.name
            nmap_command.extend(["-oX", xml_output_file])
        except Exception as e:
            logger.error(f"Lỗi khi tạo file XML tạm thời: {e}")
            xml_output_file = None  # Đảm bảo là None nếu có lỗi

    nmap_command.append(target)
    logger.info(f"Core: Chuẩn bị thực thi lệnh Nmap: {' '.join(nmap_command)}")

    try:
        process = subprocess.Popen(
            nmap_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        stdout, stderr = process.communicate(timeout=timeout_seconds)

        if process.returncode != 0:
            if xml_output_file and os.path.exists(xml_output_file):
                try:
                    os.remove(xml_output_file)
                except Exception as e_remove:
                    logger.error(
                        f"Lỗi khi xóa file XML tạm (Nmap thất bại): {e_remove}"
                    )
                xml_output_file = None
            raise NmapExecutionError(
                f"Nmap chạy thất bại (mã lỗi {process.returncode}) cho mục tiêu '{target}'.",
                stdout=stdout,
                stderr=stderr,
            )

        if output_to_xml and xml_output_file:
            if (
                not os.path.exists(xml_output_file)
                or os.path.getsize(xml_output_file) == 0
            ):
                logger.warning(
                    f"Nmap chạy xong nhưng file XML '{xml_output_file}' không tồn tại hoặc trống."
                )
                if os.path.exists(xml_output_file):
                    try:
                        os.remove(xml_output_file)
                    except Exception as e_remove_empty:
                        logger.error(
                            f"Lỗi khi xóa file XML tạm (trống): {e_remove_empty}"
                        )
                xml_output_file = None
        logger.info(
            f"Core: Nmap hoàn tất cho '{target}'. XML (nếu có): {xml_output_file}"
        )
        return xml_output_file, stdout, stderr
    except FileNotFoundError:
        logger.error(
            f"Core: Không tìm thấy Nmap tại '{NMAP_EXECUTABLE}'. Hãy đảm bảo Nmap đã được cài đặt và có trong PATH, hoặc cấu hình NMAP_PATH trong .env."
        )
        if xml_output_file and os.path.exists(xml_output_file):
            os.remove(xml_output_file)
        raise
    except subprocess.TimeoutExpired:
        logger.error(
            f"Core: Nmap quét quá thời gian ({timeout_seconds}s) cho '{target}'."
        )
        if xml_output_file and os.path.exists(xml_output_file):
            os.remove(xml_output_file)
        raise
    except Exception as e:
        logger.exception(f"Core: Lỗi không xác định khi chạy Nmap cho '{target}': {e}")
        if xml_output_file and os.path.exists(xml_output_file):
            os.remove(xml_output_file)
        raise NmapExecutionError(
            f"Lỗi không xác định trong Nmap: {str(e)}", stderr=str(e)
        )


def call_deepseek_llm(
    prompt: str,
    max_tokens: int = 4090,  # Tăng nhẹ để có không gian cho JSON output phức tạp hơn
    temperature: float = 0.3,  # Giữ nguyên để output nhất quán
    timeout_seconds: int = 240,  # Tăng timeout cho LLM call nếu prompt lớn
    require_json_output: bool = False,  # Giữ False để an toàn, tự parse text
) -> str:
    if not DEEPSEEK_API_KEY:
        raise LLMInteractionError(
            "DEEPSEEK_API_KEY chưa được cấu hình trong file .env hoặc biến môi trường."
        )
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
    }
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if require_json_output:  # Vẫn để tùy chọn này nếu muốn thử nghiệm với API
        payload["response_format"] = {"type": "json_object"}
        logger.info(
            "Core: Đã yêu cầu LLM trả về định dạng JSON object (nếu API hỗ trợ)."
        )
    else:
        logger.info(
            "Core: Không yêu cầu LLM trả về định dạng JSON object cụ thể qua API (sẽ parse text)."
        )
    logger.info(
        f"Core: Đang gửi yêu cầu đến DeepSeek API: {DEEPSEEK_API_URL}. Model: {DEEPSEEK_MODEL}, Max Tokens: {max_tokens}"
    )
    try:
        response = requests.post(
            DEEPSEEK_API_URL, headers=headers, json=payload, timeout=timeout_seconds
        )
        response.raise_for_status()
        result = response.json()
        if (
            "choices" in result
            and len(result["choices"]) > 0
            and "message" in result["choices"][0]
            and "content" in result["choices"][0]["message"]
        ):
            content = result["choices"][0]["message"]["content"]
            logger.info("Core: Nhận được phản hồi thành công từ DeepSeek API.")
            return content
        else:
            logger.error(
                f"Core: DeepSeek API không trả về kết quả hợp lệ. Phản hồi: {json.dumps(result, indent=2)}"
            )
            raise LLMInteractionError(
                f"LLM API không trả về kết quả hợp lệ. Chi tiết: {json.dumps(result)}"
            )
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"Core: Lỗi HTTP khi gọi DeepSeek API: {http_err}")
        if http_err.response is not None:
            logger.error(
                f"Core: Response content từ API khi lỗi HTTP: {http_err.response.text}"
            )
        raise LLMInteractionError(f"Lỗi HTTP từ LLM API: {str(http_err)}") from http_err
    except requests.exceptions.Timeout:
        logger.error(f"Core: Timeout khi gọi DeepSeek API.")
        raise LLMInteractionError(
            f"Timeout ({timeout_seconds}s) khi kết nối đến LLM API."
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"Core: Lỗi request chung khi gọi DeepSeek API: {e}")
        raise LLMInteractionError(f"Lỗi request đến LLM API: {str(e)}")
    except Exception as e:
        logger.exception(
            f"Core: Lỗi không xác định khi xử lý phản hồi từ DeepSeek API: {e}"
        )
        raise LLMInteractionError(f"Lỗi không xác định khi xử lý LLM: {str(e)}")


def parse_vulners_output(vulners_output_str: str) -> list:
    findings = []
    if not vulners_output_str:
        return findings
    lines = vulners_output_str.strip().split("\n")
    for line in lines:
        line = line.strip()
        if not line or (line.startswith("cpe:") and line.endswith(":")):
            continue  # Bỏ qua dòng cpe
        match = re.match(
            r"([^\s]+)\s+([0-9.]+|N/A)\s+([^\s]+)(?:\s+(\*EXPLOIT\*))?", line
        )
        if match:
            finding_id = match.group(1)
            score_str = match.group(2)
            url = match.group(3)
            is_exploit = bool(match.group(4))
            cvss_score = None
            try:
                if score_str != "N/A":
                    cvss_score = float(score_str)
            except ValueError:
                pass
            finding_data = {
                "id": finding_id,
                "cvss_score": cvss_score,
                "url": url,
                "is_exploit_flag": is_exploit,
            }
            if "cve/" in url:
                finding_data["source"] = "cve"
            elif "githubexploit/" in url:
                finding_data["source"] = "githubexploit"
            elif "packetstorm/" in url:
                finding_data["source"] = "packetstorm"
            elif "zdt/" in url:
                finding_data["source"] = "1337day"
            elif "seebug/" in url:
                finding_data["source"] = "seebug"
            else:
                finding_data["source"] = "unknown"
            findings.append(finding_data)
    if findings:
        findings.sort(
            key=lambda x: x.get("cvss_score") or 0.0, reverse=True
        )  # Sắp xếp theo điểm giảm dần
        logger.info(
            f"Core: Đã parse được {len(findings)} vulners findings. Sẽ giới hạn còn tối đa {MAX_VULNERS_FINDINGS_PER_PORT} findings (nếu nhiều hơn)."
        )
        return findings[:MAX_VULNERS_FINDINGS_PER_PORT]  # Giới hạn số lượng
    return []


def extract_relevant_nmap_info_for_llm(nmap_xml_content: str) -> str:
    try:
        root = ET.fromstring(nmap_xml_content)
        relevant_hosts_data = []
        for host_node in root.findall("host"):
            host_info = {}
            host_address_node = host_node.find("address[@addrtype='ipv4']")
            if host_address_node is None:
                host_address_node = host_node.find("address[@addrtype='ipv6']")
            if host_address_node is not None:
                host_info["address"] = host_address_node.get("addr")
            host_status_node = host_node.find("status")
            if host_status_node is not None:
                host_info["status"] = host_status_node.get("state")
            host_os_node = host_node.find("os/osmatch")  # Lấy OS match đầu tiên
            if host_os_node is not None:
                host_info["os"] = host_os_node.get("name")

            open_ports_data = []
            ports_node = host_node.find("ports")
            if ports_node is not None:
                for port_node in ports_node.findall("port"):
                    port_state_node = port_node.find("state")
                    if (
                        port_state_node is not None
                        and port_state_node.get("state") == "open"
                    ):
                        port_data = {
                            "portid": port_node.get("portid"),
                            "protocol": port_node.get("protocol"),
                            "state": port_state_node.get("state"),
                            "service": {},
                            "vulners_findings": [],
                        }
                        service_node = port_node.find("service")
                        if service_node is not None:
                            port_data["service"]["name"] = service_node.get("name")
                            port_data["service"]["product"] = service_node.get(
                                "product"
                            )
                            port_data["service"]["version"] = service_node.get(
                                "version"
                            )
                            # Sửa lại cách lấy CPE, nó là con trực tiếp của service
                            cpe_nodes = service_node.findall(
                                "cpe"
                            )  # Có thể có nhiều CPE
                            if cpe_nodes:
                                port_data["service"]["cpe"] = [
                                    cpe.text for cpe in cpe_nodes if cpe.text
                                ]
                                if not port_data["service"]["cpe"]:  # Nếu list rỗng
                                    del port_data["service"][
                                        "cpe"
                                    ]  # Xóa key nếu không có CPE hợp lệ
                                elif (
                                    len(port_data["service"]["cpe"]) == 1
                                ):  # Nếu chỉ có 1, lấy string
                                    port_data["service"]["cpe"] = port_data["service"][
                                        "cpe"
                                    ][0]

                        vulners_script_node = port_node.find("script[@id='vulners']")
                        if vulners_script_node is not None and vulners_script_node.get(
                            "output"
                        ):
                            parsed_vulns = parse_vulners_output(
                                vulners_script_node.get("output")
                            )
                            if parsed_vulns:
                                port_data["vulners_findings"] = parsed_vulns
                        open_ports_data.append(port_data)
            if open_ports_data:
                host_info["open_ports"] = open_ports_data
                relevant_hosts_data.append(host_info)

        if not relevant_hosts_data:
            return json.dumps(
                {
                    "message": "Không tìm thấy thông tin host hoặc port mở nào đáng chú ý từ Nmap XML."
                }
            )
        return json.dumps(
            relevant_hosts_data, indent=2, ensure_ascii=False
        )  # ensure_ascii=False để giữ ký tự tiếng Việt
    except ET.ParseError as e:
        logger.error(
            f"Lỗi parse Nmap XML trong extract_relevant_nmap_info_for_llm: {e}"
        )
        return json.dumps(
            {
                "error": "Lỗi khi parse Nmap XML",
                "details": str(e),
                "xml_preview": nmap_xml_content[:500],
            }
        )
    except Exception as e_extract:
        logger.error(f"Lỗi không xác định khi trích xuất thông tin Nmap: {e_extract}")
        return json.dumps(
            {
                "error": "Lỗi khi trích xuất thông tin Nmap",
                "details": str(e_extract),
                "xml_preview": nmap_xml_content[:500],
            }
        )


def get_nmap_analysis_prompt_template() -> str:
    prompt_template = """Bạn là một chuyên gia phân tích bảo mật mạng và một nhà văn kỹ thuật xuất sắc, có khả năng chuyển đổi dữ liệu kỹ thuật phức tạp thành thông tin dễ hiểu và có tính hành động cao.

Nhiệm vụ của bạn là phân tích **DỮ LIỆU NMAP ĐÃ ĐƯỢC TRÍCH XUẤT VÀ TÓM TẮT (dưới dạng JSON)** được cung cấp dưới đây. Dữ liệu này bắt nguồn từ một kết quả quét Nmap (đã chạy với tùy chọn -sV và script vulners). Dựa trên dữ liệu JSON được cung cấp, hãy tạo ra một báo cáo chi tiết dưới dạng một đối tượng JSON DUY NHẤT theo cấu trúc yêu cầu bên dưới. Input JSON cung cấp cho bạn thông tin về các host, port mở, dịch vụ và các phát hiện từ script vulners (đã được rút gọn và sắp xếp theo mức độ ưu tiên, có thể chỉ chứa một số lượng giới hạn các phát hiện quan trọng nhất cho mỗi port).

**YÊU CẦU VỀ CẤU TRÚC JSON OUTPUT (Đây là cấu trúc bạn cần tạo ra):**
Hãy tuân thủ nghiêm ngặt cấu trúc JSON sau đây. Đảm bảo tất cả các trường bắt buộc đều có mặt và có kiểu dữ liệu chính xác. Nếu không có thông tin cho một trường tùy chọn, hãy để giá trị là `null` (cho các kiểu dữ liệu cơ bản như string, number, boolean) hoặc một mảng rỗng `[]` (cho kiểu mảng).

{
  "scan_target": "string (ví dụ: banhsinhnhat.com)",
  "scan_ip": "string (ví dụ: 194.233.91.24, nếu có)",
  "scan_timestamp_utc": "string (ISO 8601 format, ví dụ: 2025-05-18T10:30:00Z)",
  "overall_summary_text": "string (Một đoạn văn ngắn tóm tắt tình hình chung, ví dụ: 'Mục tiêu có X cổng mở, với Y lỗ hổng nghiêm trọng được phát hiện cần chú ý ngay. Các dịch vụ chính bao gồm Z, W...')",
  "statistics": {
    "total_hosts_scanned": "integer",
    "total_ports_checked": "integer (Số port Nmap đã quét, nếu không có trong input JSON, bạn có thể ước tính hoặc để là null)",
    "open_ports_count": "integer",
    "vulnerabilities_by_severity": {
      "critical": "integer",
      "high": "integer",
      "medium": "integer",
      "low": "integer",
      "informational_or_likely": "integer"
    },
    "total_vulnerabilities_found": "integer"
  },
  "hosts": [
    {
      "host_address": "string (IP hoặc domain từ input JSON)",
      "host_status": "string (ví dụ: up, down, từ input JSON)",
      "os_details": "string (Nếu có trong input JSON, có thể là null)",
      "ports": [
        {
          "port_id": "string (ví dụ: 22/tcp, từ input JSON)",
          "protocol": "string (tcp/udp, từ input JSON)",
          "port_number": "integer (từ port_id)",
          "state": "string (open, từ input JSON)",
          "service_name": "string (ví dụ: ssh, http, từ input JSON)",
          "service_product": "string (ví dụ: OpenSSH, nginx, từ input JSON, có thể là null)",
          "service_version": "string (ví dụ: 8.7, 1.18.0, từ input JSON, có thể là null)",
          "service_cpe": "string (nếu có, từ input JSON, có thể là null hoặc một mảng các CPE strings)",
          "findings": [
            {
              "finding_id": "string (ID từ mục `id` trong `vulners_findings` của input JSON)",
              "type": "string (vulnerability, misconfiguration, informational, likely_vulnerability)",
              "title": "string (Tiêu đề ngắn gọn cho CVE/phát hiện, bạn có thể tạo dựa trên finding_id và service)",
              "severity": "string (critical, high, medium, low, informational_or_likely)",
              "cvss_score": "float (nếu có, từ mục `cvss_score` trong `vulners_findings` của input JSON, có thể là null)",
              "cvss_vector": "string (nếu có, bạn cần tự tạo vector dựa trên CVSS score nếu không có sẵn, hoặc để null)",
              "description_summary": "string (Mô tả ngắn gọn, dễ hiểu về CVE/phát hiện này là gì, nguy cơ chính)",
              "detailed_description": "string (Mô tả chi tiết hơn nếu cần, có thể là null)",
              "impact": "string (Ảnh hưởng tiềm tàng nếu lỗ hổng bị khai thác, có thể là null)",
              "remediation_steps": [
                "string (Bước khắc phục 1, cụ thể và rõ ràng)",
                "string (Bước khắc phục 2, nếu có)"
              ],
              "references": [
                "string (Link tham khảo 1, lấy từ `url` trong `vulners_findings` của input JSON)"
              ],
              "exploits_available": [
                { # Chỉ điền nếu is_exploit_flag là true trong vulners_findings
                  "exploit_id": "string (ID của exploit từ `vulners_findings`)",
                  "source": "string (Nguồn của exploit, từ `source` trong `vulners_findings`)",
                  "url": "string (URL của exploit, từ `url` trong `vulners_findings`)"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}

**HƯỚNG DẪN CHI TIẾT CHO TỪNG PHẦN TRONG JSON OUTPUT MÀ BẠN CẦN TẠO (dựa trên INPUT JSON đã trích xuất):**

1.  **`scan_target`**: Lấy từ `scan_target_override` (nếu được cung cấp trong prompt) hoặc từ trường `address` của host trong input JSON.
2.  **`scan_ip`**: Lấy từ trường `address` của host trong input JSON.
3.  **`scan_timestamp_utc`**: Sử dụng thời gian hiện tại khi bạn xử lý, định dạng ISO 8601 UTC.
4.  **`overall_summary_text`**: Dựa trên toàn bộ input JSON, viết tóm tắt.
5.  **`statistics`**:
    *   `total_hosts_scanned`: Đếm số host trong input JSON.
    *   `total_ports_checked`: Nếu không có thông tin này trong input JSON, bạn có thể để là `null` hoặc một giá trị ước tính như 1000.
    *   `open_ports_count`: Đếm số port có `state: "open"` trong input JSON.
    *   `vulnerabilities_by_severity`: Đếm số `findings` bạn sẽ tạo ra, dựa trên `cvss_score` từ các mục trong `vulners_findings` của input JSON. Thang điểm:
        *   `critical`: CVSS 9.0-10.0.
        *   `high`: CVSS 7.0-8.9.
        *   `medium`: CVSS 4.0-6.9.
        *   `low`: CVSS 0.1-3.9.
        *   `informational_or_likely`: Còn lại (CVSS 0.0, null, hoặc các mục không phải CVE rõ ràng từ `vulners_findings` nếu có).
    *   `total_vulnerabilities_found`: Tổng của critical, high, medium, low.

6.  **`hosts`**: Lặp qua các host trong input JSON.
    *   Điền các trường `host_address`, `host_status`, `os_details` từ host tương ứng trong input JSON.
    *   `ports`: Lặp qua các `open_ports` của mỗi host trong input JSON.
        *   Điền `port_id`, `protocol`, `service_name`, `service_product`, `service_version`, `service_cpe` từ port tương ứng trong input JSON.
        *   `port_number`: Trích xuất số từ `portid`.
        *   `findings`: **Phần quan trọng nhất.** Lặp qua danh sách `vulners_findings` cho mỗi port trong input JSON. Mỗi mục trong `vulners_findings` (chứa `id`, `cvss_score`, `url`, `is_exploit_flag`, `source`) sẽ giúp bạn tạo ra một đối tượng `finding` trong output JSON này.
            *   `finding_id`: Lấy từ `id` của `vulners_findings`.
            *   `type`: Thường là `vulnerability`.
            *   `title`: Tạo tiêu đề súc tích (ví dụ: "[ID] in [service_name]").
            *   `severity`: Xác định dựa trên `cvss_score` từ `vulners_findings`.
            *   `cvss_score`: Lấy từ `cvss_score` của `vulners_findings`.
            *   `cvss_vector`: Nếu không có trong input, để `null`. Bạn không cần tự tạo.
            *   `description_summary`, `detailed_description`, `impact`: **Viết dựa trên hiểu biết của bạn về `finding_id` (CVE).** Bạn có thể cần kiến thức chung hoặc suy luận.
            *   **`remediation_steps`**: **Đề xuất các bước khắc phục cụ thể và thực tế cho `finding_id`.**
            *   `references`: Sử dụng `url` từ `vulners_findings`.
            *   `exploits_available`: Chỉ tạo mục này nếu `is_exploit_flag` là true trong `vulners_findings`. Điền `exploit_id`, `source`, `url` từ `vulners_findings`.

**LƯU Ý QUAN TRỌNG:**
*   Output PHẢI là một đối tượng JSON duy nhất, hợp lệ.
*   Các trường `description_summary`, `detailed_description`, `impact`, `remediation_steps`, `title` (cho finding) là những trường bạn cần TỔNG HỢP, SUY LUẬN và VIẾT RA một cách thông minh dựa trên thông tin `id` (CVE), `cvss_score`, `service_name` từ input JSON.
*   Nếu input JSON (phần `vulners_findings`) không có thông tin cho một trường nào đó (ví dụ `cvss_score` là null), hãy để `null` trong output JSON của bạn.

"""
    return prompt_template


def analyze_nmap_xml_with_llm(
    nmap_xml_content: str, scan_target_override: str | None = None
) -> dict:
    prompt_template = get_nmap_analysis_prompt_template()
    logger.info("Core: Bắt đầu trích xuất thông tin liên quan từ Nmap XML...")
    relevant_nmap_info_str = extract_relevant_nmap_info_for_llm(nmap_xml_content)
    logger.info(
        f"Core: Thông tin Nmap đã rút gọn cho LLM (độ dài: {len(relevant_nmap_info_str)} chars)."
    )
    estimated_prompt_tokens = len(relevant_nmap_info_str) / 3.5  # Ước tính thô
    logger.info(
        f"Core: Ước tính số token cho phần dữ liệu Nmap rút gọn: ~{int(estimated_prompt_tokens)} tokens."
    )
    # logger.debug(f"Core: Nội dung rút gọn cho LLM: \n{relevant_nmap_info_str}") # Để debug nếu cần

    final_prompt = (
        prompt_template
        + f"\n**Dưới đây là DỮ LIỆU NMAP ĐÃ ĐƯỢC TRÍCH XUẤT VÀ TÓM TẮT để bạn phân tích:**\n```json\n{relevant_nmap_info_str}\n```"
    )

    if scan_target_override:
        final_prompt = (
            f"**Ghi chú quan trọng:** Mục tiêu quét chính là '{scan_target_override}'. "
            f"Hãy sử dụng thông tin này để điền vào trường `scan_target` trong JSON output, "
            f"và nếu có thể, cho trường `host_address` nếu input JSON không cung cấp hostname một cách rõ ràng.\n\n"
            + final_prompt
        )

    logger.info(
        "Core: Chuẩn bị gửi prompt phân tích Nmap (thông tin đã rút gọn) đến LLM."
    )

    max_tokens_for_completion = 4090  # Giữ nguyên hoặc điều chỉnh nếu cần
    llm_raw_response = call_deepseek_llm(
        final_prompt, max_tokens=max_tokens_for_completion, require_json_output=False
    )

    json_response_str = llm_raw_response.strip()
    if json_response_str.startswith("```json"):
        json_response_str = json_response_str[len("```json") :]
        if json_response_str.endswith("```"):
            json_response_str = json_response_str[: -len("```")]
    elif json_response_str.startswith("```"):
        json_response_str = json_response_str[len("```") :]
        if json_response_str.endswith("```"):
            json_response_str = json_response_str[: -len("```")]
    json_response_str = json_response_str.strip()

    try:
        parsed_json_data = json.loads(json_response_str)
        logger.info("Core: Parse JSON từ phản hồi LLM thành công.")
        if not parsed_json_data.get("scan_target") and scan_target_override:
            parsed_json_data["scan_target"] = scan_target_override
            logger.info(
                f"Core: Đã đặt 'scan_target' từ override: {scan_target_override}"
            )
        if not parsed_json_data.get("scan_ip"):
            hosts_data = parsed_json_data.get("hosts", [])
            if hosts_data and isinstance(hosts_data, list) and len(hosts_data) > 0:
                first_host_address = hosts_data[0].get("host_address")
                if first_host_address and (
                    "." in first_host_address or ":" in first_host_address
                ):
                    parsed_json_data["scan_ip"] = first_host_address
        if not parsed_json_data.get("scan_timestamp_utc"):
            now_utc_str = (
                datetime.datetime.now(pytz.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
            parsed_json_data["scan_timestamp_utc"] = now_utc_str
        stats = parsed_json_data.get("statistics", {})
        if isinstance(stats, dict):
            vulns_by_severity = stats.get("vulnerabilities_by_severity", {})
            if isinstance(vulns_by_severity, dict):
                calculated_total_vulns = sum(
                    vulns_by_severity.get(sev, 0)
                    for sev in ["critical", "high", "medium", "low"]
                    if isinstance(vulns_by_severity.get(sev), (int, float))
                )
                if (
                    stats.get("total_vulnerabilities_found") != calculated_total_vulns
                    or "total_vulnerabilities_found" not in stats
                ):
                    stats["total_vulnerabilities_found"] = calculated_total_vulns
                parsed_json_data["statistics"] = stats
            else:
                stats.setdefault("total_vulnerabilities_found", 0)
                parsed_json_data["statistics"] = stats
        else:
            parsed_json_data.setdefault(
                "statistics",
                {"total_vulnerabilities_found": 0, "vulnerabilities_by_severity": {}},
            )
        return parsed_json_data
    except json.JSONDecodeError as jde:
        error_msg = f"Lỗi parse JSON từ LLM. Phản hồi LLM (toàn bộ nếu < 5000 chars, hoặc 1000 chars): {llm_raw_response[:(5000 if len(llm_raw_response) < 5000 else 1000)]}"
        logger.error(f"{error_msg}. Lỗi chi tiết: {jde}")
        if len(llm_raw_response) < 5000:
            logger.error(f"Toàn bộ phản hồi LLM khi parse lỗi:\n{llm_raw_response}")
        raise LLMInteractionError(error_msg)
    except Exception as e:
        error_msg = f"Lỗi không mong muốn khi xử lý phản hồi JSON từ LLM: {str(e)}. Phản hồi LLM (1000 chars): {llm_raw_response[:1000]}"
        logger.exception(error_msg)
        raise LLMInteractionError(error_msg)


def cleanup_temp_file(filepath: str | None):
    if filepath and os.path.exists(filepath):
        try:
            os.remove(filepath)
            logger.info(f"Core: Đã dọn dẹp file tạm: {filepath}")
        except Exception as e:
            logger.error(f"Core: Lỗi khi dọn dẹp file tạm {filepath}: {e}")


def read_file_content(filepath: str) -> str:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        logger.info(f"Core: Đã đọc thành công file: {filepath}")
        return content
    except Exception as e:
        logger.exception(f"Core: Lỗi khi đọc file {filepath}: {str(e)}")
        raise


if __name__ == "__main__":
    # target_to_test = "banhsinhnhat.com" # Chạy thành công
    target_to_test = "tantanluc.com"  # Thử lại với target này
    # target_to_test = "scanme.nmap.org"
    # target_to_test = "testphp.vulnweb.com"
    logger.info(f"--- Bắt đầu Test Full Pipeline cho: {target_to_test} ---")
    xml_file_path = None
    try:
        nmap_fixed_args = ["-sV", "--script", "vulners"]
        xml_file_path, nmap_out, nmap_err = run_nmap_scan(
            target_to_test,
            nmap_args=nmap_fixed_args,
            output_to_xml=True,
            timeout_seconds=600,
        )
        if xml_file_path:
            logger.info(f"Nmap XML được lưu tại: {xml_file_path}")
            xml_content_for_llm = read_file_content(xml_file_path)
            placeholder_api_key_check = "YOUR_PLACEHOLDER_API_KEY"
            if DEEPSEEK_API_KEY and DEEPSEEK_API_KEY not in [
                placeholder_api_key_check,
                "YOUR_ACTUAL_DEEPSEEK_API_KEY",
                "",
            ]:
                logger.info(
                    f"--- Bắt đầu Phân Tích Nmap XML bằng LLM cho {target_to_test} ---"
                )
                try:
                    analysis_result_json = analyze_nmap_xml_with_llm(
                        xml_content_for_llm, scan_target_override=target_to_test
                    )
                    logger.info(
                        f"--- Kết quả phân tích JSON từ LLM cho {target_to_test} (đã parse): ---"
                    )
                    print(
                        json.dumps(analysis_result_json, indent=2, ensure_ascii=False)
                    )
                    overall_summary = analysis_result_json.get(
                        "overall_summary_text", "Không có tóm tắt."
                    )
                    logger.info(f"\nOverall Summary: {overall_summary}")
                    stats = analysis_result_json.get("statistics", {})
                    if isinstance(stats, dict):
                        vuln_stats = stats.get("vulnerabilities_by_severity", {})
                        logger.info(f"Vulnerabilities by Severity: {vuln_stats}")
                        logger.info(
                            f"Total Vulnerabilities Found: {stats.get('total_vulnerabilities_found')}"
                        )
                    else:
                        logger.warning(
                            f"Trường 'statistics' không phải là dictionary: {stats}"
                        )
                    hosts = analysis_result_json.get("hosts", [])
                    if isinstance(hosts, list):
                        for host_idx, host in enumerate(hosts):
                            if isinstance(host, dict):
                                logger.info(
                                    f"  Host [{host_idx}]: {host.get('host_address')}, Status: {host.get('host_status')}"
                                )
                                ports = host.get("ports", [])
                                if isinstance(ports, list):
                                    for port_idx, port_info in enumerate(ports):
                                        if isinstance(port_info, dict):
                                            logger.info(
                                                f"    Port [{port_idx}]: {port_info.get('port_id')}, Service: {port_info.get('service_name')}"
                                            )
                                            findings = port_info.get("findings", [])
                                            if isinstance(findings, list):
                                                for find_idx, finding in enumerate(
                                                    findings
                                                ):
                                                    if isinstance(finding, dict):
                                                        logger.info(
                                                            f"      Finding [{find_idx}]: {finding.get('title')} ({finding.get('severity')}), CVSS: {finding.get('cvss_score')}"
                                                        )
                                                        remediation = finding.get(
                                                            "remediation_steps", ["N/A"]
                                                        )
                                                        if (
                                                            remediation
                                                            and isinstance(
                                                                remediation, list
                                                            )
                                                            and len(remediation) > 0
                                                        ):
                                                            logger.info(
                                                                f"        Remediation (first step): {remediation[0]}"
                                                            )
                                                        else:
                                                            logger.info(
                                                                "        Remediation: N/A or empty"
                                                            )
                                                    else:
                                                        logger.warning(
                                                            f"      Finding item at index {find_idx} is not a dict: {finding}"
                                                        )
                                            else:
                                                logger.warning(
                                                    f"    'findings' for port {port_info.get('port_id')} is not a list: {findings}"
                                                )
                                        else:
                                            logger.warning(
                                                f"    Port item at index {port_idx} is not a dict: {port_info}"
                                            )
                                else:
                                    logger.warning(
                                        f"  'ports' for host {host.get('host_address')} is not a list: {ports}"
                                    )
                            else:
                                logger.warning(
                                    f"  Host item at index {host_idx} is not a dict: {host}"
                                )
                    else:
                        logger.warning(f"'hosts' is not a list: {hosts}")
                except LLMInteractionError as llm_e:
                    logger.error(f"Lỗi trong quá trình phân tích LLM: {llm_e}")
                except Exception as ex_llm_analysis:
                    logger.error(
                        f"Lỗi không mong muốn trong hàm analyze_nmap_xml_with_llm: {ex_llm_analysis}"
                    )
                    logger.exception("Traceback lỗi analyze_nmap_xml_with_llm:")
            else:
                logger.warning(
                    f"DEEPSEEK_API_KEY chưa được cấu hình đúng (giá trị hiện tại: '{DEEPSEEK_API_KEY}'). Bỏ qua bước phân tích LLM."
                )
        else:
            logger.warning("Không có file XML nào được tạo từ Nmap.")
    except NmapExecutionError as ne:
        logger.error(f"Lỗi thực thi Nmap: {ne}")
        if ne.stdout:
            print(f"Nmap STDOUT khi lỗi:\n{ne.stdout}")
        if ne.stderr:
            print(f"Nmap STDERR khi lỗi:\n{ne.stderr}")
    except FileNotFoundError:
        logger.error(
            f"LỖI: Nmap không được tìm thấy tại '{NMAP_EXECUTABLE}'. Hãy kiểm tra biến NMAP_EXECUTABLE hoặc PATH."
        )
    except Exception as e:
        logger.exception(f"Lỗi không mong muốn trong quá trình test: {e}")
    finally:
        if xml_file_path and os.path.exists(xml_file_path):
            logger.info(
                f"File XML tạm thời được giữ lại tại: {xml_file_path} (để debug). Xóa thủ công nếu cần."
            )
        logger.info(f"--- Kết thúc Test ---")
