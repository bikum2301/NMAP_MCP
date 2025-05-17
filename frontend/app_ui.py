# nmap_fastmcp_project/frontend/app_ui.py

import gradio as gr
import requests
import json
import pandas as pd
import datetime
import logging
import html
import matplotlib.pyplot as plt
import numpy as np  # Cần cho matplotlib nếu dùng mảng

# Thiết lập logging cho frontend
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [FrontendUI] %(message)s",
)
logger = logging.getLogger(__name__)

# --- Cấu hình Client ---
BACKEND_API_URL = "http://127.0.0.1:8000"
SCAN_ENDPOINT = f"{BACKEND_API_URL}/scan"
HISTORY_ENDPOINT = f"{BACKEND_API_URL}/scans/history"
SCAN_DETAIL_ENDPOINT_TEMPLATE = f"{BACKEND_API_URL}/scans"


# --- Hàm tiện ích ---
def escape_html_value(text: any) -> str:
    if text is None:
        return "N/A"
    return html.escape(str(text))


def create_vulnerability_pie_chart(vuln_summary_dict: dict | None):
    if not vuln_summary_dict or not isinstance(vuln_summary_dict, dict):
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.text(
            0.5,
            0.5,
            "Không có dữ liệu thống kê lỗ hổng.",
            ha="center",
            va="center",
            fontsize=12,
        )
        ax.axis("off")
        return fig

    labels = []
    sizes = []
    # Sắp xếp theo mức độ nghiêm trọng mong muốn cho biểu đồ
    severity_order = [
        "vulnerable_critical",
        "vulnerable_high",
        "vulnerable_medium",
        "vulnerable_low",
        "likely_vulnerable_high",
        "likely_vulnerable_medium",
        "likely_vulnerable_low",
        "informational",
    ]

    display_labels = {
        "vulnerable_critical": "Vulnerable: Critical",
        "vulnerable_high": "Vulnerable: High",
        "vulnerable_medium": "Vulnerable: Medium",
        "vulnerable_low": "Vulnerable: Low",
        "likely_vulnerable_high": "Likely: High",
        "likely_vulnerable_medium": "Likely: Medium",
        "likely_vulnerable_low": "Likely: Low",
        "informational": "Informational",
    }

    for key in severity_order:
        value = vuln_summary_dict.get(key, 0)
        if (
            isinstance(value, (int, float)) and value > 0
        ):  # Chỉ thêm vào biểu đồ nếu có số lượng
            labels.append(display_labels.get(key, key.replace("_", " ").title()))
            sizes.append(value)

    if not sizes:  # Nếu tất cả đều là 0
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.text(
            0.5,
            0.5,
            "Không có lỗ hổng nào được phát hiện.",
            ha="center",
            va="center",
            fontsize=12,
        )
        ax.axis("off")
        return fig

    # Màu sắc tương ứng (bạn có thể tùy chỉnh)
    # Thêm màu cho các mức độ "likely"
    colors_map = {
        "Vulnerable: Critical": "#d32f2f",
        "Vulnerable: High": "#f57c00",
        "Vulnerable: Medium": "#fbc02d",
        "Vulnerable: Low": "#7cb342",  # Xanh lá cây nhạt hơn
        "Likely: High": "#ef5350",  # Đỏ nhạt
        "Likely: Medium": "#ffca28",  # Vàng nhạt
        "Likely: Low": "#aed581",  # Xanh lá cây rất nhạt
        "Informational": "#1976d2",
    }
    pie_colors = [
        colors_map.get(label, "#bdbdbd") for label in labels
    ]  # Màu xám cho các mục không có màu định sẵn

    fig, ax = plt.subplots(figsize=(8, 6))  # Tăng kích thước một chút
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=None,  # Không hiển thị label trực tiếp trên miếng bánh
        autopct="%1.1f%%",
        startangle=140,  # Xoay một chút cho đẹp
        colors=pie_colors,
        pctdistance=0.85,
        wedgeprops=dict(width=0.4, edgecolor="w"),  # Tạo hiệu ứng donut
    )
    ax.axis("equal")
    plt.title("Phân bố Lỗ hổng/Phát hiện", pad=20, fontsize=14)

    # Thêm legend riêng biệt
    ax.legend(
        wedges,
        labels,
        title="Mức độ",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
        fontsize="small",
    )
    plt.tight_layout()  # Điều chỉnh layout để legend không bị cắt
    return fig


# --- Hàm gọi Backend và Xử lý Kết quả ---
def trigger_scan_and_get_results(target_host: str):
    # Hàm này sẽ trả về 7 outputs cho Gradio
    if not target_host:
        empty_fig = create_vulnerability_pie_chart(None)
        return (
            "Lỗi: Vui lòng nhập mục tiêu.",
            pd.DataFrame(columns=["Phân loại", "Số lượng"]),
            empty_fig,
            "<p>Vui lòng nhập mục tiêu.</p>",
            "Chưa có output Nmap.",
            "Lỗi",
            "Mục tiêu không được để trống.",
        )

    current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status_message = f"[{current_time_str}] Đang gửi yêu cầu quét cho '{target_host}' đến backend {SCAN_ENDPOINT}...\n"
    logger.info(status_message.strip())

    empty_df = pd.DataFrame(columns=["Phân loại", "Số lượng"])
    empty_fig_on_error = create_vulnerability_pie_chart(None)
    default_error_outputs_tuple = (
        "Đã xảy ra lỗi.",
        empty_df,
        empty_fig_on_error,
        "<p>Đã xảy ra lỗi.</p>",
        "Không có output Nmap.",
        "Lỗi",
        status_message,
    )

    try:
        response = requests.post(
            SCAN_ENDPOINT, json={"target": target_host}, timeout=900
        )
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_message += f"[{current_time_str}] Nhận được phản hồi từ backend (Status: {response.status_code}).\n"
        logger.info(f"Backend response status: {response.status_code}")

        if response.status_code == 202 or response.status_code == 200:
            data = response.json()
            session_id = data.get("session_id", "N/A")
            backend_message = data.get("message", "N/A")
            logger.info(
                f"Phản hồi từ backend: {backend_message}, Session ID: {session_id}"
            )
            status_message += f"Backend: {backend_message} (Session ID: {session_id})\n"

            analysis = data.get("analysis_result")
            if analysis and isinstance(analysis, dict):
                current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                status_message += (
                    f"[{current_time_str}] Backend xử lý xong. Định dạng kết quả...\n"
                )

                summary_text_md = analysis.get(
                    "overall_summary_text", "Không có tóm tắt."
                )

                stats_data = analysis.get("statistics", {})
                vuln_summary = (
                    stats_data.get("vulnerability_summary", {})
                    if isinstance(stats_data, dict)
                    else {}
                )

                # Tạo DataFrame từ vulnerability_summary
                if isinstance(vuln_summary, dict) and vuln_summary:
                    # Sử dụng display_labels cho DataFrame
                    df_data = {
                        display_labels.get(k, k.replace("_", " ").title()): [v]
                        for k, v in vuln_summary.items()
                        if isinstance(v, (int, float)) and v > 0
                    }
                    if df_data:
                        stats_df = pd.DataFrame.from_dict(
                            df_data, orient="index", columns=["Số lượng"]
                        )
                        stats_df.index.name = "Phân loại Lỗ hổng/Phát hiện"
                        stats_df = stats_df.reset_index()  # Chuyển index thành cột
                    else:
                        stats_df = empty_df
                else:
                    stats_df = empty_df

                pie_chart_fig = create_vulnerability_pie_chart(vuln_summary)
                findings_html_content = format_findings_to_html(analysis)
                nmap_out_text = data.get("nmap_stdout", "N/A")
                if data.get("nmap_stderr"):
                    nmap_out_text += (
                        f"\n\n--- Nmap STDERR ---\n{data.get('nmap_stderr')}"
                    )

                current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                status_message += f"[{current_time_str}] Hiển thị kết quả thành công.\n"
                logger.info(
                    f"Hiển thị kết quả cho target: {target_host}, session ID: {session_id}"
                )
                return (
                    summary_text_md,
                    stats_df,
                    pie_chart_fig,
                    findings_html_content,
                    nmap_out_text,
                    f"Hoàn tất (ID: {session_id})",
                    status_message,
                )
            else:
                error_detail = data.get("error_details", backend_message)
                status_message += (
                    f"[{current_time_str}] Backend báo lỗi: {error_detail}\n"
                )
                logger.error(status_message.strip())
                return (
                    "Lỗi từ backend.",
                    empty_df,
                    empty_fig_on_error,
                    f"<p>Lỗi: {escape_html_value(error_detail)}</p>",
                    data.get("nmap_stdout", ""),
                    f"Lỗi (ID: {session_id})",
                    status_message,
                )
        else:
            # ... (Xử lý lỗi HTTP như trước, đảm bảo trả về đủ 7 output)
            error_content_str = f"Lỗi HTTP {response.status_code}."
            try:
                error_data = response.json()
                detail = error_data.get("detail", response.text)
                if isinstance(detail, dict):
                    error_content_str = detail.get(
                        "error_details", detail.get("message", json.dumps(detail))
                    )
                elif isinstance(detail, str):
                    error_content_str = detail
                else:
                    error_content_str = response.text
            except json.JSONDecodeError:
                error_content_str = response.text
            current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status_message += f"[{current_time_str}] {error_content_str}\n"
            logger.error(status_message.strip())
            return (
                f"Lỗi: {error_content_str}",
                empty_df,
                empty_fig_on_error,
                f"<p>Lỗi: {escape_html_value(error_content_str)}</p>",
                None,
                "Lỗi Backend",
                status_message,
            )

    except requests.exceptions.Timeout:
        # ... (Trả về đủ 7 output)
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_message += (
            f"[{current_time_str}] Lỗi: Timeout khi kết nối đến backend.\n"
        )
        logger.error(status_message.strip())
        return (
            default_error_outputs_tuple[0],
            default_error_outputs_tuple[1],
            empty_fig_on_error,
            "<p>Lỗi: Backend không phản hồi kịp thời.</p>",
            default_error_outputs_tuple[4],
            default_error_outputs_tuple[5],
            status_message,
        )
    except requests.exceptions.ConnectionError:
        # ... (Trả về đủ 7 output)
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_message += f"[{current_time_str}] Lỗi: Không thể kết nối đến backend.\n"
        logger.error(status_message.strip())
        return (
            default_error_outputs_tuple[0],
            default_error_outputs_tuple[1],
            "<p>Lỗi: Không thể kết nối đến backend.</p>",
            default_error_outputs_tuple[4],
            default_error_outputs_tuple[5],
            status_message,
        )
    except Exception as e:
        # ... (Trả về đủ 7 output)
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_message += f"[{current_time_str}] Lỗi client: {str(e)}\n"
        logger.exception("Lỗi không xác định phía client:")
        return (
            default_error_outputs_tuple[0],
            default_error_outputs_tuple[1],
            f"<p>Lỗi client: {escape_html_value(str(e))}</p>",
            default_error_outputs_tuple[4],
            default_error_outputs_tuple[5],
            status_message,
        )


def format_findings_to_html(analysis_data: dict) -> str:
    if not analysis_data or not isinstance(analysis_data.get("hosts"), list):
        return "<p>Không có dữ liệu findings hoặc cấu trúc không hợp lệ.</p>"
    html_output = "<div style='font-family: sans-serif; line-height: 1.6;'>"
    hosts = analysis_data.get("hosts", [])
    if not hosts:
        html_output += "<p><em>Không có thông tin host.</em></p>"
    for host_idx, host in enumerate(hosts):
        if not isinstance(host, dict):
            continue
        html_output += f"<h3>Host: {escape_html_value(host.get('host_address'))} (Status: {escape_html_value(host.get('host_status'))})</h3>"
        if host.get("os_details"):
            html_output += f"<p><strong>OS:</strong> {escape_html_value(host.get('os_details'))}</p>"
        ports = host.get("ports", [])
        if not isinstance(ports, list) or not ports:
            html_output += "<p><em>Không có port mở cho host này.</em></p>"
            continue
        for port_idx, port in enumerate(ports):
            if not isinstance(port, dict):
                continue
            svc_parts = [
                escape_html_value(s)
                for s in [port.get("service_product"), port.get("service_version")]
                if s
            ]
            svc_str = f"({', '.join(svc_parts)})" if svc_parts else ""
            html_output += f"<h4 style='color: #2c3e50; margin-top: 20px;'>Port: {escape_html_value(port.get('port_id'))} - {escape_html_value(port.get('service_name'))} {svc_str}</h4>"
            findings = port.get("findings", [])
            if not isinstance(findings, list) or not findings:
                html_output += "<p><em>Không có findings cho port này.</em></p>"
                continue
            for find_idx, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    continue
                sev = escape_html_value(finding.get("severity_level")).capitalize()
                sev_color = {
                    "Critical": "#d32f2f",
                    "High": "#f57c00",
                    "Medium": "#fbc02d",
                    "Low": "#7cb342",
                    "Informational": "#1976d2",
                }.get(sev, "#757575")
                category_display = (
                    escape_html_value(finding.get("category", "N/A"))
                    .replace("_", " ")
                    .title()
                )

                html_output += f"<div style='border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 8px; background-color: #f9f9f9;'>"
                html_output += f"<h5 style='margin-top:0; color: {sev_color};'><strong>{escape_html_value(finding.get('title'))} (Category: {category_display} - Severity: {sev})</strong></h5>"
                html_output += f"<p><strong>ID:</strong> {escape_html_value(finding.get('finding_id'))}</p>"
                if finding.get("cvss_score") is not None:
                    html_output += f"<p><strong>CVSS Score:</strong> {escape_html_value(finding.get('cvss_score'))}"
                    if finding.get("cvss_vector"):
                        html_output += (
                            f" ({escape_html_value(finding.get('cvss_vector'))})"
                        )
                    html_output += "</p>"
                if finding.get("type"):
                    html_output += f"<p><strong>Type:</strong> {escape_html_value(finding.get('type'))}</p>"
                if finding.get("category") == "likely_vulnerability" and finding.get(
                    "evidence_for_likely"
                ):
                    html_output += "<p><strong>Lý do nghi ngờ (Evidence):</strong></p><ul style='margin-top:0;padding-left:20px;'>"
                    for ev in finding.get("evidence_for_likely", []):
                        html_output += f"<li>{escape_html_value(ev)}</li>"
                    html_output += "</ul>"
                html_output += f"<p><strong>Tóm tắt:</strong> {escape_html_value(finding.get('description_summary'))}</p>"
                if finding.get("detailed_description"):
                    html_output += f"<p><strong>Mô tả chi tiết:</strong> {escape_html_value(finding.get('detailed_description'))}</p>"
                if finding.get("impact"):
                    html_output += f"<p><strong>Ảnh hưởng:</strong> {escape_html_value(finding.get('impact'))}</p>"
                html_output += "<p style='margin-bottom:5px;'><strong>Các bước khắc phục:</strong></p><ul style='margin-top:0;padding-left:20px;'>"
                remediation = finding.get("remediation_steps", [])
                if remediation and isinstance(remediation, list):
                    for step in remediation:
                        html_output += f"<li>{escape_html_value(step)}</li>"
                else:
                    html_output += "<li>Chưa có đề xuất.</li>"
                html_output += "</ul>"
                refs = finding.get("references", [])
                if refs and isinstance(refs, list):
                    html_output += "<p style='margin-bottom:5px;'><strong>Tham khảo:</strong></p><ul style='margin-top:0;padding-left:20px;'>"
                    for ref in refs:
                        html_output += f"<li><a href='{escape_html_value(ref)}' target='_blank' rel='noopener noreferrer'>{escape_html_value(ref)}</a></li>"
                    html_output += "</ul>"
                exploits = finding.get("exploits_available", [])
                if exploits and isinstance(exploits, list):
                    html_output += "<p style='margin-bottom:5px;'><strong>Exploits:</strong></p><ul style='margin-top:0;padding-left:20px;'>"
                    for ex in exploits:
                        if isinstance(ex, dict):
                            html_output += f"<li>ID: {escape_html_value(ex.get('exploit_id'))} (<a href='{escape_html_value(ex.get('url'))}' target='_blank' rel='noopener noreferrer'>{escape_html_value(ex.get('source'))}</a>)</li>"
                    html_output += "</ul>"
                html_output += "</div>"
    html_output += "</div>"
    return html_output


with gr.Blocks(
    title="Nmap FastMCP Client",
    theme=gr.themes.Soft(
        primary_hue=gr.themes.colors.blue, secondary_hue=gr.themes.colors.sky
    ),
) as demo:
    gr.Markdown(
        "<h1 style='text-align: center; color: #2c3e50;'>Nmap FastMCP - Phân tích lỗ hổng thông minh</h1>"
    )
    gr.Markdown(
        "<p style='text-align: center;'>Nhập mục tiêu (domain hoặc IP) để quét Nmap và nhận phân tích chi tiết được hỗ trợ bởi LLM.</p>"
    )

    with gr.Row():
        target_input = gr.Textbox(
            label="Mục tiêu cần quét",
            placeholder="Ví dụ: scanme.nmap.org, example.com",
            elem_id="target-input-textbox",
            scale=3,
        )
        scan_button = gr.Button(
            "🚀 Quét Ngay!", variant="primary", elem_id="scan-button", scale=1
        )

    status_processing_message = gr.Textbox(
        label="Trạng thái xử lý",
        lines=3,
        interactive=False,
        placeholder="Nhấn 'Quét Ngay!' để bắt đầu...",
    )
    hidden_status_flag = gr.Textbox(value="idle", visible=False)

    with gr.Tabs() as tabs_output:
        with gr.TabItem("📊 Tóm tắt & Thống kê", id="tab_summary"):
            overall_summary_output = gr.Markdown(label="Tóm tắt chung từ LLM")
            # Thay đổi gr.DataFrame thành gr.Markdown để hiển thị bảng từ HTML hoặc Pandas to_html()
            # Hoặc chúng ta sẽ dùng gr.DataFrame và đảm bảo dữ liệu đầu vào đúng
            stats_table_output = gr.DataFrame(
                label="Thống kê Lỗ hổng/Phát hiện",
                headers=["Phân loại", "Số lượng"],
                wrap=True,
            )
            plot_output = gr.Plot(label="Biểu đồ Phân bố Lỗ hổng/Phát hiện")

        with gr.TabItem("📄 Chi tiết Phát hiện", id="tab_findings"):
            findings_output_html = gr.HTML(label="Chi tiết các phát hiện")

        with gr.TabItem("📋 Nmap Raw Output (Tùy chọn)", id="tab_nmap_raw"):
            nmap_raw_output = gr.Textbox(
                label="Output thô từ Nmap (dành cho chuyên gia/debug)",
                lines=20,
                interactive=False,
            )

    scan_button.click(
        fn=trigger_scan_and_get_results,
        inputs=[target_input],
        outputs=[
            overall_summary_output,
            stats_table_output,
            plot_output,  # Thêm output cho biểu đồ
            findings_output_html,
            nmap_raw_output,
            hidden_status_flag,
            status_processing_message,
        ],
        api_name="scan_target",
    )

    gr.Markdown("---")
    gr.Markdown(
        f"<p style='text-align: center; font-size: 0.9em;'>Client này giao tiếp với Backend API tại: `{BACKEND_API_URL}`. Đảm bảo backend đang chạy.</p>"
    )

if __name__ == "__main__":
    logger.info(f"Khởi chạy Gradio UI. Kết nối đến backend: {BACKEND_API_URL}")
    print(
        f"Khởi chạy Gradio UI. Đảm bảo backend FastAPI đang chạy tại {BACKEND_API_URL}"
    )
    demo.launch()
