# PTLHBM-Nhom12-AnToanMangKhongDay
# ĐỀ TÀI 16: PHÂN TÍCH VÀ ĐÁNH GIÁ AN TOÀN MẠNG KHÔNG DÂY
**Nhóm thực hiện:** Nhóm 12 – Lớp 15DHBM06 – Trường Đại học Công Thương TP.HCM (HUIT)  
**Giảng viên hướng dẫn:** ThS. Võ Hoàng Hải

## 1. Cấu trúc gói bằng chứng thực nghiệm (Evidence Pack E1 – E4)
- `E1_Inventory/`: Dữ liệu quét kiểm kê tài sản vô tuyến (`capture_E2-01.csv`, `capture_E2-01.kismet.csv`) trên Kênh 8 (`10:7C:61:84:39:91` - `Bankstown 2.4G`).
- `E2_PCAP_Traffic/`: Tệp lưu lượng đã làm sạch (`capture_E2-01.cap`) chứa khung quản lý Beacon/Deauth và chuỗi bắt tay 4 bước `EAPOL` của thiết bị kiểm thử `4E:C0:DA:52:13:E4`.
- `E3_Profile_Audit/`: Từ điển kiểm thử mật khẩu giả lập (`pass.txt`), lưu lượng đối chứng WPA3-SAE (`capture_wpa3-01.cap`) và dữ liệu kiểm chứng sau gia cố (`capture_retest_strong-01.cap`).
- `E4_Hardening_And_Detection/`: Mã nguồn kịch bản Python giám sát phát hiện Rogue AP (`detect_rogue.py`) và cấu hình mẫu gia cố AP (`secure_ap.conf`).
- `SHA256SUMS.txt`: Bảng mã băm SHA-256 kiểm chứng tính toàn vẹn dữ liệu.

## 2. Hướng dẫn tái lập nhanh kết quả (Reproducibility)
```
# Kiểm tra toàn vẹn file
sha256sum -c SHA256SUMS.txt

# Mở file PCAP lọc gói bắt tay EAPOL trên Wireshark
wireshark -r E2_PCAP_Traffic/capture_E2-01.cap -Y "eapol"

# Kiểm thử độ mạnh mật khẩu WPA2-PSK bằng Aircrack-ng
aircrack-ng -w E3_Profile_Audit/pass.txt -b 10:7C:61:84:39:91 E2_PCAP_Traffic/capture_E2-01.cap

# Chạy kịch bản Python tự động phát hiện Rogue AP / Evil Twin
python3 E4_Hardening_And_Detection/detect_rogue.py
