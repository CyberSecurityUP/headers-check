## 🛡️ HTTP Header Analyzer

A **Go-based tool** to scan multiple domains for **missing, insecure, security, and fingerprint headers**.  
It fetches HTTP headers, analyzes them, and exports results in **color-coded terminal output** and a **CSV file**.

---

### 📥 **Installation & Dependencies**
1. **Install Go** (if not already installed):  
   [Download & Install Go](https://golang.org/dl/)
   
2. **Clone the repository**:
   ```sh
   git clone https://github.com/CyberSecurityUP/http-headers-check
   cd http-headers-check
   ```

3. **Install dependencies**:
   ```sh
   go get github.com/fatih/color
   ```

---

### 🚀 **Usage**
1. **Place your domain list in a text file** (e.g., `files/domains.txt`):
   ```
   google.com
   facebook.com
   example.com
   ```

2. **Run the script**:
   ```sh
   go run header_checker.go
   ```

3. **Choose a domain input method**:
   - Enter a file name:
     ```
     📄 Enter domain file name (or press ENTER for manual input): files/domains.txt
     ```
   - OR manually enter domains:
     ```
     📝 Enter domains/subdomains (space-separated): google.com facebook.com example.com
     ```

4. **Check the results in the terminal**:
   ```
   🔎 Scanning: example.com
   🟢 Security Headers Found: Content-Security-Policy, X-Frame-Options
   🟡 Missing Headers: Strict-Transport-Security, X-Content-Type-Options
   🔴 Insecure Headers: Access-Control-Allow-Origin
   🔍 Technologies Detected (Fingerprint): Cloudflare-CDN-Cache-Control
   📄 Results saved in 'header_analysis.csv'
   ```

5. **View the results in the CSV file**:
   ```sh
   cat header_analysis.csv
   ```

---

### 📂 **Project Structure**
```
http-header-analyzer/
│── files/                     # Header definition files
│   ├── missing.txt             # List of required headers
│   ├── insecure.txt            # List of insecure headers
│   ├── security.txt            # List of security-related headers
│   ├── fingerprint.txt         # List of fingerprint headers (CDN, Azure, Cloudflare, etc.)
│── header_checker.go           # Main Go script
│── README.md                   # Project documentation
│── header_analysis.csv         # Output results (generated after scan)
```

---

### 🛠 **Features**
✅ Scans multiple **domains & subdomains**  
✅ Detects **missing** & **insecure** headers  
✅ Lists **security headers in use**  
✅ Identifies **fingerprint headers (CDN, Azure, Cloudflare, etc.)**  
✅ **Exports results to CSV** for analysis  
✅ **Color-coded terminal output** for better visibility  

---

### 📜 **License**
This project is licensed under the **MIT License**.

---

### 💡 **Contributions**
Contributions are welcome! Feel free to submit issues or pull requests.
