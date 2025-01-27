import os
import hashlib
import json
import requests
import pandas as pd
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from openpyxl import load_workbook, Workbook
from openpyxl.worksheet.datavalidation import DataValidation
from threading import Thread
from ttkbootstrap import Style
import time

# OSV API URL
OSV_API_URL = "https://api.osv.dev/v1/query"

scan_running = False
start_time = None

def query_osv(package_name, ecosystem):
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    response = requests.post(OSV_API_URL, json=payload)
    if response.status_code == 200:
        return response.json()
    return None

def scan_directory(base_dir, progress_var, progress_label, files_scanned_label, elapsed_time_label, vulnerabilities_label, scan_status_label, tk_root):
    global scan_running, start_time
    scan_running = True
    start_time = time.time()
    
    scan_status_label.config(text="SCA Scan Status: Searching for libraries...")

    libraries = []
    files = []
    
    for root, _, file_list in os.walk(base_dir):
        files.extend([os.path.join(root, f) for f in file_list])
    
    total_files = len(files)
    
    for index, file_path in enumerate(files):
        if not scan_running:
            break

        try:
            if not os.access(file_path, os.R_OK):
                continue
            
            ext = os.path.splitext(file_path)[1].lower()
            if ext in [".dll", ".jar", ".json"]:
                with open(file_path, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                libraries.append({
                    "FileName": os.path.basename(file_path),
                    "Path": file_path,
                    "Hash": file_hash
                })

            # Update Status & UI Progress
            scan_status_label.config(text=f"SCA Scan Status: {index + 1}/{total_files} libraries found.")
            progress_var.set(int((index + 1) / total_files * 100))
            elapsed_time = time.time() - start_time
            files_scanned_label.config(text=f"Files Scanned: {index + 1}/{total_files}")
            elapsed_time_label.config(text=f"Time Elapsed: {elapsed_time:.2f} sec")
            tk_root.update_idletasks()
            tk_root.update()  # Force UI update
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
    
    scan_running = False
    return libraries

def stop_scan():
    global scan_running
    scan_running = False

def search_vulnerabilities(libraries, tree, vulnerabilities_label, scan_status_label):
    xlsx_file = "SCA_vulnerabilities.xlsx"
    cve_results = []

    scan_status_label.config(text="SCA Scan Status: Scanning for CVEs...")

    for lib in libraries:
        if "Newtonsoft.Json" in lib["FileName"]:
            osv_data = query_osv("Newtonsoft.Json", "NuGet")
            if osv_data and "vulns" in osv_data:
                for vuln in osv_data["vulns"]:
                    cve_results.append([
                        vuln.get("id", "Unknown"),
                        vuln.get("cvss_score", "N/A"),
                        lib["FileName"],
                        lib["Path"],
                        "Open",
                        lib["Hash"]
                    ])

    wb = Workbook()
    sheet = wb.active
    sheet.title = "SCA Vulnerabilities"
    sheet.append(["CVE_ID", "CVSS Score", "Library Name", "Location", "Status", "Fix Status"])

    dv = DataValidation(type="list", formula1='"Open,In Progress,Noise,Passed,Fixed"', allow_blank=False)
    sheet.add_data_validation(dv)

    for row in cve_results:
        sheet.append(row)

    wb.save(xlsx_file)

    for item in tree.get_children():
        tree.delete(item)

    for row in cve_results:
        tree.insert("", "end", values=row)

    vulnerabilities_label.config(text=f"Vulnerabilities Found: {len(cve_results)}")
    scan_status_label.config(text=f"SCA Scan Status: Scan Complete")

def browse_folder():
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        folder_path.set(folder_selected)

def start_scan():
    global scan_running
    if scan_running:
        scan_running = False
        scan_btn.config(text="Start Scan")
        return
    
    directory = folder_path.get()
    if not directory:
        messagebox.showerror("Error", "Please select a folder to scan.")
        return
    
    tree.delete(*tree.get_children())
    scan_btn.config(text="Stop Scan")
    
    # Start scan thread with correct arguments
    scan_thread = Thread(target=scan_and_find, args=(
        directory, progress_var, progress_label, files_scanned_label,
        elapsed_time_label, vulnerabilities_label, scan_status_label, root))
    scan_thread.start()

def scan_and_find(directory, progress_var, progress_label, files_scanned_label, elapsed_time_label, vulnerabilities_label, scan_status_label, tk_root):
    libraries = scan_directory(directory, progress_var, progress_label, files_scanned_label, elapsed_time_label, vulnerabilities_label, scan_status_label, tk_root)
    search_vulnerabilities(libraries, tree, vulnerabilities_label, scan_status_label)
    
    # Reset Button Text
    scan_btn.config(text="Start Scan")
    messagebox.showinfo("Scan Complete", "Scanning and vulnerability search complete!")

# UI Setup
root = tk.Tk()
style = Style("darkly")
root.title("SCA Vulnerability Scanner")
root.geometry("800x600")

frame = ttk.Frame(root, padding=10)
frame.pack(fill="both", expand=True)

folder_path = tk.StringVar()

ttklbl = ttk.Label(frame, text="Select Folder:")
ttklbl.grid(row=0, column=0, padx=5, pady=5)
entry = ttk.Entry(frame, textvariable=folder_path, width=50)
entry.grid(row=0, column=1, padx=5, pady=5)
browse_btn = ttk.Button(frame, text="Browse", command=browse_folder)
browse_btn.grid(row=0, column=2, padx=5, pady=5)

scan_btn = ttk.Button(frame, text="Start Scan", command=start_scan)
scan_btn.grid(row=1, column=1, pady=10)

progress_var = tk.IntVar()
progress_label = ttk.Label(frame, text="Progress:")
progress_label.grid(row=2, column=0, pady=10)
progress_bar = ttk.Progressbar(frame, variable=progress_var, length=400)
progress_bar.grid(row=2, column=1, pady=10)

scan_status_label = ttk.Label(frame, text="SCA Scan Status: Idle")
scan_status_label.grid(row=3, column=1, pady=5)

files_scanned_label = ttk.Label(frame, text="Files Scanned: 0/0")
files_scanned_label.grid(row=4, column=1, pady=5)
elapsed_time_label = ttk.Label(frame, text="Time Elapsed: 0.00 sec")
elapsed_time_label.grid(row=4, column=2, pady=5)
vulnerabilities_label = ttk.Label(frame, text="Vulnerabilities Found: 0")
vulnerabilities_label.grid(row=5, column=1, pady=5)

columns = ("CVE_ID", "CVSS Score", "Library Name", "Location", "Status", "Fix Status")
tree = ttk.Treeview(frame, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=130)

tree.grid(row=6, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

frame.grid_columnconfigure(1, weight=1)
frame.grid_rowconfigure(6, weight=1)

root.mainloop()
