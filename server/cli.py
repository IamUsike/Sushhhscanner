# TODO 
# 1. Read the documentation on init,Fore,style libraries from colorama and enlighten this file

#!/usr/bin/env python 

"""
CLI for Advanced Direcotry Enumeration
"""

# libs

import asyncio # I am still learning this guys - hope this has the same functionality as "async" from js
import argparse
import sys
import os
import subprocess
import json
from datetime import datetime 
from dir_enum import DirectoryEnumerator # ourmain tool - inorder to keep our prjt minimal and locally deployed + independent of any global requirement
from colorama import init,Fore,Style # colors beradar - I like python now - bash can easily keep up with python need to watch Mr.ROBOT again - they use both a lot
from tabulate import tabulate
from tqdm import tqdm
import csv
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, SimpleDocTemplate

async def main():
    from colorama import init,Fore,Style
    from tabulate import tabulate
    from tqdm import tqdm
    import csv
    import pandas as pd
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle, SimpleDocTemplate
    import os
    import argparse
    import sys
    import subprocess
    import json
    from datetime import datetime
    from dir_enum import DirectoryEnumerator

    # Initalise colorama for cross-platform colored output
    init()

    def silhouette():
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                 🔍 Advanced Directory Enumerator 🔍                    ║
║                      Security Testing Tool                             ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    parser=argparse.ArgumentParser(
        description="Advanced Directory Enumerator - Security Testing Tools [ primary purpose : API testing ]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        python cli.py https://ksurajsingh.github.io 
        python cli.py https://ksurajsingh.github.io --wordlist directories --workers 100 
        python cli.py https://ksurajsingh.github.io --output results.json --delay 0.5
        """
    )
    parser.add_argument("target",help="Target URL to scan")
    parser.add_argument("-w","--wordlist",choices=["common","directories","files"],default="common",help="Wordlist type to use")
    parser.add_argument("--wordlist-file", type=str, help="Path to a custom wordlist file")
    parser.add_argument("--worker",type=int,default=50)
    parser.add_argument("--delay",type=float,default=0.1,help="Delay between requests in seconds (default: 0.1)")
    parser.add_argument("-o","--output",help="Specify json file to json")
    parser.add_argument("-to","--timeout",type=int,default=10,help="Request timeout in seconds (default:10)")
    parser.add_argument("-q","--quiet",action="store_true",help="Suppress detailed output,show only summary")
    parser.add_argument("-j","--json",action="store_true",help="Output results in JSON format")
    parser.add_argument("--recursive", action="store_true", help="Enable recursive directory enumeration")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum recursion depth (default: 2)")
    parser.add_argument("--table", action="store_true", help="Display results in a colored table format")
    parser.add_argument("--progress", action="store_true", help="Show progress bar during scan")
    parser.add_argument("--rate-limit", type=float, help="Maximum requests per second (rate limiting, takes precedence over delay)")
    parser.add_argument("--export-csv", type=str, help="Export results to CSV file")
    parser.add_argument("--export-excel", type=str, help="Export results to Excel (XLSX) file")
    parser.add_argument("--export-pdf", type=str, help="Export results to PDF file")
    parser.add_argument("--verbose", action="store_true", help="Show extra details for each result and debug info")
    parser.add_argument("--silent", action="store_true", help="Suppress all output except errors and summary")
    parser.add_argument("--error-log", type=str, help="Log errors and exceptions to this file")

    args=parser.parse_args()

    def log_error(message):
        if args.error_log:
            with open(args.error_log, 'a', encoding='utf-8') as f:
                f.write(message + '\n')

    def print_status(message,status_type="info"):
        colors = {
            "info":Fore.BLUE,
            "success":Fore.GREEN,
            "warning":Fore.YELLOW,
            "error":Fore.RED
        }
        color = colors.get(status_type,Fore.WHITE)
        print(f"{color}[{status_type.upper()}] {message}{Style.RESET_ALL}")
        if status_type == "error":
            log_error(f"[{status_type.upper()}] {message}")

    def print_result(result):
        status_code=result.status_code
        url=result.url 
        if status_code in [200,201,202,203,204,205,206,207,208,226]:
            status_color=Fore.GREEN
            status_text=f"{status_code} OK"
        elif status_code in [301,301,303,304,305,306,307,308]:
            status_color=Fore.YELLOW
            status_text=f"{status_code} Redirect"
        elif status_code == 403:
            status_color = Fore.RED
            status_text = f"{status_code} Forbidden"
        elif status_code >=500:
            status_color = Fore.RED
            status_text = f"{status_code} Server Error"
        else:
            status_color = Fore.WHITE
            status_text = str(status_code)
        size_str=f"{result.content_length} bytes" if result.content_length > 0 else "N/A"
        time_str=f"{result.response_time:.3f}s"
        type_str= "DIR" if result.is_directory else "FILE"
        print(f"{status_color}[{status_text}]{Style.RESET_ALL} {url}")
        print(f"\n\n-TYPE: {type_str}")
        print(f"-SIZE: {size_str}")
        print(f"-TIME: {time_str}")
        if result.title:
            print(f"-TITLE: {result.title}")
        if result.server:
            print(f"-SERVER: {result.server}")
        else:
            print(f"-SERVER: N/A")
        print()

    def print_summary(result,scan_stats,target_url,wordlist_type):
        print(f"\n{Fore.CYAN}══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        duration = scan_stats["end_time"] - scan_stats["start_time"] if scan_stats["end_time"] else 0
        print(f"Target URL: {target_url}")
        print(f"Wordlist: {wordlist_type}")
        print(f"Total Checked: {scan_stats['total_requests']}")
        print(f"Found Items: {len(result)}")
        print(f"Success Rate: {(len(result)/scan_stats['total_requests']*100):.1f}%")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Requests/sec: {scan_stats['total_requests']/duration:.1f}" if duration > 0 else "Requests/sec: N/A")
        status_codes={}
        for result in result:
            status_codes[result.status_code]=status_codes.get(result.status_code,0)+1
        if status_codes:
            print(f"\n{Fore.YELLOW}Status Code Breakdown:{Style.RESET_ALL}")
            for code,count in sorted(status_codes.items()):
                print(f"{code}:{count}")

    def save_results(results,target_url,output_file):
        try:
            data={
                    "target_url":target_url,
                    "scan_time":datetime.now().isoformat(),
                    "total_found":len(results),
                    "results":[
                        {
                            "url":r.url,
                            "status_code":r.status_code,
                            "response_time":r.response_time,
                            "content_length":r.content_length,
                            "is_directory":r.is_directory,
                            "title":r.title,
                            "server":r.server,
                            "content_type":r.content_type
                            }
                        for r in results
                        ]
                    }
            with open(output_file,'w') as f:
                json.dump(data,f,indent=2)
            print_status(f"Results saved to: {output_file}","success")
        except Exception as e:
            print_status(f"Error saving results: {str(e)}","error")

    # Load custom wordlist if provided
    custom_wordlist = None
    if args.wordlist_file:
        try:
            with open(args.wordlist_file, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print_status(f"Loaded custom wordlist with {len(custom_wordlist)} entries from {args.wordlist_file}", "info")
        except Exception as e:
            print_status(f"Failed to load custom wordlist: {e}", "error")
            sys.exit(1)

    # real output on console 
    silhouette()

    target_url=args.target 
    if not target_url.startswith(("https://","http://")):
        target_url:'https://'+target_url

    print_status(f"Starting scan of: {target_url}","info")
    subprocess.run(["sleep", "1"])
    if args.wordlist_file:
        print_status(f"Wordlist: {args.wordlist_file} (custom)","info")
    else:
        print_status(f"Wordlist: {args.wordlist}","info")
    print_status(f"Workers: {args.worker}","info")
    print_status(f"Delay: {args.delay}s","info")
    print()
    subprocess.run(["sleep", "2"])

    # If silent, suppress almost all output
    if args.silent:
        # Only print errors and summary at the end
        try:
            enumer=DirectoryEnumerator()
            start_time=datetime.now()
            results=await enumer.scan_target(
                target_url=target_url,
                wordlist_type=args.wordlist,
                max_workers=args.worker,
                delay=args.delay,
                custom_wordlist=custom_wordlist,
                recursive=args.recursive,
                max_depth=args.max_depth,
                show_progress=False,
                rate_limit=args.rate_limit
            )
            end_time=datetime.now()
            enumer.scan_stats["start_time"]=start_time.timestamp()
            enumer.scan_stats["end_time"]=end_time.timestamp()
            print_summary(
                enumer.results,
                enumer.scan_stats,
                target_url,
                args.wordlist
            )
            if args.export_csv:
                with open(args.export_csv, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["URL", "Status", "Type", "Size", "Time", "Server"])
                    for result in enumer.results:
                        writer.writerow([
                            result.url,
                            result.status_code,
                            "DIR" if result.is_directory else "FILE",
                            result.content_length,
                            f"{result.response_time:.3f}s",
                            result.server or "N/A"
                        ])
                print_status(f"Results exported to CSV: {args.export_csv}", "success")
            if args.export_excel:
                data = []
                for result in enumer.results:
                    data.append({
                        "URL": result.url,
                        "Status": result.status_code,
                        "Type": "DIR" if result.is_directory else "FILE",
                        "Size": result.content_length,
                        "Time": f"{result.response_time:.3f}s",
                        "Server": result.server or "N/A"
                    })
                df = pd.DataFrame(data)
                df.to_excel(args.export_excel, index=False)
                print_status(f"Results exported to Excel: {args.export_excel}", "success")
            if args.export_pdf:
                pdf_data = [["URL", "Status", "Type", "Size", "Time", "Server"]]
                for result in enumer.results:
                    pdf_data.append([
                        result.url,
                        str(result.status_code),
                        "DIR" if result.is_directory else "FILE",
                        str(result.content_length),
                        f"{result.response_time:.3f}s",
                        result.server or "N/A"
                    ])
                pdf = SimpleDocTemplate(args.export_pdf, pagesize=letter)
                table = Table(pdf_data, repeatRows=1)
                style = TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ])
                table.setStyle(style)
                elems = [table]
                pdf.build(elems)
                print_status(f"Results exported to PDF: {args.export_pdf}", "success")
            if len(enumer.results)>0:
                sys.exit(0)
            else:
                sys.exit(1)
        except Exception as e:
            print_status(f"Error during scan:(str{e})","error")
            sys.exit(1)
        return

    # In verbose mode, print extra details for each result
    if args.verbose:
        print_status("Verbose mode enabled: showing extra details for each result.", "info")

    try:
        enumer=DirectoryEnumerator() # our striker name

        start_time=datetime.now()
        results=await enumer.scan_target(
                target_url=target_url,
                wordlist_type=args.wordlist,
                max_workers=args.worker,
                delay=args.delay,
                custom_wordlist=custom_wordlist,
                recursive=args.recursive,
                max_depth=args.max_depth,
                show_progress=args.progress or (not args.quiet),
                rate_limit=args.rate_limit
                )
        end_time=datetime.now()

        enumer.scan_stats["start_time"]=start_time.timestamp()
        enumer.scan_stats["end_time"]=end_time.timestamp()

        if args.json:
            print(json.dump(results,indent=2))
        else:
            if not args.quiet:
                print_status("Scan completed! Found items: ","success")
                print()

                if args.table or not args.quiet:
                    # Table output
                    table_data = []
                    for result in enumer.results:
                        # Colorize status
                        if result.status_code in [200,201,202,203,204,205,206,207,208,226]:
                            status = f"{Fore.GREEN}{result.status_code} OK{Style.RESET_ALL}"
                        elif result.status_code in [301,302,303,304,305,306,307,308]:
                            status = f"{Fore.YELLOW}{result.status_code} Redirect{Style.RESET_ALL}"
                        elif result.status_code == 403:
                            status = f"{Fore.RED}{result.status_code} Forbidden{Style.RESET_ALL}"
                        elif result.status_code >= 500:
                            status = f"{Fore.RED}{result.status_code} Server Error{Style.RESET_ALL}"
                        else:
                            status = f"{Fore.WHITE}{result.status_code}{Style.RESET_ALL}"
                        # Colorize type
                        type_str = f"{Fore.CYAN}DIR{Style.RESET_ALL}" if result.is_directory else f"{Fore.MAGENTA}FILE{Style.RESET_ALL}"
                        table_data.append([
                            result.url,
                            status,
                            type_str,
                            f"{result.content_length} bytes" if result.content_length > 0 else "N/A",
                            f"{result.response_time:.3f}s",
                            result.server or "N/A"
                        ])
                        if args.verbose:
                            print(f"[VERBOSE] URL: {result.url}\n  Status: {result.status_code}\n  Type: {'DIR' if result.is_directory else 'FILE'}\n  Size: {result.content_length} bytes\n  Time: {result.response_time:.3f}s\n  Server: {result.server or 'N/A'}\n  Content-Type: {getattr(result, 'content_type', 'N/A')}\n  Title: {getattr(result, 'title', 'N/A')}\n")
                    headers = ["URL", "Status", "Type", "Size", "Time", "Server"]
                    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid", stralign="left", numalign="right", showindex=False))
                else:
                    for result in enumer.results:
                        print_result(result)
                        if args.verbose:
                            print(f"[VERBOSE] URL: {result.url}\n  Status: {result.status_code}\n  Type: {'DIR' if result.is_directory else 'FILE'}\n  Size: {result.content_length} bytes\n  Time: {result.response_time:.3f}s\n  Server: {result.server or 'N/A'}\n  Content-Type: {getattr(result, 'content_type', 'N/A')}\n  Title: {getattr(result, 'title', 'N/A')}\n")

                print_summary(
                        enumer.results,
                        enumer.scan_stats,
                        target_url,
                        args.wordlist
                        )
        if args.output:
                save_results(enumer.results,target_url,args.output)

        if args.export_csv:
            with open(args.export_csv, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["URL", "Status", "Type", "Size", "Time", "Server"])
                for result in enumer.results:
                    writer.writerow([
                        result.url,
                        result.status_code,
                        "DIR" if result.is_directory else "FILE",
                        result.content_length,
                        f"{result.response_time:.3f}s",
                        result.server or "N/A"
                    ])
                # Append errors if error log exists and is non-empty
                if args.error_log and os.path.exists(args.error_log):
                    with open(args.error_log, 'r', encoding='utf-8') as errfile:
                        errors = [line.strip() for line in errfile if line.strip()]
                    if errors:
                        writer.writerow([])
                        writer.writerow(["Errors"])
                        for err in errors:
                            writer.writerow([err])
            print_status(f"Results exported to CSV: {args.export_csv}", "success")

        if args.export_excel:
            data = []
            for result in enumer.results:
                data.append({
                    "URL": result.url,
                    "Status": result.status_code,
                    "Type": "DIR" if result.is_directory else "FILE",
                    "Size": result.content_length,
                    "Time": f"{result.response_time:.3f}s",
                    "Server": result.server or "N/A"
                })
            with pd.ExcelWriter(args.export_excel) as writer:
                df = pd.DataFrame(data)
                df.to_excel(writer, index=False, sheet_name="Results")
                # Append errors if error log exists and is non-empty
                if args.error_log and os.path.exists(args.error_log):
                    with open(args.error_log, 'r', encoding='utf-8') as errfile:
                        errors = [line.strip() for line in errfile if line.strip()]
                    if errors:
                        err_df = pd.DataFrame({"Errors": errors})
                        err_df.to_excel(writer, index=False, sheet_name="Errors")
            print_status(f"Results exported to Excel: {args.export_excel}", "success")

        if args.export_pdf:
            pdf_data = [["URL", "Status", "Type", "Size", "Time", "Server"]]
            for result in enumer.results:
                pdf_data.append([
                    result.url,
                    str(result.status_code),
                    "DIR" if result.is_directory else "FILE",
                    str(result.content_length),
                    f"{result.response_time:.3f}s",
                    result.server or "N/A"
                ])
            elems = []
            pdf = SimpleDocTemplate(args.export_pdf, pagesize=letter)
            table = Table(pdf_data, repeatRows=1)
            style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ])
            table.setStyle(style)
            elems.append(table)
            # Append errors if error log exists and is non-empty
            if args.error_log and os.path.exists(args.error_log):
                with open(args.error_log, 'r', encoding='utf-8') as errfile:
                    errors = [line.strip() for line in errfile if line.strip()]
                if errors:
                    error_table = Table([["Errors"]] + [[err] for err in errors])
                    error_style = TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.red),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ])
                    error_table.setStyle(error_style)
                    elems.append(error_table)
            pdf.build(elems)
            print_status(f"Results exported to PDF: {args.export_pdf}", "success")

        if len(enumer.results)>0:
                sys.exit(0)
        else:
                print_status("No items found","warning")
                sys.exit(1)
    
    except KeyboardInterrupt:
        print_status("Daijobu da👶\n\n❓What happened bro❓")
        log_error("KeyboardInterrupt: Scan interrupted by user.")
        sys.exit(1)

    except Exception as e:
        print_status(f"Error during scan:(str{e})","error")
        log_error(f"Exception: {str(e)}")
        sys.exit(1)

    # At the end of the scan, notify if error log was generated
    if args.error_log and os.path.exists(args.error_log):
        print_status(f"Error log saved to: {args.error_log}", "info")


# driver 
if __name__=="__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_status("Daijobu da?👶\n\n❓What happened bro❓","warning")
        sys.exit(1)
