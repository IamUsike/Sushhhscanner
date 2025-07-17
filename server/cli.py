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

# Initalise colorama for cross-platform colored output
init()

# comments ? just read the function mendokuse 
def silhouette():
   """silhouette : speak english loser"""
   banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                 🔍 Advanced Directory Enumerator 🔍                    
║                      Security Testing Tool                             
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
   print(banner)


def print_status(message,status_type="info"):
    # init color variables 
    # This is where it gets interesting 
    colors = {
            "info":Fore.BLUE,
            "success":Fore.GREEN,
            "warning":Fore.YELLOW,
            "error":Fore.RED
            }
    color = colors.get(status_type,Fore.WHITE)
    print(f"{color}[{status_type.upper()}] {message}{Style.RESET_ALL}")

def print_result(result):
    status_code=result.status_code
    url=result.url 

    # color code based on status 
    if status_code in [200,201,202,203,204,205,206,207,208,226]: # LEARN THIS + chekc all success code's first digit 
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


    # output info 
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

async def main():
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

    args=parser.parse_args()

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
                show_progress=args.progress or (not args.quiet)
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
                    headers = ["URL", "Status", "Type", "Size", "Time", "Server"]
                    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid", stralign="left", numalign="right", showindex=False))
                else:
                    for result in enumer.results:
                        print_result(result)

                print_summary(
                        enumer.results,
                        enumer.scan_stats,
                        target_url,
                        args.wordlist
                        )
        if args.output:
                save_results(enumer.results,target_url,args.output)

        if len(enumer.results)>0:
                sys.exit(0)
        else:
                print_status("No items found","warning")
                sys.exit(1)
    
    except KeyboardInterrupt:
        print_status("Daijobu da👶\n\n❓What happened bro❓")
        sys.exit(1)

    except Exception as e:
        print_status(f"Error during scan:(str{e})","error")
        sys.exit(1)


# driver 
if __name__=="__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_status("Daijobu da?👶\n\n❓What happened bro❓","warning")
        sys.exit(1)
