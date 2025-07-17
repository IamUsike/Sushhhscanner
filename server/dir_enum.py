import asyncio
import aiohttp
import requests
import time 
import json 
import os 
from urllib.parse import urljoin, urlparse 
from typing import List,Dict,Set,Optional
from dataclasses import dataclass 
from enum import Enum 
import threading 
from concurrent.futures import ThreadPoolExecutor 
import logging 

class StatusCode(Enum):
    SUCCESS="success"
    ERROR="error"
    NOT_FOUND="not_found"

@dataclass 
class ScanResult:
    url:str
    status_code:int 
    response_time:float 
    content_length:int 
    is_directory:bool 
    title:str=""
    server: str=""
    content_type:str=""

class DirectoryEnumerator:
    def __init__(self):
        self.session=None
        self.results=[]
        self.found_urls=set()
        self.scan_stats={
                "total_requests":0,
                "successful_requests":0,
                "failed_requests":0,
                "start_time":None,
                "end_time":None
                }
        self.wordLists={
            "common": [
                "admin", "administrator", "login", "logout", "register", "signup", "signin",
                "dashboard", "panel", "control", "manage", "management", "admin-panel",
                "wp-admin", "wp-content", "wp-includes", "wordpress", "joomla", "drupal",
                "phpmyadmin", "mysql", "database", "db", "backup", "backups", "bak",
                "config", "configuration", "settings", "setup", "install", "installation",
                "test", "testing", "dev", "development", "staging", "prod", "production",
                "api", "rest", "graphql", "swagger", "docs", "documentation",
                "images", "img", "css","download", "js", "assets", "static", "media", "uploads",
                "files", "downloads", "temp", "tmp", "cache", "logs", "log",
                "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd", "web.config",
                "favicon.ico", "crossdomain.xml", "clientaccesspolicy.xml"
            ],
            "directories": [
                "admin", "administrator", "login", "logout", "register", "signup", "signin",
                "dashboard", "panel", "control", "manage", "management", "admin-panel",
                "wp-admin", "wp-content", "wp-includes", "wordpress", "joomla", "drupal",
                "phpmyadmin", "mysql", "database", "db", "backup", "backups", "bak",
                "config", "configuration", "settings", "setup", "install", "installation",
                "test", "testing", "dev", "development", "staging", "prod", "production",
                "api", "rest", "graphql", "swagger", "docs", "documentation",
                "images", "img", "css", "js", "assets", "static", "media", "uploads",
                "files", "downloads", "temp", "tmp", "cache", "logs", "log"
            ],
            "files": [
                "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd", "web.config",
                "favicon.ico", "crossdomain.xml", "clientaccesspolicy.xml",
                "config.php", "config.json", "config.xml", "config.yml", "config.yaml",
                "database.php", "db.php", "connection.php", "connect.php",
                "admin.php", "login.php", "register.php", "signup.php",
                "index.php", "index.html", "index.htm", "default.html", "default.htm",
                "error.php", "error.html", "404.php", "404.html",
                "backup.sql", "backup.zip", "backup.tar.gz", "backup.rar",
                "readme.txt", "readme.md", "license.txt", "license.md",
                "changelog.txt", "changelog.md", "version.txt", "version.md"
            ]
        }

        self.success_codes={200,201,202,203,204,205,206,207,208,226}
        self.redirect_codes={301,302,303,304,305,306,307,308}

    async def init_session(self):
        timeout=aiohttp.ClientTimeout(total=10)
        connector=aiohttp.TCPConnector(limit=100,limit_per_host=20)
        self.session=aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding':'gzip, deflate',
                    'Connection':'keep-alive',
                    'Upgrade-Insecure-Requests':'1'
                    }
                )

    async def close_session(self):
        if self.session:
            await self.session.close()

    def normalize_url(self,url:str)->str:
        if not url.startswith(('http://','https://')):
            url='https://' + url 
        return url.rstrip('/')

    def get_title_from_html(self,html:str)->str:
        try:
            import re 
            title_match = re.search(r'<title>[^>]*>([^<]+)</title>',html,re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass 
        return ""

    async def check_url(self,base_url:str,path:str)->Optional[ScanResult]:
        url=urljoin(base_url+'/',path)

        if url in self.found_urls:
            return None 

        start_time = time.time()

        try:
            async with self.session.get(url,allow_redirects=False) as response:
                response_time=time.time() - start_time 

                status_code=response.status 
                content_length=len(await response.read())
                server=response.headers.get('Server','')
                content_type=response.headers.get('Content-Type','')

                is_directory = path.endswith('/') or '.' not in path.split('/')[-1]

                title=""
                if content_type and 'text/html' in content_type:
                    html=await response.text()

                    title=self.get_title_from_html(html)

                result=ScanResult(
                        url=url,
                        status_code=status_code,
                        response_time=response_time,
                        content_length=content_length,
                        is_directory=is_directory,
                        title=title,
                        server=server,
                        content_type=content_type
                )

                self.scan_stats["total_requests"] += 1
                
                if status_code in self.success_codes or status_code in self.redirect_codes:
                    self.scan_stats["successful_requests"] += 1
                    self.found_urls.add(url)
                    return result
                else:
                    self.scan_stats["failed_requests"] += 1
                    return None 
        except Exception as e:
            self.scan_stats["failed_requests"]+=1 
            logging.error(f"Error checking {url}:{str(e)}")
            return None 

    async def scan_target(self, target_url: str, wordlist_type: str = "common", max_workers: int = 50, delay: float = 0.1, custom_wordlist=None, recursive=False, max_depth=2, show_progress=False) -> Dict:
        target_url = self.normalize_url(target_url)
        self.scan_stats["start_time"] = time.time()

        await self.init_session()

        try:
            if custom_wordlist is not None:
                wordlist = custom_wordlist
            else:
                wordlist = self.wordLists.get(wordlist_type, self.wordLists["common"])

            from collections import deque
            from tqdm import tqdm
            queue = deque()
            queue.append((target_url, 0))  # (base_url, current_depth)
            checked_dirs = set()
            all_results = []

            # Estimate total tasks for progress bar
            est_total = len(wordlist)
            if recursive:
                est_total = est_total * (max_depth + 1)
            pbar = tqdm(total=est_total, desc="Scanning", disable=not show_progress)

            while queue:
                base_url, depth = queue.popleft()
                if (base_url, depth) in checked_dirs or depth > max_depth:
                    continue
                checked_dirs.add((base_url, depth))

                tasks = []
                for word in wordlist:
                    if not base_url.endswith('/'):
                        base_url += '/'
                    full_path = urljoin(base_url, word)
                    if full_path not in self.found_urls:
                        tasks.append(self.check_url(base_url, word))
                    if delay > 0:
                        await asyncio.sleep(delay)

                results = await asyncio.gather(*tasks, return_exceptions=True)

                valid_results = []
                for result in results:
                    if isinstance(result, ScanResult):
                        valid_results.append(result)
                        if recursive and result.is_directory and depth < max_depth:
                            queue.append((result.url, depth + 1))
                    pbar.update(1)

                all_results.extend(valid_results)

            pbar.close()
            self.results = all_results
            self.scan_stats["end_time"] = time.time()

            return {
                "target_url": target_url,
                "wordlist_type": wordlist_type,
                "total_checked": len(all_results),
                "found_count": len(all_results),
                "scan_stats": self.scan_stats,
                "results": [
                    {
                        "url": r.url,
                        "status_code": r.status_code,
                        "response_time": r.response_time,
                        "content_length": r.content_length,
                        "is_directory": r.is_directory,
                        "title": r.title,
                        "server": r.server,
                        "content_type": r.content_type
                    }
                    for r in all_results
                ]
            }
        finally:
            await self.close_session()

    def get_scan_summary(self)->Dict:
        if not self.results:
            return{"message":"No scan results available"}

        status_codes={}
        content_types={}
        servers={}

        for result in self.results:
            status_codes[result.status_code]=status_codes.get(result.status_code,0)+1 
            if result.content_type:
                content_types[result.content_type]=content_types.get(result.content_type,0)+1 
            if result.server:
                servers[result.server]=servers.get(result.server,0)+1

        return {
                "total_found":len(self.results),
                "status_codes":status_codes, 
                "content_types":content_types,
                "servers":servers,
                "scan_durations":self.scan_stats["end_time"]-self.scan_stats["start_time"] if self.scan_stats["end_time"]else 0
        }


if __name__ == "__main__":
    import asyncio 

    async def main():
        enumer=DirectoryEnumerator()
        results = await enumer.scan_target("https://example.com","common")
        print(json.dumps(results,indent=2))

    asyncio.run(main())
