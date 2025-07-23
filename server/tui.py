#!/usr/bin/env python3

"""
TUI (Text User Interface) for Advanced Directory Enumerator
"""

import asyncio
import os
import sys
from datetime import datetime
from typing import List, Optional
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Button, 
    Input, 
    Label, 
    Select, 
    Switch, 
    DataTable, 
    ProgressBar, 
    Static,
    Header,
    Footer
)
from textual.reactive import reactive
from textual import work
from textual.worker import Worker, WorkerState
from dir_enum import DirectoryEnumerator
import json
import csv
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, SimpleDocTemplate
import re
from textual.message import Message

class ScanResults(Static):
    """Widget to display scan results."""
    
    results = reactive([])
    
    def compose(self) -> ComposeResult:
        yield DataTable()
    
    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("URL", "Status", "Type", "Size", "Time", "Server")
    
    def watch_results(self, results: List) -> None:
        table = self.query_one(DataTable)
        table.clear()
        
        for result in results:
            status_color = self._get_status_color(result.status_code)
            type_str = "DIR" if result.is_directory else "FILE"
            size_str = f"{result.content_length} bytes" if result.content_length > 0 else "N/A"
            time_str = f"{result.response_time:.3f}s"
            server_str = result.server or "N/A"
            
            table.add_row(
                result.url,
                f"{status_color}{result.status_code}{status_color}",
                type_str,
                size_str,
                time_str,
                server_str
            )
    
    def _get_status_color(self, status_code: int) -> str:
        if status_code in [200, 201, 202, 203, 204, 205, 206, 207, 208, 226]:
            return "🟢"
        elif status_code in [301, 302, 303, 304, 305, 306, 307, 308]:
            return "🟡"
        elif status_code == 403:
            return "🔴"
        elif status_code >= 500:
            return "🔴"
        else:
            return "⚪"

class ScanProgress(Static):
    """Widget to display scan progress."""
    
    progress = reactive(0.0)
    status = reactive("Ready")
    
    def compose(self) -> ComposeResult:
        yield Label("Ready", id="status")
        yield ProgressBar()
    
    def watch_progress(self, progress: float) -> None:
        progress_bar = self.query_one(ProgressBar)
        progress_bar.update(progress=progress)
    
    def watch_status(self, status: str) -> None:
        status_label = self.query_one("#status")
        status_label.update(status)

class ProgressUpdate(Message):
    def __init__(self, progress: float, status: str) -> None:
        self.progress = progress
        self.status = status
        super().__init__()

class DirectoryEnumeratorTUI(App):
    """Main TUI application for directory enumeration."""
    
    CSS = """
    #main-container {
        height: 100%;
        padding: 1;
    }
    
    #input-section {
        height: auto;
        padding: 1;
        border: solid green;
    }
    
    #results-section {
        height: 70%;
        padding: 1;
        border: solid blue;
    }
    
    #progress-section {
        height: auto;
        padding: 1;
        border: solid yellow;
    }
    
    DataTable {
        height: 100%;
    }
    
    .input-group {
        height: auto;
        margin: 1;
    }
    
    .input-row {
        height: auto;
        margin: 1;
    }
    """
    
    def __init__(self):
        super().__init__()
        self.enumerator = DirectoryEnumerator()
        self.scan_worker: Optional[Worker] = None
        self.results = []
        self.scan_stats = {}
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            with Container(id="input-section"):
                yield Label("🔍 Advanced Directory Enumerator", classes="title")
                
                with Horizontal(classes="input-row"):
                    yield Label("Target URL:")
                    yield Input(placeholder="https://example.com", id="target-url")
                
                with Horizontal(classes="input-row"):
                    yield Label("Wordlist:")
                    yield Select(
                        options=[
                            ("Common", "common"),
                            ("Directories", "directories"),
                            ("Files", "files")
                        ],
                        value="common",
                        id="wordlist-select"
                    )
                
                with Horizontal(classes="input-row"):
                    yield Label("Workers:")
                    yield Input(value="50", id="workers")
                
                with Horizontal(classes="input-row"):
                    yield Label("Delay (s):")
                    yield Input(value="0.1", id="delay")
                
                with Horizontal(classes="input-row"):
                    yield Label("Recursive:")
                    yield Switch(id="recursive")
                
                with Horizontal(classes="input-row"):
                    yield Label("Max Depth:")
                    yield Input(value="2", id="max-depth")
                
                with Horizontal(classes="input-row"):
                    yield Label("Show Progress:")
                    yield Switch(value=True, id="show-progress")
                
                with Horizontal(classes="input-row"):
                    yield Button("Start Scan", id="start-scan", variant="primary")
                    yield Button("Stop Scan", id="stop-scan", variant="error")
                    yield Button("Export Results", id="export-results", variant="success")
                    yield Button("Clear Results", id="clear-results", variant="default")
            
            with Container(id="progress-section"):
                yield ScanProgress()
            
            with Container(id="results-section"):
                yield Label("Scan Results", classes="title")
                yield ScanResults()
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when the app is mounted."""
        self.title = "Advanced Directory Enumerator"
        self.sub_title = "Security Testing Tool"
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id
        
        if button_id == "start-scan":
            self.start_scan()
        elif button_id == "stop-scan":
            self.stop_scan()
        elif button_id == "export-results":
            self.export_results()
        elif button_id == "clear-results":
            self.clear_results()
    
    def start_scan(self) -> None:
        """Start the directory enumeration scan."""
        target_url = self.query_one("#target-url").value.strip()
        if not target_url:
            self.notify("Please enter a target URL", severity="error")
            return
        
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        
        try:
            workers = int(self.query_one("#workers").value)
            delay = float(self.query_one("#delay").value)
            max_depth = int(self.query_one("#max-depth").value)
        except ValueError:
            self.notify("Invalid numeric values", severity="error")
            return
        
        wordlist_type = self.query_one("#wordlist-select").value
        recursive = self.query_one("#recursive").value
        show_progress = self.query_one("#show-progress").value
        
        # Update progress widget
        progress_widget = self.query_one(ScanProgress)
        progress_widget.status = "Starting scan..."
        
        # Start the scan using the @work method
        self.scan_worker = self.scan_directory(
            target_url,
            wordlist_type,
            workers,
            delay,
            recursive,
            max_depth,
            show_progress
        )
    
    def stop_scan(self) -> None:
        """Stop the current scan."""
        if self.scan_worker and self.scan_worker.state == WorkerState.RUNNING:
            self.scan_worker.cancel()
            self.notify("Scan stopped", severity="warning")
    
    def export_results(self) -> None:
        """Export scan results to various formats."""
        if not self.results:
            self.notify("No results to export", severity="warning")
            return
        
        # Create export directory if it doesn't exist
        export_dir = "exports"
        os.makedirs(export_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export to JSON
        json_file = os.path.join(export_dir, f"scan_results_{timestamp}.json")
        self._export_to_json(json_file)
        
        # Export to CSV
        csv_file = os.path.join(export_dir, f"scan_results_{timestamp}.csv")
        self._export_to_csv(csv_file)
        
        # Export to Excel
        excel_file = os.path.join(export_dir, f"scan_results_{timestamp}.xlsx")
        self._export_to_excel(excel_file)
        
        # Export to PDF
        pdf_file = os.path.join(export_dir, f"scan_results_{timestamp}.pdf")
        self._export_to_pdf(pdf_file)
        
        self.notify(f"Results exported to {export_dir}/", severity="information")
    
    def clear_results(self) -> None:
        """Clear scan results."""
        self.results = []
        results_widget = self.query_one(ScanResults)
        results_widget.results = []
        self.notify("Results cleared", severity="information")
    
    def on_progress_update(self, message: ProgressUpdate) -> None:
        progress_widget = self.query_one(ScanProgress)
        progress_widget.progress = message.progress
        progress_widget.status = message.status
    
    def _export_to_json(self, filename: str) -> None:
        """Export results to JSON format."""
        data = {
            "target_url": getattr(self.enumerator, 'target_url', ''),
            "scan_time": datetime.now().isoformat(),
            "total_found": len(self.results),
            "results": [
                {
                    "url": r.url,
                    "status_code": r.status_code,
                    "response_time": r.response_time,
                    "content_length": r.content_length,
                    "is_directory": r.is_directory,
                    "title": getattr(r, 'title', ''),
                    "server": r.server,
                    "content_type": getattr(r, 'content_type', '')
                }
                for r in self.results
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _export_to_csv(self, filename: str) -> None:
        """Export results to CSV format."""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["URL", "Status", "Type", "Size", "Time", "Server"])
            for result in self.results:
                writer.writerow([
                    result.url,
                    result.status_code,
                    "DIR" if result.is_directory else "FILE",
                    f"{result.content_length} bytes" if result.content_length > 0 else "N/A",
                    f"{result.response_time:.3f}s",
                    result.server or "N/A"
                ])
    
    def _export_to_excel(self, filename: str) -> None:
        """Export results to Excel format."""
        data = []
        for result in self.results:
            data.append({
                "URL": result.url,
                "Status": result.status_code,
                "Type": "DIR" if result.is_directory else "FILE",
                "Size": f"{result.content_length} bytes" if result.content_length > 0 else "N/A",
                "Time": f"{result.response_time:.3f}s",
                "Server": result.server or "N/A"
            })
        
        df = pd.DataFrame(data)
        df.to_excel(filename, index=False)
    
    def _export_to_pdf(self, filename: str) -> None:
        """Export results to PDF format."""
        def status_to_pdf_color(status_code):
            if status_code in [200, 201, 202, 203, 204, 205, 206, 207, 208, 226]:
                return colors.green
            elif status_code in [301, 302, 303, 304, 305, 306, 307, 308]:
                return colors.orange
            elif status_code == 403:
                return colors.red
            elif status_code >= 500:
                return colors.red
            else:
                return colors.black
        
        def type_to_pdf_color(is_directory):
            return colors.cyan if is_directory else colors.magenta
        
        pdf_data = [["URL", "Status", "Type", "Size", "Time", "Server"]]
        for result in self.results:
            pdf_data.append([
                result.url,
                str(result.status_code),
                "DIR" if result.is_directory else "FILE",
                str(result.content_length),
                f"{result.response_time:.3f}s",
                result.server or "N/A"
            ])
        
        pdf = SimpleDocTemplate(filename, pagesize=letter)
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
    
    @work(exclusive=True)
    async def scan_directory(self, target_url, wordlist_type, max_workers, delay, recursive, max_depth, show_progress):
        def progress_callback(progress, status):
            self.post_message(ProgressUpdate(progress, status))
        try:
            results = await self.enumerator.scan_target(
                target_url=target_url,
                wordlist_type=wordlist_type,
                max_workers=max_workers,
                delay=delay,
                recursive=recursive,
                max_depth=max_depth,
                show_progress=show_progress,
                progress_callback=progress_callback
            )
            return results
        except Exception as e:
            self.notify(f"Scan error: {str(e)}", severity="error")
            return []

def main():
    """Main entry point for the TUI."""
    app = DirectoryEnumeratorTUI()
    app.run()

if __name__ == "__main__":
    main() 