#!/usr/bin/env python3
"""
Simple HTTP server for the Flash Cards web app.
Run this script to serve the application locally.
"""

import http.server
import socketserver
import webbrowser
import os
from pathlib import Path

# Configuration
PORT = 8080
DIRECTORY = Path(__file__).parent

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def end_headers(self):
        # Add CORS headers for local development
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()

def main():
    try:
        with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
            print(f"🚀 Flash Cards Server starting...")
            print(f"📍 Serving directory: {DIRECTORY}")
            print(f"🌐 Server running at: http://localhost:{PORT}")
            print(f"📖 Opening browser automatically...")
            print(f"⏹️  Press Ctrl+C to stop the server")
            
            # Open browser automatically
            webbrowser.open(f"http://localhost:{PORT}")
            
            # Start server
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print(f"\n🛑 Server stopped by user")
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"❌ Port {PORT} is already in use. Try a different port or stop the existing server.")
        else:
            print(f"❌ Error starting server: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()
