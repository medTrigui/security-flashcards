# Security Domain Flash Cards

A minimal web application for studying cybersecurity concepts across 6 key domains.

## Features

- **6 Security Categories**: Networking, Systems, Cloud, Applications, Security Operations, Automation
- **Interactive Flashcards**: Click to flip between questions and answers
- **Navigation**: Previous/Next buttons and keyboard shortcuts
- **Progress Tracking**: Visual progress bar showing current position
- **Shuffle & Reset**: Randomize card order or reset to original sequence
- **Responsive Design**: Works on desktop and mobile devices

## Categories

1. **Networking** - Network security concepts, protocols, and threats
2. **Systems** - Operating system security, hardening, and vulnerabilities
3. **Cloud** - Cloud security architecture, services, and best practices
4. **Applications** - Application security, OWASP, secure development
5. **Security Operations** - SOC operations, incident response, monitoring
6. **Automation** - Security automation, scripting, and orchestration

## Getting Started

### Option 1: Windows (Easy)
1. Double-click `start-server.bat`
2. The app will open automatically in your browser

### Option 2: Manual (Any OS)
1. Open a terminal/command prompt in this directory
2. Run: `python server.py`
3. Open your browser to `http://localhost:8080`

### Option 3: Direct File Access
Simply open `index.html` in your browser (some features may be limited)

## Usage

- **Navigation**: Use Previous/Next buttons or arrow keys (← →)
- **Flip Cards**: Click the card or press Space/Enter
- **Switch Categories**: Click category buttons at the top
- **Shuffle**: Randomize the order of cards in current category
- **Reset**: Return to original order and reset progress

## Current Status

The application is set up with placeholder content:
- ✅ Complete UI and functionality
- ✅ All 6 categories implemented
- ✅ 50 placeholder cards per category (300 total)
- 🔄 Ready for content population

## Next Steps

1. Populate flashcards with actual security questions and detailed answers
2. Each answer should be 2-3 sentences showing deep understanding
3. Content should be concise, precise, and demonstrate expertise

## Technical Details

- **Frontend**: Vanilla HTML, CSS, JavaScript
- **Server**: Python HTTP server (for local development)
- **No dependencies**: Self-contained application
- **Data Structure**: JSON-like object in `flashcards-data.js`

## File Structure

```
├── index.html          # Main application page
├── styles.css          # Styling and responsive design
├── app.js             # Application logic and interactions
├── flashcards-data.js # Question and answer data
├── server.py          # Python HTTP server
├── start-server.bat   # Windows launcher script
└── README.md          # This file
```
