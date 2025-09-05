# PhishGuard

PhishGuard is a tool that integrates with the Gmail API to help detect and analyze potential phishing attempts.  
This project demonstrates how to use Google Cloud credentials with Python to securely access and process emails.

---

## Features
- Gmail API integration with OAuth authentication  
- Local environment setup with Python virtual environment  
- Automated email fetching after user consent  
- Secure storage of authentication tokens (`credentials.json` and `token.json`)  

---

## Installation

1. Clone the repository:
   ```bash
   git clone <repo_url>
   cd PhishGuard
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate   # Windows
   source venv/bin/activate # Linux / MacOS
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Google Cloud Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/) and log in with your Gmail account.  
2. Create a new project (e.g., **PhishGuard Test**).  
3. Enable **Gmail API** from `APIs & Services > Library`.  
4. Configure the **OAuth consent screen**:  
   - User type: External  
   - App name: *My PhishGuard Test App*  
   - User support email: your Gmail address  
   - Developer contact email: your Gmail address  
   - Leave other sections empty and save.  
5. Go to `APIs & Services > Credentials` and create a new **OAuth client ID**:  
   - Application type: Desktop App  
   - Download the JSON file and rename it to `credentials.json`  
   - Place it inside the cloned project folder.  

---

## Usage

Run the project for the first time with:
```bash
python main.py
```

- The app will open your browser and ask for Gmail permission.  
- Once granted, a `token.json` file will be created for future use.  

---

## Why This Setup?

This process tells Google that the user is authorizing the PhishGuard app to access Gmail securely.  
Instead of storing your password, Google issues tokens that can safely be used by the script.  
