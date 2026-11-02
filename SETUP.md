# Setup & Installation Guide

This document provides detailed instructions on how to install, configure, and run the CCTV Monitoring System locally or prepare it for cloud deployment.

## Prerequisites

Ensure you have the following installed on your local machine:
* **Python 3.10 or higher**
* **Git** for repository management
* **pip** (Python package manager)

## Step-by-Step Installation

### 1. Clone the Repository
Open your terminal and clone the repository, then navigate into the project root:
```bash
git clone https://github.com/CharmanderTheGreat/cctv-monitoring-system.git
cd cctv-monitoring-system
```

### 2. Navigate to the Backend Directory
All core application logic, runners, and configuration files reside inside the `backend/` folder:
```bash
cd backend
```

### 3. Create and Activate a Virtual Environment
Set up an isolated Python virtual environment to manage project dependencies:
* **On Windows (Command Prompt / PowerShell):**
  ```bash
  python -m venv venv
  venv\Scripts\activate
  ```
* **On macOS / Linux:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 4. Install Project Dependencies
Install all required Python packages listed in `requirements.txt`:
```bash
pip install --no-cache-dir -r requirements.txt
```

### 5. Configure Environment Variables
Create a `.env` file inside the `backend/` directory with the required environment configurations:
```env
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=sqlite:///cctv_local.db
REDIS_URL=memory://
```

## Running the Application

### 1. Local Development Server
Make sure you are inside the `backend/` directory with your virtual environment activated, then execute the application entry point:
```bash
python run.py
```

### 2. Accessing the System
Open your preferred web browser and access the local server URL:
```text
http://127.0.0.1:5000
```

## Production Deployment Notes (Railway / Cloud)

* **Procfile Configuration:** Ensure the cloud platform utilizes Gunicorn pointing to the backend module:
  ```text
  web: gunicorn --chdir backend run:app
  ```
* **Environment Variables:** Set production-grade variables on your hosting dashboard, including a secure `SECRET_KEY`, live PostgreSQL `DATABASE_URL`, and a cloud `REDIS_URL` for rate limiting.