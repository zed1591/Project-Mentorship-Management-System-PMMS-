Project Mentorship Management System (PMMS)
📝 Overview
The Project Mentorship Management System (PMMS) is a comprehensive web application designed to streamline and manage mentorship programs for educational institutions and organizations. Built with Flask and MongoDB, it provides distinct dashboards and functionalities for Administrators, Coordinators, Mentors, and Mentees.

Key Features
Role-Based Access Control (RBAC): Separate dashboards and permissions for Administrator, Coordinator, Mentor, and Mentee roles.

User Authentication: Secure login, registration, and password reset functionalities.

Project Management: Mentees can propose projects, Coordinators can approve and assign them, and Mentors can manage tasks.

Real-Time Progress Tracking: Mentors and Mentees can track project tasks and visualize progress using tools like a Gantt Chart.

Email Notifications: Integrated Flask-Mail for secure operations like password resets.

Security: Utilizes Flask-Talisman for CSP, Flask-WTF/CSRFProtect for CSRF, and Flask-Limiter for rate limiting to ensure a robust application environment.

🚀 Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

Prerequisites
You need the following installed on your system:

Python 3.8+

MongoDB Server (running locally or accessible via a connection string).

Git LFS (required for the large video file: background.mp4).

Installation
1. Clone the repository
First, ensure you have the repository cloned, and that Git LFS is installed and initialized, especially after resolving the recent push issues.

# Clone the repository
git clone [https://github.com/zed1591/Project-Mentorship-Management-System-PMMS-.git](https://github.com/zed1591/Project-Mentorship-Management-System-PMMS-.git)
cd Project-Mentorship-Management-System-PMMS-

# Ensure LFS files are pulled (required for the background video)
git lfs pull

2. Create and Activate Virtual Environment
It's highly recommended to use a virtual environment.

python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

3. Install Dependencies
Install the required Python packages (Flask, PyMongo, etc.).

pip install -r requirements.txt
# (Assuming you have a requirements.txt file)

4. Configure Environment Variables
Create a file named .env in the root directory and define the following essential variables:

# .env file content
SECRET_KEY='your_super_secret_flask_key'
MONGO_URI='mongodb://localhost:27017/pmms_db'
REGISTRATION_SECRET_KEY='secure_key_for_admin_registration'

# Flask-Mail (Example: using a dedicated Gmail app password)
MAIL_USERNAME='your_email@gmail.com'
MAIL_PASSWORD='your_app_password' 
MAIL_DEFAULT_SENDER='PMMS Admin <your_email@gmail.com>'
MAIL_SERVER='smtp.gmail.com'
MAIL_PORT=587
MAIL_USE_TLS=True

Note: Do not use your main Gmail password; use a [Google App Password] for security.

5. Run the Application
Execute the main application file.

python app.py

The application will typically start on http://127.0.0.1:5000/.

🛠 Project Structure (Based on Snippets)
File / Route

Description

app.py

Main Flask application file. Handles routing, authentication, MongoDB connection, and configuration (including Mail, Talisman, CSRF, and Rate Limiting).

index.html

The landing page featuring a full-width video background (using Git LFS for background.mp4).

dashboard_*.html

Contains the role-specific dashboards for Administrator, Coordinator, Mentor, and Mentee.

create_project.html

Form for Mentees to submit a new project proposal.

gantt_chart.html

Displays the project schedule using Google Charts, allowing for visual task tracking.

👤 Initial Setup & Roles
When you first run the application, you will need to register the first Administrator.

Navigate to the /register route.

Use a special registration key (the value set in REGISTRATION_SECRET_KEY in your .env) when signing up to assign the initial Administrator role.

Subsequent users can register as Mentee or Mentor, or be assigned roles by the Administrator/Coordinator.

🤝 Contribution
We welcome contributions to the Project Mentorship Management System! Please feel free to fork the repository, make changes, and submit a Pull Request
