🕵️‍♂️ Fake Websites & Email Detection System
📌 Project Overview

The Fake Websites and Email Detection System is a machine learning and web scraping-based project that helps identify fraudulent websites and suspicious emails. The system extracts key features such as domain age, SSL certificate validity, presence of login forms, suspicious keywords, and email patterns. It then classifies them as Legit or Fake using trained models.

This project addresses rising concerns in cybersecurity, helping users detect phishing websites and fraudulent emails in real time.

🚀 Features

Fake Website Detection:

Checks domain age, SSL certificate, HTTPS usage.

Detects suspicious keywords and login forms.

Scrapes website content for risk analysis.

Fake Email Detection:

Identifies phishing indicators in subject, sender, and content.

Flags suspicious words, spoofed domains, and spam patterns.

Web Application (Flask):

User & Admin login system with SQLite database.

Simple UI for checking websites and emails.

Contact & About Us sections.

🛠️ Tech Stack

Python (Flask, Pandas, Scikit-learn, BeautifulSoup, Selenium)

Machine Learning Models (Logistic Regression, Random Forest, etc.)

SQLite (User authentication & admin dashboard)

HTML, CSS, Bootstrap (Frontend UI)

📊 Methodology

Data Collection – Gathered phishing/fake websites and spam email datasets.

Feature Extraction – Extracted website (domain, SSL, keywords) and email features.

Model Training – Applied classification models for fake/legit detection.

Flask Integration – Built a web app for real-time input and predictions.

User System – Implemented login/register and admin dashboard.
