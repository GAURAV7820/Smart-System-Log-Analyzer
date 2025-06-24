# Smart-System-Log-Analyzer
Smart System Log Analyzer is a lightweight tool that scans system logs to detect suspicious activities like failed logins. It uses regex for log parsing, highlights threats, and displays insights through a visual dashboard. Ideal for beginners and small-scale system monitoring.

Developed a Smart System Log Analyzer to detect login-related threats in system logs.

Used Python and regex to parse /var/log/auth.log and extract key data (IP, time, status).

Identified suspicious patterns like repeated failed login attempts using threshold rules.

Built a web dashboard using Streamlit/Flask for filtering logs by IP, date, or threat type.

Integrated Plotly/Matplotlib for visual representation of log trends and threats.

Designed for ease of use, making it ideal for students or small-scale system admins.

Aims to simplify log analysis and offer a lightweight alternative to heavy SIEM systems.
