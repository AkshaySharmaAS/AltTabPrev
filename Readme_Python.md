System Process Monitor and Control Service
A Python-based system monitoring and control service that provides process management, keyboard control, and taskbar visibility management across Windows, Linux (X11/Wayland), and macOS platforms.
Features

Process monitoring and termination of specified applications
Keyboard input control for system keys (Tab, Escape, Windows/Command keys)
Taskbar visibility management
HTTP server for remote control (localhost:3000)
Cross-platform support (Windows, Linux, macOS)
Comprehensive logging system

Requirements

Python 3.x
Required Python packages:

pynput
psutil
Additional Linux dependencies: wmctrl (for X11), gsettings (for GNOME/Wayland)



Installation

Clone the repository
Install required packages:

pip install pynput psutil

For Linux X11 users:

bashCopysudo apt-get install wmctrl
Usage
Run the script with Python:
python monitor_service.py
The service starts an HTTP server on port 3000 with the following endpoints:

/startService: Initiates monitoring and control features
/stopService: Stops the service and restores default system settings

Security Notice
This script provides system-level control and should be used responsibly in controlled environments. It is not recommended to run this service on production systems or virtual machines.
Logging
All actions are logged to log.txt in the same directory as the script.
