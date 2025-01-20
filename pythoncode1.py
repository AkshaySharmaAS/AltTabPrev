import os
import signal
import sys
import logging
import threading
import time
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
import platform
import ctypes
from pynput import keyboard
import psutil
import subprocess
from screeninfo import get_monitors
import winreg as reg
# Global variables
monitor_processes = True

server_running = True
service_started = threading.Event()


# Logging setup
logging.basicConfig(filename="log.txt", level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log_file = open("log.txt", "a")
sys.stdout = log_file
sys.stderr = log_file
# Get current time
def get_current_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

# Log message
def log_message(message, level="INFO"):
    if level == "INFO":
        logging.info(message)
    elif level == "ERROR":
        logging.error(message)

def get_battery_status():
    while True:
        battery = psutil.sensors_battery()
        if battery:
            percent = battery.percent
            plugged = battery.power_plugged
            status = "Charging" if plugged else "Not Charging"

            if battery.secsleft == psutil.POWER_TIME_UNLIMITED:
                time_left = "Unlimited (Charging)"
            elif battery.secsleft == psutil.POWER_TIME_UNKNOWN:
                time_left = "Unknown"
            else:
                hours = battery.secsleft // 3600
                minutes = (battery.secsleft % 3600) // 60
                seconds = battery.secsleft % 60
                time_left = f"{hours} hrs, {minutes} mins, {seconds} secs"

        
            return percent, status, time_left
        else:
            print("Battery information not available.")
        time.sleep(100)

# Signal handler
def signal_handler(signal_received, frame):
    global monitor_processes, server_running
    monitor_processes = False
    server_running = False
    log_message("Service stopped.", "INFO")
    os._exit(1)

# Check if wmctrl is installed
def is_wmctrl_installed():
    import shutil
    return shutil.which("wmctrl") is not None


# Taskbar visibility
def hide_taskbar():
    try:
        if platform.system() == "Windows":
            ctypes.windll.user32.ShowWindow(ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None), 0)
        elif platform.system() == "Linux":
            log_message("Taskbar hidden on Windows.", "INFO")
            if is_wayland_session():
                # Hide GNOME taskbar and side navigation bar for Wayland
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "autohide", "true"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "dock-fixed", "false"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "intellihide", "true"], 
                    check=True
                )
                subprocess.run(
            ["gnome-extensions", "enable", "hidetopbar@mathieu.bidon.ca"],
            check=True,
        )
                log_message("Taskbar and side navigation bar hidden on Wayland.", "INFO")
            else:
                # Hide taskbar and side navigation bar for X11
                # if is_wmctrl_installed():
                #     os.system("wmctrl -k on")
                #     log_message("Taskbar hidden on X11.", "INFO")
                # else:
                #     log_message("wmctrl not installed. Cannot hide taskbar on X11.", "ERROR")
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "autohide", "true"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "dock-fixed", "false"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "intellihide", "true"], 
                    check=True
                )
                subprocess.run(
            ["gnome-extensions", "enable", "hidetopbar@mathieu.bidon.ca"],
            check=True,
        )
                log_message("Taskbar and side navigation bar hidden on Wayland.", "INFO")
    except Exception as e:
        log_message(f"Error hiding taskbar: {e}", "ERROR")


def get_keycode_map():
    try:
        output = subprocess.check_output(['xmodmap', '-pke']).decode()
        keycode_map = {}
        for line in output.splitlines():
            parts = line.split('=')
            if len(parts) < 2:
                continue
            keycode = parts[0].strip().split()[1]
            keysyms = parts[1].strip().split()
            for keysym in keysyms:
                if keysym not in keycode_map:
                    keycode_map[keysym] = keycode
        print(keycode_map)
        return keycode_map
    except subprocess.CalledProcessError as e:
        log_message(f"Error getting keycode map: {e}", "ERROR")
        return {}

def show_taskbar():
    try:
        if platform.system() == "Windows":
            ctypes.windll.user32.ShowWindow(ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None), 1)
            log_message("Taskbar shown on Windows.", "INFO")
        elif platform.system() == "Linux":
            if is_wayland_session():
                # Show GNOME taskbar and side navigation bar for Wayland
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "autohide", "false"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "dock-fixed", "true"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "intellihide", "false"], 
                    check=True
                )
                subprocess.run(
            ["gnome-extensions", "disable", "hidetopbar@mathieu.bidon.ca"],
            check=True,
        )
                log_message("Taskbar and side navigation bar shown on Wayland.", "INFO")
            else:
                # Show taskbar for X11
                # if is_wmctrl_installed():
                #     os.system("wmctrl -k off")
                #     log_message("Taskbar shown on X11.", "INFO")
                # else:
                #     log_message("wmctrl not installed. Cannot show taskbar on X11.", "ERROR")
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "autohide", "false"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "dock-fixed", "true"], 
                    check=True
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.shell.extensions.dash-to-dock", "intellihide", "false"], 
                    check=True
                )
                subprocess.run(
            ["gnome-extensions", "disable", "hidetopbar@mathieu.bidon.ca"],
            check=True,
        )
                log_message("Taskbar and side navigation bar shown on Wayland.", "INFO")
    except Exception as e:
        log_message(f"Error showing taskbar: {e}", "ERROR")
    except Exception as e:
        log_message(f"Error showing taskbar: {e}", "ERROR")



# def check_multiple_displays():
#     # open_chrome()
#     while True:
#         monitors = get_monitors()
#         if len(monitors) > 1:
#             log_message("Detected extended Monitor")
#             try:
#                 subprocess.run(["powershell", "-Command", "DisplaySwitch.exe /internal"], check=True)
#             except subprocess.CalledProcessError as e:
#                 log_message(f"Error executing DisplaySwitch.exe: {e}")
#         time.sleep(5)

def get_active_displays():
    """
    Uses PowerShell to fetch connected displays and their video output technologies.
    Returns a list of active displays with details.
    """
    try:
        # Run PowerShell command to get display information
        cmd = (
            "Get-CimInstance -Namespace root\\wmi -ClassName WmiMonitorBasicDisplayParams "
            "| Select-Object InstanceName, VideoOutputTechnology"
        )
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # Suppress window
        result = subprocess.check_output(
            ["powershell", "-Command", cmd], text=True,startupinfo=startupinfo
        )
        # Parse result and extract display information
        active_displays = [
            line.strip() for line in result.split("\n") if line.strip() and "InstanceName" not in line
        ]
        return active_displays
    except subprocess.CalledProcessError as e:
        print(f"Error executing PowerShell command: {e}")
        return []

def check_multiple_displays():
    """Continuously monitors active displays and switches to internal mode when necessary."""
    last_display_count = None  # Cache the last known number of displays

    while True:
        # Get the current active displays
        active_displays = get_active_displays()
        display_count = len(active_displays)
        # Check if more than one display is active
        if display_count >= 3 and display_count != last_display_count:
            logging.info("More than one display detected. Switching to internal mode...")
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # Suppress window
                subprocess.run(
                    ["powershell", "-Command", "DisplaySwitch.exe /internal"],
                    check=True,startupinfo=startupinfo
                )
                logging.info("Switched to internal display mode.")
            except subprocess.CalledProcessError as e:
                logging.info(f"Error executing DisplaySwitch.exe: {e}")
        elif display_count == 1:
            logging.info("Only one display detected")

        # Update last known display count
        last_display_count = display_count

        # Delay before rechecking (can be reduced or increased as needed)
        time.sleep(5)


# Kill specified processes
#Try Killing the screen capturing or screen recording services
recording_processes = [

    "obs64.exe",         # OBS Studio
    "obs32.exe",         # OBS Studio 32-bit
    "XSplit.exe",        # XSplit
    "Zoom.exe",          # Zoom
    "Teams.exe",         # Microsoft Teams
    "CamtasiaStudio.exe",  # Camtasia
    "SnagitEditor.exe",  # Snagit
    "ScreenRecorder.exe", # Generic screen recorders
    "GameBar.exe",       # Windows Game Bar
    "SkypeApp.exe",      # Skype
    "ffmpeg.exe",        # FFmpeg (command-line recorder)
    "vlc.exe",           # VLC Media Player (record screen)
    "SnippingTool.exe",  # Windows Snipping Tool
    "bdcam.exe",         # Bandicam
    "smartcapture.exe",  # Other generic tools
]

def terminate_recording_processes():
    """
    Detect and terminate processes associated with screen recording or desktop sharing.
    """
    for process in psutil.process_iter(['pid', 'name']):
        try:
            process_name = process.info['name']
            process_pid = process.info['pid']

            # Check if the process matches known screen recording tools
            if process_name.lower() in [p.lower() for p in recording_processes]:
                print(f"Terminating process: {process_name} (PID: {process_pid})")
                psutil.Process(process_pid).terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
def kill_processes(process_names):
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            if any(name.lower() in proc.info['name'].lower() for name in process_names):
                proc.terminate()
                log_message(f"Terminated process: {proc.info['name']}", "INFO")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Monitor processes in a separate thread
def monitor_processes_thread(process_names):
    global monitor_processes
    while monitor_processes:
        kill_processes(process_names)
        time.sleep(5)
BLOCKED_KEYS = {keyboard.Key.tab, keyboard.Key.esc, keyboard.Key.cmd}  # Tab, Escape, Command keys

def block_keyboard_mac():
    def on_press(key):
        if key in BLOCKED_KEYS:
            log_message(f"Blocked key in Mac: {key}","INFO")
            return False  # Stop the listener to simulate key blocking
        log_message(f"Key pressed in Mac: {key}","INFO")

    def on_release(key):
        # Optionally handle key release events if needed
        pass

    # Start the listener
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

# Key blocking for Windows
if platform.system() == "Windows":
    import ctypes
    from ctypes import WINFUNCTYPE, windll, wintypes, POINTER, c_long, c_longlong

    if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
        LRESULT = c_longlong
    else:  # 32-bit
        LRESULT = c_long

    LowLevelKeyboardProc = WINFUNCTYPE(
        LRESULT,  # Return type
        wintypes.INT,  # nCode
        wintypes.WPARAM,  # wParam
        wintypes.LPARAM  # lParam
    )

    hook = None
    proc_ptr = None

    def block_keys_windows():
        global hook, proc_ptr

        def low_level_keyboard_proc(nCode, wParam, lParam):
            if nCode == 0:  # HC_ACTION
                vk_code = wintypes.DWORD.from_address(lParam).value
                blocked_keys = [164, 162, 0x5B, 0xA2, 0xA3]  # Tab, Escape, Win, Ctrl (left & right) 
                if vk_code in blocked_keys:  # Tab, Escape, Left Windows key
                    log_message(f"Blocked key: {hex(vk_code)}", "INFO")
                    return 1  # Block the key
            return windll.user32.CallNextHookEx(hook, nCode, wParam, lParam)

        proc_ptr = LowLevelKeyboardProc(low_level_keyboard_proc)
        hook = windll.user32.SetWindowsHookExW(13, proc_ptr, None, 0)

        if not hook:
            log_message("Failed to set keyboard hook!", "ERROR")
            return

        msg = wintypes.MSG()
        while server_running:  # Keep the hook active while the server is running
            windll.user32.GetMessageW(POINTER(wintypes.MSG)(msg), 0, 0, 0)

        release_keyboard_hook()  # Clean up when exiting

    def release_keyboard_hook():
        global hook
        if hook:
            windll.user32.UnhookWindowsHookEx(hook)
            log_message("Keyboard hook released.", "INFO")
            hook = None
# Key blocking for Linux
def block_keys_linux():
    try:
        if is_wayland_session():
            block_keys_wayland()
        else:
            block_keys_wayland()
            #block_keys_x11()
    except Exception as e:
        log_message(f"Unexpected error while blocking keys on Linux: {e}", "ERROR")

# Detect Wayland session
def is_wayland_session():
    return os.getenv("XDG_SESSION_TYPE") == "wayland"

# Block keys for X11
def block_keys_x11():
    try:
        keys_to_block = ["Tab", "Control_L", "Alt_L"]
        keymap = "\n".join([f'key <{key}> {{ [ NoSymbol ] }};' for key in keys_to_block])
        keymap_path = "/tmp/x11_keyblock.xkb"
        with open(keymap_path, "w") as f:
            f.write(keymap)
        subprocess.run(["xkbcomp", keymap_path, ":0"], check=True)
        log_message("Blocked keys on X11 using xkbcomp.", "INFO")
    except subprocess.CalledProcessError as e:
        log_message(f"Error blocking keys on X11: {e}", "ERROR")

# Reset keys for X11
def reset_keys_x11():
    try:
        subprocess.run(["setxkbmap"], check=True)
        log_message("Key mappings reset on X11.", "INFO")
    except subprocess.CalledProcessError as e:
        log_message(f"Error resetting keys on X11: {e}", "ERROR")

# Block keys for Wayland
def block_keys_wayland():
    try:
        # Actions and keys to block in GNOME, including Alt+Escape and Alt+~
        keys_to_block = {
    "activate-window-menu":[],
    "switch-applications": [],
    "switch-applications-backward": [],
    "switch-windows": [],
    "switch-windows-backward": [],
    "close": [],
    "show-desktop": [],
    "cycle-windows": [], 
    "cycle-windows-backward": [],
    "switch-group": [], 
    "switch-panels":[], # Alt+~ behavior
    "move-to-workspace-last":[], # Focus shift backward,
    "move-to-workspace-left":[], # Focus shift backward,
    "move-to-workspace-right":[], # Focus shift backward,
    "move-to-workspace-down":[],
    "switch-to-workspace-last":[], # Focus shift backward,
    "switch-to-workspace-left":[], # Focus shift backward,
    "switch-to-workspace-right":[], # Focus shift backward,
    "switch-to-workspace-down":[],
    "toggle-maximized":[],
    "unmaximize":[],
    "panel-run-dialog":[],
    "minimize":[]
}


        # Disable the Super key (overlay key) functionality
        subprocess.run(["gsettings", "set", "org.gnome.mutter", "overlay-key", "''"], check=True)
        log_message("Disabled Super key (overlay-key) on Wayland.", "INFO")

        # Disable other actions
        for key_action, new_binding in keys_to_block.items():
            subprocess.run(
                ["gsettings", "set", "org.gnome.desktop.wm.keybindings", key_action, str(new_binding)],
                check=True
            )
            log_message(f"Blocked action: {key_action} on Wayland using gsettings.", "INFO")

    except subprocess.CalledProcessError as e:
        log_message(f"Error blocking keys on Wayland: {e}", "ERROR")


# Reset keys for Wayland
def reset_keys_wayland():
    try:
        actions_to_reset = [
   "activate-window-menu",
    "switch-applications",
    "switch-applications-backward",
    "switch-windows",
    "switch-windows-backward",
    "close",
    "show-desktop",
    "cycle-windows", 
    "cycle-windows-backward",
    "switch-group", 
    "switch-panels", # Alt+~ behavior
    "move-to-workspace-last", # Focus shift backward,
    "move-to-workspace-left", # Focus shift backward,
    "move-to-workspace-right", # Focus shift backward,
    "move-to-workspace-down",
    "switch-to-workspace-last", # Focus shift backward,
    "switch-to-workspace-left", # Focus shift backward,
    "switch-to-workspace-right", # Focus shift backward,
    "switch-to-workspace-down",
    "toggle-maximized",
    "unmaximize",
    "panel-run-dialog",
    "minimize"
]


        # Reset the Super key (overlay key)
        subprocess.run(["gsettings", "reset", "org.gnome.mutter", "overlay-key"], check=True)
        log_message("Reset Super key (overlay-key) on Wayland.", "INFO")

        # Reset other actions
        for action in actions_to_reset:
            subprocess.run(
                ["gsettings", "reset", "org.gnome.desktop.wm.keybindings", action],
                check=True
            )
            log_message(f"Reset action: {action} on Wayland using gsettings.", "INFO")

    except subprocess.CalledProcessError as e:
        log_message(f"Error resetting keys on Wayland: {e}", "ERROR")


# Reset keys for Linux
def reset_keys_linux():
    if is_wayland_session():
        reset_keys_wayland()
    else:
        reset_keys_wayland()
        # reset_keys_x11()

# Generic key blocking function
def block_keys():
    if platform.system() == "Windows":
        block_keys_windows()
    elif platform.system() == "Linux":
        block_keys_linux()
    elif platform.system() == "Darwin":
        block_keyboard_mac()

def is_virtual_machine():
    try:
        if platform.system() == "Windows":
            # Windows - use wmic to check BIOS
            output = subprocess.check_output("wmic bios get serialnumber", shell=True).decode()
        else:
            # Linux or MacOS - check CPU info
            output = subprocess.check_output("cat /proc/cpuinfo", shell=True).decode()
        
        virtual_keywords = ["hypervisor", "vmware", "vbox", "qemu"]
        for keyword in virtual_keywords:
            if keyword.lower() in output.lower():
                return True
        return False
    except Exception as e:
        print(f"Error occurred: {e}")
        return False
def disable_ctrl_alt_del_options():
    try:
        # Registry path for disabling "Switch User"
        switch_user_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with reg.CreateKey(reg.HKEY_LOCAL_MACHINE, switch_user_path) as key:
            reg.SetValueEx(key, "HideFastUserSwitching", 0, reg.REG_DWORD, 1)

        print("Switch User option disabled.")

        # Registry path for disabling "Lock"
        lock_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # Open or create the registry key
        with reg.CreateKey(reg.HKEY_CURRENT_USER, lock_path) as key:
            # Set or update the DisableLockWorkstation DWORD value
            reg.SetValueEx(key, "DisableLockWorkstation", 0, reg.REG_DWORD, 1)
        
        print("Lock option disabled.")
        log_message("Lock option disabled.", "INFO")
    except PermissionError:
        print("Permission denied. Please run this script as an administrator.")
        log_message("Permission denied. Please run this script as an administrator.", "ERROR")
        pass
    except Exception as e:
        print(f"An error occurred: {e}")
        log_message(f"An error occurred: {e}", "ERROR")
        pass


def enable_ctrl_alt_del_options():
    try:
        # Registry path for enabling "Switch User"
        switch_user_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with reg.CreateKey(reg.HKEY_LOCAL_MACHINE, switch_user_path) as key:
            reg.SetValueEx(key, "HideFastUserSwitching", 0, reg.REG_DWORD, 0)

        print("Switch User option enabled.")

        lock_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # Open or create the registry key
        with reg.CreateKey(reg.HKEY_CURRENT_USER, lock_path) as key:
            # Set or update the DisableLockWorkstation DWORD value
            reg.SetValueEx(key, "DisableLockWorkstation", 0, reg.REG_DWORD, 0)
        
        print("Lock option disabled.")
        log_message("Lock option disabled.", "INFO")
    except PermissionError:
        print("Permission denied. Please run this script as an administrator.")
        log_message("Permission denied. Please run this script as an administrator.", "ERROR")
        pass
    except Exception as e:
        print(f"An error occurred: {e}")
        log_message(f"An error occurred: {e}", "ERROR")
        pass
# HTTP Server
class RequestHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        global server_running
        if self.path == "/startService":
            log_message("Start Service", "INFO")
            disable_ctrl_alt_del_options()
            service_started.set()
            self._send_response({"message": "Service started successfully"})
        elif self.path == "/stopService":
            log_message("Stop Service", "INFO")
            self._send_response({"message": "Service started successfully"})
            enable_ctrl_alt_del_options()
            server_running = False
            if platform.system() == "Windows":
                release_keyboard_hook()
            elif platform.system() == "Linux":
                reset_keys_linux()
            show_taskbar()
            self._send_response({"message": "Service stopped successfully"})
            log_message("HTTP server stopped.", "INFO")
            signal_handler(None, None)
            
        else:
            self._send_response({"error": "Invalid endpoint"}, 404)

    def _send_response(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(bytes(str(data).replace("'", '"'), "utf-8"))

# Start HTTP server
def start_http_server():
    if is_virtual_machine():
        log_message("Running in a virtual machine, please run outside the VM")
        os._exit(1)
        return
    [percent,status,time_info]=get_battery_status()
    if percent<=20 and status=="Not Charging":
        log_message("Battery percentage is less than 20%","INFO")
        os._exit(1)
        return
    
    logging.info(f"Battery percentage: {percent}%")
    logging.info(f"Battery status: {status}")
    logging.info(f"Battery time: {time_info}")
    global server_running
    server = HTTPServer(("localhost", 3000), RequestHandler)
    log_message("HTTP server running on port 3000...", "INFO")
    while server_running:
        server.handle_request()
    
# Main Service
def start_service(processes_to_kill):
    global monitor_processes
    threading.Thread(target=monitor_processes_thread, args=(processes_to_kill,), daemon=True).start()
    threading.Thread(target=block_keys, daemon=True).start()
    hide_taskbar()
    while monitor_processes:
        terminate_recording_processes()
        time.sleep(5)
    
def open_chrome():
    try:
        subprocess.run(["taskkill", "/IM", "chrome.exe", "/F"], check=True)
    except:
        log_message("ERROR","ERRoR")

# Step 2: Wait for a moment to ensure all processes are terminated
    time.sleep(2)  # Waits for 2 seconds
    command = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "--kiosk",
    "--new-window",
    "https://localhost/TestPage/child.html",
    "--disable-address-bar",
    "--disable-options-button",
    "--disable-popup-blocking"
]

# Running the command
    subprocess.run(command)        
# Main execution
if __name__ == "__main__":
    

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    processes_to_kill = ["notepad.exe", "calc.exe", "mstsc", "notepad++","gedit","calculator","Skype"]
    thread = threading.Thread(target=check_multiple_displays, daemon=True)
    thread.start()
    # Start the HTTP server in a separate thread
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    # Wait for /startService request
    service_started.wait()
    # Start the main service
    start_service(processes_to_kill)
    # Keep the script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
