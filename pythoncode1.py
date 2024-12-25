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
            log_message("Taskbar hidden on Windows.", "INFO")
        elif platform.system() == "Linux":
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
                log_message("Taskbar and side navigation bar hidden on Wayland.", "INFO")
            else:
                # Hide taskbar and side navigation bar for X11
                if is_wmctrl_installed():
                    os.system("wmctrl -k on")
                    log_message("Taskbar hidden on X11.", "INFO")
                else:
                    log_message("wmctrl not installed. Cannot hide taskbar on X11.", "ERROR")
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
                log_message("Taskbar and side navigation bar shown on Wayland.", "INFO")
            else:
                # Show taskbar for X11
                if is_wmctrl_installed():
                    os.system("wmctrl -k off")
                    log_message("Taskbar shown on X11.", "INFO")
                else:
                    log_message("wmctrl not installed. Cannot show taskbar on X11.", "ERROR")
    except Exception as e:
        log_message(f"Error showing taskbar: {e}", "ERROR")



def check_multiple_displays():
    monitors = get_monitors()
    if len(monitors) > 1:
        return True
    else:
        return False

def detect_monitors():
    monitors = get_monitors()
    
    if check_multiple_displays():
        print("ALERT: Multiple displays detected!")
        print(f"Total number of displays: {len(monitors)}\n")
    
    for i, monitor in enumerate(monitors):
        print(f"Monitor {i+1}:")
        print(f"    Name: {monitor.name}")
        print(f"    Width: {monitor.width}px")
        print(f"    Height: {monitor.height}px")
        print(f"    Position: x={monitor.x}, y={monitor.y}")
        print(f"    Primary: {monitor.is_primary}\n")
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
            block_keys_x11()
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
    "switch-applications": [],
    "switch-applications-backward": [],
    "switch-windows": [],
    "switch-windows-backward": [],
    "close": [],
    "show-desktop": [],
    "cycle-windows": [], 
    "cycle-windows-backward": [],
    "switch-group": [],  # Alt+~ behavior
    
    # Tab switching and focus change actions:
    "switch-tab-forward": ["<Control><Tab>"],  # Ctrl+Tab switches forward between browser tabs
    "switch-tab-backward": ["<Control><Shift><Tab>"],  # Ctrl+Shift+Tab switches backward between browser tabs
    "focus-next-field": ["<Tab>"],  # Focus next field (Tab key to navigate through elements)
    "focus-previous-field": ["<Shift><Tab>"],  # Shift+Tab goes backward through elements
    "move-focus-forward": ["<Control><Tab>"],  # Alt or Control based for focus shift
    "move-focus-backward": ["<Shift><Control><Tab>"], # Focus shift backward,
    "move-to-workspace-last":[], # Focus shift backward,
    "move-to-workspace-left":[], # Focus shift backward,
    "move-to-workspace-right":[], # Focus shift backward,
    "move-to-workspace-down":[]
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
    "switch-applications",
    "switch-applications-backward",
    "switch-windows",
    "switch-windows-backward",
    "close",
    "show-desktop",
    "cycle-windows",
    "cycle-windows-backward",  
    "switch-group",  # Alt+~ behavior

    # Add reset actions related to focus change or tab switching:
    "switch-tab-forward",  # Reset any actions related to switching tabs forward
    "switch-tab-backward",  # Reset any actions related to switching tabs backward
    "focus-next-field",  # Reset Tab focus switching (next field)
    "focus-previous-field"  # Reset Shift+Tab focus switching (previous field),
    "move-to-workspace-right",
    "move-to-workspace-left",
    "move-to-workspace-last",
    "move-to-workspace-end",
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
        reset_keys_x11()

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
        
        virtual_keywords = ["hypervisor", "vmware", "vbox", "qemu", "virtual"]
        for keyword in virtual_keywords:
            if keyword.lower() in output.lower():
                return True
        return False
    except Exception as e:
        print(f"Error occurred: {e}")
        return False

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
            if check_multiple_displays():
                log_message("Detected extended Monitor")
                subprocess.run(["powershell", "-Command", "DisplaySwitch.exe /clone"], check=True)
                #return
            
            log_message("Start Service", "INFO")
            service_started.set()
            self._send_response({"message": "Service started successfully"})
        elif self.path == "/stopService":
            log_message("Stop Service", "INFO")
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
        return
    if check_multiple_displays():
        log_message("Extended Monitor has been detected, please try running without an extended monitor")
        subprocess.run(["powershell", "-Command", "DisplaySwitch.exe /clone"], check=True)
        #return
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
    

# Main execution
if __name__ == "__main__":
    

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    processes_to_kill = ["notepad.exe", "calc.exe", "mstsc", "notepad++","gedit","calculator","Skype"]

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
