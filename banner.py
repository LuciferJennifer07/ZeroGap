import pyfiglet
import os

def banner():
    os.system("clear")  # Clears Termux screen
    ascii_banner = pyfiglet.figlet_format("ZeroGap")  # Tool name
    print("\033[1;32m" + ascii_banner + "\033[0m")  # Green ASCII text
    
    print("\033[1;34m" + "="*60 + "\033[0m")
    print("\033[1;36m   🔒 Vulnerability Scanner Tool - Created by Yuvraj Tyagi 🔒   \033[0m")
    print("\033[1;34m" + "="*60 + "\033[0m\n")

# Run when script starts
if __name__ == "__main__":
    banner()
