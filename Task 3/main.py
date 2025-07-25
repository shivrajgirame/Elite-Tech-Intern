import sys
from modules import port_scanner, brute_forcer

def main():
    print("""
Penetration Testing Toolkit
==========================
1. Port Scanner
2. Brute-Forcer
0. Exit
""")
    choice = input("Select a module: ")
    if choice == '1':
        port_scanner.run()
    elif choice == '2':
        brute_forcer.run()
    elif choice == '0':
        print("Exiting.")
        sys.exit(0)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()