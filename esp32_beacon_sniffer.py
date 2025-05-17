import network
import time
import ustruct
import ubinascii

def set_promiscuous_mode(wlan, enable=True):
    """Enable or disable promiscuous mode on the WLAN interface."""
    wlan.init(mode=network.WLAN.STA)
    if enable:
        wlan.config(promiscuous=True)
    else:
        wlan.config(promiscuous=False)

def set_channel(wlan, channel):
    """Set the WiFi channel (1-13)."""
    wlan.config(channel=channel)
    print(f"Switched to channel {channel}")

def parse_beacon_frame(packet):
    """Parse a WiFi beacon frame and extract SSID, BSSID, and channel."""
    try:
        # Check if packet is a beacon frame (type 0x80)
        if len(packet) < 36 or packet[0] != 0x80:
            return None
        
        # Extract BSSID (MAC address, bytes 10-15)
        bssid = ubinascii.hexlify(packet[10:16]).decode()
        bssid = ':'.join(bssid[i:i+2] for i in range(0, 12, 2)).upper()
        
        # Extract channel from DS Parameter Set (if present)
        channel = None
        pos = 36  # Start after fixed fields
        while pos + 1 < len(packet):
            tag_num = packet[pos]
            tag_len = packet[pos + 1]
            if tag_num == 3:  # DS Parameter Set
                channel = packet[pos + 2]
                break
            pos += 2 + tag_len
        
        # Extract SSID from tagged parameters
        ssid = ""
        pos = 36
        while pos + 1 < len(packet):
            tag_num = packet[pos]
            tag_len = packet[pos + 1]
            if tag_num == 0:  # SSID tag
                if tag_len > 0:
                    ssid = packet[pos + 2:pos + 2 + tag_len].decode('utf-8', 'ignore')
                break
            pos += 2 + tag_len
        
        return {
            'SSID': ssid,
            'BSSID': bssid,
            'Channel': channel
        }
    except Exception as e:
        print(f"Error parsing packet: {e}")
        return None

def beacon_sniffer():
    """Main function to sniff WiFi beacon frames."""
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    
    # Enable promiscuous mode
    set_promiscuous_mode(wlan, True)
    
    print("Starting beacon sniffer...")
    
    # Cycle through channels 1-13
    while True:
        for channel in range(1, 14):
            set_channel(wlan, channel)
            
            # Sniff for 1 second on each channel
            start_time = time.time()
            while time.time() - start_time < 1:
                # Read raw packet
                packet = wlan.read_raw()
                if packet:
                    beacon_info = parse_beacon_frame(packet)
                    if beacon_info:
                        print(f"Beacon - SSID: {beacon_info['SSID']}, "
                              f"BSSID: {beacon_info['BSSID']}, "
                              f"Channel: {beacon_info['Channel']}")
                
                time.sleep_ms(10)  # Small delay to avoid CPU hogging
            
            # Allow stopping the sniffer (e.g., via Ctrl+C)
            try:
                time.sleep_ms(100)
            except KeyboardInterrupt:
                print("Stopping sniffer...")
                set_promiscuous_mode(wlan, False)
                wlan.active(False)
                return

# Run the sniffer
beacon_sniffer()