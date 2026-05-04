# Overview

- Iterates over detected access points, silently deauthenticates a handful of clients, and grabs the resulting WPA handshake.
  
- Every captured handshake is verified against its HCPX structure before being stored, and each target is tracked in a local database so you never waste cycles on a BSSID you already own.
  
- Converts the capture to hccapx with cap2hccapx and validates it with wlanhcxinfo.
  
- Stores valid handshakes under /usr/share/wavebreaker/handshakes/ and logs the success.

<img width="757" height="410" alt="fronnnnt" src="https://github.com/user-attachments/assets/d9150bd6-8164-4522-9c57-f4aba3624ead" />

## Prerequisites

- wavebreaker` expects these binaries in your `$PATH`:

         aireplay-ng (Aircrack‑ng suite)
         airodump-ng
         cap2hccapx (hcxtools)
         wlanhcxinfo (hcxtools)
         iwconfig (wireless‑tools)

- Install them via your distribution’s package manager:

          sudo apt install aircrack-ng hcxtools wireless-tools

# Installation

        git clone https://github.com/Alb4don/Wavebreaker.git
        cd wavebreaker
        chmod +x wavebreaker.py

- Run the guided setup as root. It will erase any previous config, handshake database, and captured PCAPs it asks for explicit confirmation before doing so.

        sudo python3 wavebreaker.py --setup

- ou will be prompted for:

- The wireless interface to use (must support monitor mode and packet injection).

- The setup tests injection automatically ***with aireplay-ng --test.*** If it fails, you’ll be asked to provide a different interface.

- After completion the configuration is stored in /etc/wavebreaker/wavebreaker.conf, and empty databases are initialised under ***/usr/share/wavebreaker/.***

# Usage

        sudo python3 wavebreaker.py

- Passing an ignore list

- Edit ***/etc/wavebreaker/wavebreaker.conf*** and add a comma separated list of ESSIDs to skip:

        interface=wlan0mon
        ignore=""

- The file is only read at startup; changes take effect on the next invocation.

# Geolocation (optional)

- Place a SQLite database at one of these paths:

        /usr/share/wavebreaker/geoip/wigle.db
        
        /var/lib/wavebreaker/wifi_geo.db

- The database must have a table wifi with columns ***bssid TEXT PRIMARY KEY, lat REAL, lon REAL, accuracy REAL.*** Wavebreaker queries this table after each successful capture and enriches the main DB.

- No built‑in WiGLE API calls are made the lookups are fully offline.

- Every captured handshake is:

- Checked for the HCPX magic number.

- Passed to wlanhcxinfo to ensure it loads at least one record.

- Invalid files are deleted immediately. Only confirmed HCPX files land in ***/usr/share/wavebreaker/handshakes/.***

# Disclaimer

- The author is not responsible for the illegal use of the tool.
