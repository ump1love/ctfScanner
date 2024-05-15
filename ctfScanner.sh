#!/bin/bash

current_date=$(date +"%Y-%m-%d")
base_directory="Scanner/$current_date"
filepath_tmp="$base_directory/ip_address.tmp"
filepath_txt="$base_directory/ip_address.txt"

if [ "$1" == "" ]; then
    echo "[-] You forgot to put an IP address"
    echo "For more help use ./ctfScanner -h or ./ctfScanner --help"
    exit 1
    
# uses provided ip address to ping its pool and print it in ip_addresses.txt file    
elif [ "$1" == "-i" ]; then
    if [ "$2" == "" ]; then
        echo "[-] You forgot to put an IP address after the -i flag"
        echo "For more help use ./ctfScanner -h or ./ctfScanner --help"
        exit 1
    else
        user_ip=$(ifconfig | grep -oP 'inet \K\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | head -n 1)
        
        mkdir -p "$base_directory"
        echo "[+] Directory created: $base_directory"
        for ip in $(seq 1 254); do
            ping -c 1 "$2.$ip" | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" >> "$filepath_tmp" &
        done
        wait
        sed -i "/$user_ip/d" "$filepath_tmp"
        mv "$filepath_tmp" "$filepath_txt"
        echo "[+] IP addresses from your pool will be placed in this file(in case scanner will find any): $filepath_txt"
    fi

    
# automatic scan using arp-scan -l command        
elif [ "$1" == "-a" ]; then
    mkdir -p "$base_directory"
    echo "[+] Directory created: $base_directory"
    arp-scan -l | tail -n +4 | head -n -4 | cut -f 1 | grep -v "Interface" > "$filepath_tmp"
    mv "$filepath_tmp" "$filepath_txt"
    echo "[+] IP addresses from your pool will be placed in this file(in case scanner will find any): $filepath_txt"
    
elif [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    echo "This is a very simplified version of scanner for personal uses of author, because he wanted to automate some of his routine in ctf."
    echo "There might be a lot of bugs, because this scanner is scuffed as hell. Author has low knowledge in bash, pentest tools and english."
    echo "-h or --help   --- help menu {example: ./ctfScanner -h or ./ctfScanner --help}"
    echo "-i             --- scans ip addresses using first 3 octets of an ip {example: ./ctfScanner -i 192.168.0}"
    echo "-a             --- kind of automatized scan, may has bugs {example: ./ctfScanner -a}"
    exit 1
    
else
    echo "[-] Wrong input"
    echo "For more help use ./ctfScanner -h or ./ctfScanner --help"
    exit 1
fi

amount_of_ip=$(wc -l < "$filepath_txt")
number_of_the_current_ip=1
ip_found="true"

if [ "$amount_of_ip" -gt 0 ]; then
    echo "[+] Scanner found $amount_of_ip IP(s)"
else
    echo "[-] Scanner was not able to find any ip's in this pool"
    ip_found="false"
    rm -r "$base_directory"
fi

if [ "$ip_found" = "true" ]; then
    
    # take one ip from the list
    while IFS= read -r line || [ -n "$line" ]; do
        echo "[$number_of_the_current_ip] $line"
        
        # Create directory with IP address as its name
        ip_directory="$base_directory/$line"
        mkdir -p "$ip_directory"
        echo "[+] Directory created: $ip_directory"
        
        ports_txt="$ip_directory/open_ports.txt"
        ports_tmp="$ip_directory/open_ports.tmp"
        ports_details_txt="$ip_directory/open_ports_details.txt"
        directories_txt_80="$ip_directory/web_directories_port80.txt"
        directories_txt_443="$ip_directory/web_directories_port443.txt"
        
        echo "[+] Looking for open ports"
        # run nmap and save the output to open_ports_tmp.txt
        nmap -T5 -p- "$line" | awk '/^[0-9]/{split($1, port, "/"); print port[1]}' >> "$ports_tmp"
        mv "$ports_tmp" "$ports_txt"
        
        echo "[+] Looking for more information on founded ports(using -A flag. Some information may gone missing)"
        while IFS= read -r port || [ -n "$port" ] && [ -s "$ports_txt" ]; do
            nmap -T5 -p "$port" -A "$line" | tail -n +6 | head -n -14 >> "$ports_tmp"
            echo " " >> "$ports_tmp"
        done < "$ports_txt"
        mv "$ports_tmp" "$ports_details_txt"
        echo "[+] More details on all ports you can find in file open_ports_details.txt"
        
        echo "[+] Scanning for additional information on ports"
        while IFS= read -r port || [ -n "$port" ] && [ -s "$ports_txt" ]; do
            if [ "$port" = 80 ] || [ "$port" = 443 ]; then
        echo "[+] Looking for web-directories"
                if [ "$port" = 80 ]; then
            > "$ports_tmp"
                    ffuf_output_directories=$(ffuf -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-2.3-small.txt -mc 301 -u http://"$line"/FUZZ 2>/dev/null | awk '!/^#|^$/' | cut -c6- | rev | cut -c5- | rev)
                    echo "$ffuf_output_directories" >> "$ports_tmp"
                    ffuf_output_files=$(ffuf -w /usr/share/wordlists/dirb/common.txt -u http://"$line"/FUZZ -e .php,.html,.txt -mc 200,301 2>/dev/null | awk '!/^#|^$/' | cut -c6- | rev | cut -c5- | rev)
                    echo "$ffuf_output_files" >> "$ports_tmp"
                    
                    mv "$ports_tmp" "$directories_txt_80"
                    
                elif [ "$port" = 443 ]; then
            > "$ports_tmp"
                    ffuf_output_directories=$(ffuf -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-2.3-big.txt -mc 301 -u https://"$line"/FUZZ 2>/dev/null | awk '!/^#|^$/' | cut -c6- | rev | cut -c5- | rev)
                    echo "$ffuf_output_directories" >> "$ports_tmp"
                    ffuf_output_files=$(ffuf -w /usr/share/wordlists/dirb/big.txt -u https://"$line"/FUZZ -e .php,.html,.txt -mc 200,301 2>/dev/null | awk '!/^#|^$/' | cut -c6- | rev | cut -c5- | rev)
                    echo "$ffuf_output_files" >> "$ports_tmp"
                    
                    mv "$ports_tmp" "$directories_txt_443"
                fi
                if [ $(wc -l < "$directories_txt_80") -gt 1 ] || [ $(wc -l < "$directories_txt_443") -gt 1 ]; then
                    echo "[+] Search for web-directories completed"
                else
                    echo "[-] Scanner was not able to find any web directories, or an unexpected error occurred"
                fi
            fi
        done < "$ports_txt"
        
        number_of_the_current_ip=$((number_of_the_current_ip + 1))
    done < "$filepath_txt"
else
    echo "[-] Aborting scan"
    exit 1
fi