import subprocess
import time
import sys
import colorama
from colorama import Fore

from FlowEntry import FlowEntry
def log(entry : FlowEntry, logLevel: str = "INFO"):
    if (entry.Arp):
        if(logLevel == "WARN"):
            print(Fore.RED + f"[{logLevel}]ARP\tduration={entry.Duration},n_packets={entry.NPackets},dl_src={entry.DLSrc},dl_dst={entry.DLDst},arp_spa={entry.ARPSrcIP},arp_tpa={entry.ARPTgtIP},actions={entry.Actions}")
            return
        print(Fore.GREEN + f"[{logLevel}]ARP\tduration={entry.Duration},n_packets={entry.NPackets},dl_src={entry.DLSrc},dl_dst={entry.DLDst},arp_spa={entry.ARPSrcIP},arp_tpa={entry.ARPTgtIP},actions={entry.Actions}")
        return
    if (entry.Icmp):
        print(Fore.GREEN + f"[{logLevel}]ICMP\tduration={entry.Duration},n_packets={entry.NPackets},dl_src={entry.DLSrc},dl_dst={entry.DLDst},nw_src={entry.NWSrc},nw_dst={entry.NWDst},actions={entry.Actions}")
        return
    print(entry._input)

def ParseEntries(input_str: str) -> list:
    entries = []
    for entry in input_str.split('\n'):
        if('actions' in entry):
            entries.append(FlowEntry(entry))
    return entries

def main():
    if sys.argv[1] is None:
        print("Please pass switch name.")
        return
    detectTime = 0
    while True:
        
        switch = sys.argv[1]
        try:
            output = subprocess.check_output(['/usr/bin/sudo', 'ovs-ofctl', 'dump-flows', switch], stderr=subprocess.STDOUT)
            outputMessage = output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            errorMessage = e.output.decode('utf-8')
            if errorMessage.strip():
                print(errorMessage)
            time.sleep(1)
            continue
        
        # # read from file
        # outputMessage = ""
        # with open('sample.txt', 'r') as file:
        #     outputMessage = file.read()
        
        entries = ParseEntries(outputMessage)
        if len(entries) == 0:
            print('Flow table empty!')
            time.sleep(1)
            continue
        else:
            for flowEntry in entries:
                if(flowEntry.ARPOperation == "2" and float(flowEntry.Duration) > 3.5 and 'output' in flowEntry.Actions):
                    packagePerSeconds = int(flowEntry.NPackets) / float(flowEntry.Duration)
                    if (packagePerSeconds >= 0.45):
                        detectTime += 1
                        log(flowEntry, "WARN")
                        if(detectTime >= 5):
                            print(Fore.RED + "ARP Spoofing detected!")
                            print(Fore.RED + f"Drop pakcets from attacker dl_src={flowEntry.DLSrc}")
                            # drop packets from attacker
                            subprocess.check_output(['/usr/bin/sudo', 'ovs-ofctl', 'add-flow', switch, f'dl_src={flowEntry.DLSrc},dl_dst={flowEntry.DLDst},arp,arp_op=2,actions=drop'], stderr=subprocess.STDOUT)
                            detectTime = 0
                        
                    continue
                log(flowEntry, "INFO")

        print("========================================================================================================================================")
        time.sleep(1)



if __name__ == "__main__":
    colorama.init(autoreset=True)
    main()