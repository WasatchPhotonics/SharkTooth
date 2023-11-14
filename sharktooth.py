"""
Program Name: WP SharkTooth 
   File Name: sharktooth.py
      Author: Samie Bee
        Date: 2023.11.14

 Description: SharkTooth is a utility program meant to be used with WireShark.
              It provides meaningful diagnostic information with regards to
              Wasatch Photonic's ENG-0001 USB Specificiation.

              This program is an extension of the python shell and should be
              invoked in interactive mode:

                  python -i sharktooth.py input_file.json

Instructions: 1. Use Wireshark to capture from USBPcap2.
              2. Use any driver to interact with the spectrometer.
                 Options include Enlighten, Wasatch.PY, Wasatch.NET.
                 It does not have to be a driver written by us.
              3. When you are done, close the driver and disconnect the
                 spectrometer.
              4. In Wireshark: File > Export Packet Dissections > As JSON
              5. In the export window, make sure all settings are correct.
                 Be sure to check Packet Bytes and Each packet on a new page.
                 Also check Include Secondary Data Sources.
                 Set Packet Details to "All Expanded".
                 The packet range should be set to All Packets & Captured.
              6. Call the program in interactive mode:
                 $ python -i sharktooth.py packets.json
              7. Use interactive help to learn the usage of this program:
                 >>> help()
                 ...
                 >>> help(select_spectrometer)
                 ...
"""

import os
import sys
import json

import pyreadline3

_packet_data_path = None
_packet_data_file = None
_packet_data = None

_spec_cmd_addr = None
_spec_read_addr = None

_help = help

# opcode table

_opcode_lookup = {
  "ad": "Spectral Acquisition",
}

# helper functions

def _json_nav_path(json_obj, path, errout=False):

    for p in path:
        if type(json_obj) == list and type(p) == int and 0 <= p < len(json_obj):
            json_obj = json_obj[p]
        elif type(json_obj) == dict and p in json_obj.keys():
            json_obj = json_obj[p]
        else:
            if errout:
                print("Key failure:", p)
                print(json_obj.keys())
                exit(1)
            return None

    return json_obj

# maintain a list of symbols to NOT show under help("commands")
_private_symbols = dir()
_private_symbols += ["_private_symbols"]

def help(*k):
    """
    The help function has been modified for WP SharkTooth.

    Call it with no arguments to recieve a basic orientation of this program.

    Call it with a function or object as an argument to read its inline 
    documentation.
    """
    if len(k)==0:
        print("""Welcome to WP Shark Tooth.

SharkTooth is a utility program meant to be used with WireShark.
It provides meaningful diagnostic information with regards to
Wasatch Photonic's ENG-0001 USB Specificiation.

Type help("wireshark") to learn how to use Wireshark to record spectrometer
activity and export it in a format compatible with this program.

Once you have created a JSON export of your Wireshark capture, use
select_spectrometer() to detect a WP spectrometer in the packet data and to
filter all future commands to be about that unit.

You can use the help function to learn more about a particular command.
For example help(select_spectrometer) tells you more about that command.

Type help("commands") for a complete list of commands.

Type clear() to clear the screen.

Type exit() to close this program.
        """)
    elif k[0] == "wireshark":
        print("""1. Use Wireshark to capture from USBPcap2.
2. Use any driver to interact with the spectrometer.
   Options include Enlighten, Wasatch.PY, Wasatch.NET.
   It does not have to be a driver written by us.
3. When you are done, close the driver and disconnect the
   spectrometer.
4. In Wireshark: File > Export Packet Dissections > As JSON
5. In the export window, make sure all settings are correct.
   Be sure to check Packet Bytes and Each packet on a new page.
   Also check Include Secondary Data Sources.
   Set Packet Details to "All Expanded".
   The packet range should be set to All Packets & Captured.
6. Call this program to enter interactive mode:
   $ python -i sharktooth.py packets.json
7. Use interactive help to learn the usage of this program:
   >>> help()
   ...
   >>> help(select_spectrometer)
   ...""")
    elif k[0] == "commands":
        print(
"""Commands consist of python functions with parenthesis at the end of each 
call. Some functions may take an argument. See a function's help page for 
information on how to call it.

Here is a complete list of available commands (functions):
""")
        i = 0
        for cmd in _total_symbols:
            if cmd not in _private_symbols:
                print(cmd, end="    ")
                i += 1
                if i % 4 == 0:
                    print("")
        print("")
    else:
        _help(*k)

def clear():
    """
    Clears the screen.
    """

    # it's not enough to check if we're on Windows, because some Windows shells
    # still have the clear command
    os.system("clear") and os.system("cls")

def get_usb_addr(packet):
    """
    USB packets consist of two addresses. Usually it will be "host" and a
    device address such as "2.2.0". This function returns the one that is not
    "host" regardless of the data direction.
    """
    src = _json_nav_path(packet, ["_source", "layers", "usb", "usb.src"])
    dst = _json_nav_path(packet, ["_source", "layers", "usb", "usb.dst"])

    if src == "host":
        return dst
    else:
        return src

def select_spectrometer(index=0):
    """
    Scan packet data for Wasatch Photonics spectrometers.
    The scanned spectrometer will be used by subsequently issued commands.

    If there is more than one, the selection can be specified via index.

    Note that spectrometers come with pairs of USB addresses.
    """
    if not _packet_data:
        raise Exception("No packet data loaded. Call this program with a json "
                        "file as its first argument.")

    collected_acq_packets = []
    collected_read_packets = []
    collected_acq_addrs = set()
    collected_read_addrs = set()
    for packet in _packet_data:

        # collect all packets that look like acquisition requests (0xAD)
        frame_raw = _json_nav_path(packet, ["_source", "layers", 
        "frame_raw", 0])
        if frame_raw and "0040ad0000" in frame_raw:
            collected_acq_packets.append(packet)

        # collect all packets that look like bulk reads 2-4 kbytes of pixels
        frame_raw_size = _json_nav_path(packet, ["_source", "layers", 
        "frame_raw", 2])
        if frame_raw_size and frame_raw_size >= 2075:
            collected_read_packets.append(packet)

    # figure out which usb addresses were making acquisition requests
    # usually something like 2.2.0, 2.7.0, etc
    for packet in collected_acq_packets:
        collected_acq_addrs.add(get_usb_addr(packet))

    # figure out which usb addresses were making bulk reads
    # usually something like 2.255.2, 2.255.0, etc
    for packet in collected_read_packets:
        collected_read_addrs.add(get_usb_addr(packet))

    if len(collected_acq_addrs) != 1 or len(collected_read_addrs) != 1:
        raise Exception("Was not able to identify a single operating "
                "spectrometer.")
        # this exception occurs when the program does not able to find anything
        # that resembles a WP spectrometer OR when it's seeing more than one
        # device that resembles one of our specs.

        # multispec support is possible, but left out for now for simplicity

    global _spec_cmd_addr, _spec_read_addr 
    _spec_cmd_addr = list(collected_acq_addrs)[0]
    _spec_read_addr = list(collected_read_addrs)[0]

    print("Successfully selected spectrometer.")

def get_relevant_frame_numbers():
    """
    Returns frame numbers corresponding to relevant packets
    """

    if not _spec_cmd_addr or not _spec_read_addr:
        raise Exception("Spectrometer has not yet been selected.")

    selected_packets = []

    line_count = 0
    for i in range(len(_packet_data)):
        if get_usb_addr(_packet_data[i]) in [_spec_cmd_addr, _spec_read_addr]:
            selected_packets.append(i)

    return selected_packets

def get_relevant_packets():
    """
    Returns list of relevant packets for further Python processing.
    """

    if not _spec_cmd_addr or not _spec_read_addr:
        raise Exception("Spectrometer has not yet been selected.")

    selected_packets = []

    line_count = 0
    for i in range(len(_packet_data)):
        if get_usb_addr(_packet_data[i]) in [_spec_cmd_addr, _spec_read_addr]:
            selected_packets.append(_packet_data[i])

    return selected_packets

def decode_packet(packet):

    packet_data = _json_nav_path(packet, ["_source", "layers", "frame_raw", 0])
    packet_time = _json_nav_path(packet, ["_source", "layers", "frame", "frame.time_relative"])
    packet_size = _json_nav_path(packet, ["_source", "layers", "frame_raw", 2])

    # Not sure if opcode is always located at this offset
    packet_opcode = packet_data[58:60]

    if packet_size >= 2075:
        packet_type = "BULK READ"
    elif packet_opcode and packet_opcode in _opcode_lookup.keys():
        packet_type = _opcode_lookup[packet_opcode]
    elif packet_opcode:
        packet_type = "0x"+packet_opcode
    else:
        packet_type = "unknown"

    packet_src = _json_nav_path(packet, ["_source", "layers", "usb", "usb.src"])
    packet_dst = _json_nav_path(packet, ["_source", "layers", "usb", "usb.dst"])

    if packet_src == "host":
        packet_direction = "  toSpec"
    else:
        packet_direction = "fromSpec"

    return "%s <%s [%s] %d bytes>" % (packet_time, packet_type, packet_direction, 
            packet_size or "??")

def print_relevant_packets(offset=0, count=0):
    """
    Prints decoded packet information.

    The parameters offset and count can be used to page through the data.

    Use count=0 to get all packets.
    """

    if not _spec_cmd_addr or not _spec_read_addr:
        raise Exception("Spectrometer has not yet been selected.")

    line_count = 0
    for i in range(len(_packet_data)):
        if get_usb_addr(_packet_data[i]) in [_spec_cmd_addr, _spec_read_addr]:

            if line_count >= offset:
                print(i, decode_packet(_packet_data[i]))

            line_count += 1

            if line_count >= offset+count and count != 0:
                return

if __name__=="__main__":
    print("""WP Shark Tooth [Version 0.1.0] 2023.11.14 
(c) Wasatch Photonics. All Rights Reserved. 

Type help() for more information.
    """)

    # Load packet data into program
    if len(sys.argv) >= 2:
        _packet_data_path = sys.argv[1]
        if _packet_data_path.endswith(".json"):
            with open(_packet_data_path, 'rt') as _packet_data_file:
                _packet_data = json.load(_packet_data_file)

    # autocmd, for now
    print(">>> select_spectrometer()")
    select_spectrometer()
    print(">>> print_relevant_packets()")
    print_relevant_packets()

    _total_symbols = sorted(dir() + ["exit"])
