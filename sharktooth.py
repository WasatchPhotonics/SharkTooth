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
                 (One time I had to use USBPcap1 for it to work.
                 Make sure it is filling up with messages.)
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

# This table of opcodes should be as comprehensive as possible,
# including elements which have been deprecated.
# Here we include anything that we may want to identify in the field.
_opcode_lookup = {
  "39": "GET_ACCESSORY_ENABLE",
  "38": "SET_ACCESSORY_ENABLE",
  "ad": "ACQUIRE_SPECTRUM",
  "e4": "ACTUAL_FRAMES*",
  "df": "ACTUAL_INTEGRATION_TIME*",
  "35": "AMBIENT_TEMPERATURE",
  "eb": "AREA_SCAN_ENABLE",
  "86": "BATTERY_CHARGER_ENABLE",
  "13": "BATTERY_STATE",
  "14": "BATTERY_REG",
  "04": "COMPILATION_OPTIONS",
  "cc": "GET_CONTINUOUS_ACQUISITION*",
  "c8": "SET_CONTINUOUS_ACQUISITION*",
  "cd": "GET_CONTINUOUS_FRAMES*",
  "c9": "SET_CONTINUOUS_FRAMES*",
  "c5": "GET_DETECTOR_GAIN",
  "b7": "SET_DETECTOR_GAIN",
  "9f": "GET_DETECTOR_GAIN_ODD*",
  "9d": "SET_DETECTOR_GAIN_ODD*",
  "c4": "GET_DETECTOR_OFFSET",
  "b6": "SET_DETECTOR_OFFSET",
  "9e": "DETECTOR_OFFSET_ODD*",
  "25": "DETECTOR_ROI",
  "d1": "GET_DETECTOR_SENSING_THRESHOLD*",
  "d0": "SET_DETECTOR_SENSING_THRESHOLD*",
  "22": "GET_DETECTOR_START_LINE",
  "21": "SET_DETECTOR_START_LINE",
  "24": "GET_DETECTOR_STOP_LINE",
  "23": "SET_DETECTOR_STOP_LINE",
  "da": "GET_DETECTOR_TEC_ENABLE",
  "d6": "SET_DETECTOR_TEC_ENABLE",
  "d9": "GET_DETECTOR_TEC_SETPOINT",
  "d8": "SET_DETECTOR_TEC_SETPOINT",
  "d7": "DETECTOR_TEMPERATURE",
  "cf": "GET_DETECTOR_THRESHOLD_SENSING_MODE*",
  "ce": "SET_DETECTOR_THRESHOLD_SENSING_MODE*",
  "fe": "DFU_MODE",
  "26": "ERASE_STORAGE",
  "37": "GET_FAN_ENABLE",
  "36": "SET_FAN_ENABLE",
  "27": "FEEDBACK",
  "c0": "FIRMWARE_VERSION",
  "b4": "FPGA_FIRMWARE_VERSION",
  "ec": "GET_HIGH_GAIN_MODE_ENABLE",
  "eb": "SET_HIGH_GAIN_MODE_ENABLE",
  "bc": "GET_HORIZONTAL_BINNING*",
  "b8": "SET_HORIZONTAL_BINNING*",
  "bf": "GET_INTEGRATION_TIME",
  "b2": "SET_INTEGRATION_TIME",
  "33": "GET_LAMP_ENABLE",
  "32": "SET_LAMP_ENABLE",
  "e2": "GET_LASER_ENABLE",
  "be": "SET_LASER_ENABLE",
  "ef": "LASER_INTERLOCK",
  "0d": "LASER_IS_FIRING",
  "83": "GET_LASER_POWER_ATTENUATOR",
  "82": "SET_LASER_POWER_ATTENUATOR",
  "84": "LASER_TEC_ENABLE",
  "e8": "GET_LASER_TEC_SETPOINT",
  "e7": "SET_LASER_TEC_SETPOINT",
  "ea": "GET_LASER_RAMPING_MODE*", # removed from FID ICD 1.16
  "e9": "SET_LASER_RAMPING_MODE*",
  "e8": "GET_LASER_TEC_SETPOINT",
  "e7": "SET_LASER_TEC_SETPOINT",
  "d5": "LASER_TEMPERATURE",
  "15": "GET_LASER_WATCHDOG",
  "16": "SET_LASER_WATCHDOG",
  "03": "LINE_LENGTH",
  "c3": "GET_MOD_DURATION*",
  "b9": "SET_MOD_DURATION*",
  "e3": "GET_MOD_ENABLE",
  "bd": "SET_MOD_ENABLE",
  "de": "GET_MOD_LINKED_TO_INTEGRATION",
  "dd": "SET_MOD_LINKED_TO_INTEGRATION",
  "cb": "GET_MOD_PULSE_PERIOD",
  "c7": "SET_MOD_PULSE_PERIOD",
  "ca": "GET_MOD_PULSE_DELAY",
  "c6": "SET_MOD_PULSE_DELAY",
  "dc": "GET_MOD_PULSE_WIDTH",
  "db": "SET_MOD_PULSE_WIDTH",
  "01": "GET_MODEL_CONFIG",
  "a2": "SET_MODEL_CONFIG",
  "01": "GET_MODEL_CONFIG",
  "02": "SET_MODEL_CONFIG",
  "0b": "OPT_ACTUAL_INTEGRATION_TIME*",
  "0a": "OPT_AREA_SCAN*",
  "07": "OPT_CF_SELECT*",
  "06": "OPT_DATA_HEADER_TAB*",
  "0c": "OPT_HORIZONTAL_BINNING*",
  "05": "OPT_INTEGRATION_TIME_RESOLUTION*",
  "08": "OPT_LASER_TYPE*",
  "09": "OPT_LASER_CONTROL*",
  "fd": "PIXEL_MODE",
  "19": "GET_RAMAN_DELAY",
  "20": "SET_RAMAN_DELAY",
  "17": "GET_RAMAN_MODE",
  "18": "SET_RAMAN_MODE",
  "b5": "RESET_FPGA",
  "ee": "GET_SELECTED_ADC",
  "ed": "SET_SELECTED_ADC",
  "31": "GET_SHUTTER_ENABLE",
  "30": "SET_SHUTTER_ENABLE",
  "25": "STORAGE_BLOCK",
  "ab": "GET_TRIGGER_DELAY",
  "aa": "SET_TRIGGER_DELAY",
  "27": "TRIGGER_FEEDBACK",
  "e1": "GET_TRIGGER_OUTPUT",
  "e0": "SET_TRIGGER_OUTPUT",
  "d3": "GET_TRIGGER_SOURCE",
  "d2": "SET_TRIGGER_SOURCE",
  "d4": "UNTETHERED_CAPTURE_STATUS",
}

# helper functions

def _json_nav_path(json_obj, path, errout=False):
    """
    Iterate through path to collect a specific json element. Return None if path does not resolve.
    """

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

def _json_search_key(packet, key):
    """
    searches json object for a specific key, possibly nested.
    return a complete path that can be used with _json_nav_path
    """

    if key in packet.keys():
        return [key]

    for (k,v) in packet.items():
        if type(v) == dict:
            res = _json_search_key(v, key)
            if res:
                return [k] + res
    return None

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

def select_spectrometer():
    """
    Scan packet data for Wasatch Photonics spectrometers.
    The scanned spectrometer will be used by subsequently issued commands.

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
        print(len(collected_acq_addrs), len(collected_read_addrs))
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

    selected_frame_numbers = []

    line_count = 0
    for i in range(len(_packet_data)):
        if get_usb_addr(_packet_data[i]) in [_spec_cmd_addr, _spec_read_addr]:
            selected_frame_numbers.append(i)

    return selected_frame_numbers

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

def decode_packet(packet, partial_decode=True):

    packet_data = _json_nav_path(packet, ["_source", "layers", "frame_raw", 0])
    packet_time = _json_nav_path(packet, ["_source", "layers", "frame", "frame.time_relative"])
    packet_size = _json_nav_path(packet, ["_source", "layers", "frame_raw", 2])

    packet_opcode = _json_nav_path(packet, ["_source", "layers", "Setup Data", "usb.setup.bRequest_raw", 0])
    packet_value = _json_nav_path(packet, ["_source", "layers", "Setup Data", "usb.setup.wValue"])
    if packet_value == "0":
        packet_value = "0000"
    elif packet_value:
        # remove '0x' prefix
        packet_value = packet_value[2:]
    packet_index = _json_nav_path(packet, ["_source", "layers", "Setup Data", "usb.setup.wIndex"])
    if packet_index == "0":
        packet_index = "0000"
    elif packet_index:
        # remote '0x' prefix
        packet_index = packet_index[2:]

    packet_src = _json_nav_path(packet, ["_source", "layers", "usb", "usb.src"])
    packet_dst = _json_nav_path(packet, ["_source", "layers", "usb", "usb.dst"])

    # packet direction is determined two ways
    # (1) by checking whether the src or dst is "host"
    # (2) by checking the byte before the opcode
    # these two results can be compared

    # data direction found on byte 28 of frame
    packet_direction_byte = packet_data[28*2:29*2]

    # opcode also found on byte 29 of frame
    #packet_opcode = packet_data[29*2:30*2]

    if packet_src == "host":
        packet_direction = "HOST_TO_DEVICE"
        if packet_direction_byte != "40":
            # if we don't have a direction indication on the previous byte, we probably don't have an opcode
            packet_opcode = None
    else:
        packet_direction = "DEVICE_TO_HOST"

        if packet_direction_byte != "c0":
            # if we don't have a direction indication on the previous byte, we probably don't have an opcode
            packet_opcode = None

    if packet_size >= 2075:
        packet_type = "BULK READ"
    elif packet_opcode and packet_opcode in _opcode_lookup.keys():
        packet_type = _opcode_lookup[packet_opcode] + " 0x"+packet_opcode
    elif packet_opcode:
        if not partial_decode:
            return None
        packet_type = "unknown 0x"+packet_opcode
    else:
        if not partial_decode:
            return None
        packet_type = "unknown"
    
    value = packet_value or ""
    if value == "0000": value = ""
    if value:
        value = "value_raw="+value

    index = packet_index or ""
    if index == "0000": index = ""
    if index:
        index = "index_raw="+index

    val_24bit = None
    if packet_value and packet_index:
        val_24bit = int(packet_value, 16)|(int(packet_index, 16)<<16)
        if val_24bit != None:
            val_24bit = "value="+str(val_24bit)
    
    return "%s <%s [%s] %d bytes> %s %s %s" % (packet_time, packet_type, packet_direction, packet_size or "??", value, index, val_24bit)

def print_relevant_packets(offset=0, count=0, skip_unknown=True):
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
                decoded = decode_packet(_packet_data[i], not skip_unknown)
                if decoded:
                    print(i, decoded)

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
        else:
           print("Only JSON files supported.")
           exit(2)

    # autocmd, for now
    print(">>> select_spectrometer()")
    select_spectrometer()
    print(">>> print_relevant_packets()")
    print_relevant_packets()

    _total_symbols = sorted(dir() + ["exit"])
