# WP SharkTooth

Wasatch Photonics USB bindings for Wireshark.
Author: Samie Bee, Date: 2023.11.14

## Description

SharkTooth is a utility program meant to be used with WireShark.
It provides meaningful diagnostic information with regards to
Wasatch Photonic's ENG-001 USB Specificiation.

This program is an extension of the python shell and should be
invoked in interactive mode:

    python -i sharktooth.py input_file.json

## Instructions

1. Use Wireshark to capture from USBPcap2.
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
                 ...
```
