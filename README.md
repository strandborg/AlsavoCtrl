# AlsavoCtrl
 Alsavo Heat Pump control application

This command-line tool can be used to control pool heat pumps manufactured by Zealux (rebranded as Swim&Fun etc), replacing the "Alsavo Pro" Android/iOS application. Only tested on one specific heat pump; use at your own risk.

# Building from sources

The example build system uses cmake, at least version 3.10. In addition you'll need a C++ compiler (for example g++) installed.

Clone the repository in a directory, and from that directory, run the following commands:
```
mkdir build
cd build
cmake ..
make
```

After those commands you should have a 'AlsavoCtrl' executable in the build dir.

# Docker image

Peter Haislund has created a readymade [Docker image](https://hub.docker.com/r/peterhaislund/alsavo_status) that can be used to publish the status values to MQTT. 

# Usage
```
Usage: AlsavoCtrl [OPTIONS] [conf_idx] [value]

Positionals:
  conf_idx INT                Config index to write
  value INT                   Value to write

Options:
  -h,--help                   Print this help message and exit
  -s,--serial TEXT REQUIRED   Serial number string of the heat pump
  -l,--password TEXT REQUIRED Password
  -a,--address TEXT           Override server address, defaults to 47.254.157.150
  -p,--port INT               Override server port, default 51194
  --listen                    Keep listening for status updates
  -g,--logfile TEXT           Write log to file
  ```

Running AlsavoCtrl without config_idx and value will query the current status and config values as JSON and exit. 

# Known status and config parameter indices

```
Status params:

Values are signed int16s.
All temperature values are in tenths of a Celsius, for example a value of -123 means -12.3 degrees C.

16 = Water in temp
17 = Water out temp
18 = Ambient temperature
19 = "Cold pipe temperature"
20 = "Heating pipe temperature"
21 = IPM module temperature
22 = Fan speed (RPM)
23 = Exhaust temperature
24 = Compressor input temperature? Always zero for me.
25 = Electronic exhaust valve opening setting, Range: 0-450'ish
26 = Compressor current in amps
27 = Compressor running frequency
33 = Compressor speed setting (0 = off, 1 = P1 40Hz, 5 = P5 82Hz)
34 = Frequency limit code
48 = Alarm code 1
49 = Alarm code 2
50 = Alarm code 3
51 = Alarm code 4
52 = System status code (0 in heating operation)
53 = System running code (3 = heating operation, 2 = defrost)
54 = Device status code (231 = heating operation, 175 = defrost)
55 = Heating max temperature
56 = Cooling min temperature
64 = Device type
65 = Main board HW revision
66 = Main board SW revision
67 = Manual HW code
68 = Manual SW code

Config params:

1 = Heating mode target temp
2 = Cooling mode target temp
3 = Auto mode target temp
4 = System config bitmask 1 (See below)
5 = System config bitmask 2 (See below)
6 = Manual frequency setting
7 = Manual EEV setting
8 = Manual fan speed setting
9 = Defrost in temp
10 = Defrost out temp (Heating pipe temperature required to end defrost)
11 = Water temperature calibration (offset for all temperature measurements)
12 = Defrost in time (minimum time between defrost sequences, in minutes)
13 = Defrost out time (max defrost time?)
14 = "Hot over", looks like temperature, but without x10? Default value 30
15 = "Cold over" default -20
16 = Power mode (0 = silent, 1 = smart 2 = powerful)
17 = Unknown, default value 6
32 = Current time, hibyte=hours, lobyte=minutes
33 = Timer on time
34 = Timer off time

Sys config 1:

Bits 0-1:   Operating mode: 0 = cool, 1 = heat, 2 = Auto
Bit 2:      Timer on enabled
Bit 3:      Water pump running mode (see manual, 0 = heat pump controls water pump, 1 = always on)
Bit 4:      Electronic Valve style ?
Bit 5:      On/off
Bit 6:      Debug mode (0 = auto, 1 = manual config C6, C7, C8 in effect)
Bit 7:      Timer off enabled

Sys config 2:
Bit 0:      Manual Defrost
Bit 1:      Reset to factory settings OR set Valve mode, you'll never know!
Bit 2:
```
