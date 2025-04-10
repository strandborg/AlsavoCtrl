import os
import time
import subprocess
import json
from homie.device_base import Device_Base
from homie.node.node_base import Node_Base

from homie.node.property.property_setpoint import Property_Setpoint
from homie.node.property.property_temperature import Property_Temperature
from homie.node.property.property_integer import Property_Integer
from homie.node.property.property_enum import Property_Enum
from homie.node.property.property_switch import Property_Switch


# Get MQTT broker configuration from environment variables

mqtt_settings = {
    'MQTT_BROKER' : os.environ.get("MQTT_BROKER_HOST", "localhost"),
    'MQTT_PORT' : int(os.environ.get("MQTT_BROKER_PORT", 1883)),
    'MQTT_USERNAME' : os.environ.get("MQTT_BROKER_USER", None),
    'MQTT_PASSWORD' : os.environ.get("MQTT_BROKER_PASS", None),
}

alsavo_ip = os.environ.get("ALSAVO_IP", "47.254.157.150")
alsavo_port = os.environ.get("ALSAVO_PORT", "51192")
alsavo_serial = os.environ.get("ALSAVO_SERIAL", None)
alsavo_pass = os.environ.get("ALSAVO_PASS", None)
alsavoctrl_exe = os.environ.get("ALSAVO_CTRL_PATH", "./AlsavoCtrl")
alsavo_verbosity = os.environ.get("ALSAVO_VERBOSITY", "WARNING")

device_id = os.environ.get("MQTT_DEVICE_BASE", "alsavo")
device_name = os.environ.get("MQTT_DEVICE_NAME", "Alsavo")

mqtt_publish_interval = int(os.environ.get("MQTT_PUBLISH_INTERVAL", 120))

class Device_Alsavo(Device_Base):
    def __init__(
        self,
        device_id=None,
        name=None,
        homie_settings=None,
        mqtt_settings=None,
    ):

        super().__init__(device_id, name, homie_settings, mqtt_settings)

        self.statuses = []
        self.configs = []
        self.state_json = {}
        node = Node_Base(self, "controls", "Controls", "controls")
        self.node = node
        self.add_node(node)

        self.addTempMeasurement(16, "waterin", "Water In Temp")
        self.addTempMeasurement(17, "waterout", "Water Out Temp")
        self.addTempMeasurement(18, "ambient", "Ambient Temp")
        self.addTempMeasurement(19, "coldpipe", "Cold Pipe Temp")
        self.addTempMeasurement(20, "hotpipe", "Hot Pipe Temp")
        self.addTempMeasurement(21, "ipmtemp", "IPM Module Temp")
        self.addTempMeasurement(23, "exhaust", "Exhaust Temp")
        self.addIntegerMeasurement(22, "fanrpm", "Fan RPM", "RPM")
        self.addIntegerMeasurement(25, "eev", "EEV", "steps")
        self.addIntegerMeasurement(26, "comprcurrent", "Compressor current", "A")
        self.addIntegerMeasurement(27, "comprfreq", "Compressor frequency", "Hz")
        self.addIntegerMeasurement(33, "comprmode", "Compressor running mode")
        self.addIntegerMeasurement(52, "status", "Status Code")
        self.addIntegerMeasurement(53, "running", "Running Code")
        self.addIntegerMeasurement(54, "devstatus", "Dev Status")
        self.addSetpointConfig(1, "heatsetpoint", "Heating mode target temperature")
        self.addSetpointConfig(2, "coolsetpoint", "Cooling mode target temperature")
        self.addSetpointConfig(3, "autosetpoint", "Auto mode target temperature")

        self.addEnumConfig(16, "power-mode", "Power mode", {"Silent": 0, "Smart": 1, "Powerful": 2})

        self.addBitfieldEnumConfig(4, 3, 0, "operatingmode", "Operating mode", {"Cooling": 0, "Heating": 1, "Auto": 2})
        self.addBitfieldSwitch(4, 2, "timeronenabled", "Timer On enabled")
        self.addBitfieldSwitch(4, 7, "timeroffenabled", "Timer Off enabled")
        self.addBitfieldSwitch(4, 3, "waterpumpmode", "Water pump always on")
        self.addBitfieldSwitch(4, 5, "power", "Heat pump On/Off")
        self.addBitfieldSwitch(5, 0, "defrost", "Manual defrost", retained=False)

        self.start()

    def update_json(self):
        response = subprocess.check_output([alsavoctrl_exe, "-v", alsavo_verbosity, "--json", "-s", alsavo_serial, "-l", alsavo_pass, "-a", alsavo_ip, "-p", alsavo_port], text=True, universal_newlines=True)
        try:
            self.state_json = json.loads(response)
        except Exception as e:
            print(f"Failed to parse AlsavoCtrl results: {e}")

    def setConfig(self, config, newVal):
        subprocess.check_output([alsavoctrl_exe, "--json", "-s", alsavo_serial, "-l", alsavo_pass, "-a", alsavo_ip, "-p", alsavo_port, str(config), str(newVal)], text=True, universal_newlines=True)
        self.update()


    def addTempMeasurement(self, status_idx, id, name):
        prop = Property_Temperature(self.node, id=id, name=name, unit="°C", value=20)
        self.node.add_property(prop)
        self.statuses.append((status_idx, prop))

    def addIntegerMeasurement(self, status_idx, id, name, unit=None):
        prop = Property_Integer(self.node, id=id, name=name, unit=unit, settable=False)
        self.node.add_property(prop)
        self.statuses.append((status_idx, prop))

    def addSetpointConfig(self, config_idx, id, name):
        prop = Property_Setpoint(self.node, id=id, name=name, unit="°C", set_value=lambda newTemp: self.setConfig(config_idx, int(newTemp*10)))
        prop.read_transform = lambda inVal: float(inVal/10)
        self.node.add_property(prop)
        self.configs.append((config_idx, prop))

    def addEnumConfig(self, config_idx, id, name, enum_dict):
        prop = Property_Enum(self.node, id=id, name=name, data_format=",".join(enum_dict.keys()), set_value=lambda newVal: self.setConfig(config_idx, enum_dict[newVal]))
        prop.read_transform = lambda inVal: dict((v,k) for k,v in enum_dict.items())[inVal]
        self.node.add_property(prop)
        self.configs.append((config_idx, prop))

    def addBitfieldEnumConfig(self, config_idx, mask, shift, id, name, enum_dict):
        prop = Property_Enum(self.node, id=id, name=name, data_format=",".join(enum_dict.keys()), set_value=lambda newVal: self.setBitfieldValue(config_idx, mask, shift, enum_dict[newVal]))
        prop.read_transform = lambda inVal: dict((v,k) for k,v in enum_dict.items())[(int(inVal) >> shift) & mask]
        self.node.add_property(prop)
        self.configs.append((config_idx, prop))

    def addBitfieldSwitch(self, config_idx, shift, id, name, retained=True):
        prop = Property_Switch(self.node, id=id, name=name, retained=retained, set_value=lambda newVal: self.setBitfieldValue(config_idx, 1, shift, 1 if newVal == 'ON' else 0))
        prop.read_transform = lambda inVal: 'ON' if bool((int(inVal) >> shift) & 1) else 'OFF'
        self.node.add_property(prop)
        self.configs.append((config_idx, prop))

    def setBitfieldValue(self, config_idx, mask, shift, newVal):
        if("config" in self.state_json and str(config_idx) in self.state_json["config"]):
            currVal = self.state_json["config"][str(config_idx)]
            currVal = currVal & ~(mask << shift)
            currVal |= (newVal << shift)
            self.setConfig(config_idx, currVal)

    def update_props(self):
#        json.dumps(self.state_json)
        for idx, prop in self.statuses:
            if("status" in self.state_json and str(idx) in self.state_json["status"]):
                rawVal = self.state_json["status"][str(idx)]
                translatedVal = rawVal if not hasattr(prop, "read_transform") else prop.read_transform(rawVal)
                prop.value = translatedVal
#                print(f"Updated status {idx}, json val {rawVal} propVal: {prop.value}")
        for idx, prop in self.configs:
            if("config" in self.state_json and str(idx) in self.state_json["config"]):
                rawVal = self.state_json["config"][str(idx)]
                translatedVal = rawVal if not hasattr(prop, "read_transform") else prop.read_transform(rawVal)
                prop.value = translatedVal

    def update(self):
        self.update_json()
        self.update_props()

def main():

    ctrl = Device_Alsavo(f"{device_id}", f"{device_name}", mqtt_settings=mqtt_settings)

    while True:
        ctrl.update()

        time.sleep(mqtt_publish_interval)

if __name__ == "__main__":
    main()
