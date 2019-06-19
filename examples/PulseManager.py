#!/usr/bin/env python

'''
PulseManager OTX Example Script

An example script that:
- Creates a pulse if it doesnt exist; or
- Adds domains to a pulse if it already exists

I've redcated some bits so I can share publicly, so this won't run as is

'''
import logging
import os
import socket
import traceback
import sys

from OTXv2 import OTXv2
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# store OTX API key in environment variable OTX_API_KEY
API_KEY = os.getenv("OTX_API_KEY")

# Only need to set this environment variable if you need to override the default value (typically you do not)
OTX_SERVER = os.getenv("OTX_SERVER")

class PulseManager(object):
    def __init__(self):
        self.otx = OTXv2(API_KEY, server=OTX_SERVER)

    def pulse_name(self, malware_name):
        return "{} - Malware Domain Feed".format(malware_name)

    def indicators(self, domains):
        return [{'indicator': domain, 'type': 'hostname', 'title': 'Command and Control'} for domain in domains]

    # Returns the pulse id if it can find it, else None
    def find_pulse(self, malware_name):
        try:
            # Timeout for network connections
            socket.setdefaulttimeout(120)
            retries = 0
            while retries <= 5:
                try:
                    retries += 1
                    log.info('Looking for pulse: ' + malware_name)
                    query='name:"{}"'.format(self.pulse_name(malware_name))
                    pulses = self.otx.get_my_pulses(query=query)
                    if pulses:
                        return pulses[0]['id']
                    else:
                        return None
                except socket.timeout:
                    log.error("Timeout looking for pulse. Retrying")
                except AttributeError:
                    log.error("OTX API internal error")

            log.error("Max retries (5) exceeded")
            return None
        except Exception:
            log.error(traceback.format_exc())
        finally:
            socket.setdefaulttimeout(5)

        return None

    def create_pulse_request(self, malware_name, domains):
        try:
            description = "Command and Control domains for malware known as " + malware_name
            self.otx.create_pulse(
                name=self.pulse_name(malware_name), public=True, tlp="white", description=description,
                indicators=self.indicators(domains),
                tags=[malware_name],
                malware_families=[malware_name]
            )
        except Exception as ex:
            log.info(ex)

    def modify_pulse_request(self, pulse_id, domains):
        try:
            self.otx.add_pulse_indicators(pulse_id=pulse_id, new_indicators=self.indicators(domains))
        except Exception as ex:
            log.info(ex)

    # Updates a pulse if it exists, else creates it
    def maintain_pulse(self, malware_name, domains):
        if not domains:
            return

        pulse_id = self.find_pulse(malware_name)
        if not pulse_id:
            log.info('Making pulse, doesnt exist')
            self.create_pulse_request(malware_name, domains)
        else:
            log.info('Updating pulse, already exists')
            self.modify_pulse_request(pulse_id, domains)


if __name__ == '__main__':
    """
    As a simple testing mechanism, run like
    OTX_API_KEY=YOURKEYHERE ./PulseManager.py "Malware Name" domain1.com domain2.com domain3.com .... moredomains.com
    """
    p = PulseManager()
    p.maintain_pulse(malware_name=sys.argv[1], domains=sys.argv[2:])
