'''
PulseManager OTX Example Script

An example script that:
- Creates a pulse if it doesnt exist; or
- Adds domains to a pulse if it already exists

I've redcated some bits so I can share publicly, so this won't run as is

'''
import socket
import logging
import traceback
import IndicatorTypes

from OTXv2 import OTXv2

class PulseManager():

    def __init__(self):
        self.otx = OTXv2("otx_key", "otx_server")

    # Returns the pulse id if it can find it, else 'NoPulse'
    def find_pulse(self, malware_name):
        try:
            # Timeout for network connections
            socket.setdefaulttimeout(120)
            retries = 0
            while retries <= 5:
                try:
                    retries += 1
                    log.info('Looking for pulse: ' + malware_name)
                    name = malware_name + " - Malware Domain Feed"
                    name = name.replace(' ', '%20')
                    result = self.otx.search_pulses(name)
                    if 'results' in str(result):
                        for pulse in result['results']:
                            if 'id' in pulse:
                                return pulse['id']
                    return None
                except socket.timeout:
                    log.error("Timeout looking for pulse. Retrying")
                except AttributeError:
                    log.error("OTX API internal error")
            log.error("Max retries (5) exceeded")
            return None
        except Exception as exc:
            log.error(traceback.format_exc())
        finally:
            socket.setdefaulttimeout(5)

    def make_pulse(self, name,indicators,tags, description):
        self.otx.create_pulse(name=name, public=True, indicators=indicators, tags=[],
                              references=[], description=description, tlp="White")

    def create_pulse_request(self, malware_name, domains):
        try:
            name = malware_name + " - Malware Domain Feed"
            tags = [malware_name]
            description = "Command and Control domains for malware known as " + malware_name

            indicators = []
            for domain in domains:
                indicators.append({'indicator': domain, 'type': 'hostname', 'title': 'Command and Control'})

            self.make_pulse(name, indicators, tags, description)
        except Exception as ex:
            log.info(ex)

    def modify_pulse_request(self, pulse_id, domains):
        try:
            new_domains = False

            # Get domains from pulse
            result = self.otx.get_pulse_details(pulse_id)
            indicators = result['indicators']
            for indicator in indicators:
                domain = indicator['indicator']
                if domain not in domains:
                    domains.append(domain)
                    new_domains = True

            new_indicators = []
            for domain in domains:
                new_indicators.append({'indicator': domain, 'type': 'hostname', 'title': 'Command and Control'})

            # Update the pulse - if there are new domains
            if new_domains:
                self.otx.replace_pulse_indicators(pulse_id, new_indicators)

        except Exception as ex:
            log.info(ex)

    # Updates a pulse if it exists, else creates it
    def maintain_pulse(self, malware_name, domains):
        if domains:
            pulse_id = self.find_pulse(malware_name)
            if not pulse_id:
                log.info('Making pulse, doesnt exist')
                self.create_pulse_request(malware_name, domains)
            else:
                log.info('Updating pulse, already exists')
                self.modify_pulse_request(pulse_id, domains)
