from datetime import time, date, datetime
from typing import Union
import json

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

myapp_name = "switch_team_2"

HOST_HOST_TIME = 1
HOST_HOST = 2
HOST_SEGMENT_TIME = 3
HOST_SEGMENT = 4
SEGMENT_SEGMENT_TIME = 5
SEGMENT_SEGMENT = 6


class SwitchController(app_manager.RyuApp):
    _CONTEXTS = {"wsgi": WSGIApplication}
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchController, self).__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(SwitchControllerHttp, {myapp_name: self})

        self.mac_to_port = {}

        self.segments: dict[str, list[str]] = {}

        self.permissions: dict[int, dict[str, dict]] = {
            HOST_HOST_TIME: {},
            HOST_HOST: {},
            HOST_SEGMENT_TIME: {},
            HOST_SEGMENT: {},
            SEGMENT_SEGMENT_TIME: {},
            SEGMENT_SEGMENT: {}
        }

        self.switches: dict[int, Datapath] = {}

    def get_segment_by_mac_address(self, mac_address: str) -> Union[str, None]:
        for segment, mac_addresses in self.segments.items():
            if mac_address in mac_addresses:
                return segment

        return None

    def get_ordered_string(self, items: list[str]) -> str:
        try:
            ordered = sorted(items)
            return "{}-{}".format(ordered[0], ordered[1])
        except TypeError:
            return None
        
        
    def get_priority_rule(self, first:str, second:str) -> bool:
        first_segment: str = self.get_segment_by_mac_address(mac_address=first)
        second_segment: str = self.get_segment_by_mac_address(mac_address=second)
        
        mac_key: str = self.get_ordered_string([first, second])
        segment_key: str = self.get_ordered_string([first_segment, second_segment])
        host_segment_key1: str = self.get_ordered_string([first, second_segment])
        host_segment_key2: str = self.get_ordered_string([first_segment, second])
        keys: list[str] = [mac_key, segment_key, host_segment_key1, host_segment_key2]
        
        for level in range(HOST_HOST_TIME, SEGMENT_SEGMENT + 1):
            for key in keys:
                permission = self.permissions[level].get(key)
                if permission:
                    if permission.get("allow") == True:
                        return permission
                    if permission.get("allow") == False:
                        return None
        return None


    def find_port_datapath_by_mac(self, mac_address) -> Union[Datapath, int]:
        for datapathid, mac_port in self.mac_to_port.items():
            for mac, port in mac_port.items():
                if mac == mac_address:
                    return self.switches[datapathid], port
        return None, None
    
    
    def weekday_allowed(self, week_range: str) -> bool:
        conversion_day_week_int = {
            "Seg": 1, "Ter": 2, "Qua": 3, "Qui": 4, "Sex":5, "Sab": 6, "Dom": 7
        }

        week_range = week_range.split("-")
        first_day_week = week_range[0]
        second_day_week = week_range[1]

        first_day_week_int = conversion_day_week_int[first_day_week]
        second_day_week_int = conversion_day_week_int[second_day_week]
        temp_week_int = first_day_week_int
        week_range_int = []
        while temp_week_int != second_day_week_int:
            week_range_int.append(temp_week_int)
            if temp_week_int == conversion_day_week_int.get("Dom"):
                temp_week_int = 0
            else:
                temp_week_int += 1
        return date.today().isoweekday() in week_range_int
        
    def time_allowed(self, time_range: str) -> bool:
        time_range = time_range.split("-")
        time1 = time.fromisoformat(time_range[0])
        time2 = time.fromisoformat(time_range[1])
        now = datetime.now().time()
        
        now = datetime.now().time()
        
        return time1 < now < time2

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        message: ofproto_v1_3_parser.OFPSwitchFeatures = ev.msg
        datapath: Datapath = message.datapath
        protocol_constants: ofproto_v1_3 = datapath.ofproto
        protocol_parser: ofproto_v1_3_parser = datapath.ofproto_parser
        match: ofproto_v1_3_parser.OFPMatch = protocol_parser.OFPMatch()

        datapathid: int = datapath.id

        actions: list[protocol_parser.OFPActionOutput] = [
            protocol_parser.OFPActionOutput(
                protocol_constants.OFPP_CONTROLLER, protocol_constants.OFPCML_NO_BUFFER
            )
        ]

        self.switches.setdefault(datapathid, datapath)

        self.add_flow(datapath=datapath, match=match, actions=actions, priority=0)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg: ofproto_v1_3_parser.OFPPacketIn = ev.msg

        datapath: Datapath = msg.datapath
        protocol_constants: ofproto_v1_3 = datapath.ofproto
        protocol_parser: ofproto_v1_3_parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]

        pkt: packet.Packet = packet.Packet(msg.data)
        eth: ethernet.ethernet = pkt.get_protocols(ethernet.ethernet)[0]

        dst: str = eth.dst
        src: str = eth.src
        datapathid: int = datapath.id

        self.mac_to_port.setdefault(datapathid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[datapathid][src] = in_port

        if dst in self.mac_to_port[datapathid]:
            out_port = self.mac_to_port[datapathid][dst]
        else:
            out_port = protocol_constants.OFPP_FLOOD

        actions: list[ofproto_v1_3_parser.OFPActionOutput] = [
            protocol_parser.OFPActionOutput(out_port)
        ]

        # install a flow to avoid packet_in next time
        if out_port != protocol_constants.OFPP_FLOOD:

            priority_rule = self.get_priority_rule(src, dst)
            if not priority_rule:
                return

            hard_timeout = 0
            time: str = priority_rule.get("time")
            if time:
                weekdaytime_range = time.split(" ")
                week_range = weekdaytime_range[0]
                time_range = weekdaytime_range[1]
                if (not self.weekday_allowed(week_range)) or (not self.time_allowed(time_range)):
                    return
                
                hard_timeout = 30
            
            match: ofproto_v1_3_parser.OFPMatch = protocol_parser.OFPMatch(
                in_port=in_port, eth_dst=dst
            )
            if msg.buffer_id != protocol_constants.OFP_NO_BUFFER:
                self.add_flow(
                    datapath=datapath,
                    match=match,
                    actions=actions,
                    buffer_id=msg.buffer_id,
                    hard_timeout=hard_timeout
                )
            else:
                self.add_flow(
                    datapath=datapath,
                    match=match,
                    actions=actions,
                    hard_timeout=hard_timeout
                )

        data = None
        if msg.buffer_id == protocol_constants.OFP_NO_BUFFER:
            data = msg.data

        out = protocol_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def add_flow(
        self,
        datapath: Datapath,
        match: ofproto_v1_3_parser.OFPMatch,
        actions: ofproto_v1_3_parser.OFPAction,
        hard_timeout: int,
        priority: int = 1000,
        buffer_id = None,
    ):
        protocol_constants: ofproto_v1_3 = datapath.ofproto
        protocol_parser: ofproto_v1_3_parser = datapath.ofproto_parser

        instructions: list[ofproto_v1_3_parser.OFPInstructionActions] = [
            protocol_parser.OFPInstructionActions(
                protocol_constants.OFPIT_APPLY_ACTIONS, actions
            )
        ]

        if buffer_id:
            mod: ofproto_v1_3_parser.OFPFlowMod = protocol_parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions,
                hard_timeout=hard_timeout
            )
        else:
            mod: ofproto_v1_3_parser.OFPFlowMod = protocol_parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    def del_flow(
        self, datapath: Datapath, in_port: int, eth_dst: str
    ) -> None:
        protocol_constants: ofproto_v1_3 = datapath.ofproto
        protocol_parser: ofproto_v1_3_parser = datapath.ofproto_parser
        match: ofproto_v1_3_parser.OFPMatch = protocol_parser.OFPMatch(
            in_port=in_port, eth_dst=eth_dst
        )

        mod: ofproto_v1_3_parser.OFPFlowMod = protocol_parser.OFPFlowMod(
            datapath=datapath,
            command=protocol_constants.OFPFC_DELETE,
            out_port=protocol_constants.OFPP_ANY,
            out_group=protocol_constants.OFPG_ANY,
            match=match,
        )
        datapath.send_msg(mod)


class SwitchControllerHttp(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SwitchControllerHttp, self).__init__(req, link, data, **config)
        self.controller: SwitchController = data[myapp_name]

    @route(myapp_name, "/nac/segmentos/", methods=["POST"])
    def add_segments(self, req, **kwargs):
        new_segments = req.json
        segments = self.controller.segments

        for segment_name, mac_addresses in new_segments.items():
            if segments.get(segment_name):
                segments[segment_name] = list(
                    set(segments[segment_name] + mac_addresses)
                )
            else:
                self.controller.segments[segment_name] = mac_addresses
        return Response(status=204)

    @route(myapp_name, "/nac/segmentos/", methods=["GET"])
    def get_segments(self, req, **kwargs):
        segments = json.dumps(self.controller.segments)
        return Response(content_type="application/json", body=segments, status=200)

    @route(myapp_name, "/nac/segmentos/{segment_name}", methods=["DELETE"])
    def remove_segments_by_name(self, req, **kwargs):
        segment_name = kwargs.get("segment_name")
        segments = self.controller.segments
        if segment_name in segments.keys():
            del segments[segment_name]
        else:
            return Response(status=404)
        return Response(status=204)

    @route(
        myapp_name, "/nac/segmentos/{segment_name}/{mac_address}", methods=["DELETE"]
    )
    def remove_segments_by_name(self, req, **kwargs):
        segment_name = kwargs.get("segment_name")
        mac_address = kwargs.get("mac_address")
        segments = self.controller.segments
        if segment_name in segments.keys():
            segment = segments.get(segment_name)
            if mac_address in segment:
                segment.remove(mac_address)

                return Response(status=204)
        return Response(status=404)

    @route(
        myapp_name, "/nac/segmentos/{segment_name}/{mac_address}", methods=["DELETE"]
    )
    def remove_segments_by_name(self, req, **kwargs):
        segment_name = kwargs.get("segment_name")
        mac_address = kwargs.get("mac_address")
        segments = self.controller.segments
        if segment_name in segments.keys():
            segment = segments.get(segment_name)
            if mac_address in segment:
                segment.remove(mac_address)

                return Response(status=204)
        return Response(status=404)

    @route(myapp_name, "/nac/controle/", methods=["GET"])
    def get_acess_control_rules(self, req, **kwargs):
        rules = json.dumps(self.controller.permissions)
        return Response(content_type="application/json", body=rules, status=200)

    @route(myapp_name, "/nac/controle/", methods=["POST"])
    def access_control(self, req, **kwargs):
        rule_json = req.json
        segment_a: str = rule_json.get("segmento_a")
        segment_b: str = rule_json.get("segmento_b")
        host_a: str = rule_json.get("host_a")
        host_b: str = rule_json.get("host_b")
        host: str = rule_json.get("host")
        segment: str = rule_json.get("segmento")
        action: str = rule_json.get("acao")
        download_bandwidth: str = rule_json.get("banda_download")
        time: str = rule_json.get("horario")

        if host_a and host_b and time:
            item_key: str = self.controller.get_ordered_string(items=[host_a, host_b])
            allow: bool = True if action == "permitir" else False

            self.controller.permissions[HOST_HOST][item_key] = {
                "target": [host_a, host_b],
                "allow": allow,
                "time": time,
            }

            self.remove_permissions(item_a=host_a, item_b=host_b)
        elif host_a and host_b:
            item_key: str = self.controller.get_ordered_string(items=[host_a, host_b])
            allow: bool = True if action == "permitir" else False

            self.controller.permissions[HOST_HOST][item_key] = {
                "target": [host_a, host_b],
                "allow": allow
            }
            
            self.remove_permissions(item_a=host_a, item_b=host_b)
                    
        elif host and segment and time:
            item_key: str = self.controller.get_ordered_string(items=[host, segment])
            allow: bool = True if action == "permitir" else False

            self.controller.permissions[HOST_HOST][item_key] = {
                "target": [host, segment],
                "allow": allow,
                "time": time,
            }

            self.remove_permissions(item_a=host, item_b=segment)
        elif host and segment:
            item_key: str = self.controller.get_ordered_string(items=[host, segment])
            allow: bool = True if action == "permitir" else False
            segment_addresses = self.controller.segments[segment]
            
            self.controller.permissions[HOST_SEGMENT][item_key] = {
                "target": [host, self.controller.segments[segment]],
                "allow": allow
            }

            self.remove_permissions(item_a=host, item_b=segment_addresses)
            
        elif segment_a and segment_b and time:
            item_key: str = self.controller.get_ordered_string(items=[segment_a, segment_b])
            allow: bool = True if action == "permitir" else False

            self.controller.permissions[HOST_HOST][item_key] = {
                "target": [segment_a, segment_b],
                "allow": allow,
                "time": time,
            }

            self.remove_permissions(item_a=segment_a, item_b=segment_b)
        elif segment_a and segment_b:
            item_key: str = self.controller.get_ordered_string(items=[segment_a, segment_b])
            allow: bool = True if action == "permitir" else False
            segment_a_addresses = self.controller.segments[segment_a]
            segment_b_addresses = self.controller.segments[segment_b]
            
            self.controller.permissions[HOST_SEGMENT][item_key] = {
                "allow": allow
            }

            self.remove_permissions(item_a=segment_a_addresses, item_b=segment_b_addresses)


    def remove_permissions(self, item_a: Union[str, list[str]], item_b: Union[str, list[str]]):
        mac_addresses_list: list[list[str]] = []

        if isinstance(item_a, str) and isinstance(item_b, str):
            mac_addresses_list = [[item_a, item_b]]
        elif isinstance(item_a, list) and isinstance(item_b, str):
            mac_addresses_list = [[mac_address_a, item_b] for mac_address_a in item_a]
        elif isinstance(item_a, str) and isinstance(item_b, list):
            mac_addresses_list = [[item_a, mac_address_b] for mac_address_b in item_b]
        elif isinstance(item_a, list) and isinstance(item_b, list):
            mac_addresses_list = [
                [mac_address_a, mac_address_b]
                for mac_address_a in item_a
                for mac_address_b in item_b
            ]
        
        for mac_addresses in mac_addresses_list:
            self.controller.logger.info(mac_addresses)
            self.del_host_rule(mac_addresses[0], mac_addresses[1])


    def del_host_rule(self, mac_address_a, mac_address_b):
        try:
            datapath_a, port_a = self.controller.find_port_datapath_by_mac(
                mac_address_a
            )
            if datapath_a and port_a:
                self.controller.del_flow(
                    datapath=datapath_a,
                    in_port=port_a,
                    eth_dst=mac_address_b,
                )
            
            datapath_b, port_b = self.controller.find_port_datapath_by_mac(
                mac_address_b
            )
            if datapath_b and port_b:
                self.controller.del_flow(
                    datapath=datapath_b,
                    in_port=port_b,
                    eth_dst=mac_address_a,
                )
        except ValueError:
            pass
