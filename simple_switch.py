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
from ryu.lib import dpid as datapathid_lib

from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

myapp_name = "switch_team_2"

DEFAULT_PRIORITY = 1000


class SimpleSwitch(app_manager.RyuApp):
    _CONTEXTS = {"wsgi": WSGIApplication}
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(SimpleSwitchController, {myapp_name: self})

        self.mac_to_port = {}

        self.segments: dict[str, Union[list[str], Datapath]] = {}

        self.permissions = []

        self.switches: dict[str, Datapath] = {}


    def add_flow(
        self,
        datapath: Datapath,
        match: ofproto_v1_3_parser.OFPMatch,
        actions: ofproto_v1_3_parser.OFPAction,
        priority: int,
        buffer_id=None,
    ):
        protocol_constants: ofproto_v1_3 = datapath.ofproto
        protocol_parser: ofproto_v1_3_parser = datapath.ofproto_parser

        instructions: list[protocol_parser.OFPInstructionActions] = [
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
            )
        else:
            mod: ofproto_v1_3_parser.OFPFlowMod = protocol_parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
            )
        datapath.send_msg(mod)


    def del_flow(
        self, datapath: Datapath, in_port: int, eth_dst: str, priority: int
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
            priority=priority,
            match=match,
        )
        datapath.send_msg(mod)


    def get_segment_by_mac_address(self, mac_address: str) -> Union[str, None]:
        for segment, mac_addresses in self.segments.items():
            if mac_address in mac_addresses:
                return segment

        return None


    def allowed_to_talk(self, first, second) -> bool:
        for permission in self.permissions:
            if first in permission and second in permission:
                return True
        return False


    def find_port_datapath_by_mac(self, mac_address) -> Union[Datapath, int]:
        for _, mac_port in self.mac_to_port.items():
            for mac, port in mac_port.items():
                if mac == mac_address:
                    return mac_port["datapath"], port

    def create_set_sorted(item_a, item_b):
        return set([item_a, item_b].sort())


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

        src_segment: str = self.get_segment_by_mac_address(mac_address=src)
        dst_segment: str = self.get_segment_by_mac_address(mac_address=dst)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[datapathid][src] = in_port

        if dst in self.mac_to_port[datapathid]:
            out_port = self.mac_to_port[datapathid][dst]
        else:
            out_port = protocol_constants.OFPP_FLOOD

        actions: list[protocol_parser.OFPActionOutput] = [
            protocol_parser.OFPActionOutput(out_port)
        ]

        # install a flow to avoid packet_in next time
        if out_port != protocol_constants.OFPP_FLOOD:
            added_rule = False
            if self.allowed_to_talk(src_segment, dst_segment):
                match: ofproto_v1_3_parser.OFPMatch = protocol_parser.OFPMatch(
                    in_port=in_port, eth_dst=dst
                )
                if msg.buffer_id != protocol_constants.OFP_NO_BUFFER:
                    self.add_flow(
                        datapath=datapath,
                        match=match,
                        actions=actions,
                        buffer_id=msg.buffer_id,
                        priority=DEFAULT_PRIORITY,
                    )
                else:
                    self.add_flow(
                        datapath, match, actions, priority=DEFAULT_PRIORITY
                    )
                added_rule = True

            # compare hosts
            if self.allowed_to_talk(src, dst):
                match: ofproto_v1_3_parser.OFPMatch = protocol_parser.OFPMatch(
                    in_port=in_port, eth_dst=dst
                )
                if msg.buffer_id != protocol_constants.OFP_NO_BUFFER:
                    self.add_flow(
                        datapath=datapath,
                        match=match,
                        actions=actions,
                        buffer_id=msg.buffer_id,
                        priority=DEFAULT_PRIORITY,
                    )
                else:
                    self.add_flow(
                        datapath=datapath,
                        match=match,
                        actions=actions,
                        priority=DEFAULT_PRIORITY
                    )
                added_rule = True

            if not added_rule:
                return

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


class SimpleSwitchController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_app: SimpleSwitch = data[myapp_name]


    def del_host_rule(self, mac_address_a, mac_address_b, priority):
        try:
            datapath, port = self.simple_switch_app.find_port_datapath_by_mac(
                mac_address_a
            )

            self.simple_switch_app.del_flow(
                datapath=datapath,
                in_port=port,
                eth_dst=mac_address_b,
                priority=priority,
            )

            datapath, port = self.simple_switch_app.find_port_datapath_by_mac(
                mac_address_b
            )
            self.simple_switch_app.del_flow(
                datapath=datapath,
                in_port=port,
                eth_dst=mac_address_a,
                priority=priority,
            )
        except ValueError:
            pass


    @route(myapp_name, "/nac/segmentos/", methods=["POST"])
    def add_segments(self, req, **kwargs):
        new_segments = req.json
        segments = self.simple_switch_app.segments

        for segment_name, mac_addresses in new_segments.items():
            if segments.get(segment_name):
                segments[segment_name] = list(
                    set(segments[segment_name] + mac_addresses)
                )
            else:
                self.simple_switch_app.segments[segment_name] = mac_addresses
        return Response(status=204)


    @route(myapp_name, "/nac/segmentos/", methods=["GET"])
    def get_segments(self, req, **kwargs):
        segments = json.dumps(self.simple_switch_app.segments)
        return Response(content_type="application/json", body=segments, status=200)


    @route(myapp_name, "/nac/segmentos/{segment_name}", methods=["DELETE"])
    def remove_segments_by_name(self, req, **kwargs):
        segment_name = kwargs.get("segment_name")
        segments = self.simple_switch_app.segments
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
        segments = self.simple_switch_app.segments
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
        segments = self.simple_switch_app.segments
        if segment_name in segments.keys():
            segment = segments.get(segment_name)
            if mac_address in segment:
                segment.remove(mac_address)

                return Response(status=204)
        return Response(status=404)


    @route(myapp_name, "/nac/controle/", methods=["POST"])
    def access_control(self, req, **kwargs):
        rule_json = req.json
        if rule_json.get("segmento_a"):
            if rule_json.get("acao") == "permitir":
                rule = sorted(
                    [rule_json.get("segmento_a"), rule_json.get("segmento_b")]
                )
                if rule not in self.simple_switch_app.permissions:
                    self.simple_switch_app.permissions.append(rule)
            if rule_json.get("acao") == "bloquear":
                rule = sorted(
                    [rule_json.get("segmento_a"), rule_json.get("segmento_b")]
                )
                if rule in self.simple_switch_app.permissions:
                    self.simple_switch_app.permissions.remove(rule)

                segments = self.simple_switch_app.segments
                segment_a = segments.get(rule_json.get("segmento_a"))
                segment_b = segments.get(rule_json.get("segmento_b"))

                [
                    self.del_host_rule(
                        mac_address_a=mac_address_a,
                        mac_address_b=mac_address_b,
                        priority=DEFAULT_PRIORITY,
                    )
                    for mac_address_a in segment_a
                    for mac_address_b in segment_b
                ]
        elif rule_json.get("host_a"):
            if rule_json.get("acao") == "permitir":
                rule = sorted([rule_json.get("host_a"), rule_json.get("host_b")])
                if rule not in self.simple_switch_app.permissions:
                    self.simple_switch_app.permissions.append(rule)
            elif rule_json.get("acao") == "bloquear":
                rule = sorted([rule_json.get("host_a"), rule_json.get("host_b")])
                if rule in self.simple_switch_app.permissions:
                    self.simple_switch_app.permissions.remove(rule)
                self.del_host_rule(
                    mac_address_a=rule_json.get("host_a"),
                    mac_address_b=rule_json.get("host_b"),
                    priority=DEFAULT_PRIORITY,
                )
