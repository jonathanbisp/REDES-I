import json

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.lib import dpid as dpid_lib

myapp_name = "simpleswitch"

DEFAULT_PRIORITY_HOST = 100
DEFAULT_PRIORITY_SEGMENT = 1000


class SimpleSwitch(app_manager.RyuApp):
    _CONTEXTS = {"wsgi": WSGIApplication}
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(SimpleSwitchController, {myapp_name: self})

        self.mac_to_port = {}

        self.segments = {}

        self.permissions = []

    def find_port_datapath_by_mac(self, mac_address):
        for _, mac_port in self.mac_to_port.items():
            for mac, port in mac_port.items():
                if mac == mac_address:
                    return mac_port["datapath"], port

    def add_flow(self, datapath, match, actions, priority, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    def del_flow(self, datapath, in_port, eth_dst, priority):
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=priority,
            match=match,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, match, actions, priority=0)

    def get_segment_by_mac_address(self, mac_address: str) -> str:
        for segment, mac_addresses in self.segments.items():
            if mac_address in mac_addresses:
                return segment

        return None

    def allowed_to_talk(self, first, second):
        for permission in self.permissions:
            if first in permission and second in permission:
                return True
        return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg

        msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {"datapath": dp})

        src_segment = self.get_segment_by_mac_address(mac_address=src)
        dst_segment = self.get_segment_by_mac_address(mac_address=dst)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [ofp_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofp.OFPP_FLOOD:

            added_rule = False
            if self.allowed_to_talk(src_segment, dst_segment):
                match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    self.add_flow(
                        dp,
                        match,
                        actions,
                        buffer_id=msg.buffer_id,
                        priority=DEFAULT_PRIORITY_SEGMENT,
                    )
                else:
                    self.add_flow(dp, match, actions, priority=DEFAULT_PRIORITY_SEGMENT)
                added_rule = True

            # compare hosts
            if self.allowed_to_talk(src, dst):
                match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    self.add_flow(
                        dp,
                        match,
                        actions,
                        buffer_id=msg.buffer_id,
                        priority=DEFAULT_PRIORITY_HOST,
                    )
                else:
                    self.add_flow(dp, match, actions, priority=DEFAULT_PRIORITY_HOST)
                added_rule = True

            if not added_rule:
                return

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        dp.send_msg(out)


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

    @route(myapp_name, "/nac/mactable/{dpid}", methods=["GET"])
    def list_mac_table(self, req, **kwargs):
        dpid = dpid_lib.str_to_dpid(kwargs.get("dpid"))

        if dpid not in self.simple_switch_app.mac_to_port:
            return Response(status=404)

        mac_table = self.simple_switch_app.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type="application/json", body=body)

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
                        priority=DEFAULT_PRIORITY_SEGMENT,
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
                    priority=DEFAULT_PRIORITY_HOST,
                )
