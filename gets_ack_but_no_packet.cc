/*
 * rtds-Tap-ICS-Mod-One_Net.cc
 *
 * Realtime inline classifier for PMU TCP flows:
 *   tap00 (GTNET ingress) -> n0 (classifier)
 *   -> n{1,2,4,5} (internal PMU group nodes)
 *   -> n3 (attacker app + inspector)
 *   -> n6 (egress) -> tap01 (openHistorian side)
 *
 * Simplified version:
 *   - VLAN handling removed
 *   - Explicit real IP/MAC for GTNET and openHistorian
 */

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ethernet-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/tcp-header.h"
#include "ns3/attack-app.h"

using namespace ns3;
using std::cout;
using std::endl;

NS_LOG_COMPONENT_DEFINE("RTDS-Tap-PMU-IDCODE-Debug");

// ---------------------------------------------------------------------------
// Global containers
// ---------------------------------------------------------------------------
static NodeContainer g_nodes;
static NetDeviceContainer g_devs;

// ---------------------------------------------------------------------------
// Real-world addresses (for clarity and debugging)
// ---------------------------------------------------------------------------
static const Ipv4Address kOpenHistIp ("10.201.7.40");
static const Ipv4Address kGtNetIp    ("10.201.7.169");
static const Mac48Address kOpenHistMac ("04:0e:3c:25:54:40");
static const Mac48Address kGtNetMac    ("70:b3:d5:54:22:1b");

// ---------------------------------------------------------------------------
// PMU port and ID helpers
// ---------------------------------------------------------------------------
static inline bool InPmuPortRange(uint16_t p) { return p >= 5022 && p <= 5036; }
static inline int PortToPmuId(uint16_t p) { return static_cast<int>(p) - 5020; }

static int MapIdcodeToNodeIndex(uint16_t idcode)
{
  if (idcode >=  2 && idcode <=  5) return 1; // n1
  if (idcode >=  7 && idcode <= 10) return 2; // n2
  if (idcode >= 11 && idcode <= 13) return 4; // n4
  if (idcode >= 14 && idcode <= 16) return 5; // n5
  return -1;
}

static int MapTcpPortsToInternalNode(uint16_t sport, uint16_t dport)
{
  if (InPmuPortRange(dport)) return MapIdcodeToNodeIndex(PortToPmuId(dport));
  if (InPmuPortRange(sport)) return MapIdcodeToNodeIndex(PortToPmuId(sport));
  return -1;
}

// ---------------------------------------------------------------------------
// PMU header parser
// ---------------------------------------------------------------------------
struct PmuHeader {
  uint16_t sync;
  uint16_t frameSize;
  uint16_t idcode;
  uint32_t soc;
  uint32_t fracsec;
};

static bool ParsePmuHeader(Ptr<Packet> pktAfterTcp, PmuHeader &h)
{
  const size_t NEED = 14;
  if (pktAfterTcp->GetSize() < NEED) return false;
  std::vector<uint8_t> b(NEED);
  pktAfterTcp->CopyData(b.data(), NEED);
  h.sync      = (uint16_t)((b[0] << 8) | b[1]);
  h.frameSize = (uint16_t)((b[2] << 8) | b[3]);
  h.idcode    = (uint16_t)((b[4] << 8) | b[5]);
  h.soc       = ((uint32_t)b[6] << 24) | ((uint32_t)b[7] << 16) | ((uint32_t)b[8] << 8) | (uint32_t)b[9];
  h.fracsec   = ((uint32_t)b[10] << 24) | ((uint32_t)b[11] << 16) | ((uint32_t)b[12] << 8) | (uint32_t)b[13];
  return true;
}

static std::string PmuHeaderToString(const PmuHeader &h)
{
  std::ostringstream oss;
  oss << std::hex << "SYNC=0x" << std::setw(4) << std::setfill('0') << h.sync
      << std::dec << " IDCODE=" << h.idcode
      << " Frame=" << h.frameSize
      << " SOC=" << h.soc
      << " FRAC=" << h.fracsec;
  return oss.str();
}

// ---------------------------------------------------------------------------
// Ethernet frame sender helper
// ---------------------------------------------------------------------------
static bool SendWithNewDst(Ptr<NetDevice> outDev,
                           Ptr<const Packet> original,
                           const Mac48Address &newDst,
                           uint16_t etherType,
                           const Mac48Address *forceSrc = nullptr)
{
  Ptr<Packet> tx = original->Copy();
  EthernetHeader oldEth;
  if (tx->PeekHeader(oldEth)) tx->RemoveHeader(oldEth);
  EthernetHeader newEth;
  newEth.SetLengthType(etherType);
  newEth.SetDestination(newDst);
  newEth.SetSource(forceSrc ? *forceSrc : Mac48Address::ConvertFrom(outDev->GetAddress()));
  tx->AddHeader(newEth);
  return outDev->Send(tx, newDst, etherType);
}

// ---------------------------------------------------------------------------
// n0: Ingress classifier
// ---------------------------------------------------------------------------
static bool
N0Classifier(Ptr<NetDevice> dev,
             Ptr<const Packet> pktConst,
             uint16_t /*proto*/,
             const Address &src,
             const Address &dst,
             NetDevice::PacketType /*ptype*/)
{
  cout << "[n0] pktSize=" << pktConst->GetSize()
       << " src=" << src << " dst=" << dst << endl;

  Ptr<Packet> pktParse = pktConst->Copy();
  EthernetHeader eth;
  if (!pktParse->PeekHeader(eth)) return true;
  uint16_t etherType = eth.GetLengthType();
  if (etherType != 0x0800) return true;
  pktParse->RemoveHeader(eth);

  Ipv4Header ip;
  if (!pktParse->PeekHeader(ip)) return true;
  if (ip.GetProtocol() != 6) return true;
  pktParse->RemoveHeader(ip);

  TcpHeader tcp;
  if (!pktParse->PeekHeader(tcp)) return true;
  uint16_t sport = tcp.GetSourcePort();
  uint16_t dport = tcp.GetDestinationPort();

  cout << "[n0] IPv4 " << ip.GetSource() << ":" << sport
       << " -> " << ip.GetDestination() << ":" << dport << endl;

  // Identify traffic endpoints
  if (ip.GetSource() == kGtNetIp || ip.GetDestination() == kGtNetIp)
    cout << "[n0] ↳ GTNET traffic" << endl;
  if (ip.GetSource() == kOpenHistIp || ip.GetDestination() == kOpenHistIp)
    cout << "[n0] ↳ openHistorian traffic" << endl;

  int internalIdx = MapTcpPortsToInternalNode(sport, dport);
  if (internalIdx < 0) {
    cout << "[n0] non-PMU TCP flow, letting pass" << endl;
    return true;
  }

  pktParse->RemoveHeader(tcp);
  PmuHeader pmu;
  if (ParsePmuHeader(pktParse, pmu))
    cout << "[n0] PMU " << PmuHeaderToString(pmu)
         << " -> n" << internalIdx << endl;
  else
    cout << "[n0] (no payload yet) -> n" << internalIdx << endl;

  Ptr<NetDevice> internalDev = g_devs.Get((uint32_t)internalIdx);
  Mac48Address dstMac = Mac48Address::ConvertFrom(internalDev->GetAddress());
  bool ok = SendWithNewDst(dev, pktConst, dstMac, 0x0800);
  cout << "[n0] -> n" << internalIdx << " mac=" << dstMac << " ok=" << ok << endl;
  return false;
}

// ---------------------------------------------------------------------------
// Internal forwarders: n1,n2,n4,n5 -> n3 (attacker)
// ---------------------------------------------------------------------------
static bool
InternalForwarder(Ptr<NetDevice> dev,
                  Ptr<const Packet> pktConst,
                  uint16_t /*proto*/,
                  const Address &src,
                  const Address &dst,
                  NetDevice::PacketType /*ptype*/)
{
  Address my = dev->GetAddress();
  if (dst != my) return true;

  uint32_t myIdx = 0;
  for (uint32_t i = 0; i < g_devs.GetN(); ++i)
    if (g_devs.Get(i) == dev) { myIdx = i; break; }

  cout << "[n" << myIdx << "] got frame for me -> forwarding to attacker n3" << endl;

  Ptr<NetDevice> attackerDev = g_devs.Get(3);
  Mac48Address attackerMac = Mac48Address::ConvertFrom(attackerDev->GetAddress());
  uint16_t etherType = 0x0800;
  EthernetHeader eth;
  if (pktConst->PeekHeader(eth)) etherType = eth.GetLengthType();
  Mac48Address myMac = Mac48Address::ConvertFrom(my);

  bool ok = SendWithNewDst(dev, pktConst, attackerMac, etherType, &myMac);
  cout << "[n" << myIdx << "] -> n3 mac=" << attackerMac << " ok=" << ok << endl;
  return false;
}

// ---------------------------------------------------------------------------
// n3: Attacker node -> inspects and forwards to n6
// ---------------------------------------------------------------------------
static bool
AttackerForwarder(Ptr<NetDevice> dev,
                  Ptr<const Packet> pktConst,
                  uint16_t /*proto*/,
                  const Address &src,
                  const Address &dst,
                  NetDevice::PacketType /*ptype*/)
{
  if (dst != dev->GetAddress()) return true;

  Ptr<Packet> p = pktConst->Copy();
  EthernetHeader eth;
  if (!p->PeekHeader(eth)) return true;
  uint16_t etherType = eth.GetLengthType();

  if (etherType == 0x0800) {
    p->RemoveHeader(eth);
    Ipv4Header ip;
    if (p->PeekHeader(ip)) {
      p->RemoveHeader(ip);
      if (ip.GetProtocol() == 6) {
        TcpHeader tcp;
        if (p->PeekHeader(tcp)) {
          p->RemoveHeader(tcp);
          PmuHeader pmu;
          if (ParsePmuHeader(p, pmu))
            cout << "[n3] saw PMU " << PmuHeaderToString(pmu) << endl;
        }
      }
    }
  }

  Ptr<NetDevice> egressDev = g_devs.Get(6);
  Mac48Address egressMac = Mac48Address::ConvertFrom(egressDev->GetAddress());
  bool ok = SendWithNewDst(dev, pktConst, egressMac, etherType);
  cout << "[n3] -> n6 mac=" << egressMac << " ok=" << ok << endl;
  return false;
}

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
  GlobalValue::Bind("SimulatorImplementationType", StringValue("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

  g_nodes.Create(7);

  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
  csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));
  g_devs = csma.Install(g_nodes);

  InternetStackHelper stack; stack.Install(g_nodes);
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.201.0.0", "255.255.248.0");
  Ipv4InterfaceContainer ifaces = ipv4.Assign(g_devs);
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // --- Tap bridges ---
  TapBridgeHelper tap;
  tap.SetAttribute("Mode", StringValue("UseLocal"));
  tap.SetAttribute("DeviceName", StringValue("tap00"));
  tap.Install(g_nodes.Get(0), g_devs.Get(0));   // ingress (GTNET)

  tap.SetAttribute("DeviceName", StringValue("tap01"));
  tap.Install(g_nodes.Get(6), g_devs.Get(6));   // egress (openHistorian)

  // --- Attacker app setup (n3) ---
  uint32_t attackerId = 3;
  std::pair<Ptr<Ipv4>, uint32_t> ret = ifaces.Get(attackerId);
  Ptr<Ipv4> ipv4Obj = ret.first;
  uint32_t ifaceIndex = ret.second;
  Ptr<Ipv4Interface> ipIface = ipv4Obj->GetObject<Ipv4L3Protocol>()->GetInterface(ifaceIndex);

  Ptr<AttackApp> attacker = CreateObject<AttackApp>();
  std::vector<Ipv4Address> spoof { kOpenHistIp };   // openHistorian
  std::vector<Ipv4Address> victims { kGtNetIp };    // GTNET
  std::vector<Address> vicMacs { kGtNetMac };
  attacker->Setup(g_nodes.Get(attackerId), g_devs.Get(attackerId), ipIface, spoof, victims, vicMacs);
  g_nodes.Get(attackerId)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(1.0));
  attacker->SetStopTime(Seconds(3600.0));

  // --- Register callbacks ---
  g_devs.Get(0)->SetPromiscReceiveCallback(MakeCallback(&N0Classifier)); // n0
  g_devs.Get(1)->SetPromiscReceiveCallback(MakeCallback(&InternalForwarder)); // n1
  g_devs.Get(2)->SetPromiscReceiveCallback(MakeCallback(&InternalForwarder)); // n2
  g_devs.Get(4)->SetPromiscReceiveCallback(MakeCallback(&InternalForwarder)); // n4
  g_devs.Get(5)->SetPromiscReceiveCallback(MakeCallback(&InternalForwarder)); // n5
  g_devs.Get(3)->SetPromiscReceiveCallback(MakeCallback(&AttackerForwarder)); // n3

  // --- Diagnostics ---
  csma.EnablePcapAll("pmu_pcap_debug", false);
  LogComponentEnable("RTDS-Tap-PMU-IDCODE-Debug", LOG_LEVEL_INFO);
  LogComponentEnable("AttackApp", LOG_LEVEL_INFO);

  Simulator::Stop(Seconds(3600.0));
  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
