#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/ethernet-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/tcp-header.h"

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("SynchrophasorTap");

static void
SnifferCallback(Ptr<NetDevice> egressDev, Ptr<const Packet> pkt)
{
  if (!pkt) return;
  Ptr<Packet> p=pkt->Copy();
  EthernetHeader eth;
  if (!p->PeekHeader(eth)) return;
  
  uint16_t etherType=eth.GetLengthType();
  Mac48Address sMac=eth.GetSource();
  Mac48Address dMac=eth.GetDestination();

  cout <<"[RX] len="<<dec<<pkt->GetSize()
       <<" | eth=0x"<<hex<<etherType
       <<" | src="<<sMac
       <<" | dst="<<dMac;

  if (etherType==0x0800) // IPv4
  {
    p->RemoveHeader(eth);
    Ipv4Header ip;
    if (p->PeekHeader(ip))
    {
      cout <<" | ip=" <<ip.GetSource()<<"->"<<ip.GetDestination();
      if (ip.GetProtocol()==6)
      {
        p->RemoveHeader(ip);
        TcpHeader th;
        if (p->PeekHeader(th))
        {
          cout<<" | tcp="<<th.GetSourcePort()
              <<"->"<<th.GetDestinationPort();
        }
      }
    }
  }
  cout<<endl;


  // Forward to tap01 (EtherType IPv4 by default
  bool ok=egressDev->Send(p,dMac,0x0800);
  cout <<"[->] Forwarded to tap01 (" << (ok ? "OK" : "FAIL") << ")" << endl;
}

int main(int argc, char *argv[])
{
  GlobalValue::Bind("SimulatorImplementationType", StringValue("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));
  LogComponentEnable("SynchrophasorTap", LOG_LEVEL_INFO);

  NodeContainer nodes;
  nodes.Create(2);

  CsmaHelper csma;
  NetDeviceContainer devs=csma.Install(nodes);

  Ptr<NetDevice> ingressDev=devs.Get(0);
  Ptr<NetDevice> egressDev=devs.Get(1);

  TapBridgeHelper tap0;
  tap0.SetAttribute("Mode", StringValue("UseLocal"));
  tap0.SetAttribute("DeviceName",StringValue("tap00"));
  tap0.Install(nodes.Get(0),ingressDev);

  TapBridgeHelper tap1;
  tap1.SetAttribute("Mode",StringValue("UseLocal"));
  tap1.SetAttribute("DeviceName",StringValue("tap01"));
  tap1.Install(nodes.Get(1),egressDev);

  ingressDev->TraceConnectWithoutContext(
      "PromiscSnifferRx",
      MakeBoundCallback(&SnifferCallback, egressDev));

  cout<<"[ns3 main] Bridge active: tap00->n0->n1->tap01" << endl;
  cout.flush();

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
