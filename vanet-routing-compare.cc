#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/config-store-module.h"
#include "ns3/core-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/integer.h"
#include "ns3/internet-module.h"
#include "ns3/itu-r-1411-los-propagation-loss-model.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/ocb-wifi-mac.h"
#include "ns3/olsr-module.h"
#include "ns3/wave-bsm-helper.h"
#include "ns3/wave-helper.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/point-to-point-module.h"
#include <fstream>
#include <cstdio> // For popen
#include <memory> // For pope
#include "ns3/loopback-net-device.h"
#include <iostream>


#include "ns3/olsr-module.h"
using namespace ns3;
using namespace dsr;
NS_LOG_COMPONENT_DEFINE("vanet-routing-compare");
// vvv ADD THIS FUNCTION PROTOTYPE HERE vvv
std::map<uint32_t, std::string> nodePrivateKeys = {
    {0, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"},
    {1, "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"},
    {2, "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"},
    {3, "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"},
    {4, "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"},
    {5, "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"},
    {6, "0x92db14e403b83dfe36c923d6a7b3a114febaf7b55594660db7f3a5f4d24a5444"},
    {7, "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"},
    {8, "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"},
    {9, "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"}
    // ... Add more keys as needed for all your nodes ...
};
   // Place this function after your executeCommand function

void ReadKeysFromFile(const std::string& filename, std::map<uint32_t, std::string>& keyMap)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        NS_LOG_ERROR("Could not open keys file: " << filename);
        return;
    }

    std::string line;
    // Clear the map to ensure we only have keys from the file
    keyMap.clear();

    while (std::getline(file, line))
    {
        std::stringstream ss(line);
        std::string id_str, pk_str, addr_str, ip_str;

        // Assumes format: ID,PrivateKey,EthAddress,IPAddress
        if (std::getline(ss, id_str, ',') &&
            std::getline(ss, pk_str, ',') &&
            std::getline(ss, addr_str, ',') &&
            std::getline(ss, ip_str, ','))
        {
            try
            {
                uint32_t nodeId = std::stoul(id_str);
                keyMap[nodeId] = pk_str;
            }
            catch (const std::exception& e)
            {
                NS_LOG_WARN("Error parsing line in keys file: " << line);
            }
        }
    }
    file.close();
    NS_LOG_UNCOND("Loaded " << keyMap.size() << " private keys from " << filename);
}






// Function to execute a shell command and get the output
std::string executeCommand(const char* cmd) {
    std::string result = "";
    char buffer[128];
    // Use popen() for Linux/Unix systems
    FILE* pipe = popen(cmd, "r");

    if (!pipe) {
        return "Error: popen failed.";
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    // Use pclose() for Linux/Unix systems
    pclose(pipe);
    return result;
}

void PrintNodeRoutingTable(Ptr<Node> node, Ptr<OutputStreamWrapper> rtw);
/**
 * \ingroup wave
 * \brief The RoutingStats class manages collects statistics
 * on routing data (application-data packet and byte counts)
 * for the vehicular network
 */
class RoutingStats
{
 public:
    /**
     * \brief Constructor
     */
    RoutingStats();
    /**
     * \brief Returns the number of bytes received
     * \return the number of bytes received
     */
    uint32_t GetRxBytes() const;
    /**
     * \brief Returns the cumulative number of bytes received
     * \return the cumulative number of bytes received
     */
    uint32_t GetCumulativeRxBytes() const;
    /**
     * \brief Returns the count of packets received
     * \return the count of packets received
     */
    uint32_t GetRxPkts() const;
    /**
     * \brief Returns the cumulative count of packets received
     * \return the cumulative count of packets received
     */
    uint32_t GetCumulativeRxPkts() const;
    /**
     * \brief Increments the number of (application-data)
     * bytes received, not including MAC/PHY overhead
     * \param rxBytes the number of bytes received
     */
    void IncRxBytes(uint32_t rxBytes);
    /**
     * \brief Increments the count of packets received
     */
    void IncRxPkts();
    /**
     * \brief Sets the number of bytes received.
     * \param rxBytes the number of bytes received
     */
    void SetRxBytes(uint32_t rxBytes);
    /**
     * \brief Sets the number of packets received
     * \param rxPkts the number of packets received
     */
    void SetRxPkts(uint32_t rxPkts);
    /**
     * \brief Returns the number of bytes transmitted
     * \return the number of bytes transmitted
     */
    uint32_t GetTxBytes() const;
    /**
     * \brief Returns the cumulative number of bytes transmitted
     * \return the cumulative number of bytes transmitted
     */
    uint32_t GetCumulativeTxBytes() const;
    /**
     * \brief Returns the number of packets transmitted
     * \return the number of packets transmitted
     */
    uint32_t GetTxPkts() const;
    /**
     * \brief Returns the cumulative number of packets transmitted
     * \return the cumulative number of packets transmitted
     */
    uint32_t GetCumulativeTxPkts() const;
    /**
     * \brief Increment the number of bytes transmitted
     * \param txBytes the number of additional bytes transmitted
     */
    void IncTxBytes(uint32_t txBytes);
    /**
     * \brief Increment the count of packets transmitted
     */
    void IncTxPkts();
    /**
     * \brief Sets the number of bytes transmitted
     * \param txBytes the number of bytes transmitted
     */
    void SetTxBytes(uint32_t txBytes);
    /**
     * \brief Sets the number of packets transmitted
     * \param txPkts the number of packets transmitted
     */
    void SetTxPkts(uint32_t txPkts);
 private:
    uint32_t m_RxBytes;         ///< receive bytes
    uint32_t m_cumulativeRxBytes; ///< cumulative receive bytes
    uint32_t m_RxPkts;            ///< receive packets
    uint32_t m_cumulativeRxPkts; ///< cumulative receive packets
    uint32_t m_TxBytes;         ///< transmit bytes
    uint32_t m_cumulativeTxBytes; ///< cumulative transmit bytes
    uint32_t m_TxPkts;            ///< transmit packets
    uint32_t m_cumulativeTxPkts; ///< cumulative transmit packets
};
RoutingStats::RoutingStats()
    : m_RxBytes(0),
     m_cumulativeRxBytes(0),
     m_RxPkts(0),
     m_cumulativeRxPkts(0),
     m_TxBytes(0),
     m_cumulativeTxBytes(0),
     m_TxPkts(0),
     m_cumulativeTxPkts(0)
{
}
uint32_t
RoutingStats::GetRxBytes() const
{
    return m_RxBytes;
}
uint32_t
RoutingStats::GetCumulativeRxBytes() const
{
    return m_cumulativeRxBytes;
}
uint32_t
RoutingStats::GetRxPkts() const
{
    return m_RxPkts;
}
uint32_t
RoutingStats::GetCumulativeRxPkts() const
{
    return m_cumulativeRxPkts;
}
void
RoutingStats::IncRxBytes(uint32_t rxBytes)
{
    m_RxBytes += rxBytes;
    m_cumulativeRxBytes += rxBytes;
}
void
RoutingStats::IncRxPkts()
{
    m_RxPkts++;
    m_cumulativeRxPkts++;
}
void
RoutingStats::SetRxBytes(uint32_t rxBytes)
{
    m_RxBytes = rxBytes;
}
void
RoutingStats::SetRxPkts(uint32_t rxPkts)
{
    m_RxPkts = rxPkts;
}
uint32_t
RoutingStats::GetTxBytes() const
{
    return m_TxBytes;
}
uint32_t
RoutingStats::GetCumulativeTxBytes() const
{
    return m_cumulativeTxBytes;
}
uint32_t
RoutingStats::GetTxPkts() const
{
    return m_TxPkts;
}
uint32_t
RoutingStats::GetCumulativeTxPkts() const
{
    return m_cumulativeTxPkts;
}
void
RoutingStats::IncTxBytes(uint32_t txBytes)
{
    m_TxBytes += txBytes;
    m_cumulativeTxBytes += txBytes;
}
void
RoutingStats::IncTxPkts()
{
    m_TxPkts++;
    m_cumulativeTxPkts++;
}
void
RoutingStats::SetTxBytes(uint32_t txBytes)
{
    m_TxBytes = txBytes;
}
void
RoutingStats::SetTxPkts(uint32_t txPkts)
{
    m_TxPkts = txPkts;
}
/**
 * \ingroup wave
 * \brief The RoutingHelper class generates routing data between
 * nodes (vehicles) and uses the RoutingStats class to collect statistics
 * on routing data (application-data packet and byte counts).
 * A routing protocol is configured, and all nodes attempt to send
 * (i.e. route) small packets to another node, which acts as
 * data sinks. Not all nodes act as data sinks.
 * for the vehicular network
 */
class RoutingHelper : public Object
{
 public:
    Ptr<Socket> SetupRoutingPacketReceive(Ipv4Address addr, Ptr<Node> node);
    /**
     * \brief Get class TypeId
     * \return the TypeId for the class
     */
    static TypeId GetTypeId();
    /**
     * \brief Constructor
     */
    RoutingHelper();
    /**
     * \brief Destructor
     */
    ~RoutingHelper() override;
    /**
     * \brief Installs routing functionality on nodes and their
     * devices and interfaces.
     * \param c node container
     * \param d net device container
     * \param i IPv4 interface container
     * \param totalTime the total time that nodes should attempt to
     * route data
     * \param protocol the routing protocol (1=OLSR;2=AODV;3=DSDV;4=DSR)
     * \param nSinks the number of nodes which will act as data sinks
     * \param routingTables whether to dump routing tables at t=5 seconds
     */
    void Install(NodeContainer& vehicles,
                 NodeContainer& rsus,
                 NetDeviceContainer& d,
                 NetDeviceContainer& rsudev,
                 Ipv4InterfaceContainer& i,
                 double totalTime,
                 int protocol,
                 uint32_t nSinks,
                 bool routingTables);
    /**
     * \brief Trace the receipt of an on-off-application generated packet
     * \param context this object
     * \param packet a received packet
     */
    void OnOffTrace(std::string context, Ptr<const Packet> packet);
    /**
     * \brief Returns the RoutingStats instance
     * \return the RoutingStats instance
     */
    RoutingStats& GetRoutingStats();
    /**
     * \brief Enable/disable logging
     * \param log whether to enable logging
     */
    void SetLogging(bool log);
 private:
 
    /**
     * \brief Sets up the protocol protocol on the nodes
     * \param c node container
     */
    void SetupRoutingProtocol(NodeContainer& vehicles);
    /**
     * \brief Assigns IPv4 addresses to net devices and their interfaces
     * \param d net device container
     * \param adhocTxInterfaces IPv4 interface container
     */
    void AssignIpAddresses(NetDeviceContainer& d, Ipv4InterfaceContainer& adhocTxInterfaces);
    /**
     * \brief Sets up routing messages on the nodes and their interfaces
     * \param c node container
     * \param adhocTxInterfaces IPv4 interface container
     */
    void SetupRoutingMessages(NodeContainer& c, Ipv4InterfaceContainer& adhocTxInterfaces);
 
    /**
     * \brief Sets up a routing packet for transmission
     * \param addr destination address
     * \param node source node
     * \return Socket to be used for sending/receiving a routed data packet
     */
    /**
     * \brief Process a received routing packet
     * \param socket the receiving socket
     */
    void ReceiveRoutingPacket(Ptr<Socket> socket);

    double m_TotalSimTime;     ///< seconds
    uint32_t m_protocol;        ///< routing protocol; 0=NONE, 1=OLSR, 2=AODV, 3=DSDV, 4=DSR
    uint32_t m_port;            ///< port
    uint32_t m_nSinks;         ///< number of sink nodes (< all nodes)
    bool m_routingTables;     ///< dump routing table (at t=5 sec). 0=No, 1=Yes
    RoutingStats routingStats; ///< routing statistics
    std::string m_protocolName; ///< protocol name
    bool m_log;                 ///< log
};
NS_OBJECT_ENSURE_REGISTERED(RoutingHelper);
TypeId
RoutingHelper::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::RoutingHelper").SetParent<Object>().AddConstructor<RoutingHelper>();
    return tid;
}
RoutingHelper::RoutingHelper()
    : m_TotalSimTime(300.01),
     m_protocol(0),
     m_port(9),
     m_nSinks(2),
     m_routingTables(true),
     m_log(false)
{
}
RoutingHelper::~RoutingHelper()
{
}
void
RoutingHelper::Install(NodeContainer& vehicles,
                     NodeContainer& rsus,
                     NetDeviceContainer& d,
                     NetDeviceContainer& rsudev,
                     Ipv4InterfaceContainer& i,
                     double totalTime,
                     int protocol,
                     uint32_t nSinks,
                     bool routingTables)
{
    m_TotalSimTime = totalTime;
    m_protocol = protocol;
    m_nSinks = nSinks;
    m_routingTables = routingTables;
    NodeContainer allNodes;
    allNodes.Add(rsus);
    allNodes.Add(vehicles);
    NetDeviceContainer allDev;
    allDev.Add(rsudev);
    allDev.Add(d);
 
    SetupRoutingProtocol(allNodes);
    AssignIpAddresses(allDev, i);
    SetupRoutingMessages(allNodes, i);
}
Ptr<Socket>
RoutingHelper::SetupRoutingPacketReceive(Ipv4Address addr, Ptr<Node> node)
{
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sink = Socket::CreateSocket(node, tid);
    InetSocketAddress local = InetSocketAddress(addr, m_port);
    sink->Bind(local);
    sink->SetRecvCallback(MakeCallback(&RoutingHelper::ReceiveRoutingPacket, this));
    return sink;
}

void
RoutingHelper::SetupRoutingProtocol(NodeContainer& vehicles)
{
    AodvHelper aodv;
    OlsrHelper olsr;
    DsdvHelper dsdv;
    DsrHelper dsr;
    DsrMainHelper dsrMain;
    Ipv4ListRoutingHelper list;
    InternetStackHelper internet;
    Time rtt = Time(5.0);
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> rtw = ascii.CreateFileStream("routing_table");
    switch (m_protocol)
    {
    case 0:
        m_protocolName = "NONE";
        break;
    case 1: // OLSR
        if (m_routingTables)
        {
            // *** NEW CODE TO PRINT PERIODICALLY ***
            // Schedule printing every 5 seconds until the simulation ends.
            for (double t = 5.0; t <= m_TotalSimTime; t += 5.0)
            {
                Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(t), rtw);
            }
        }
        list.Add(olsr, 100);
        m_protocolName = "OLSR";
        break;
    case 2: // AODV
        if (m_routingTables)
        {
            // *** NEW CODE TO PRINT PERIODICALLY ***
            for (double t = 5.0; t <= m_TotalSimTime; t += 5.0)
            {
                Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(t), rtw);
            }
        }
        list.Add(aodv, 100);
        m_protocolName = "AODV";
        break;
    case 3: // DSDV
        if (m_routingTables)
        {
            // *** NEW CODE TO PRINT PERIODICALLY ***
            for (double t = 5.0; t <= m_TotalSimTime; t += 5.0)
            {
                ns3::DsdvHelper::PrintRoutingTableAllAt(Seconds(t), rtw);
            }
        }
        list.Add(dsdv, 100);
        m_protocolName = "DSDV";
        break;
    case 4:
        // setup is later
        m_protocolName = "DSR";
        break;
    default:
        NS_FATAL_ERROR("No such protocol:" << m_protocol);
        break;
    }
    if (m_protocol < 4)
    {
        internet.SetRoutingHelper(list);
    }
    else if (m_protocol == 4)
    {
        dsrMain.Install(dsr, vehicles);
    }
    if (m_log)
    {
        NS_LOG_UNCOND("Routing Setup for " << m_protocolName);
    }
}
void
RoutingHelper::AssignIpAddresses(NetDeviceContainer& d, Ipv4InterfaceContainer& adhocTxInterfaces)
{
    NS_LOG_INFO("Assigning IP addresses");
    Ipv4AddressHelper addressAdhoc;
    // we may have a lot of nodes, and want them all
    // in same subnet, to support broadcast
    addressAdhoc.SetBase("10.1.0.0", "255.255.0.0");
    adhocTxInterfaces = addressAdhoc.Assign(d);
 
}





void RoutingHelper::ReceiveRoutingPacket(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from)))
    {
        // This confirms the packet completed its journey and reached the application layer
        NS_LOG_UNCOND("Final sink node received application packet of size " << packet->GetSize() << " bytes.");
        routingStats.IncRxBytes(packet->GetSize());
        routingStats.IncRxPkts();

        // --- MODIFIED LOGIC TO HANDLE PROTOCOL-SPECIFIC TAGS ---

        uint32_t packetId = 0;
        std::string packetSecret = "";
        bool tagFound = false;

        // Check for the tag based on the configured protocol
        // (Assuming m_protocol is a member variable of your RoutingHelper class)
        if (m_protocol == 1) // OLSR
        {
            ns3::olsr::SecretForDestinationTag olsrTag;
            if (packet->PeekPacketTag(olsrTag))
            {
                packetId = olsrTag.GetId();
                packetSecret = olsrTag.GetSecret();
                tagFound = true;
                NS_LOG_INFO("Found OLSR Tag.");
            }
        }
        else if (m_protocol == 2) // AODV
        {
            // Make sure you have included the AODV tag header
            ns3::aodv::SecretForDestinationTag aodvTag;
            if (packet->PeekPacketTag(aodvTag))
            {
                packetId = aodvTag.GetId();
                packetSecret = aodvTag.GetSecret();
                tagFound = true;
                NS_LOG_INFO("Found AODV Tag.");
            }
        }

        // Common logic for blockchain interaction if any tag was found
        if (tagFound)
        {
            NS_LOG_UNCOND("Sink received packet with ID: " << packetId << " and Secret: " << packetSecret);

            // Get the node that owns this socket to find its private key
            Ptr<Node> receivingNode = socket->GetNode();
            uint32_t nodeId = receivingNode->GetId();
            std::string privateKey = nodePrivateKeys[nodeId];

            // Construct and execute the command using the extracted ID and Secret
            std::stringstream receive_cmd;
            receive_cmd << "cast send 0x5FbDB2315678afecb367f032d93F642f64180aa3 "
                        << "\"receivePacket(uint256,bytes32)\" "
                        << packetId << " " << packetSecret
                        << " --private-key " << privateKey
                        << " --rpc-url http://127.0.0.1:8545"; // Always good to specify RPC URL

            NS_LOG_UNCOND("Executing receive command: " << receive_cmd.str());
            std::string receiveOutput = executeCommand(receive_cmd.str().c_str());
            NS_LOG_UNCOND("Receive TX Output: " << receiveOutput);
        }
    }
}


void
RoutingHelper::OnOffTrace(std::string context, Ptr<const Packet> packet)
{
    uint32_t pktBytes = packet->GetSize();
    routingStats.IncTxBytes(pktBytes);
}
RoutingStats&
RoutingHelper::GetRoutingStats()
{
    return routingStats;
}
void
RoutingHelper::SetLogging(bool log)
{
    m_log = log;
}






/**
 * \ingroup wave
 * \brief The WifiPhyStats class collects Wifi MAC/PHY statistics
 */
class WifiPhyStats : public Object
{
 public:
    /**
     * \brief Gets the class TypeId
     * \return the class TypeId
     */
    static TypeId GetTypeId();
    /**
     * \brief Constructor
     */
    WifiPhyStats();
    /**
     * \brief Destructor
     */
    ~WifiPhyStats() override;
    /**
     * \brief Returns the number of bytes that have been transmitted
     * (this includes MAC/PHY overhead)
     * \return the number of bytes transmitted
     */
    uint32_t GetTxBytes() const;
    /**
     * \brief Callback signature for Phy/Tx trace
     * \param context this object
     * \param packet packet transmitted
     * \param mode wifi mode
     * \param preamble wifi preamble
     * \param txPower transmission power
     */
    void PhyTxTrace(std::string context,
                     Ptr<const Packet> packet,
                     WifiMode mode,
                     WifiPreamble preamble,
                     uint8_t txPower);
    /**
     * \brief Callback signature for Phy/TxDrop
     * \param context this object
     * \param packet the tx packet being dropped
     */
    void PhyTxDrop(std::string context, Ptr<const Packet> packet);
    /**
     * \brief Callback signature for Phy/RxDrop
     * \param context this object
     * \param packet the rx packet being dropped
     * \param reason the reason for the drop
     */
    void PhyRxDrop(std::string context, Ptr<const Packet> packet, WifiPhyRxfailureReason reason);
 private:
    uint32_t m_phyTxPkts; ///< phy transmit packets
    uint32_t m_phyTxBytes; ///< phy transmit bytes
};
NS_OBJECT_ENSURE_REGISTERED(WifiPhyStats);
TypeId
WifiPhyStats::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::WifiPhyStats").SetParent<Object>().AddConstructor<WifiPhyStats>();
    return tid;
}
WifiPhyStats::WifiPhyStats()
    : m_phyTxPkts(0),
     m_phyTxBytes(0)
{
}
WifiPhyStats::~WifiPhyStats()
{
}
void
WifiPhyStats::PhyTxTrace(std::string context,
                         Ptr<const Packet> packet,
                         WifiMode mode,
                         WifiPreamble preamble,
                         uint8_t txPower)
{
    NS_LOG_FUNCTION(this << context << packet << "PHYTX mode=" << mode);
    ++m_phyTxPkts;
    uint32_t pktSize = packet->GetSize();
    m_phyTxBytes += pktSize;
     //NS_LOG_UNCOND ("Received PHY size=" << pktSize);
}
void
WifiPhyStats::PhyTxDrop(std::string context, Ptr<const Packet> packet)
{
    NS_LOG_UNCOND("PHY Tx Drop");
}
void
WifiPhyStats::PhyRxDrop(std::string context,
                        Ptr<const Packet> packet,
                        WifiPhyRxfailureReason reason)
{
    //NS_LOG_UNCOND("PHY Rx Drop");
}
uint32_t
WifiPhyStats::GetTxBytes() const
{
    return m_phyTxBytes;
}
/**
 * \ingroup wave
 * \brief The WifiApp class enforces program flow for ns-3 wifi applications
 */
class WifiApp
{
 public:
    /**
     * \brief Constructor
     */
    WifiApp();
    /**
     * \brief Destructor
     */
    virtual ~WifiApp();
    /**
     * \brief Enacts simulation of an ns-3 wifi application
     * \param argc program arguments count
     * \param argv program arguments
     */
    void Simulate(int argc, char** argv);
 protected:
    /**
     * \brief Sets default attribute values
     */
    virtual void SetDefaultAttributeValues();
    /**
     * \brief Process command line arguments
     * \param argc program arguments count
     * \param argv program arguments
     */
    virtual void ParseCommandLineArguments(int argc, char** argv);
    /**
     * \brief Configure nodes
     */
    virtual void ConfigureNodes();
    /**
     * \brief Configure channels
     */
    virtual void ConfigureChannels();
    /**
     * \brief Configure devices
     */
    virtual void ConfigureDevices();
    /**
     * \brief Configure mobility
     */
    virtual void ConfigureMobility();
    /**
     * \brief Configure applications
     */
    virtual void ConfigureApplications();
    /**
     * \brief Configure tracing
     */
    virtual void ConfigureTracing();
    /**
     * \brief Run the simulation
     */
    virtual void RunSimulation();
    /**
     * \brief Process outputs
     */
    virtual void ProcessOutputs();
};
WifiApp::WifiApp()
{
}
WifiApp::~WifiApp()
{
}
void
WifiApp::Simulate(int argc, char** argv)
{
    // Simulator Program Flow:
    // (source: NS-3 Annual Meeting, May, 2014, session 2 slides 6, 28)
    // (HandleProgramInputs:)
    // SetDefaultAttributeValues
    // ParseCommandLineArguments
    // (ConfigureTopology:)
    // ConfigureNodes
    // ConfigureChannels
    // ConfigureDevices
    // ConfigureMobility
    // ConfigureApplications
    //     e.g AddInternetStackToNodes
    //         ConfigureIpAddressingAndRouting
    //         configureSendMessages
    // ConfigureTracing
    // RunSimulation
    // ProcessOutputs
    SetDefaultAttributeValues();
    ParseCommandLineArguments(argc, argv);
    ConfigureNodes();
    ConfigureChannels();
    ConfigureDevices();
    ConfigureMobility();
    ConfigureApplications();
    ConfigureTracing();
    RunSimulation();
    ProcessOutputs();
}
void
WifiApp::SetDefaultAttributeValues()
{
}
void
WifiApp::ParseCommandLineArguments(int argc, char** argv)
{
}
void
WifiApp::ConfigureNodes()
{
}
void
WifiApp::ConfigureChannels()
{
}
void
WifiApp::ConfigureDevices()
{
}
void
WifiApp::ConfigureMobility()
{
}
void
WifiApp::ConfigureApplications()
{
}
void
WifiApp::ConfigureTracing()
{
}
void
WifiApp::RunSimulation()
{
}
void
WifiApp::ProcessOutputs()
{
}
/**
 * \ingroup wave
 * \brief The ConfigStoreHelper class simplifies config-store raw text load and save
 */
class ConfigStoreHelper
{
 public:
    /**
     * \brief Constructor
     */
    ConfigStoreHelper();
    /**
     * \brief Loads a saved config-store raw text configuration from a given named file
     * \param configFilename the name of the config-store raw text file
     */
    void LoadConfig(std::string configFilename);
    /**
     * \brief Saves a configuration to a given named config-store raw text configuration file
     * \param configFilename the name of the config-store raw text file
     */
    void SaveConfig(std::string configFilename);
};
ConfigStoreHelper::ConfigStoreHelper()
{
}
void
ConfigStoreHelper::LoadConfig(std::string configFilename)
{
    // Input config store from txt format
    Config::SetDefault("ns3::ConfigStore::Filename", StringValue(configFilename));
    Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("RawText"));
    Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Load"));
    ConfigStore inputConfig;
    inputConfig.ConfigureDefaults();
    // inputConfig.ConfigureAttributes ();
}
void
ConfigStoreHelper::SaveConfig(std::string configFilename)
{
    // only save if a non-empty filename has been specified
    if (!configFilename.empty())
    {
        // Output config store to txt format
        Config::SetDefault("ns3::ConfigStore::Filename", StringValue(configFilename));
        Config::SetDefault("ns3::ConfigStore::FileFormat", StringValue("RawText"));
        Config::SetDefault("ns3::ConfigStore::Mode", StringValue("Save"));
        ConfigStore outputConfig;
        outputConfig.ConfigureDefaults();
        // outputConfig.ConfigureAttributes ();
    }
}
/**
 * \ingroup wave
 * \brief The ggExperiment class implements a wifi app that
 * allows VANET routing experiments to be simulated
 */
class VanetRoutingExperiment : public WifiApp
{
 public:
 Ptr<Socket> SetupRoutingPacketReceive(Ipv4Address addr, Ptr<Node> node);
    /**
     * \brief Constructor
     */
    VanetRoutingExperiment();
 protected:
    /**
     * \brief Sets default attribute values
     */
    void SetDefaultAttributeValues() override;
    /**
     * \brief Process command line arguments
     * \param argc program arguments count
     * \param argv program arguments
     */
    void ParseCommandLineArguments(int argc, char** argv) override;
    /**
     * \brief Configure nodes
     */
    void ConfigureNodes() override;
    /**
     * \brief Configure channels
     */
    void ConfigureChannels() override;
    /**
     * \brief Configure devices
     */
    void ConfigureDevices() override;
    /**
     * \brief Configure mobility
     */
    void ConfigureMobility() override;
    /**
     * \brief Configure applications
     */
    void ConfigureApplications() override;
    /**
     * \brief Configure tracing
     */
    void ConfigureTracing() override;
    /**
     * \brief Run the simulation
     */
    void RunSimulation() override;
    /**
     * \brief Process outputs
     */
    void ProcessOutputs() override;
 private:

 
    /**
     * \brief Run the simulation
     */
    void Run();
    /**
     * \brief Run the simulation
     * \param argc command line argument count
     * \param argv command line parameters
     */
    void CommandSetup(int argc, char** argv);
    /**
     * \brief Checks the throughput and outputs summary to CSV file1.
     * This is scheduled and called once per second
     */
    void CheckThroughput();
    /**
     * \brief Set up log file
     */
    void SetupLogFile();
    /**
     * \brief Set up logging
     */
    void SetupLogging();
    /**
     * \brief Configure default attributes
     */
    void ConfigureDefaults();
    /**
     * \brief Set up the adhoc mobility nodes
     */
    void SetupAdhocMobilityNodes();
    /**
     * \brief Set up the adhoc devices
     */
    void SetupAdhocDevices();
    /**
     * \brief Set up generation of IEEE 1609 WAVE messages,
     * as a Basic Safety Message (BSM). The BSM is typically
     * a ~200-byte packets broadcast by all vehicles at a nominal
     * rate of 10 Hz
     */
    void SetupWaveMessages();

    
    void AddTagsToPacket(uint32_t nodeId, Ptr<const Packet> packet);
    /**
     * \brief Set up generation of packets to be routed
     * through the vehicular network
     */
    // CORRECTED DECLARATION
void SetupRoutingMessages(NodeContainer& c, Ipv4InterfaceContainer& adhocTxInterfaces);
    /**
     * \brief Set up a prescribed scenario
     */
    void SetupScenario();
    /**
     * \brief Write the header line to the CSV file1
     */
    void WriteCsvHeader();
    /**
     * \brief Set up configuration parameter from the global variables
     */
    void SetConfigFromGlobals();
    /**
     * \brief Set up the global variables from the configuration parameters
     */
    void SetGlobalsFromConfig();
    /**
     * Course change function
     * \param os the output stream
     * \param context trace source context (unused)
     * \param mobility the mobility model
     */
    static void CourseChange(std::ostream* os,
                             std::string context,
                             Ptr<const MobilityModel> mobility);
    uint32_t m_port;            ///< port
    std::string m_CSVfileName; ///< CSV file name
    std::string m_CSVfileName2; ///< CSV file name
    uint32_t m_nSinks;         ///< number of sinks
    std::string m_protocolName; ///< protocol name
    double m_txp;             ///< distance
    double m_txpRSU; 
    bool m_traceMobility;     ///< trace mobility
    uint32_t m_protocol;        ///< protocol
    uint32_t m_lossModel;     ///< loss model
    uint32_t m_fading;         ///< fading
    std::string m_lossModelName; ///< loss model name
    std::string m_phyMode; ///< phy mode
    uint32_t m_80211mode; ///< 80211 mode
    std::string m_traceFile;                 ///< trace file
    std::string m_traceFile1; 
    std::string m_logFile;                    ///< log file
    uint32_t m_mobility;                     ///< mobility
    uint32_t m_nNodes;                        ///< number of nodes
    uint32_t m_nRSUs;                        ///< number of RSUS
    double m_TotalSimTime;                    ///< total sim time
    std::string m_rate;                     ///< rate
    std::string m_phyModeB;                 ///< phy mode
    std::string m_trName;                     ///< trace file name
    int m_nodeSpeed;                         ///< in m/s
    int m_nodePause;                         ///< in s
    uint32_t m_wavePacketSize;                ///< bytes
    double m_waveInterval;                    ///< seconds
    bool m_verbose;                         ///< verbose
    std::ofstream m_os;                     ///< output stream
    NetDeviceContainer m_adhocTxDevices;     ///< adhoc transmit devices
    NetDeviceContainer m_RSUTxDevices;     ///< RSU transmit devices
    Ipv4InterfaceContainer m_adhocTxInterfaces; ///< adhoc transmit interfaces
    uint32_t m_scenario;                     ///< scenario
    double m_gpsAccuracyNs;                 ///< GPS accuracy
    double m_txMaxDelayMs;                    ///< transmit maximum delay
    bool m_routingTables;                     ///< routing tables
    bool m_asciiTrace;                        ///< ascii trace
    bool m_pcap;                             ///< PCAP
    std::string m_loadConfigFilename;         ///< load config file name
    std::string m_saveConfigFilename;         ///< save config file name
    WaveBsmHelper m_waveBsmHelper;    ///< helper
    Ptr<RoutingHelper> m_routingHelper; ///< routing helper
    Ptr<WifiPhyStats> m_wifiPhyStats; ///< wifi phy statistics
    bool m_log;                         ///< log
    int64_t m_streamIndex;             ///< used to get consistent random numbers across scenarios
    NodeContainer m_adhocTxNodes;     ///< adhoc transmit nodes
    NodeContainer m_adhocTxRSUs;
    double m_txSafetyRange1;            ///< range 1
    double m_txSafetyRange2;            ///< range 2
    double m_txSafetyRange3;            ///< range 3
    double m_txSafetyRange4;            ///< range 4
    double m_txSafetyRange5;            ///< range 5
    double m_txSafetyRange6;            ///< range 6
    double m_txSafetyRange7;            ///< range 7
    double m_txSafetyRange8;            ///< range 8
    double m_txSafetyRange9;            ///< range 9
    double m_txSafetyRange10;         ///< range 10
    std::vector<double> m_txSafetyRanges; ///< list of ranges
    std::string m_exp;                    ///< exp
    Time m_cumulativeBsmCaptureStart;     ///< capture start
};
VanetRoutingExperiment::VanetRoutingExperiment()
    : m_port(9),
     m_CSVfileName("vanet-routing.output.csv"),
     m_CSVfileName2("vanet-routing.output2.csv"),
     m_nSinks(2),
     m_protocolName("protocol"),
     m_txp(15),
     m_txpRSU(30),
     m_traceMobility(false),
     // AODV
     m_protocol(2),
     // Two-Ray ground
     m_lossModel(3),
     m_fading(0),
     m_lossModelName(""),
     m_phyMode("OfdmRate6MbpsBW10MHz"),
     // 1=802.11p
     m_80211mode(1),
     m_traceFile(""),
     m_traceFile1(""),
     m_logFile("low99-ct-unterstrass-1day.filt.7.adj.log"),
     m_mobility(1),
     m_nNodes(156),
     m_nRSUs(4),
     m_TotalSimTime(300.01),
     m_rate("2048bps"),
     m_phyModeB("DsssRate11Mbps"),
     m_trName("vanet-routing-compare"),
     m_nodeSpeed(20),
     m_nodePause(0),
     m_wavePacketSize(200),
     m_waveInterval(0.1),
     m_verbose(false),
     m_scenario(1),
     m_gpsAccuracyNs(40),
     m_txMaxDelayMs(10),
     m_routingTables(true),
     m_asciiTrace(false),
     m_pcap(false),
     m_loadConfigFilename("load-config.txt"),
     m_saveConfigFilename(""),
     m_log(false),
     m_streamIndex(0),
     m_adhocTxNodes(),
     m_adhocTxRSUs(),
     m_txSafetyRange1(50.0),
     m_txSafetyRange2(100.0),
     m_txSafetyRange3(150.0),
     m_txSafetyRange4(200.0),
     m_txSafetyRange5(250.0),
     m_txSafetyRange6(300.0),
     m_txSafetyRange7(350.0),
     m_txSafetyRange8(400.0),
     m_txSafetyRange9(450.0),
     m_txSafetyRange10(500.0),
     m_txSafetyRanges(),
     m_exp(""),
     m_cumulativeBsmCaptureStart(0)
{
    m_wifiPhyStats = CreateObject<WifiPhyStats>();
    m_routingHelper = CreateObject<RoutingHelper>();
    // simply uncond logging during simulation run
    m_log = true;
}
void
VanetRoutingExperiment::SetDefaultAttributeValues()
{
    // handled in constructor
}
// important configuration items stored in global values
/// Port
static ns3::GlobalValue g_port("VRCport",
                             "Port",
                             ns3::UintegerValue(9),
                             ns3::MakeUintegerChecker<uint32_t>());
/// Number of sink nodes for routing non-BSM traffic
static ns3::GlobalValue g_nSinks("VRCnSinks",
                                 "Number of sink nodes for routing non-BSM traffic",
                                 ns3::UintegerValue(10),
                                 ns3::MakeUintegerChecker<uint32_t>());
/// Trace mobility 1=yes;0=no
static ns3::GlobalValue g_traceMobility("VRCtraceMobility",
                                         "Enable trace mobility",
                                         ns3::BooleanValue(false),
                                         ns3::MakeBooleanChecker());
/// Routing protocol
static ns3::GlobalValue g_protocol("VRCprotocol",
                                 "Routing protocol",
                                 ns3::UintegerValue(2),
                                 ns3::MakeUintegerChecker<uint32_t>());
/// Propagation Loss Model
static ns3::GlobalValue g_lossModel("VRClossModel",
                                    "Propagation Loss Model",
                                    ns3::UintegerValue(3),
                                    ns3::MakeUintegerChecker<uint32_t>());
/// Fast Fading Model
static ns3::GlobalValue g_fading("VRCfading",
                                 "Fast Fading Model",
                                 ns3::UintegerValue(0),
                                 ns3::MakeUintegerChecker<uint32_t>());
/// 802.11 mode (0=802.11a;1=802.11p)
static ns3::GlobalValue g_80211mode("VRC80211mode",
                                    "802.11 mode (0=802.11a;1=802.11p)",
                                    ns3::UintegerValue(1),
                                    ns3::MakeUintegerChecker<uint32_t>());
/// Mobility mode 0=random waypoint;1=mobility trace file
static ns3::GlobalValue g_mobility("VRCmobility",
                                 "Mobility mode 0=random waypoint;1=mobility trace file",
                                 ns3::UintegerValue(1),
                                 ns3::MakeUintegerChecker<uint32_t>());
/// Number of nodes (vehicles)
static ns3::GlobalValue g_nNodes("VRCnNodes",
                                 "Number of nodes (vehicles)",
                                 ns3::UintegerValue(156),
                                 ns3::MakeUintegerChecker<uint32_t>());
/// Node speed (m/s) for RWP model
static ns3::GlobalValue g_nodeSpeed("VRCnodeSpeed",
                                     "Node speed (m/s) for RWP model",
                                     ns3::UintegerValue(20),
                                     ns3::MakeUintegerChecker<uint32_t>());
/// Node pause time (s) for RWP model
static ns3::GlobalValue g_nodePause("VRCnodePause",
                                     "Node pause time (s) for RWP model",
                                     ns3::UintegerValue(0),
                                     ns3::MakeUintegerChecker<uint32_t>());
/// Size in bytes of WAVE BSM
static ns3::GlobalValue g_wavePacketSize("VRCwavePacketSize",
                                         "Size in bytes of WAVE BSM",
                                         ns3::UintegerValue(200),
                                         ns3::MakeUintegerChecker<uint32_t>());
/// Verbose 0=no;1=yes
static ns3::GlobalValue g_verbose("VRCverbose",
                                 "Enable verbose",
                                 ns3::BooleanValue(false),
                                 ns3::MakeBooleanChecker());
/// Scenario
static ns3::GlobalValue g_scenario("VRCscenario",
                                 "Scenario",
                                 ns3::UintegerValue(1),
                                 ns3::MakeUintegerChecker<uint32_t>());
/// Dump routing tables at t=5 seconds 0=no;1=yes
static ns3::GlobalValue g_routingTables("VRCroutingTables",
                                         "Dump routing tables at t=5 seconds",
                                         ns3::BooleanValue(false),
                                         ns3::MakeBooleanChecker());
/// Dump ASCII trace 0=no;1=yes
static ns3::GlobalValue g_asciiTrace("VRCasciiTrace",
                                     "Dump ASCII trace",
                                     ns3::BooleanValue(false),
                                     ns3::MakeBooleanChecker());
/// Generate PCAP files 0=no;1=yes
static ns3::GlobalValue g_pcap("VRCpcap",
                             "Generate PCAP files",
                             ns3::BooleanValue(false),
                             ns3::MakeBooleanChecker());
/// Simulation start time for capturing cumulative BSM
static ns3::GlobalValue g_cumulativeBsmCaptureStart(
    "VRCcumulativeBsmCaptureStart",
    "Simulation start time for capturing cumulative BSM",
    ns3::TimeValue(Seconds(0)),
    ns3::MakeTimeChecker());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange1("VRCtxSafetyRange1",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(50.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange2("VRCtxSafetyRange2",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(100.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange3("VRCtxSafetyRange3",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(150.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange4("VRCtxSafetyRange4",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(200.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange5("VRCtxSafetyRange5",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(250.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange6("VRCtxSafetyRange6",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(300.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange7("VRCtxSafetyRange7",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(350.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange8("VRCtxSafetyRange8",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(400.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange9("VRCtxSafetyRange9",
                                         "BSM range for PDR inclusion",
                                         ns3::DoubleValue(450.0),
                                         ns3::MakeDoubleChecker<double>());
/// BSM range for PDR inclusion
static ns3::GlobalValue g_txSafetyRange10("VRCtxSafetyRange10",
                                            "BSM range for PDR inclusion",
                                            ns3::DoubleValue(500.0),
                                            ns3::MakeDoubleChecker<double>());
/// Transmission power dBm
static ns3::GlobalValue g_txp("VRCtxp",
                                "Transmission power dBm",
                                ns3::DoubleValue(7.5),
                                ns3::MakeDoubleChecker<double>());
/// Total simulation time (s)
static ns3::GlobalValue g_totalTime("VRCtotalTime",
                                     "Total simulation time (s)",
                                     ns3::DoubleValue(300.01),
                                     ns3::MakeDoubleChecker<double>());
/// Interval (s) between WAVE BSMs
static ns3::GlobalValue g_waveInterval("VRCwaveInterval",
                                         "Interval (s) between WAVE BSMs",
                                         ns3::DoubleValue(0.1),
                                         ns3::MakeDoubleChecker<double>());
/// GPS sync accuracy (ns)
static ns3::GlobalValue g_gpsAccuracyNs("VRCgpsAccuracyNs",
                                         "GPS sync accuracy (ns)",
                                         ns3::DoubleValue(40),
                                         ns3::MakeDoubleChecker<double>());
/// Tx May Delay (ms)
static ns3::GlobalValue g_txMaxDelayMs("VRCtxMaxDelayMs",
                                         "Tx May Delay (ms)",
                                         ns3::DoubleValue(10),
                                         ns3::MakeDoubleChecker<double>());
/// CSV filename (for time series data)
static ns3::GlobalValue g_CSVfileName("VRCCSVfileName",
                                        "CSV filename (for time series data)",
                                        ns3::StringValue("vanet-routing.output.csv"),
                                        ns3::MakeStringChecker());
/// CSV filename 2 (for overall simulation scenario results)
static ns3::GlobalValue g_CSVfileName2("VRCCSVfileName2",
                                         "CSV filename 2 (for overall simulation scenario results)",
                                         ns3::StringValue("vanet-routing.output2.csv"),
                                         ns3::MakeStringChecker());
/// PHY mode (802.11p)
static ns3::GlobalValue g_phyMode("VRCphyMode",
                                 "PHY mode (802.11p)",
                                 ns3::StringValue("OfdmRate6MbpsBW10MHz"),
                                 ns3::MakeStringChecker());
/// Mobility trace filename
static ns3::GlobalValue g_traceFile(
    "VRCtraceFile",
    "Mobility trace filename",
    ns3::StringValue("./src/wave/examples/low99-ct-unterstrass-1day.filt.7.adj.mob"),
    ns3::MakeStringChecker());
/// Log filename
static ns3::GlobalValue g_logFile("VRClogFile",
                                 "Log filename",
                                 ns3::StringValue("low99-ct-unterstrass-1day.filt.7.adj.log"),
                                 ns3::MakeStringChecker());
/// Data rate
static ns3::GlobalValue g_rate("VRCrate",
                             "Data rate",
                             ns3::StringValue("2048bps"),
                             ns3::MakeStringChecker());
/// PHY mode (802.11a)
static ns3::GlobalValue g_phyModeB("VRCphyModeB",
                                     "PHY mode (802.11a)",
                                     ns3::StringValue("DsssRate11Mbps"),
                                     ns3::MakeStringChecker());
/// Trace name)
static ns3::GlobalValue g_trName("VRCtrName",
                                 "Trace name",
                                 ns3::StringValue("vanet-routing-compare"),
                                 ns3::MakeStringChecker());
void
VanetRoutingExperiment::ParseCommandLineArguments(int argc, char** argv)
{
    CommandSetup(argc, argv);
    SetupScenario();
    // user may specify up to 10 different tx distances
    // to be used for calculating different values of Packet
    // Delivery Ratio (PDR). Used to see the effects of
    // fading over distance
    m_txSafetyRanges.resize(10, 0);
    m_txSafetyRanges[0] = m_txSafetyRange1;
    m_txSafetyRanges[1] = m_txSafetyRange2;
    m_txSafetyRanges[2] = m_txSafetyRange3;
    m_txSafetyRanges[3] = m_txSafetyRange4;
    m_txSafetyRanges[4] = m_txSafetyRange5;
    m_txSafetyRanges[5] = m_txSafetyRange6;
    m_txSafetyRanges[6] = m_txSafetyRange7;
    m_txSafetyRanges[7] = m_txSafetyRange8;
    m_txSafetyRanges[8] = m_txSafetyRange9;
    m_txSafetyRanges[9] = m_txSafetyRange10;
    ConfigureDefaults();
    // we are done with all configuration
    // save config-store, if requested
    SetGlobalsFromConfig();
    ConfigStoreHelper configStoreHelper;
    configStoreHelper.SaveConfig(m_saveConfigFilename);
    m_waveBsmHelper.GetWaveBsmStats()->SetLogging(m_log);
    m_routingHelper->SetLogging(m_log);
}
void
VanetRoutingExperiment::ConfigureNodes()
{
    NS_LOG_UNCOND("Creating nodes.");
    m_adhocTxRSUs.Create(m_nRSUs);
    m_adhocTxNodes.Create(m_nNodes);
}

void
VanetRoutingExperiment::ConfigureChannels()
{
    // set up channel and devices
    SetupAdhocDevices();
}
void
VanetRoutingExperiment::ConfigureDevices()
{
    // 1. Setup the ad-hoc (wireless) devices
    SetupAdhocDevices();

    // ... (Your existing trace connection logic for PhyStats can remain here) ...
    if (m_80211mode == 3)
    {
        // WAVE
        Config::Connect("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/State/Tx",
                        MakeCallback(&WifiPhyStats::PhyTxTrace, m_wifiPhyStats));
        Config::Connect("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/PhyTxDrop",
                        MakeCallback(&WifiPhyStats::PhyTxDrop, m_wifiPhyStats));
        Config::Connect("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/PhyRxDrop",
                        MakeCallback(&WifiPhyStats::PhyRxDrop, m_wifiPhyStats));
    }
    else
    {
        Config::Connect("/NodeList/*/DeviceList/*/Phy/State/Tx",
                        MakeCallback(&WifiPhyStats::PhyTxTrace, m_wifiPhyStats));
        Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxDrop",
                        MakeCallback(&WifiPhyStats::PhyTxDrop, m_wifiPhyStats));
        Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxDrop",
                        MakeCallback(&WifiPhyStats::PhyRxDrop, m_wifiPhyStats));
    }
}
void
VanetRoutingExperiment::ConfigureMobility()
{
    SetupAdhocMobilityNodes();
}

/**
* \brief Callback function triggered by the Tx trace of an OnOffApplication.
*
* This function gets triggered whenever an OnOffApplication sends a packet.
* It parses the context string provided by the trace source to identify
* which node sent the packet, and then calls another function to send a
* corresponding message to the blockchain server.
*
* \param context The trace source context string (e.g., "/NodeList/5/...").
* \param packet The packet that was just transmitted by the application.
*/




void
VanetRoutingExperiment::ConfigureApplications()
{
    // --- STEP 1: Install Internet Stack on ALL nodes ---
    // This step creates the Ipv4L3Protocol objects that we need to trace.
    NS_LOG_UNCOND("Installing internet stack and routing protocols.");
    InternetStackHelper internet;
    
    // Use the routing protocol specified by the 'protocol' variable
    AodvHelper aodv;
    OlsrHelper olsr;
    DsdvHelper dsdv;
    Ipv4ListRoutingHelper list;
    switch (m_protocol)
    {
        case 1:
            list.Add(olsr, 100);
            break;
        case 2:
            list.Add(aodv, 100);
            break;
        case 3:
            list.Add(dsdv, 100);
            break;
        default:
            NS_FATAL_ERROR("Protocol not supported in this simplified setup");
            break;
    }
    internet.SetRoutingHelper(list);
    
    NodeContainer allNodes;
    allNodes.Add(m_adhocTxNodes);
    allNodes.Add(m_adhocTxRSUs);
    internet.Install(allNodes);


    // --- STEP 2: Assign IP Addresses to ALL devices ---
    NS_LOG_UNCOND("Assigning IP addresses.");
    Ipv4AddressHelper addressAdhoc;
    addressAdhoc.SetBase("10.1.0.0", "255.255.0.0");
    NetDeviceContainer allDevices;
    allDevices.Add(m_adhocTxDevices);
    allDevices.Add(m_RSUTxDevices);
    m_adhocTxInterfaces = addressAdhoc.Assign(allDevices);
  
  
  
    // --- STEP 4: Install Applications and Connect Their Traces ---
    NS_LOG_UNCOND("Installing applications (e.g., OnOff, WAVE BSMs).");
    SetupRoutingMessages(allNodes, m_adhocTxInterfaces);
    SetupWaveMessages();
    
    // Connect the trace for routing statistics
    std::ostringstream oss;
    oss << "/NodeList/*/ApplicationList/*/$ns3::OnOffApplication/Tx";
    Config::Connect(oss.str(), MakeCallback(&RoutingHelper::OnOffTrace, m_routingHelper));
}
void
VanetRoutingExperiment::ConfigureTracing()
{
    WriteCsvHeader();
    SetupLogFile();
    SetupLogging();
    AsciiTraceHelper ascii;
    MobilityHelper::EnableAsciiAll(ascii.CreateFileStream(m_trName + ".mob"));
}
void
VanetRoutingExperiment::RunSimulation()
{
    Run();
}
void
VanetRoutingExperiment::ProcessOutputs()
{
    // calculate and output final results
    double bsm_pdr1 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(1);
    double bsm_pdr2 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(2);
    double bsm_pdr3 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(3);
    double bsm_pdr4 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(4);
    double bsm_pdr5 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(5);
    double bsm_pdr6 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(6);
    double bsm_pdr7 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(7);
    double bsm_pdr8 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(8);
    double bsm_pdr9 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(9);
    double bsm_pdr10 = m_waveBsmHelper.GetWaveBsmStats()->GetCumulativeBsmPdr(10);
    double averageRoutingGoodputKbps = 0.0;
    uint32_t totalBytesTotal = m_routingHelper->GetRoutingStats().GetCumulativeRxBytes();
    averageRoutingGoodputKbps = (((double)totalBytesTotal * 8.0) / m_TotalSimTime) / 1000.0;
    // calculate MAC/PHY overhead (mac-phy-oh)
    // total WAVE BSM bytes sent
    uint32_t cumulativeWaveBsmBytes = m_waveBsmHelper.GetWaveBsmStats()->GetTxByteCount();
    uint32_t cumulativeRoutingBytes = m_routingHelper->GetRoutingStats().GetCumulativeTxBytes();
    uint32_t totalAppBytes = cumulativeWaveBsmBytes + cumulativeRoutingBytes;
    uint32_t totalPhyBytes = m_wifiPhyStats->GetTxBytes();
    // mac-phy-oh = (total-phy-bytes - total-app-bytes) / total-phy-bytes
    double mac_phy_oh = 0.0;
    if (totalPhyBytes > 0)
    {
        mac_phy_oh = (double)(totalPhyBytes - totalAppBytes) / (double)totalPhyBytes;
    }
    if (m_log)
    {
        NS_LOG_UNCOND("BSM_PDR1=" << bsm_pdr1 << " BSM_PDR2=" << bsm_pdr2
                                 << " BSM_PDR3=" << bsm_pdr3 << " BSM_PDR4=" << bsm_pdr4
                                 << " BSM_PDR5=" << bsm_pdr5 << " BSM_PDR6=" << bsm_pdr6
                                 << " BSM_PDR7=" << bsm_pdr7 << " BSM_PDR8=" << bsm_pdr8
                                 << " BSM_PDR9=" << bsm_pdr9 << " BSM_PDR10=" << bsm_pdr10
                                 << " Goodput=" << averageRoutingGoodputKbps
                                 << "Kbps MAC/PHY-oh=" << mac_phy_oh);
    }
    std::ofstream out(m_CSVfileName2, std::ios::app);
    out << bsm_pdr1 << "," << bsm_pdr2 << "," << bsm_pdr3 << "," << bsm_pdr4 << "," << bsm_pdr5
        << "," << bsm_pdr6 << "," << bsm_pdr7 << "," << bsm_pdr8 << "," << bsm_pdr9 << ","
        << bsm_pdr10 << "," << averageRoutingGoodputKbps << "," << mac_phy_oh << "" << std::endl;
    out.close();
    m_os.close(); // close log file
}
void
VanetRoutingExperiment::Run()
{
    NS_LOG_INFO("Run Simulation.");
    CheckThroughput();
    Simulator::Stop(Seconds(m_TotalSimTime));
    AnimationInterface anim ("animation1.xml");
    anim.AnimationInterface::EnablePacketMetadata(true);
    anim.SetBackgroundImage ("/home/mehtix/Documents/1.png",-4, 612, 1.15, -1.14, 0.6);
    anim.SetMaxPktsPerTraceFile(500000000);
    uint32_t resourceId1;
    resourceId1 = anim.AddResource("/home/mehtix/Documents/2.png");
    anim.UpdateNodeImage(0,resourceId1);
    anim.UpdateNodeImage(1,resourceId1);
    anim.UpdateNodeImage(2,resourceId1);
    anim.UpdateNodeImage(3,resourceId1);
    anim.UpdateNodeSize(0,100,1000);
    anim.UpdateNodeSize(1,100,100);
    anim.UpdateNodeSize(2,100,100);
    anim.UpdateNodeSize(3,100,100);
    uint32_t resourceId2;
    resourceId2 = anim.AddResource("/home/mehtix/Documents/3.png");
    for (int x =0 ; x<=19;x++){
    anim.UpdateNodeImage(x+4,resourceId2);
    anim.UpdateNodeSize(x+4,25,25);
    }
    anim.EnableIpv4RouteTracking ("1.xml",Seconds(0),Seconds(m_TotalSimTime),Seconds(1));
 
    Simulator::Run();
    Simulator::Destroy();
}
// Prints actual position and velocity when a course change event occurs
void
VanetRoutingExperiment::CourseChange(std::ostream* os,
                                    std::string context,
                                    Ptr<const MobilityModel> mobility)
{
    Vector pos = mobility->GetPosition(); // Get position
    Vector vel = mobility->GetVelocity(); // Get velocity
    pos.z = 1.5;
    int nodeId = mobility->GetObject<Node>()->GetId();
    double t = (Simulator::Now()).GetSeconds();
    if (t >= 1.0)
    {
        WaveBsmHelper::GetNodesMoving()[nodeId] = 1;
    }
    // NS_LOG_UNCOND ("Changing pos for node=" << nodeId << " at " << Simulator::Now () );
    // Prints position and velocities
    *os << Simulator::Now() << " POS: x=" << pos.x << ", y=" << pos.y << ", z=" << pos.z
        << "; VEL:" << vel.x << ", y=" << vel.y << ", z=" << vel.z << std::endl;
}
void
VanetRoutingExperiment::CheckThroughput()
{
    uint32_t bytesTotal = m_routingHelper->GetRoutingStats().GetRxBytes();
    uint32_t packetsReceived = m_routingHelper->GetRoutingStats().GetRxPkts();
    double kbps = (bytesTotal * 8.0) / 1000;
    double wavePDR = 0.0;
    int wavePktsSent = m_waveBsmHelper.GetWaveBsmStats()->GetTxPktCount();
    int wavePktsReceived = m_waveBsmHelper.GetWaveBsmStats()->GetRxPktCount();
    if (wavePktsSent > 0)
    {
        int wavePktsReceived = m_waveBsmHelper.GetWaveBsmStats()->GetRxPktCount();
        wavePDR = (double)wavePktsReceived / (double)wavePktsSent;
    }
    int waveExpectedRxPktCount = m_waveBsmHelper.GetWaveBsmStats()->GetExpectedRxPktCount(1);
    int waveRxPktInRangeCount = m_waveBsmHelper.GetWaveBsmStats()->GetRxPktInRangeCount(1);
    double wavePDR1_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(1);
    double wavePDR2_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(2);
    double wavePDR3_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(3);
    double wavePDR4_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(4);
    double wavePDR5_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(5);
    double wavePDR6_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(6);
    double wavePDR7_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(7);
    double wavePDR8_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(8);
    double wavePDR9_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(9);
    double wavePDR10_2 = m_waveBsmHelper.GetWaveBsmStats()->GetBsmPdr(10);
    // calculate MAC/PHY overhead (mac-phy-oh)
    // total WAVE BSM bytes sent
    uint32_t cumulativeWaveBsmBytes = m_waveBsmHelper.GetWaveBsmStats()->GetTxByteCount();
    uint32_t cumulativeRoutingBytes = m_routingHelper->GetRoutingStats().GetCumulativeTxBytes();
    uint32_t totalAppBytes = cumulativeWaveBsmBytes + cumulativeRoutingBytes;
    uint32_t totalPhyBytes = m_wifiPhyStats->GetTxBytes();
    // mac-phy-oh = (total-phy-bytes - total-app-bytes) / total-phy-bytes
    double mac_phy_oh = 0.0;
    if (totalPhyBytes > 0)
    {
        mac_phy_oh = (double)(totalPhyBytes - totalAppBytes) / (double)totalPhyBytes;
    }
    std::ofstream out(m_CSVfileName, std::ios::app);
    if (m_log)
    {
        NS_LOG_UNCOND("At t=" << (Simulator::Now()).As(Time::S) << " BSM_PDR1=" << wavePDR1_2
                             << " BSM_PDR1=" << wavePDR2_2 << " BSM_PDR3=" << wavePDR3_2
                             << " BSM_PDR4=" << wavePDR4_2 << " BSM_PDR5=" << wavePDR5_2
                             << " BSM_PDR6=" << wavePDR6_2 << " BSM_PDR7=" << wavePDR7_2
                             << " BSM_PDR8=" << wavePDR8_2 << " BSM_PDR9=" << wavePDR9_2
                             << " BSM_PDR10=" << wavePDR10_2 << " Goodput=" << kbps
                             << "Kbps" /*<< " MAC/PHY-OH=" << mac_phy_oh*/);
    }
    out << (Simulator::Now()).As(Time::S) << "," << kbps << "," << packetsReceived << ","
        << m_nSinks << "," << m_protocolName << "," << m_txp << "," << wavePktsSent << ","
        << wavePktsReceived << "," << wavePDR << "," << waveExpectedRxPktCount << ","
        << waveRxPktInRangeCount << "," << wavePDR1_2 << "," << wavePDR2_2 << "," << wavePDR3_2
        << "," << wavePDR4_2 << "," << wavePDR5_2 << "," << wavePDR6_2 << "," << wavePDR7_2 << ","
        << wavePDR8_2 << "," << wavePDR9_2 << "," << wavePDR10_2 << "," << mac_phy_oh << ""
        << std::endl;
    out.close();
    m_routingHelper->GetRoutingStats().SetRxBytes(0);
    m_routingHelper->GetRoutingStats().SetRxPkts(0);
    m_waveBsmHelper.GetWaveBsmStats()->SetRxPktCount(0);
    m_waveBsmHelper.GetWaveBsmStats()->SetTxPktCount(0);
    for (int index = 1; index <= 10; index++)
    {
        m_waveBsmHelper.GetWaveBsmStats()->SetExpectedRxPktCount(index, 0);
        m_waveBsmHelper.GetWaveBsmStats()->SetRxPktInRangeCount(index, 0);
    }
    Time currentTime = Simulator::Now();
    if (currentTime <= m_cumulativeBsmCaptureStart)
    {
        for (int index = 1; index <= 10; index++)
        {
            m_waveBsmHelper.GetWaveBsmStats()->ResetTotalRxPktCounts(index);
        }
    }
    Simulator::Schedule(Seconds(1.0), &VanetRoutingExperiment::CheckThroughput, this);
}
void
VanetRoutingExperiment::SetConfigFromGlobals()
{
    // get settings saved from config-store
    UintegerValue uintegerValue;
    DoubleValue doubleValue;
    StringValue stringValue;
    TimeValue timeValue;
    BooleanValue booleanValue;
    // This may not be the best way to manage program configuration
    // (directing them through global values), but management
    // through the config-store here is copied from
    // src/lte/examples/lena-dual-stripe.cc
    GlobalValue::GetValueByName("VRCport", uintegerValue);
    m_port = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCnSinks", uintegerValue);
    m_nSinks = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCtraceMobility", booleanValue);
    m_traceMobility = booleanValue.Get();
    GlobalValue::GetValueByName("VRCprotocol", uintegerValue);
    m_protocol = uintegerValue.Get();
    GlobalValue::GetValueByName("VRClossModel", uintegerValue);
    m_lossModel = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCfading", uintegerValue);
    m_fading = uintegerValue.Get();
    GlobalValue::GetValueByName("VRC80211mode", uintegerValue);
    m_80211mode = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCmobility", uintegerValue);
    m_mobility = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCnNodes", uintegerValue);
    m_nNodes = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCnodeSpeed", uintegerValue);
    m_nodeSpeed = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCnodePause", uintegerValue);
    m_nodePause = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCwavePacketSize", uintegerValue);
    m_wavePacketSize = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCverbose", booleanValue);
    m_verbose = booleanValue.Get();
    GlobalValue::GetValueByName("VRCscenario", uintegerValue);
    m_scenario = uintegerValue.Get();
    GlobalValue::GetValueByName("VRCroutingTables", booleanValue);
    m_routingTables = booleanValue.Get();
    GlobalValue::GetValueByName("VRCasciiTrace", booleanValue);
    m_asciiTrace = booleanValue.Get();
    GlobalValue::GetValueByName("VRCpcap", booleanValue);
    m_pcap = booleanValue.Get();
    GlobalValue::GetValueByName("VRCcumulativeBsmCaptureStart", timeValue);
    m_cumulativeBsmCaptureStart = timeValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange1", doubleValue);
    m_txSafetyRange1 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange2", doubleValue);
    m_txSafetyRange2 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange3", doubleValue);
    m_txSafetyRange3 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange4", doubleValue);
    m_txSafetyRange4 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange5", doubleValue);
    m_txSafetyRange5 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange6", doubleValue);
    m_txSafetyRange6 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange7", doubleValue);
    m_txSafetyRange7 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange8", doubleValue);
    m_txSafetyRange8 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange9", doubleValue);
    m_txSafetyRange9 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxSafetyRange10", doubleValue);
    m_txSafetyRange10 = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxp", doubleValue);
    m_txp = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtotalTime", doubleValue);
    m_TotalSimTime = doubleValue.Get();
    GlobalValue::GetValueByName("VRCwaveInterval", doubleValue);
    m_waveInterval = doubleValue.Get();
    GlobalValue::GetValueByName("VRCgpsAccuracyNs", doubleValue);
    m_gpsAccuracyNs = doubleValue.Get();
    GlobalValue::GetValueByName("VRCtxMaxDelayMs", doubleValue);
    m_txMaxDelayMs = doubleValue.Get();
    GlobalValue::GetValueByName("VRCCSVfileName", stringValue);
    m_CSVfileName = stringValue.Get();
    GlobalValue::GetValueByName("VRCCSVfileName2", stringValue);
    m_CSVfileName2 = stringValue.Get();
    GlobalValue::GetValueByName("VRCphyMode", stringValue);
    m_phyMode = stringValue.Get();
    GlobalValue::GetValueByName("VRCtraceFile", stringValue);
    m_traceFile = stringValue.Get();
    GlobalValue::GetValueByName("VRClogFile", stringValue);
    m_logFile = stringValue.Get();
    GlobalValue::GetValueByName("VRCrate", stringValue);
    m_rate = stringValue.Get();
    GlobalValue::GetValueByName("VRCphyModeB", stringValue);
    m_phyModeB = stringValue.Get();
    GlobalValue::GetValueByName("VRCtrName", stringValue);
    m_trName = stringValue.Get();
}
void
VanetRoutingExperiment::SetGlobalsFromConfig()
{
    // get settings saved from config-store
    UintegerValue uintegerValue;
    DoubleValue doubleValue;
    StringValue stringValue;
    g_port.SetValue(UintegerValue(m_port));
    g_nSinks.SetValue(UintegerValue(m_nSinks));
    g_traceMobility.SetValue(BooleanValue(m_traceMobility));
    g_protocol.SetValue(UintegerValue(m_protocol));
    g_lossModel.SetValue(UintegerValue(m_lossModel));
    g_fading.SetValue(UintegerValue(m_fading));
    g_80211mode.SetValue(UintegerValue(m_80211mode));
    g_mobility.SetValue(UintegerValue(m_mobility));
    g_nNodes.SetValue(UintegerValue(m_nNodes));
    g_nNodes.SetValue(UintegerValue(m_nRSUs));
    g_nodeSpeed.SetValue(UintegerValue(m_nodeSpeed));
    g_nodePause.SetValue(UintegerValue(m_nodePause));
    g_wavePacketSize.SetValue(UintegerValue(m_wavePacketSize));
    g_verbose.SetValue(BooleanValue(m_verbose));
    g_scenario.SetValue(UintegerValue(m_scenario));
    g_routingTables.SetValue(BooleanValue(m_routingTables));
    g_asciiTrace.SetValue(BooleanValue(m_asciiTrace));
    g_pcap.SetValue(BooleanValue(m_pcap));
    g_cumulativeBsmCaptureStart.SetValue(TimeValue(m_cumulativeBsmCaptureStart));
    g_txSafetyRange1.SetValue(DoubleValue(m_txSafetyRange1));
    g_txSafetyRange2.SetValue(DoubleValue(m_txSafetyRange2));
    g_txSafetyRange3.SetValue(DoubleValue(m_txSafetyRange3));
    g_txSafetyRange4.SetValue(DoubleValue(m_txSafetyRange4));
    g_txSafetyRange5.SetValue(DoubleValue(m_txSafetyRange5));
    g_txSafetyRange6.SetValue(DoubleValue(m_txSafetyRange6));
    g_txSafetyRange7.SetValue(DoubleValue(m_txSafetyRange7));
    g_txSafetyRange8.SetValue(DoubleValue(m_txSafetyRange8));
    g_txSafetyRange9.SetValue(DoubleValue(m_txSafetyRange9));
    g_txSafetyRange10.SetValue(DoubleValue(m_txSafetyRange10));
    g_txp.SetValue(DoubleValue(m_txp));
    g_totalTime.SetValue(DoubleValue(m_TotalSimTime));
    g_waveInterval.SetValue(DoubleValue(m_waveInterval));
    g_gpsAccuracyNs.SetValue(DoubleValue(m_gpsAccuracyNs));
    g_txMaxDelayMs.SetValue(DoubleValue(m_txMaxDelayMs));
    g_CSVfileName.SetValue(StringValue(m_CSVfileName));
    g_CSVfileName2.SetValue(StringValue(m_CSVfileName2));
    g_phyMode.SetValue(StringValue(m_phyMode));
    g_traceFile.SetValue(StringValue(m_traceFile));
    g_traceFile.SetValue(StringValue(m_traceFile1));
    g_logFile.SetValue(StringValue(m_logFile));
    g_rate.SetValue(StringValue(m_rate));
    g_phyModeB.SetValue(StringValue(m_phyModeB));
    g_trName.SetValue(StringValue(m_trName));
    GlobalValue::GetValueByName("VRCtrName", stringValue);
    m_trName = stringValue.Get();
}
void
VanetRoutingExperiment::CommandSetup(int argc, char** argv)
{
    CommandLine cmd(__FILE__);
    double txDist1 = 50.0;
    double txDist2 = 100.0;
    double txDist3 = 150.0;
    double txDist4 = 200.0;
    double txDist5 = 250.0;
    double txDist6 = 300.0;
    double txDist7 = 350.0;
    double txDist8 = 350.0;
    double txDist9 = 350.0;
    double txDist10 = 350.0;
    // allow command line overrides
    cmd.AddValue("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
    cmd.AddValue("CSVfileName2", "The name of the CSV output file name2", m_CSVfileName2);
    cmd.AddValue("totaltime", "Simulation end time", m_TotalSimTime);
    cmd.AddValue("nodes", "Number of nodes (i.e. vehicles)", m_nNodes);
    cmd.AddValue("nodes", "Number of nodes (i.e. vehicles)", m_nRSUs);
    cmd.AddValue("sinks", "Number of routing sinks", m_nSinks);
    cmd.AddValue("txp", "Transmit power (dB), e.g. txp=7.5", m_txp);
    cmd.AddValue("traceMobility", "Enable mobility tracing", m_traceMobility);
    cmd.AddValue("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR", m_protocol);
    cmd.AddValue("lossModel", "1=Friis;2=ItuR1411Los;3=TwoRayGround;4=LogDistance", m_lossModel);
    cmd.AddValue("fading", "0=None;1=Nakagami;(buildings=1 overrides)", m_fading);
    cmd.AddValue("phyMode", "Wifi Phy mode", m_phyMode);
    cmd.AddValue("80211Mode", "1=802.11p; 2=802.11b; 3=WAVE-PHY", m_80211mode);
    cmd.AddValue("traceFile", "Ns2 movement trace file", m_traceFile);
    cmd.AddValue("traceFile", "Ns2 movement trace file", m_traceFile1);
    cmd.AddValue("logFile", "Log file", m_logFile);
    cmd.AddValue("mobility", "1=trace;2=RWP", m_mobility);
    cmd.AddValue("rate", "Rate", m_rate);
    cmd.AddValue("phyModeB", "Phy mode 802.11b", m_phyModeB);
    cmd.AddValue("speed", "Node speed (m/s)", m_nodeSpeed);
    cmd.AddValue("pause", "Node pause (s)", m_nodePause);
    cmd.AddValue("verbose", "Enable verbose output", m_verbose);
    cmd.AddValue("bsm", "(WAVE) BSM size (bytes)", m_wavePacketSize);
    cmd.AddValue("interval", "(WAVE) BSM interval (s)", m_waveInterval);
    cmd.AddValue("scenario", "1=synthetic, 2=playback-trace", m_scenario);
    // User is allowed to have up to 10 different PDRs (Packet
    // Delivery Ratios) calculate, and so can specify up to
    // 10 different tx distances.
    cmd.AddValue("txdist1", "Expected BSM tx range, m", txDist1);
    cmd.AddValue("txdist2", "Expected BSM tx range, m", txDist2);
    cmd.AddValue("txdist3", "Expected BSM tx range, m", txDist3);
    cmd.AddValue("txdist4", "Expected BSM tx range, m", txDist4);
    cmd.AddValue("txdist5", "Expected BSM tx range, m", txDist5);
    cmd.AddValue("txdist6", "Expected BSM tx range, m", txDist6);
    cmd.AddValue("txdist7", "Expected BSM tx range, m", txDist7);
    cmd.AddValue("txdist8", "Expected BSM tx range, m", txDist8);
    cmd.AddValue("txdist9", "Expected BSM tx range, m", txDist9);
    cmd.AddValue("txdist10", "Expected BSM tx range, m", txDist10);
    cmd.AddValue("gpsaccuracy", "GPS time accuracy, in ns", m_gpsAccuracyNs);
    cmd.AddValue("txmaxdelay", "Tx max delay, in ms", m_txMaxDelayMs);
    cmd.AddValue("routingTables", "Whether to dump routing tables at t=5 seconds", m_routingTables);
    cmd.AddValue("asciiTrace", "Whether to dump ASCII Trace data", m_asciiTrace);
    cmd.AddValue("pcap", "Whether to create PCAP files for all nodes", m_pcap);
    cmd.AddValue("loadconfig", "Config-store filename to load", m_loadConfigFilename);
    cmd.AddValue("saveconfig", "Config-store filename to save", m_saveConfigFilename);
    cmd.AddValue("exp", "Experiment", m_exp);
    cmd.AddValue("BsmCaptureStart",
                "Start time to begin capturing pkts for cumulative Bsm",
                m_cumulativeBsmCaptureStart);
    cmd.Parse(argc, argv);
    m_txSafetyRange1 = txDist1;
    m_txSafetyRange2 = txDist2;
    m_txSafetyRange3 = txDist3;
    m_txSafetyRange4 = txDist4;
    m_txSafetyRange5 = txDist5;
    m_txSafetyRange6 = txDist6;
    m_txSafetyRange7 = txDist7;
    m_txSafetyRange8 = txDist8;
    m_txSafetyRange9 = txDist9;
    m_txSafetyRange10 = txDist10;
    // load configuration info from config-store
    ConfigStoreHelper configStoreHelper;
    configStoreHelper.LoadConfig(m_loadConfigFilename);
    // transfer config-store values to config parameters
    SetConfigFromGlobals();
    // parse again so you can override input file default values via command line
    cmd.Parse(argc, argv);
    m_txSafetyRange1 = txDist1;
    m_txSafetyRange2 = txDist2;
    m_txSafetyRange3 = txDist3;
    m_txSafetyRange4 = txDist4;
    m_txSafetyRange5 = txDist5;
    m_txSafetyRange6 = txDist6;
    m_txSafetyRange7 = txDist7;
    m_txSafetyRange8 = txDist8;
    m_txSafetyRange9 = txDist9;
    m_txSafetyRange10 = txDist10;
}
void
VanetRoutingExperiment::SetupLogFile()
{
    // open log file for output
    m_os.open(m_logFile);
}
void
VanetRoutingExperiment::SetupLogging()
{
    // Enable logging from the ns2 helper
    LogComponentEnable("Ns2MobilityHelper", LOG_LEVEL_DEBUG);
    Packet::EnablePrinting();
}
void
VanetRoutingExperiment::ConfigureDefaults()
{
    Config::SetDefault("ns3::OnOffApplication::PacketSize", StringValue("256"));
    Config::SetDefault("ns3::OnOffApplication::DataRate", StringValue(m_rate));
    // Set Non-unicastMode rate to unicast mode
    if (m_80211mode == 2)
    {
        Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode",
                         StringValue(m_phyModeB));
    }
    else
    {
        Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(m_phyMode));
    }
}
void 
 VanetRoutingExperiment::SetupAdhocMobilityNodes() 
 { 
     // THIS IS THE CRITICAL FIX: 
     // Resize the tracking vector for ALL mobility modes at the beginning of the function. 
     WaveBsmHelper::GetNodesMoving().resize(m_nNodes + m_nRSUs, 0); 
     if (m_mobility == 1) // Trace File Mobility 
     { 
         Ns2MobilityHelper ns2 = Ns2MobilityHelper(m_traceFile); 
         ns2.Install(); 
     } 
     else if (m_mobility == 2) // Random Waypoint Mobility 
     { 
         MobilityHelper mobilityAdhoc; 
         ObjectFactory pos; 
         pos.SetTypeId("ns3::RandomBoxPositionAllocator"); 
         pos.Set("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]")); 
         pos.Set("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]")); 
         pos.Set("Z", StringValue("ns3::UniformRandomVariable[Min=1.0|Max=2.0]")); 
         Ptr<PositionAllocator> taPositionAlloc = pos.Create()->GetObject<PositionAllocator>(); 
         m_streamIndex += taPositionAlloc->AssignStreams(m_streamIndex); 
         std::stringstream ssSpeed; 
         ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << m_nodeSpeed << "]"; 
         std::stringstream ssPause; 
         ssPause << "ns3::ConstantRandomVariable[Constant=" << m_nodePause << "]"; 
         mobilityAdhoc.SetMobilityModel("ns3::RandomWaypointMobilityModel", 
                                     "Speed", StringValue(ssSpeed.str()), 
                                     "Pause", StringValue(ssPause.str()), 
                                     "PositionAllocator", PointerValue(taPositionAlloc)); 
         mobilityAdhoc.SetPositionAllocator(taPositionAlloc); 
         mobilityAdhoc.Install(m_adhocTxNodes); 
         m_streamIndex += mobilityAdhoc.AssignStreams(m_adhocTxNodes, m_streamIndex); 
     } 
     // Set constant position for stationary nodes (RSUs) 
     MobilityHelper stationaryMobility; 
     stationaryMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel"); 
     stationaryMobility.Install(m_adhocTxRSUs); 
 
     // Manually set the position for each RSU 
     for (uint32_t i = 0; i < m_adhocTxRSUs.GetN(); ++i) 
     { 
         Ptr<MobilityModel> mobility = m_adhocTxRSUs.Get(i)->GetObject<MobilityModel>(); 
         if (i == 0) mobility->SetPosition(Vector(307.0, 124.0, 10.0)); 
         if (i == 1) mobility->SetPosition(Vector(600.0, 160.0, 10.0)); 
         if (i == 2) mobility->SetPosition(Vector(600.0, 450.0, 10.0)); 
         if (i == 3) mobility->SetPosition(Vector(300.0, 430.0, 10.0)); 
     } 
     // Configure callback for logging 
     Config::Connect("/NodeList/*/$ns3::MobilityModel/CourseChange", 
                     MakeBoundCallback(&VanetRoutingExperiment::CourseChange, &m_os)); 
 } 
 void 
 VanetRoutingExperiment::SetupAdhocDevices() 
 { 
     if (m_lossModel == 1) 
     { 
         m_lossModelName = "ns3::FriisPropagationLossModel"; 
     } 
     else if (m_lossModel == 2) 
     { 
         m_lossModelName = "ns3::ItuR1411LosPropagationLossModel"; 
     } 
     else if (m_lossModel == 3) 
     { 
         m_lossModelName = "ns3::TwoRayGroundPropagationLossModel"; 
     } 
     else if (m_lossModel == 4) 
     { 
         m_lossModelName = "ns3::LogDistancePropagationLossModel"; 
     } 
     else 
     { 
         // Unsupported propagation loss model. 
         // Treating as ERROR 
         NS_LOG_ERROR("Invalid propagation loss model specified. Values must be [1-4], where " 
                     "1=Friis;2=ItuR1411Los;3=TwoRayGround;4=LogDistance"); 
     } 
     // frequency 
     double freq = 0.0; 
     if ((m_80211mode == 1) || (m_80211mode == 3)) 
     { 
         // 802.11p 5.9 GHz 
         freq = 5.9e9; 
     } 
     else 
     { 
         // 802.11b 2.4 GHz 
         freq = 2.4e9; 
     } 
     // Setup propagation models 
     YansWifiChannelHelper wifiChannel; 
     wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel"); 
     if (m_lossModel == 3) 
     { 
         // two-ray requires antenna height (else defaults to Friis) 
         wifiChannel.AddPropagationLoss(m_lossModelName, 
                                     "Frequency", 
                                     DoubleValue(freq), 
                                     "HeightAboveZ", 
                                     DoubleValue(1.5)); 
     } 
     else 
     { 
         wifiChannel.AddPropagationLoss(m_lossModelName, "Frequency", DoubleValue(freq)); 
     } 
     // Propagation loss models are additive. 
     if (m_fading != 0) 
     { 
         // if no obstacle model, then use Nakagami fading if requested 
         wifiChannel.AddPropagationLoss("ns3::NakagamiPropagationLossModel"); 
     } 
     // the channel 
     Ptr<YansWifiChannel> channel = wifiChannel.Create(); 
     // The below set of helpers will help us to put together the wifi NICs we want 
     YansWifiPhyHelper wifiPhy; 
     YansWifiPhyHelper wifiPhyRSU; 
     wifiPhy.SetChannel(channel); 
     wifiPhyRSU.SetChannel(channel); 
     // ns-3 supports generate a pcap trace 
     wifiPhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11); 
     wifiPhyRSU.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11); 
     YansWavePhyHelper wavePhy = YansWavePhyHelper::Default(); 
     wavePhy.SetChannel(channel); 
     wavePhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11); 
 
     // Setup WAVE PHY and MAC 
     NqosWaveMacHelper wifi80211pMac = NqosWaveMacHelper::Default(); 
     WaveHelper waveHelper = WaveHelper::Default(); 
     Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default(); 
     if (m_verbose) 
     { 
         Wifi80211pHelper::EnableLogComponents(); // Turn on all Wifi 802.11p logging 
         // likewise, turn on WAVE PHY logging 
         WaveHelper::EnableLogComponents(); 
     } 
     WifiHelper wifi; 
     // Setup 802.11b stuff 
     wifi.SetStandard(WIFI_STANDARD_80211b); 
     wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", 
                                 "DataMode", 
                                 StringValue(m_phyModeB), 
                                 "ControlMode", 
                                 StringValue(m_phyModeB)); 
     // Setup 802.11p stuff 
     wifi80211p.SetRemoteStationManager("ns3::ConstantRateWifiManager", 
                                     "DataMode", 
                                     StringValue(m_phyMode), 
                                     "ControlMode", 
                                     StringValue(m_phyMode)); 
     // Setup WAVE-PHY stuff 
     waveHelper.SetRemoteStationManager("ns3::ConstantRateWifiManager", 
                                     "DataMode", 
                                     StringValue(m_phyMode), 
                                     "ControlMode", 
                                     StringValue(m_phyMode)); 
     // Set Tx Power 
     wifiPhy.Set("TxPowerStart", DoubleValue(m_txp)); 
     wifiPhy.Set("TxPowerEnd", DoubleValue(m_txp)); 
     wifiPhyRSU.Set("TxPowerStart", DoubleValue(m_txpRSU)); 
     wifiPhyRSU.Set("TxPowerEnd", DoubleValue(m_txpRSU)); 
     wavePhy.Set("TxPowerStart", DoubleValue(m_txp)); 
     wavePhy.Set("TxPowerEnd", DoubleValue(m_txp)); 
     // Add an upper mac and disable rate control 
     WifiMacHelper wifiMac; 
     wifiMac.SetType("ns3::AdhocWifiMac"); 
     QosWaveMacHelper waveMac = QosWaveMacHelper::Default(); 
     // Setup net devices 
     NodeContainer allNodes; 
     allNodes.Add(m_adhocTxNodes); 
     allNodes.Add(m_adhocTxRSUs); 
     if (m_80211mode == 3) 
     {  
         m_adhocTxDevices = waveHelper.Install(wavePhy, waveMac, m_adhocTxNodes); 
     } 
     else if (m_80211mode == 1) 
     { 
     m_RSUTxDevices = wifi80211p.Install(wifiPhyRSU, wifi80211pMac, m_adhocTxRSUs); 
     m_adhocTxDevices = wifi80211p.Install(wifiPhy, wifi80211pMac, m_adhocTxNodes); 
     } 
     else 
     {  
     m_RSUTxDevices = wifi.Install(wifiPhyRSU, wifiMac,m_adhocTxRSUs);  
     m_adhocTxDevices = wifi.Install(wifiPhy, wifiMac,m_adhocTxNodes); 
 
         
     } 
     if (m_asciiTrace) 
     { 
         AsciiTraceHelper ascii; 
         Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream(m_trName + ".tr"); 
         wifiPhy.EnableAsciiAll(osw); 
         wifiPhyRSU.EnablePcapAll("vanet-routing-compare-pcap"); 
         wavePhy.EnableAsciiAll(osw); 
     } 
     if (m_pcap) 
     { 
         wifiPhy.EnablePcapAll("vanet-routing-compare-pcap"); 
         wifiPhyRSU.EnablePcapAll("vanet-routing-compare-pcap"); 
         wavePhy.EnablePcapAll("vanet-routing-compare-pcap"); 
     } 
 } 
 void 
 VanetRoutingExperiment::SetupWaveMessages() 
 { 
     NodeContainer allNodes; 
     allNodes.Add(m_adhocTxRSUs); 
     allNodes.Add(m_adhocTxNodes); 
     // WAVE PHY mode 
     // 0=continuous channel; 1=channel-switching 
     int chAccessMode = 0; 
     if (m_80211mode == 3) 
     { 
         chAccessMode = 1; 
     } 
     m_waveBsmHelper.Install(m_adhocTxInterfaces, 
                             Seconds(m_TotalSimTime), 
                             m_wavePacketSize, 
                             Seconds(m_waveInterval), 
                             // GPS accuracy (i.e, clock drift), in number of ns 
                             m_gpsAccuracyNs, 
                             m_txSafetyRanges, 
                             chAccessMode, 
                             // tx max delay before transmit, in ms 
                             MilliSeconds(m_txMaxDelayMs)); 
     // fix random number streams 
     //m_streamIndex += m_waveBsmHelper.AssignStreams(allNodes, m_streamIndex); 
 } 
 void
RoutingHelper::SetupRoutingMessages(NodeContainer& vehicles, Ipv4InterfaceContainer& adhocTxInterfaces)
{

}


 
 void
 VanetRoutingExperiment::SetupRoutingMessages (NodeContainer & c,
                                      Ipv4InterfaceContainer & adhocTxInterfaces)
 {
   // Setup routing transmissions
   OnOffHelper onoff1 ("ns3::UdpSocketFactory",Address ());
   onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
   onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
 
   Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
   int64_t stream = 2;
   var->SetStream (stream);
   for (uint32_t i = 0; i < m_nSinks; i++)
     {
       // protocol == 0 means no routing data, WAVE BSM only
       // so do not set up sink
       if (m_protocol != 0)
         {
           // CORRECT
Ptr<Socket> sink = m_routingHelper->SetupRoutingPacketReceive (adhocTxInterfaces.GetAddress (i), c.Get (i));
         }
 
       AddressValue remoteAddress (InetSocketAddress (adhocTxInterfaces.GetAddress (i), m_port));
       onoff1.SetAttribute ("Remote", remoteAddress);
 
       ApplicationContainer temp = onoff1.Install (c.Get (i + m_nSinks));
       temp.Start (Seconds (var->GetValue (1.0,2.0)));
       temp.Stop (Seconds (m_TotalSimTime));
     }
 }





 void 
 VanetRoutingExperiment::SetupScenario() 
 { 
     // member variable parameter use 
     // defaults or command line overrides, 
     // except where scenario={1,2,3,...} 
     // have been specified, in which case 
     // specify parameters are overwritten 
     // here to setup for specific scenarios 
     // certain parameters may be further overridden 
     // i.e. specify a scenario, override tx power. 
     if (m_scenario == 1) 
     { 
         // 40 nodes in RWP 300 m x 1500 m synthetic highway, 10s 
         m_traceFile = ""; 
         m_logFile = ""; 
         m_mobility = 2; 
         if (m_nNodes == 156) 
         { 
             m_nNodes = 40; 
         } 
         if (m_TotalSimTime == 300.01) 
         { 
             m_TotalSimTime = 10.0; 
         } 
     } 
     else if (m_scenario == 2) 
     { 
         // Realistic vehicular trace in 4.6 km x 3.0 km suburban Zurich 
         // "low density, 99 total vehicles" 
         m_traceFile = "/home/mehtix/Desktop/mobility.tcl"; 
         m_logFile = "low99-ct-unterstrass-1day.filt.7.adj.log"; 
         m_mobility = 1; 
         m_nNodes = 20; 
         m_nRSUs =4 ; 
         m_txp=17; 
         m_txpRSU=22; 
         m_nSinks=4; 
         m_TotalSimTime = 730.9; 
         m_nodeSpeed = 20; 
         m_nodePause = 0; 
         m_CSVfileName = "low_vanet-routing-compare.csv"; 
         m_CSVfileName = "low_vanet-routing-compare2.csv"; 
     } 
 } 
 void 
 VanetRoutingExperiment::WriteCsvHeader() 
 { 
     // blank out the last output file and write the column headers 
     std::ofstream out(m_CSVfileName); 
     out << "SimulationSecond," 
         << "ReceiveRate," 
         << "PacketsReceived," 
         << "NumberOfSinks," 
         << "RoutingProtocol," 
         << "TransmissionPower," 
         << "WavePktsSent," 
         << "WavePtksReceived," 
         << "WavePktsPpr," 
         << "ExpectedWavePktsReceived," 
         << "ExpectedWavePktsInCoverageReceived," 
         << "BSM_PDR1," 
         << "BSM_PDR2," 
         << "BSM_PDR3," 
         << "BSM_PDR4," 
         << "BSM_PDR5," 
         << "BSM_PDR6," 
         << "BSM_PDR7," 
         << "BSM_PDR8," 
         << "BSM_PDR9," 
         << "BSM_PDR10," 
         << "MacPhyOverhead" << std::endl; 
     out.close(); 
     std::ofstream out2(m_CSVfileName2); 
     out2 << "BSM_PDR1," 
         << "BSM_PDR2," 
         << "BSM_PDR3," 
         << "BSM_PDR4," 
         << "BSM_PDR5," 
         << "BSM_PDR6," 
         << "BSM_PDR7," 
         << "BSM_PDR8," 
         << "BSM_PDR9," 
         << "BSM_PDR10," 
         << "AverageRoutingGoodputKbps," 
         << "MacPhyOverhead" << std::endl; 
     out2.close(); 
 } 
 int 
 main(int argc, char* argv[]) 
 { 
     std::string keysFilePath = "/home/mehtix/Desktop/1.txt";
    
    // Call the function to populate the global nodePrivateKeys map
    ReadKeysFromFile(keysFilePath, nodePrivateKeys);
     NS_LOG_UNCOND("\n\n\n");
    NS_LOG_UNCOND("======================================================");
    NS_LOG_UNCOND("   COMPILATION CHECK: Starting main() function v2     ");
    NS_LOG_UNCOND("======================================================");
    NS_LOG_UNCOND("\n\n\n");
     LogComponentEnable("Ipv4L3Protocol", LOG_LEVEL_WARN); 
     VanetRoutingExperiment experiment; 
     experiment.Simulate(argc, argv); 
     // ... your scheduling code inside main ... 
 
     return 0; 
 } 
 // vvv PLACE THE FULL FUNCTION DEFINITION HERE (AFTER MAIN) vvv 
 void 
 PrintNodeRoutingTable(Ptr<Node> node, Ptr<OutputStreamWrapper> rtw) 
 { 
     if (!node) 
     { 
         return; 
     } 
     Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>(); 
     if (!ipv4) 
     { 
         return; 
     } 
     // This is a generic way to get the routing protocol and print the table 
     Ptr<Ipv4RoutingProtocol> routingProtocol = ipv4->GetRoutingProtocol(); 
     routingProtocol->PrintRoutingTable(rtw, Time::S); 
     // Schedule the next print 
     Simulator::Schedule(Seconds(377.0), 
                         &PrintNodeRoutingTable, 
                         node, 
                         rtw); 
 }
