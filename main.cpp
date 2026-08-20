#include <arpa/inet.h>
#include <atomic>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <onnxruntime_cxx_api.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <tuple>
#include <vector>
#include <unordered_map>
#include <numeric>
#include <algorithm>
#include <cmath>
#include <optional>


// ----------------------------------------------------------------------
// Constants matching Python parser
// ----------------------------------------------------------------------
const std::string TUNNEL_NET = "10.66.0.";
const size_t WINDOW_SIZE = 40;

// ----------------------------------------------------------------------
// Feature structure (same 9 values as pcap_parser)
// ----------------------------------------------------------------------
struct FlowFeatures {
  float mean_sz;
  float std_sz;
  float min_sz;
  float max_sz;
  float mean_iat;
  float std_iat;
  float pps;
  float bps;
  float up_dn;
};

// ----------------------------------------------------------------------
// Flow key: (proto, (src_ip, src_port), (dst_ip, dst_port)) with sorted
// endpoints
// ----------------------------------------------------------------------
struct Endpoint {
  uint32_t ip;   // network byte order
  uint16_t port; // host byte order? We'll store as uint16_t for comparison
  bool operator==(const Endpoint &other) const {
    return ip == other.ip && port == other.port;
  }
};

struct EndpointHash {
  std::size_t operator()(const Endpoint &e) const {
    return std::hash<uint32_t>()(e.ip) ^ (std::hash<uint16_t>()(e.port) << 1);
  }
};

struct FlowKey {
  uint8_t proto;
  Endpoint src;
  Endpoint dst;
  bool operator==(const FlowKey &other) const {
    return proto == other.proto && src == other.src && dst == other.dst;
  }
};

struct FlowKeyHash {
  std::size_t operator()(const FlowKey &k) const {
    return std::hash<uint8_t>()(k.proto) ^ (EndpointHash()(k.src) << 1) ^
           (EndpointHash()(k.dst) << 2);
  }
};

// ----------------------------------------------------------------------
// Packet record: timestamp (seconds), length, direction (+1 or -1)
// ----------------------------------------------------------------------
struct PacketRecord {
  double timestamp;
  int length;
  int direction;
};

// ----------------------------------------------------------------------
// Flow state: stores up to WINDOW_SIZE packets and computes features
// ----------------------------------------------------------------------
class FlowState {
public:
  void addPacket(double ts, int len, int dir) {
    records.push_back({ts, len, dir});
    if (records.size() >= WINDOW_SIZE) {
      // Window is full – compute features and predict
      features = computeFeatures();
      // Then clear for next non‑overlapping window
      records.clear();
    }
  }

  bool hasFeatures() const { return features.has_value(); }
  const FlowFeatures &getFeatures() const { return features.value(); }
  void resetFeatures() { features.reset(); }

private:
  std::vector<PacketRecord> records;
  std::optional<FlowFeatures> features;

  FlowFeatures computeFeatures() {
    // Sort by timestamp
    std::sort(records.begin(), records.end(),
              [](const PacketRecord &a, const PacketRecord &b) {
                return a.timestamp < b.timestamp;
              });
    const auto &records_len{records.size()};
    std::vector<double> times;
    times.reserve(records_len);
    std::vector<double> sizes;
    sizes.reserve(records_len);
    std::vector<int> dirs;
    dirs.reserve(records_len);
    for (const auto &r : records) {
      times.push_back(r.timestamp);
      sizes.push_back(r.length);
      dirs.push_back(r.direction);
    }

    // Inter-arrival times
    std::vector<double> iats;
    for (size_t i = 1; i < times.size(); ++i) {
      iats.push_back(times[i] - times[i - 1]);
    }

    // Up/down bytes
    double up_bytes = 0.0, down_bytes = 0.0;
    for (size_t i = 0; i < sizes.size(); ++i) {
      if (dirs[i] > 0)
        up_bytes += sizes[i];
      else
        down_bytes += sizes[i];
    }

    double duration = std::max(1e-3, times.back() - times.front());

    // Statistics
    double mean_sz =
        std::accumulate(sizes.begin(), sizes.end(), 0.0) / sizes.size();
    double std_sz = 0.0;
    if (sizes.size() > 1) {
      double sq_sum =
          std::inner_product(sizes.begin(), sizes.end(), sizes.begin(), 0.0);
      double val = (sq_sum / sizes.size()) - (mean_sz * mean_sz);
      std_sz = std::sqrt(std::max(0.0, val));
    }

    double min_sz = *std::min_element(sizes.begin(), sizes.end());
    double max_sz = *std::max_element(sizes.begin(), sizes.end());

    double mean_iat = 0.0, std_iat = 0.0;
    if (!iats.empty()) {
      mean_iat = std::accumulate(iats.begin(), iats.end(), 0.0) / iats.size();
      if (iats.size() > 1) {
        double sq_sum =
            std::inner_product(iats.begin(), iats.end(), iats.begin(), 0.0);
        double val = (sq_sum / iats.size()) - (mean_iat * mean_iat);
        std_iat = std::sqrt(std::max(0.0, val));
      }
    }

    double pps = records.size() / duration;
    double bps = std::accumulate(sizes.begin(), sizes.end(), 0.0) / duration;
    double up_dn = (up_bytes + 1.0) / (down_bytes + 1.0); // smoothing

    return FlowFeatures{
        static_cast<float>(mean_sz),  static_cast<float>(std_sz),
        static_cast<float>(min_sz),   static_cast<float>(max_sz),
        static_cast<float>(mean_iat), static_cast<float>(std_iat),
        static_cast<float>(pps),      static_cast<float>(bps),
        static_cast<float>(up_dn)};
  }
};

// ----------------------------------------------------------------------
// Model wrapper (same as before, but now predicts on features)
// ----------------------------------------------------------------------
class Model {
public:

  Model() {
    env_ = Ort::Env(ORT_LOGGING_LEVEL_WARNING, "VPNClassifier");
    Ort::SessionOptions session_options;
    session_options.SetIntraOpNumThreads(1);
    session_ = Ort::Session(env_, "model/model.onnx", session_options);

    Ort::AllocatorWithDefaultOptions allocator;
    auto in_name_alloc = session_.GetInputNameAllocated(0, allocator);
    auto out_name_alloc = session_.GetOutputNameAllocated(0, allocator);
    input_name_ = in_name_alloc.get();
    output_name_ = out_name_alloc.get();

    std::cout << "Model loaded. Input name: " << input_name_
              << ", Output name: " << output_name_ << std::endl;
  }

  std::string predict(const FlowFeatures &feat){
    // Convert features to vector of 9 floats in exact order: mean_sz, std_sz,
    // min_sz, max_sz, mean_iat, std_iat, pps, bps, up_dn
    std::vector<float> features = {feat.mean_sz, feat.std_sz,   feat.min_sz,
                                   feat.max_sz,  feat.mean_iat, feat.std_iat,
                                   feat.pps,     feat.bps,      feat.up_dn};

    std::vector<int64_t> shape = {1, static_cast<int64_t>(features.size())};
    static auto memory_info =
        Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
        memory_info, features.data(), features.size(), shape.data(),
        shape.size());

    const char *input_names[] = {input_name_.c_str()};
    const char *output_names[] = {output_name_.c_str()};
    std::vector<Ort::Value> output_tensors =
        session_.Run(Ort::RunOptions{nullptr}, input_names, &input_tensor, 1,
                     output_names, 1);
    auto &output_tensor = output_tensors[0];
    size_t count = output_tensor.GetTensorTypeAndShapeInfo().GetElementCount();
    size_t total_len = output_tensor.GetStringTensorDataLength();
    std::vector<char> buffer(total_len);
    std::vector<size_t> offsets(count);
    output_tensor.GetStringTensorContent(buffer.data(), total_len, offsets.data(), count);
    size_t start = offsets[0];
    size_t end = (count > 1) ? offsets[1] : total_len;

    return std::string(buffer.data() + start, end - start);
  }

private:
  Ort::Env env_{nullptr};
  Ort::Session session_{nullptr};
  std::string input_name_;
  std::string output_name_;
};

// ----------------------------------------------------------------------
// Helper: build flow key from packet
// ----------------------------------------------------------------------
static std::optional<FlowKey> buildFlowKey(const pcpp::Packet &packet, pcpp::IPv4Layer* ipLayer) {
  if (!ipLayer) {
    return std::nullopt;
  }

  uint8_t proto = ipLayer->getIPv4Header()->protocol;
  uint32_t src_ip = ipLayer->getSrcIPv4Address().toInt();
  uint32_t dst_ip = ipLayer->getDstIPv4Address().toInt();

  uint16_t src_port = 0, dst_port = 0;
  auto *tcp = packet.getLayerOfType<pcpp::TcpLayer>();
  auto *udp = packet.getLayerOfType<pcpp::UdpLayer>();
  if (tcp) {
    src_port = tcp->getSrcPort();
    dst_port = tcp->getDstPort();
  } else if (udp) {
    src_port = udp->getSrcPort();
    dst_port = udp->getDstPort();
  } else {
    return std::nullopt; // only TCP/UDP
  }

  // Sort endpoints for bidirectionality
  Endpoint e1{src_ip, src_port};
  Endpoint e2{dst_ip, dst_port};
  if (e1.ip < e2.ip || (e1.ip == e2.ip && e1.port < e2.port)) {
    return FlowKey{proto, e1, e2};
  } else {
    return FlowKey{proto, e2, e1};
  }
}

// ----------------------------------------------------------------------
// Packet callback
// ----------------------------------------------------------------------
static std::unordered_map<FlowKey, FlowState, FlowKeyHash> flowMap;

static void onPacketArrives(pcpp::RawPacket *rawPacket,
                            pcpp::PcapLiveDevice *dev, void *cookie) {
  Model *model = static_cast<Model *>(cookie);
  pcpp::Packet packet(rawPacket);

  // Determine direction: +1 if source IP starts with TUNNEL_NET, else -1
  pcpp::IPv4Layer *ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
  if (!ipLayer) {
    return;
  }
  std::string src_ip_str = ipLayer->getSrcIPAddress().toString();
  int direction =
      (src_ip_str.compare(0, TUNNEL_NET.size(), TUNNEL_NET) == 0) ? 1 : -1;

  auto keyOpt = buildFlowKey(packet, ipLayer);
  if (!keyOpt)
    return;
  FlowKey key = keyOpt.value();

  // Get timestamp as double seconds
  timespec ts = rawPacket->getPacketTimeStamp();
  double timestamp = ts.tv_sec + ts.tv_nsec / 1e9;

  // Add packet to flow
  auto &flow = flowMap[key];
  // std::cout << "Packet timestamp " << timestamp << " len: " << packet.getRawPacket()->getRawDataLen() << " direction " << direction << std::endl;
  flow.addPacket(timestamp, packet.getRawPacket()->getRawDataLen(), direction);

  // If flow has computed features, run inference and print result
  if (flow.hasFeatures()) {
    const FlowFeatures &feat = flow.getFeatures();
    std::cout << "Predicted class: " << model->predict(feat) << std::endl;
    flow.resetFeatures(); 
  }
}

// ----------------------------------------------------------------------
// Signal handling for graceful shutdown (Ctrl+C / SIGTERM)
// ----------------------------------------------------------------------
static std::atomic<bool> g_stop{false};

static void onSignal(int) { g_stop.store(true); }

// ----------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------
int main() {
  std::signal(SIGINT, onSignal);
  std::signal(SIGTERM, onSignal);

  Model model;

  const std::string interfaceIP = "10.66.0.1";
  auto *dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(
      interfaceIP);
  if (dev == nullptr) {
    std::cerr << "Cannot find interface with IP " << interfaceIP << std::endl;
    return 1;
  }

  std::cout << "Using interface: " << dev->getName() << std::endl;

  if (!dev->open()) {
    std::cerr << "Cannot open device" << std::endl;
    return 1;
  }

  // Filter to IP packets only
  if (!dev->setFilter("ip")) {
    std::cerr << "Warning: failed to set BPF filter" << std::endl;
  }

  dev->startCapture(onPacketArrives, &model);

  std::cout << "Capturing packets. Press Ctrl+C to stop..." << std::endl;
  while (!g_stop.load()) {
    pcpp::multiPlatformSleep(1);
  }

  std::cout << "Stopping capture..." << std::endl;
  dev->stopCapture();
  dev->close();

  return 0;
}