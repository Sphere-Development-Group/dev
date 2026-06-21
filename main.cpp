#include <getopt.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>

// YAML parser
#include <yaml-cpp/yaml.h>

#include "src/core/manager.hpp"

static void print_usage(const char* progname) {
  std::cout << "Usage: " << progname << " [options]\n\n"
            << "Options:\n"
            << "  -c, --config <path>      Path to YAML config file (default: "
               "/etc/traffic_gen/config.yaml)\n"
            << "  -s, --socket <path>      UNIX socket path (default: "
               "/tmp/traffic_gen.sock)\n"
            << "  -h, --help               Show this help\n"
            << std::endl;
}

struct Config {
  std::string socket_path = "/tmp/traffic_gen.sock";
  std::vector<std::string> pci_devices;
  std::string core_mask;
};

// Парсинг YAML конфигурации
Config parse_yaml_config(const std::string& config_path) {
  Config cfg;

  try {
    YAML::Node yaml = YAML::LoadFile(config_path);

    // Socket path
    if (yaml["socket_path"]) {
      cfg.socket_path = yaml["socket_path"].as<std::string>();
    }

    // Core mask (опционально, если не указан — используем все ядра)
    if (yaml["core_mask"]) {
      cfg.core_mask = yaml["core_mask"].as<std::string>();
    }

    // PCI devices (обязательно)
    if (!yaml["pci_devices"]) {
      throw std::runtime_error("'pci_devices' not found in YAML config");
    }

    auto devices = yaml["pci_devices"].as<std::vector<std::string>>();
    if (devices.empty()) {
      throw std::runtime_error("'pci_devices' list is empty in YAML config");
    }

    cfg.pci_devices = devices;

    RTE_LOG(INFO, USER1, "Config loaded: socket=%s, devices=%zu\n",
            cfg.socket_path.c_str(), cfg.pci_devices.size());

  } catch (const YAML::Exception& e) {
    RTE_LOG(ERR, USER1, "YAML parsing error: %s\n", e.what());
    throw;
  } catch (const std::exception& e) {
    RTE_LOG(ERR, USER1, "Config error: %s\n", e.what());
    throw;
  }

  return cfg;
}

// Построение аргументов EAL из конфига
std::vector<char*> build_eal_config(const Config& cfg) {
  std::vector<char*> eal_args;

  // Program name
  eal_args.push_back(const_cast<char*>("traffic_gen"));

  // Core mask
  std::string core_mask;
  if (!cfg.core_mask.empty()) {
    core_mask = cfg.core_mask;
  } else {
    // Автоматически: все ядра
    int num_cpus = sysconf(_SC_NPROCESSORS_CONF);
    if (num_cpus <= 0)
      num_cpus = 4;  // fallback
    core_mask = "0-" + std::to_string(num_cpus - 1);
  }

  eal_args.push_back(const_cast<char*>("-l"));
  eal_args.push_back(const_cast<char*>(core_mask.c_str()));

  // PCI devices: -a <pci> для каждого
  std::vector<std::string> pci_strings;
  for (const auto& pci : cfg.pci_devices) {
    eal_args.push_back(const_cast<char*>("-a"));
    pci_strings.push_back(pci);
    eal_args.push_back(const_cast<char*>(pci_strings.back().c_str()));
  }

  return eal_args;
}

int main(int argc, char* argv[]) {
  std::string config_path = "/etc/traffic_gen/config.yaml";
  std::string socket_path = "/tmp/traffic_gen.sock";

  // Парсинг командной строки
  const struct option long_options[] = {
      {"config", required_argument, nullptr, 'c'},
      {"socket", required_argument, nullptr, 's'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "c:s:h", long_options, nullptr)) !=
         -1) {
    switch (opt) {
      case 'c':
        config_path = optarg;
        break;
      case 's':
        socket_path = optarg;
        break;
      case 'h':
        print_usage(argv[0]);
        return 0;
      default:
        print_usage(argv[0]);
        return 1;
    }
  }

  // ====================== Загрузка конфигурации ======================
  Config cfg;
  try {
    cfg = parse_yaml_config(config_path);
    // Если указана сокет опция, перезаписываем конфиг
    if (socket_path != "/tmp/traffic_gen.sock") {
      cfg.socket_path = socket_path;
    }
  } catch (const std::exception& e) {
    std::cerr << "Failed to load config: " << e.what() << std::endl;
    std::cerr << "Using default config path: " << config_path << std::endl;
    return 1;
  }

  // ====================== Построение аргументов EAL ======================
  auto eal_config = build_eal_config(cfg);

  RTE_LOG(INFO, USER1,
          "Initializing DPDK with core mask and %zu PCI device(s)\n",
          cfg.pci_devices.size());

  // ====================== Инициализация DPDK ======================
  int ret =
      rte_eal_init(static_cast<int>(eal_config.size()), eal_config.data());
  if (ret < 0) {
    RTE_LOG(ERR, USER1, "EAL initialization failed\n");
    return 1;
  }

  RTE_LOG(INFO, USER1, "DPDK EAL initialized. Running on lcore %u\n",
          rte_lcore_id());

  // ====================== Запуск Manager ======================
  try {
    Manager manager(cfg.socket_path);

    if (!manager.init_socket()) {
      RTE_LOG(ERR, USER1, "Failed to initialize UNIX socket: %s\n",
              cfg.socket_path.c_str());
      return 1;
    }

    std::cout << "==================================================\n";
    std::cout << "Sphere Traffic Generator started\n";
    std::cout << "Control socket: " << cfg.socket_path << "\n";
    std::cout << "PCI Devices: ";
    for (const auto& pci : cfg.pci_devices) {
      std::cout << pci << " ";
    }
    std::cout << "\nAvailable worker lcores: ";

    unsigned lcore;
    RTE_LCORE_FOREACH_WORKER(lcore) {
      std::cout << lcore << " ";
    }
    std::cout << "\n==================================================\n"
              << std::endl;

    manager.run();  // Блокирующий вызов — основной цикл

  } catch (const std::exception& e) {
    RTE_LOG(ERR, USER1, "Exception: %s\n", e.what());
    return 1;
  }

  RTE_LOG(INFO, USER1, "Traffic Generator shutting down...\n");
  return 0;
}