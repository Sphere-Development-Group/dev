#include <iostream>
#include <string>
#include <vector>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>

#include <string>
using namespace std;

#include "src/core/manager.hpp"

static void print_usage(const char* progname) {
  std::cout << "Usage: " << progname << " [EAL options] -- [APP options]\n\n"
            << "APP options:\n"
            << "  --socket-path <path>     UNIX socket path (default: "
               "/tmp/traffic_gen.sock)\n"
            << "  -h, --help               Show this help\n"
            << std::endl;
}

int main() {
  std::string sock_path = "/tmp/traffic_gen.sock";
  string core_mask = "0-" + to_string(sysconf(_SC_NPROCESSORS_CONF) - 1);

  vector<const char*> eal_config = {
      "main",         "-l", core_mask.c_str(), "-a",
      "0000:01:00.0", "-a", "0000:01:00.1"};
};

// ====================== Парсинг APP аргументов ======================
// int opt;
// while ((opt = getopt(argc, argv, "h")) != -1) {
//   switch (opt) {
//     case 'h':
//       print_usage(argv[0]);
//       return 0;
//     default:
//       print_usage(argv[0]);
//       return 1;
//   }
// }

// // Если после -- остались аргументы — можно их обработать позже
// if (optind < argc) {
//   if (std::string(argv[optind]) == "--socket-path" && optind + 1 < argc) {
//     sock_path = argv[optind + 1];
//   }
// }

// ====================== Инициализация DPDK ======================
int ret =
    rte_eal_init(eal_config.size(), const_cast<char**>(eal_config.data()));
if (ret < 0) {
  RTE_LOG(ERR, USER1, "EAL initialization failed\n");
  return 1;
}

RTE_LOG(INFO,
        USER1,
        "DPDK EAL initialized. Running on lcore %u\n",
        rte_lcore_id());

// ====================== Запуск Manager ======================
try {
  Manager manager(sock_path);

  if (!manager.init_socket()) {
    RTE_LOG(ERR, USER1, "Failed to initialize UNIX socket: %s\n",
            sock_path.c_str());
    return 1;
  }

  std::cout << "==================================================\n";
  std::cout << "Sphere Traffic Generator started\n";
  std::cout << "Control socket: " << sock_path << "\n";
  std::cout << "Available worker lcores: ";

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