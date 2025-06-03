#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <signal.h>
#include <cstdlib>
#include <algorithm>
#include <iomanip>

// cpp-httplib (header-only)
#include "httplib.h"

// nlohmann json (header-only)
#include "json.hpp"

using json = nlohmann::json;

// Strukturen für Systemdaten
struct Process {
    int pid;
    std::string name;
    std::string user;
    float cpu_usage;
    float memory_usage;
    long memory_kb;
    std::string state;
    std::string cmd;
};

struct SystemInfo {
    double cpu_usage;
    double cpu_user;
    double cpu_system;
    long memory_total;
    long memory_used;
    long memory_free;
    double memory_usage_percent;
    long disk_total;
    long disk_used;
    long disk_free;
    double disk_usage_percent;
    std::string uptime;
    std::string load_avg;
    std::string hostname;
    std::string os_version;
    std::string kernel_version;
    std::string architecture;
    long network_rx_bytes;
    long network_tx_bytes;
};

// Utility-Funktionen
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(trim(token));
    }
    return tokens;
}

std::string read_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return "";
    
    std::string content;
    std::string line;
    while (std::getline(file, line)) {
        content += line + "\n";
    }
    return content;
}

// CPU-Statistiken lesen
SystemInfo get_system_info() {
    SystemInfo info = {};
    
    // CPU-Statistiken aus /proc/stat
    std::ifstream stat_file("/proc/stat");
    std::string line;
    if (std::getline(stat_file, line)) {
        std::istringstream iss(line);
        std::string cpu_label;
        long user, nice, system, idle, iowait, irq, softirq;
        iss >> cpu_label >> user >> nice >> system >> idle >> iowait >> irq >> softirq;
        
        long total = user + nice + system + idle + iowait + irq + softirq;
        long active = total - idle - iowait;
        
        info.cpu_usage = (double)active / total * 100.0;
        info.cpu_user = (double)(user + nice) / total * 100.0;
        info.cpu_system = (double)(system + irq + softirq) / total * 100.0;
    }
    
    // Memory-Informationen
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.memory_total = si.totalram / 1024; // KB
        info.memory_free = si.freeram / 1024;   // KB
        info.memory_used = info.memory_total - info.memory_free;
        info.memory_usage_percent = (double)info.memory_used / info.memory_total * 100.0;
    }
    
    // Disk-Informationen (Root-Partition)
    struct statvfs disk_info;
    if (statvfs("/", &disk_info) == 0) {
        info.disk_total = (disk_info.f_blocks * disk_info.f_frsize) / (1024 * 1024); // MB
        info.disk_free = (disk_info.f_bavail * disk_info.f_frsize) / (1024 * 1024);  // MB
        info.disk_used = info.disk_total - info.disk_free;
        info.disk_usage_percent = (double)info.disk_used / info.disk_total * 100.0;
    }
    
    // Uptime
    std::ifstream uptime_file("/proc/uptime");
    if (uptime_file) {
        double uptime_seconds;
        uptime_file >> uptime_seconds;
        
        int days = uptime_seconds / 86400;
        int hours = (uptime_seconds - days * 86400) / 3600;
        int minutes = (uptime_seconds - days * 86400 - hours * 3600) / 60;
        
        std::ostringstream oss;
        oss << days << "d " << hours << "h " << minutes << "m";
        info.uptime = oss.str();
    }
    
    // Load Average
    std::ifstream loadavg_file("/proc/loadavg");
    if (loadavg_file) {
        std::string load_line;
        std::getline(loadavg_file, load_line);
        auto parts = split(load_line, ' ');
        if (parts.size() >= 3) {
            info.load_avg = parts[0] + ", " + parts[1] + ", " + parts[2];
        }
    }
    
    // Hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        info.hostname = hostname;
    }
    
    // OS Version
    info.os_version = read_file("/etc/os-release");
    if (!info.os_version.empty()) {
        // Extrahiere PRETTY_NAME
        size_t pos = info.os_version.find("PRETTY_NAME=\"");
        if (pos != std::string::npos) {
            pos += 13; // Länge von "PRETTY_NAME=\""
            size_t end = info.os_version.find("\"", pos);
            if (end != std::string::npos) {
                info.os_version = info.os_version.substr(pos, end - pos);
            }
        }
    }
    
    // Kernel Version
    std::ifstream version_file("/proc/version");
    if (version_file) {
        std::string version_line;
        std::getline(version_file, version_line);
        auto parts = split(version_line, ' ');
        if (parts.size() >= 3) {
            info.kernel_version = parts[2];
        }
    }
    
    // Architecture
    info.architecture = "x86_64"; // Vereinfacht
    
    // Network Statistics (vereinfacht)
    std::ifstream net_file("/proc/net/dev");
    if (net_file) {
        std::string line;
        std::getline(net_file, line); // Header 1
        std::getline(net_file, line); // Header 2
        
        while (std::getline(net_file, line)) {
            if (line.find("eth0:") != std::string::npos || line.find("enp") != std::string::npos) {
                auto parts = split(line, ' ');
                if (parts.size() >= 10) {
                    info.network_rx_bytes = std::stol(parts[1]);
                    info.network_tx_bytes = std::stol(parts[9]);
                    break;
                }
            }
        }
    }
    
    return info;
}

// Prozessliste lesen
std::vector<Process> get_process_list() {
    std::vector<Process> processes;
    
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return processes;
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Prüfe ob es eine PID ist (nur Zahlen)
        std::string name = entry->d_name;
        if (name.find_first_not_of("0123456789") != std::string::npos) {
            continue;
        }
        
        int pid = std::stoi(name);
        Process proc;
        proc.pid = pid;
        
        // Lese /proc/PID/stat
        std::string stat_path = "/proc/" + name + "/stat";
        std::ifstream stat_file(stat_path);
        if (!stat_file) continue;
        
        std::string stat_line;
        std::getline(stat_file, stat_line);
        
        // Parse stat file (vereinfacht)
        std::istringstream iss(stat_line);
        std::string token;
        std::vector<std::string> stat_fields;
        while (iss >> token) {
            stat_fields.push_back(token);
        }
        
        if (stat_fields.size() < 24) continue;
        
        // Prozessname (entferne Klammern)
        proc.name = stat_fields[1];
        if (proc.name.front() == '(' && proc.name.back() == ')') {
            proc.name = proc.name.substr(1, proc.name.length() - 2);
        }
        
        // Status
        proc.state = stat_fields[2];
        
        // CPU-Zeit (vereinfacht)
        long utime = std::stol(stat_fields[13]);
        long stime = std::stol(stat_fields[14]);
        proc.cpu_usage = (utime + stime) / 100.0; // Vereinfachte Berechnung
        
        // Memory (RSS in Pages, konvertiere zu KB)
        long rss_pages = std::stol(stat_fields[23]);
        proc.memory_kb = rss_pages * 4; // 4KB pro Page (typisch)
        
        // Memory-Prozentsatz
        SystemInfo sys_info = get_system_info();
        proc.memory_usage = (double)proc.memory_kb / sys_info.memory_total * 100.0;
        
        // Lese cmdline für vollständigen Befehl
        std::string cmdline_path = "/proc/" + name + "/cmdline";
        std::ifstream cmdline_file(cmdline_path);
        if (cmdline_file) {
            std::getline(cmdline_file, proc.cmd);
            // Ersetze Null-Bytes durch Leerzeichen
            std::replace(proc.cmd.begin(), proc.cmd.end(), '\0', ' ');
            if (proc.cmd.empty()) {
                proc.cmd = "[" + proc.name + "]";
            }
        }
        
        // User (vereinfacht - immer "system")
        proc.user = "system";
        
        processes.push_back(proc);
    }
    
    closedir(proc_dir);
    
    // Sortiere nach CPU-Verbrauch
    std::sort(processes.begin(), processes.end(), 
              [](const Process& a, const Process& b) {
                  return a.cpu_usage > b.cpu_usage;
              });
    
    // Begrenze auf Top 50 Prozesse
    if (processes.size() > 50) {
        processes.resize(50);
    }
    
    return processes;
}

// Prozess beenden
bool kill_process(int pid) {
    if (pid <= 1) return false; // Schütze kritische Prozesse
    
    int result = kill(pid, SIGTERM);
    if (result != 0) {
        // Versuche SIGKILL falls SIGTERM fehlschlägt
        result = kill(pid, SIGKILL);
    }
    
    return result == 0;
}

// Programm starten
bool start_program(const std::string& program) {
    if (program.empty()) return false;
    
    // Einfacher Aufruf mit system() - in Produktion sollte exec() verwendet werden
    std::string command = program + " &";
    int result = system(command.c_str());
    
    return result == 0;
}

int main() {
    httplib::Server svr;
    
    // CORS-Header für alle Requests
    svr.set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return httplib::Server::HandlerResponse::Unhandled;
    });
    
    // OPTIONS-Handler für CORS Preflight
    svr.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        return;
    });
    
    // GET /processes -> JSON-Liste von Prozessen
    svr.Get("/processes", [](const httplib::Request&, httplib::Response& res) {
        try {
            auto processes = get_process_list();
            
            json j = json::array();
            for (const auto& p : processes) {
                j.push_back({
                    {"pid", p.pid},
                    {"name", p.name},
                    {"user", p.user},
                    {"cpu", std::round(p.cpu_usage * 10) / 10.0}, // Runde auf 1 Dezimalstelle
                    {"memory", std::round(p.memory_usage * 10) / 10.0},
                    {"memory_kb", p.memory_kb},
                    {"state", p.state},
                    {"cmd", p.cmd}
                });
            }
            
            std::cout << "[INFO] Sent " << processes.size() << " processes" << std::endl;
            res.set_content(j.dump(2), "application/json");
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] /processes: " << e.what() << std::endl;
            res.status = 500;
            res.set_content("{\"error\":\"Internal server error\"}", "application/json");
        }
    });
    
    // GET /system -> Systeminformationen
    svr.Get("/system", [](const httplib::Request&, httplib::Response& res) {
        try {
            auto sys_info = get_system_info();
            
            json j = {
                {"cpu", {
                    {"usage", std::round(sys_info.cpu_usage * 10) / 10.0},
                    {"user", std::round(sys_info.cpu_user * 10) / 10.0},
                    {"system", std::round(sys_info.cpu_system * 10) / 10.0}
                }},
                {"memory", {
                    {"total_kb", sys_info.memory_total},
                    {"used_kb", sys_info.memory_used},
                    {"free_kb", sys_info.memory_free},
                    {"usage_percent", std::round(sys_info.memory_usage_percent * 10) / 10.0}
                }},
                {"disk", {
                    {"total_mb", sys_info.disk_total},
                    {"used_mb", sys_info.disk_used},
                    {"free_mb", sys_info.disk_free},
                    {"usage_percent", std::round(sys_info.disk_usage_percent * 10) / 10.0}
                }},
                {"network", {
                    {"rx_bytes", sys_info.network_rx_bytes},
                    {"tx_bytes", sys_info.network_tx_bytes}
                }},
                {"uptime", sys_info.uptime},
                {"load_avg", sys_info.load_avg},
                {"hostname", sys_info.hostname},
                {"os_version", sys_info.os_version},
                {"kernel_version", sys_info.kernel_version},
                {"architecture", sys_info.architecture}
            };
            
            std::cout << "[INFO] Sent system information" << std::endl;
            res.set_content(j.dump(2), "application/json");
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] /system: " << e.what() << std::endl;
            res.status = 500;
            res.set_content("{\"error\":\"Internal server error\"}", "application/json");
        }
    });
    
    // POST /kill -> Prozess beenden
    svr.Post("/kill", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            int pid = j.at("pid").get<int>();
            
            std::cout << "[KILL] Attempting to kill PID: " << pid << std::endl;
            
            if (pid <= 1) {
                res.status = 400;
                res.set_content("{\"status\":\"error\", \"message\":\"Cannot kill system processes (PID <= 1)\"}", "application/json");
                return;
            }
            
            bool success = kill_process(pid);
            
            if (success) {
                std::cout << "[KILL] Successfully killed PID: " << pid << std::endl;
                res.set_content("{\"status\":\"success\", \"message\":\"Process killed successfully\"}", "application/json");
            } else {
                std::cout << "[KILL] Failed to kill PID: " << pid << std::endl;
                res.status = 500;
                res.set_content("{\"status\":\"error\", \"message\":\"Failed to kill process - may not exist or insufficient permissions\"}", "application/json");
            }
        } catch (const json::exception& e) {
            std::cerr << "[ERROR] /kill JSON error: " << e.what() << std::endl;
            res.status = 400;
            res.set_content("{\"status\":\"error\", \"message\":\"Invalid JSON format\"}", "application/json");
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] /kill: " << e.what() << std::endl;
            res.status = 500;
            res.set_content("{\"status\":\"error\", \"message\":\"Internal server error\"}", "application/json");
        }
    });
    
    // POST /start -> Programm starten
    svr.Post("/start", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            std::string program = j.at("program").get<std::string>();
            
            std::cout << "[START] Attempting to start program: " << program << std::endl;
            
            // Einfache Sicherheitsprüfung
            if (program.find("rm") != std::string::npos || 
                program.find("dd") != std::string::npos ||
                program.find("mkfs") != std::string::npos ||
                program.find("format") != std::string::npos) {
                res.status = 403;
                res.set_content("{\"status\":\"error\", \"message\":\"Dangerous command blocked\"}", "application/json");
                return;
            }
            
            bool success = start_program(program);
            
            if (success) {
                std::cout << "[START] Successfully started program: " << program << std::endl;
                res.set_content("{\"status\":\"success\", \"message\":\"Program started successfully\"}", "application/json");
            } else {
                std::cout << "[START] Failed to start program: " << program << std::endl;
                res.status = 500;
                res.set_content("{\"status\":\"error\", \"message\":\"Failed to start program\"}", "application/json");
            }
        } catch (const json::exception& e) {
            std::cerr << "[ERROR] /start JSON error: " << e.what() << std::endl;
            res.status = 400;
            res.set_content("{\"status\":\"error\", \"message\":\"Invalid JSON format\"}", "application/json");
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] /start: " << e.what() << std::endl;
            res.status = 500;
            res.set_content("{\"status\":\"error\", \"message\":\"Internal server error\"}", "application/json");
        }
    });
    
    // GET /health -> Health Check
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json j = {
            {"status", "healthy"},
            {"timestamp", time(nullptr)},
            {"server", "rhtop-backend"},
            {"version", "1.0.0"}
        };
        res.set_content(j.dump(2), "application/json");
    });
    
    // Error Handler
    svr.set_error_handler([](const httplib::Request&, httplib::Response& res) {
        json error_response = {
            {"error", "Not Found"},
            {"status", res.status},
            {"message", "The requested endpoint does not exist"}
        };
        res.set_content(error_response.dump(2), "application/json");
    });
    
    std::cout << "========================================" << std::endl;
    std::cout << "    rhtop Backend Server v1.0.0" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Server starting on http://0.0.0.0:8080" << std::endl;
    std::cout << "Available endpoints:" << std::endl;
    std::cout << "  GET  /processes - List all processes" << std::endl;
    std::cout << "  GET  /system    - System information" << std::endl;
    std::cout << "  POST /kill      - Kill process by PID" << std::endl;
    std::cout << "  POST /start     - Start new program" << std::endl;
    std::cout << "  GET  /health    - Health check" << std::endl;
    std::cout << "========================================" << std::endl;
    
    bool server_started = svr.listen("0.0.0.0", 8080);
    
    if (!server_started) {
        std::cerr << "[ERROR] Failed to start server on port 8080" << std::endl;
        std::cerr << "Make sure the port is not already in use." << std::endl;
        return 1;
    }
    
    return 0;
}