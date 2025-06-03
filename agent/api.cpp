#include <iostream>
#include <string>
#include <vector>

// cpp-httplib (header-only)
#include "httplib.h"

// nlohmann json (header-only)
#include "json.hpp"

using json = nlohmann::json;

// Dummy Prozessstruktur
struct Process {
    int pid;
    std::string name;
    float cpu_usage;
};

// Beispiel-Daten (kannst du später durch echte Daten ersetzen)
std::vector<Process> get_process_list() {
    return {
        {1234, "bash", 1.5},
        {5678, "firefox", 10.3},
        {9012, "code", 5.2}
    };
}

int main() {
    httplib::Server svr;

    // GET /processes -> JSON-Liste von Prozessen
    svr.Get("/processes", [](const httplib::Request&, httplib::Response& res) {
        auto procs = get_process_list();

        json j = json::array();
        for (auto& p : procs) {
            j.push_back({
                {"pid", p.pid},
                {"name", p.name},
                {"cpu", p.cpu_usage}
            });
        }

        res.set_content(j.dump(4), "application/json");
    });

    // POST /kill -> kill Prozess per PID (dummy)
    svr.Post("/kill", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            int pid = j.at("pid").get<int>();

            std::cout << "[Kill] PID: " << pid << std::endl;

            // Hier killest du den Prozess (später echte Logik)
            res.set_content("{\"status\":\"success\", \"message\":\"Process killed\"}", "application/json");
        } catch (...) {
            res.status = 400;
            res.set_content("{\"status\":\"error\", \"message\":\"Invalid JSON or PID\"}", "application/json");
        }
    });

    // POST /start -> Prozess starten (dummy)
    svr.Post("/start", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            std::string program = j.at("program").get<std::string>();

            std::cout << "[Start] Program: " << program << std::endl;

            // Hier startest du den Prozess (später echte Logik)
            res.set_content("{\"status\":\"success\", \"message\":\"Process started\"}", "application/json");
        } catch (...) {
            res.status = 400;
            res.set_content("{\"status\":\"error\", \"message\":\"Invalid JSON or program\"}", "application/json");
        }
    });

    std::cout << "Server läuft auf http://localhost:8080\n";
    svr.listen("0.0.0.0", 8080);

    return 0;
}
