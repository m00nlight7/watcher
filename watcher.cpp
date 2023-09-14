#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>
#include <sstream>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

// LOGGING TO SPECIFIC FILE
void logMessage(const std::string& message, std::ofstream& logFile) {
    // GET SYSTEM TIME$DATE
    time_t now = time(0);
    struct tm* timeinfo = localtime(&now);
    char timestamp[80];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    logFile << "[" << timestamp << "] " << message << std::endl;
}

// TCP connect to logstash
int sendToLogstash(const std::string& jsonData, const std::string& logstashHost, int logstashPort) {
    int sockfd;
    struct sockaddr_in server_addr;

    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error socket creation." << std::endl;
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(logstashPort);
    server_addr.sin_addr.s_addr = inet_addr(logstashHost.c_str());

    // connect to Logstash
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error during Logstash connection." << std::endl;
        close(sockfd);
        return 1;
    }

    // Send data
    if (send(sockfd, jsonData.c_str(), jsonData.size(), 0) < 0) {
        std::cerr << "Error sending data to Logstash." << std::endl;
        close(sockfd);
        return 1;
    }

    // close socket
    close(sockfd);

    return 0;
}

// Scanning 
void scanAndWriteResult(const std::string& targetIP, std::ofstream& outputFile, std::ofstream& logFile, const std::string& logstashHost, int logstashPort) {
    time_t now = time(0);
    struct tm* timeinfo = localtime(&now);
    char timestamp[80];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    //Command for scanning
    std::string nmapCommand = "nmap -sS -p- " + targetIP;

    FILE* pipe = popen(nmapCommand.c_str(), "r");
    if (!pipe) {
        logMessage("Error during scanning " + targetIP, logFile);
        return;
    }

    // Parsing
    char buffer[128];
    std::string openPorts;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        // Find open ports
        if (strstr(buffer, "open") != NULL) {
            char* token = strtok(buffer, "/");
            while (token != NULL) {
                if (isdigit(token[0])) {
                    openPorts += token;
                    openPorts += " ";
                }
                token = strtok(NULL, "/");
            }
        }
    }
    pclose(pipe);

    // Create JSON
    std::ostringstream jsonStream;
    jsonStream << "{"
               << "\"date\": \"" << timestamp << "\", "
               << "\"ip\": \"" << targetIP << "\", "
               << "\"open_ports\": \"" << openPorts << "\""
               << "}";

    std::string jsonPayload = jsonStream.str();

    outputFile << "| " << timestamp << " | ----- | " << targetIP << " | ------ | open ports | " << openPorts << " |" << std::endl;

    // sen data to Logstash
    sendToLogstash(jsonPayload, logstashHost, logstashPort);
    logMessage("Сканирование завершено для IP: " + targetIP, logFile);
}

int main() {
    std::ifstream ipFile("ip_to_scan.txt");
    if (!ipFile.is_open()) {
        std::cerr << "Coudln't open file with IPs." << std::endl;
        return 1;
    }
    std::ofstream outputFile("scan_result.txt");
    if (!outputFile.is_open()) {
        std::cerr << "Couldn't write results to file" << std::endl;
        return 1;
    }


    std::ofstream logFile("log.txt", std::ios::app); 
    if (!logFile.is_open()) {
        std::cerr << "Не удалось открыть файл лога." << std::endl;
    }

    std::vector<std::string> ipAddresses;

   
    std::string ipAddress;
    while (getline(ipFile, ipAddress)) {
        ipAddresses.push_back(ipAddress);
    }

    ipFile.close();

    // Configuring connection
    std::string logstashHost = "IP_OF_YOUR_LOGSTASH";
    int logstashPort = PORT;

    
    for (const std::string& ip : ipAddresses) {
        scanAndWriteResult(ip, outputFile, logFile, logstashHost, logstashPort);
    }
    outputFile.close();
    logFile.close();

    std::cout << "Scanning and sending data to logstash was succesful" << std::endl;

    return 0;
}
