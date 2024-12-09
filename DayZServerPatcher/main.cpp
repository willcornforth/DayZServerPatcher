#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>

const char* FILE_PATH = "DayZServer_x64.exe"; // Patch executable in relative directory.

// Function to convert a hex string pattern with wildcards to a byte vector
std::vector<unsigned char> parseSignature(const std::string& signature) {
    std::vector<unsigned char> parsedSignature;
    std::istringstream iss(signature);
    std::string byte;

    while (iss >> byte) {
        if (byte == "?") {
            parsedSignature.push_back(0x00); // Wildcard is represented as 0x00
        }
        else {
            parsedSignature.push_back(static_cast<unsigned char>(std::strtol(byte.c_str(), nullptr, 16))); // Convert hex to byte.
        }
    }
    return parsedSignature;
}

std::vector<char> fileToBuffer(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    std::vector<char> buffer;

    if (file.is_open()) {
        // Create buffer the size of the input file.
        file.seekg(0, std::ios::end);
        std::streamsize fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        buffer.resize(fileSize);

        if (file.read(buffer.data(), fileSize)) {
            std::cout << "[+] File Size 0x" << std::hex << fileSize << std::endl;
            file.close();

            return buffer;
        }
        else {
            std::cerr << "[-] Failed to read file. File size: " << fileSize << std::endl;
            return buffer;
        }
    }
    else {
        std::cerr << "[-] Failed to open file. Path: " << filePath << std::endl;
        return buffer;
    }
}

bool bufferToFile(std::vector<char>& buffer, std::string filePath) {
    std::ofstream outFile(filePath, std::ios::binary);

    if (!outFile) {
        std::cerr << "[-] Couldn't create/open file to write buffer!" << std::endl;
        return 0;
    }

    outFile.write(buffer.data(), buffer.size());
    outFile.close();
    return 1;
}

// Function to find the signature in a file and return the address (offset) of the first match
uintptr_t findSignature(const std::vector<char>& buffer, const char* signatureStr) {
    const std::vector<unsigned char> signature = parseSignature(signatureStr);

    if (signature.empty()) {
        return -1;
    }

    uint64_t i = 0;
    uint64_t match = 0;
    int bestMatch = 0;

    // Iterate through each byte in the buffer
    for (; i < buffer.size(); i++) {
        const auto byte = buffer[i];

        for (int j = 0; j < signature.size(); j++) {
            const char sigByte = signature[j];
            const char pointerByte = buffer[i + j];

            if (pointerByte == sigByte || sigByte == 0) {

                if (j > bestMatch) {
                    bestMatch = j;
                    match = i;
                }

                // Direct match, return.
                if (j + 1 == signature.size()) {
                    return i;
                }
            }
            else {
                break;
            }
        }
    }

    // No direct match was found so return the closest.
    return match;
}

int main() {

    // Load file into memory buffer.
    std::vector<char> buffer = fileToBuffer(FILE_PATH);

    if (buffer.empty()) {
        std::cerr << "[-] Could not read file into buffer. (Is DayZServer_x64.exe in this directory?)" << std::endl;
        return -2;
    }

    // Find the signature in the file
    uintptr_t jumpFail = findSignature(buffer, "7D 52 48 8D 0D ? ? ? ?");
    uintptr_t testReturn = findSignature(buffer, "84 C0 75 4D 48 8D 15 ? ? ? ?");

    std::cout << "[#] jge onFail @ 0x" << std::hex << std::uppercase << jumpFail << std::endl;
    std::cout << "[#] test al, al @ 0x" << std::hex << std::uppercase << testReturn << std::endl;

    if (jumpFail != 0 && testReturn != 0) {

        // test al, 2
        buffer[testReturn] = static_cast<char>(0xA8);
        buffer[testReturn + 1] = static_cast<char>(0x02);

        char jumpDist = buffer[jumpFail + 1];
        std::cout << "[+] jge distance: 0x" << std::hex << std::uppercase << static_cast<int>(jumpDist) << std::endl;

        int jumpDestinationOffset = jumpFail + jumpDist + 2; // Jump address + jump distance + jump instruction size = destination.
        std::cout << "[+] xor al, al: 0x" << std::hex << std::uppercase << buffer[jumpDestinationOffset] << " [0x" << jumpDestinationOffset << "]" << std::endl;

        // mov al, 2
        buffer[jumpDestinationOffset] = static_cast<char>(0xB0);
        buffer[jumpDestinationOffset + 1] = static_cast<char>(0x02);

        bufferToFile(buffer, FILE_PATH);
        std::cout << "[+] Done patching! You can close this window..." << std::endl;
        std::cin.get(); // Keep window open.

        return 0;
    }
    else {
        return -1;
    }
}