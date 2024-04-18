#include <iostream>
#include <random>
#include <string>
#include <Windows.h>

constexpr size_t CYCLE = 20;
constexpr size_t MIN_LEN = 5;
constexpr size_t MAX_LEN = 50;

std::string fuzzer(size_t min_len, size_t max_len, const std::string& alphabet)
{
    std::string rand_string;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, alphabet.size() - 1);
    size_t len = std::uniform_int_distribution<size_t>(min_len, max_len)(gen);

    rand_string.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        rand_string.push_back(alphabet[dist(gen)]);
    }
    return rand_string;
}

int main(int argc, char** argv)
{
    std::string cmd = ".\\vuln.exe";

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    for (size_t i = 0; i < CYCLE; i++) {
        std::string test_case = fuzzer(MIN_LEN, MAX_LEN, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        std::string cmd_arg = cmd + " " + test_case;

        if (CreateProcessA(NULL, const_cast<char*>(cmd_arg.c_str()), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            DWORD exit_code;
            if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
                std::cerr << "Failed to get exit code: " << GetLastError() << std::endl;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return 1;
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            if (exit_code != 0) {
                std::cerr << "Test Case: " << test_case << std::endl;
                std::cerr << "Error Code: " << std::hex << exit_code << std::endl;
                std::cout << "=====================================\n";
            }
        }
        else {
            std::cerr << "Failed to create process: " << GetLastError() << std::endl;
            return 1;
        }
    }
    return 0;
}