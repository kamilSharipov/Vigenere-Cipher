#include "vigenere.hpp"

#include <iostream>
#include <string>

#include <boost/program_options.hpp>

namespace po = boost::program_options;

int main(int argc, const char* argv[]) {
    std::string key, gamma_str, action, text;

    po::options_description desc{"Vigenere Cipher Tool"};

    desc.add_options()
        ("key,k", po::value<std::string>(&key)->required(), "Secret key")

        ("gamma,g", po::value<std::string>(&gamma_str)->default_value("repeat"), 
         "Gamma mode: repeat, auto_plain, auto_cipher")

        ("action,a", po::value<std::string>(&action)->default_value("encrypt"), 
         "Action: encrypt or decrypt")

        ("text,t", po::value<std::string>(&text), 
         "Input text (if omitted, reads from stdin)")

        ("help,h", "Show help message");

    po::positional_options_description p;
    p.add("text", -1);

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv)
                      .options(desc)
                      .positional(p)
                      .run(), vm);
        if (vm.count("help")) {
            std::cout << desc << "\n";

            return 0;
        }

        po::notify(vm);
    } catch (const std::exception& e) {
        std::cerr << "Argument error: " << e.what() << "\n" << desc << "\n";

        return 1;
    }

    vigenere::GammaMode mode;
    if (gamma_str == "repeat") {
        mode = vigenere::GammaMode::RepeatKey;
    } else if (gamma_str == "auto_plain") {
        mode = vigenere::GammaMode::AutokeyPlaintext;
    } else if (gamma_str == "auto_cipher") {
        mode = vigenere::GammaMode::AutokeyCiphertext;
    } else {
        std::cerr << "Unknown gamma mode\n";

        return 1;
    }

    std::string input_text = text;
    if (input_text.empty()) {
        std::getline(std::cin, input_text);
    }

    try {
        if (action == "encrypt") {
            std::cout << vigenere::encrypt(input_text, key, mode) << std::endl;
        } else if (action == "decrypt") {
            std::cout << vigenere::decrypt(input_text, key, mode) << std::endl;
        } else {
            std::cerr << "Action must be 'encrypt' or 'decrypt'\n";

            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Execution error: " << e.what() << "\n";

        return 1;
    }

    return 0;
}
