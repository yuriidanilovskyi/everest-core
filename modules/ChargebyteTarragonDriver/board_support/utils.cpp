#include "utils.hpp"

#include <boost/algorithm/string/trim.hpp>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace Everest {
namespace Utils {

std::string sysfs_read_string(boost::filesystem::path path) {
    std::ifstream sysfs_istream(path.c_str());
    std::stringstream sysfs_stringstream;
    sysfs_stringstream << sysfs_istream.rdbuf();
    sysfs_istream.close();

    std::string value = sysfs_stringstream.str();
    boost::algorithm::trim(value);

    return value;
}

float sysfs_read_float(boost::filesystem::path path) {
    return std::stof(sysfs_read_string(path));
}

void sysfs_write_string(boost::filesystem::path path, std::string value) {
    std::ofstream sysfs_ostream(path.c_str());
    sysfs_ostream << value << std::endl;
    sysfs_ostream.close();
}

bool wait_until_exists(boost::filesystem::path path, std::chrono::milliseconds timeout) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() < start + timeout) {
        if (boost::filesystem::exists(path)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    return false;
}

void wait_until_exists_exception(boost::filesystem::path path, std::chrono::milliseconds timeout) {
    if (!wait_until_exists(path, timeout)) {
        std::string error = path.string() + " did not exist after provided timeout";
        throw std::runtime_error(error);
    }
}

} // namespace Utils
} // namespace Everest
