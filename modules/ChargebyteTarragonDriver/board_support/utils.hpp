#ifndef SRC_EVDRIVERS_UTILS_H_
#define SRC_EVDRIVERS_UTILS_H_

#include <boost/filesystem.hpp>
#include <chrono>

namespace Everest {
namespace Utils {

std::string sysfs_read_string(boost::filesystem::path path);

float sysfs_read_float(boost::filesystem::path path);

void sysfs_write_string(boost::filesystem::path path, std::string value);

bool wait_until_exists(boost::filesystem::path path, std::chrono::milliseconds timeout);

void wait_until_exists_exception(boost::filesystem::path path, std::chrono::milliseconds timeout);

} // namespace Utils
} // namespace Everest

#endif
