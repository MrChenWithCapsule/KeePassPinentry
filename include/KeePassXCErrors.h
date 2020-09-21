#ifndef KEEPASSPINENTRY_KEEPASSXCEXCEPTIONS_H
#define KEEPASSPINENTRY_KEEPASSXCEXCEPTIONS_H
#include <stdexcept>
namespace KeePassPinentry {
struct DatabaseNotOpenedError : public std::runtime_error {
    DatabaseNotOpenedError() : std::runtime_error{"database not opened"} {}
};
} // namespace KeePassPinentry
#endif // !KEEPASSPINENTRY_KEEPASSXCEXCEPTIONS_H
