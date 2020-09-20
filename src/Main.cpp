#include "GpgAgentHandler.h"
#include "Log.h"
#include <boost/asio.hpp>
#include <sodium.h>

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        _debug_cerr << "libsodium initialize failed\n";
        exit(-1);
    }

    boost::asio::io_context ctx;
    KeePassPinentry::GpgAgentHandler handler{ctx};
    handler.serveAgent();
    return 0;
}
