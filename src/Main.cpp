#include "GpgAgentHandler.h"
#include "Log.h"
#include <sodium.h>

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        _debug_cerr << "libsodium initialize failed\n";
        exit(-1);
    }
    KeePassPinentry::GpgAgentHandler handler;
    handler.serveAgent();
    return 0;
}
