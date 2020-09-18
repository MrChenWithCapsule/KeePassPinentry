#include "GpgAgentHandler.h"

int main(int argc, char **argv) {
    KeePassPinentry::GpgAgentHandler handler;
    handler.serveAgent();
    return 0;
}
