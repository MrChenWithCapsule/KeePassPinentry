#include "GpgAgentHandler.h"
#include "Log.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using namespace std;
using namespace boost::process;
namespace KeePassPinentry {
GpgAgentHandler::GpgAgentHandler() {
    _pinentry =
        make_unique<child>(search_path("pinentry"), std_out > _pinentryStdout,
                           std_err > stderr, std_in < _pinentryStdin);
}

void GpgAgentHandler::serveAgent() {
    _debug_cerr << "starting KeePassPinentry\n";
    thread t{&GpgAgentHandler::handleOutput, this};
    handleInput();
    t.join();
}

void GpgAgentHandler::handleInput() {
    string cmd;
    while (getline(cin, cmd)) {
        _debug_cerr << "agent: " << cmd << '\n';
        _pinentryStdin << cmd << endl;
    }
}

void GpgAgentHandler::handleOutput() {
    string resp;
    while (getline(_pinentryStdout, resp)) {
        _debug_cerr << "pinentry: " << resp << '\n';
        cout << resp << endl;
    }
}
} // namespace KeePassPinentry
