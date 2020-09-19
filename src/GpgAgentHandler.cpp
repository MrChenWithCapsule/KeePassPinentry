#include "GpgAgentHandler.h"
#include "Log.h"
#include <cctype>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using namespace std;
using namespace boost::process;
using namespace boost::asio;
using std::placeholders::_1;
namespace KeePassPinentry {
GpgAgentHandler::GpgAgentHandler(io_context &ioContext)
    : _client{ioContext, {}} {
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

string capitalize(string str) {
    for (char &c : str)
        c = toupper(c);
    return str;
}

void GpgAgentHandler::handleInput() {
    string cmd;
    while (getline(cin, cmd)) {
        _debug_cerr << "agent: " << cmd << '\n';
        if (const auto &p = _inputHandler.find(
                capitalize(cmd.substr(0, cmd.find_first_of(' '))));
            p != _inputHandler.end()) {
            bool needProxy = p->second(cmd);
            if (!needProxy)
                continue;
        }
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

bool GpgAgentHandler::handleSetKeyInfo(const string &cmd) {
    if (cmd == "SETKEYINFO --clear")
        _keygrip.clear();
    else
        _keygrip.assign(cmd, sizeof("SETKEYINFO n/") - 1);
    return true;
}
bool GpgAgentHandler::handleGetPin(const string &cmd) {
    if (_keygrip.empty())
        return true;
    string p = _client.getPassphrase(_keygrip);
    if (p.empty())
        return true;
    cout << "D " << p << "\nOK\n";
    return false;
}
} // namespace KeePassPinentry
