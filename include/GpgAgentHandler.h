#ifndef KEEPASSPINENTRY_GPGAGENTHANDlER_H
#define KEEPASSPINENTRY_GPGAGENTHANDlER_H

#include <boost/process.hpp>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace KeePassPinentry {
class GpgAgentHandler {
  public:
    GpgAgentHandler();
    void serveAgent();

  private:
    /**
     * Input handler
     * @param _1 the command received from gpg-agent
     * @return true means the command should be passed to pinentry
     */
    using InputHandlerType = bool(const std::string &);

    // pinentry
    std::unique_ptr<boost::process::child> _pinentry;
    boost::process::opstream _pinentryStdin;
    boost::process::ipstream _pinentryStdout;

    const std::map<std::string, std::function<InputHandlerType>> _inputHandler{
        {"SETKEYINFO", std::bind(&GpgAgentHandler::handleSetKeyInfo, this,
                                 std::placeholders::_1)},
        {"GETPIN", std::bind(&GpgAgentHandler::handleGetPin, this,
                             std::placeholders::_1)}};

    std::string _keygrip;

    // handle pinentry output. This is blocking.
    void handleOutput();
    // handle gpg-agent input. This is blocking.
    void handleInput();

    bool handleSetKeyInfo(const std::string &cmd);
    bool handleGetPin(const std::string &cmd);
};
} // namespace KeePassPinentry

#endif
