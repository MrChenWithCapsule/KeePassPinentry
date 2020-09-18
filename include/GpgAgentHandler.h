#ifndef KEEPASSPINENTRY_GPGAGENTHANDlER_H
#define KEEPASSPINENTRY_GPGAGENTHANDlER_H

#include <boost/process.hpp>
#include <memory>

namespace KeePassPinentry {
class GpgAgentHandler {
  public:
    GpgAgentHandler();
    void serveAgent();

  private:
    std::unique_ptr<boost::process::child> _pinentry;
    boost::process::opstream _pinentryStdin;
    boost::process::ipstream _pinentryStdout;

    // handle pinentry output. This is blocking.
    void handleOutput();
    // handle gpg-agent input. This is blocking.
    void handleInput();
};
} // namespace KeePassPinentry

#endif
