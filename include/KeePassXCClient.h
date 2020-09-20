#ifndef KEEPASSPINENTRY_KEEPASSXC_CLIENT
#define KEEPASSPINENTRY_KEEPASSXC_CLiENT
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cstddef>
#include <set>
#include <sodium.h>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace KeePassPinentry {

class KeePassXCClient {
  public:
    using KeyType = std::vector<unsigned char>;
    KeePassXCClient(boost::asio::io_context &ioContext,
                    std::string identificationKey);

    std::string getPassphrase(const std::string &keygrip);

    KeyType getPrivateKey();

    std::set<std::string> getDatabaseHash();

  private:
    void connectSocket();

    void handShake();

    void changePublicKey();

    void associate();

    boost::property_tree::ptree
    transact(const boost::property_tree::ptree &data);

    boost::property_tree::ptree
    transact_entrypted(const boost::property_tree::ptree &data);

    boost::asio::io_context &_ioContext;
    KeyType _publicKey;
    KeyType _privateKey;
    KeyType _serverPublicKey;
    std::string _b64ClientID;
    std::string _b64DatabaseHash;
    std::string _b64IdentificationKey;

#ifdef _WIN32
#else
    boost::asio::local::stream_protocol::socket _socket;
#endif
};

} // namespace KeePassPinentry
#endif
