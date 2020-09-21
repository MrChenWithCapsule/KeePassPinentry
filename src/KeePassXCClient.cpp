#include "KeePassXCClient.h"
#include "KeePassXCErrors.h"
#include "Log.h"

#include <array>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cstdlib>
#include <set>
#include <sodium.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace std;
using namespace boost::asio;
using namespace boost::property_tree;
using namespace boost::iostreams;
using KeyType = KeePassPinentry::KeePassXCClient::KeyType;
using DataType = KeyType;
namespace asio = boost::asio;

struct Actions {
    static constexpr char changePublicKeys[] = "change-public-keys";
    static constexpr char getDatabasehash[] = "get-databasehash";
    static constexpr char associate[] = "associate";
    static constexpr char testAssociate[] = "test-associate";
    static constexpr char generatePassword[] = "generate-password";
    static constexpr char getLogins[] = "get-logins";
    static constexpr char setLogin[] = "set-login";
    static constexpr char lockDatabase[] = "lock-database";
    static constexpr char databaseLocked[] = "database-locked";
    static constexpr char databaseUnlocked[] = "database-unlocked";
    static constexpr char getTotp[] = "get-totp";
};

struct Keys {
    static constexpr char action[] = "action";
    static constexpr char publicKey[] = "publicKey";
    static constexpr char nonce[] = "nonce";
    static constexpr char id[] = "id";
    static constexpr char key[] = "key";
    static constexpr char keys[] = "keys";
    static constexpr char entries[] = "entries";
    static constexpr char idKey[] = "idKey";
    static constexpr char clientID[] = "clientID";
    static constexpr char version[] = "version";
    static constexpr char success[] = "success";
    static constexpr char message[] = "message";
    static constexpr char hash[] = "hash";
    static constexpr char url[] = "url";
    static constexpr char password[] = "password";
    static constexpr char errorCode[] = "errorCode";
    static constexpr char error[] = "error";
};

struct SuccessCodes {
    static constexpr char success[] = "true";
    static constexpr char failed[] = "false";
};

constexpr auto base64Variant = sodium_base64_VARIANT_ORIGINAL;
static KeyType base64Decode(string_view str) {
    KeyType ret(str.length() * 3 / 4);
    size_t sz;
    if (-1 == sodium_base642bin(ret.data(), ret.size(), str.data(),
                                str.length(), "", &sz, NULL, base64Variant)) {
        _debug_cerr << "base64 decode failed\n";
        throw runtime_error{"base64 decode failed"};
    }
    ret.resize(sz);
    return ret;
}
static KeyType base64Decode(const string &str) {
    return base64Decode(string_view{str.c_str(), str.size()});
}
static string base64Encode(const KeyType &data, size_t size) {
    string ret(sodium_base64_ENCODED_LEN(size, base64Variant), '\0');
    sodium_bin2base64(ret.data(), ret.length(), data.data(), size,
                      base64Variant);
    ret.resize(ret.size() - 1);
    return ret;
}
static string base64Encode(const KeyType &data) {
    return base64Encode(data, data.size());
}
static KeyType generateNonce() {
    constexpr auto nonceLength = 24U;

    KeyType nonce(nonceLength);
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}
static string generateClientID() { return base64Encode(generateNonce()); }

static size_t serialize(const ptree &data, DataType &buf) {
    stream<array_sink> os{reinterpret_cast<char *>(buf.data()), buf.size()};
    write_json(os, data);
    return os.tellp();
}
static void deserialize(const DataType &data, size_t sz, ptree &tree) {
    stream<array_source> is{reinterpret_cast<const char *>(data.data()), sz};
    read_json(is, tree);
}

namespace KeePassPinentry {
KeePassXCClient::KeePassXCClient(io_context &ioContext,
                                 string identificationKey)
    : _ioContext{ioContext}, _socket{ioContext}, _b64IdentificationKey{
                                                     identificationKey} {}

void KeePassXCClient::connect() {
    if (_isConnected)
        return;

    // generate client id
    _b64ClientID = generateClientID();
    _debug_cerr << "generated client id: " << _b64ClientID << '\n';

    // if I don't have an identification, generate one
    if (_b64IdentificationKey.empty()) {
        KeyType bkey(crypto_box_PUBLICKEYBYTES);
        randombytes_buf(bkey.data(), bkey.size());
        _b64IdentificationKey = base64Encode(bkey);
        _debug_cerr << "generated identification key\n";
    }

    // generate key pair
    _privateKey.resize(crypto_kx_SECRETKEYBYTES);
    _publicKey.resize(crypto_kx_PUBLICKEYBYTES);
    crypto_kx_keypair(_publicKey.data(), _privateKey.data());
    _debug_cerr << "generated key pair\n";

    connectSocket();
    handShake();
}

bool KeePassXCClient::isConnected() { return _isConnected; }

KeePassXCClient::~KeePassXCClient() { _socket.close(); }

string KeePassXCClient::getPassphrase(const string &keygrip) {
    ptree resp;

    // construct message and transact
    {
        ptree msg;
        msg.add(Keys::action, Actions::getLogins);
        msg.add(Keys::url, "gpg://" + keygrip);
        ptree keys, key;
        key.add(Keys::id, _b64DatabaseHash);
        keys.add_child("", key);
        msg.add_child(Keys::keys, keys);
        resp = transact(msg, true);
    }

    if (resp.get<string>(Keys::success) != SuccessCodes::success)
        return {};
    return resp.get_child(Keys::entries)
        .begin()
        ->second.get<string>(Keys::password);
}

KeyType KeePassXCClient::getPrivateKey() { return _privateKey; }

void KeePassXCClient::handShake() {
    changePublicKey();
    associate();
}

constexpr auto max_message_size = 1048576;

ptree KeePassXCClient::transact(const ptree &data, bool encrypt) {
    // prepare the buffer to send
    DataType buf(max_message_size + crypto_box_MACBYTES);
    auto bufsz = serialize(data, buf);
    KeyType nonce;
    if (encrypt) {
        ptree box;
        nonce = generateNonce();
        box.add(Keys::action, data.get<string>(Keys::action));
        box.add(Keys::nonce, base64Encode(nonce));
        box.add(Keys::clientID, _b64ClientID);
        if (0 != crypto_box_easy(buf.data(), buf.data(), bufsz, nonce.data(),
                                 _serverPublicKey.data(), _privateKey.data())) {
            _debug_cerr << "encryption failed\n";
            throw runtime_error{"encryption failed"};
        }
        bufsz += crypto_box_MACBYTES;
        box.add(Keys::message, base64Encode(buf, bufsz));
        bufsz = serialize(box, buf);
    }

    // send and receive data
    write(_socket, buffer(buf.data(), bufsz));
    _debug_cerr << "sent data of length " << bufsz << '\n';
    bufsz = _socket.read_some(buffer(buf));
    _debug_cerr << "read data of length " << bufsz << '\n';

    // prepare responce
    ptree ret;
    deserialize(buf, bufsz, ret);
    if (ret.get(Keys::errorCode, 0))
        throw DatabaseNotOpenedError{};
    if (encrypt) {
        auto m = base64Decode(ret.get<string>(Keys::message));
        sodium_increment(nonce.data(), nonce.size());
        if (-1 == crypto_box_open_easy(buf.data(), m.data(), m.size(),
                                       nonce.data(), _serverPublicKey.data(),
                                       _privateKey.data())) {
            _debug_cerr << "authentication failed\n";
            throw runtime_error{"authentication failed"};
        }
        bufsz = m.size() - crypto_box_MACBYTES;
        deserialize(buf, bufsz, ret);
    }

    return ret;
}

void KeePassXCClient::changePublicKey() {
    _debug_cerr << "change public key\n";
    ptree serverMsg;
    // construct the change-public-key message and send it to server
    {
        ptree msg;
        msg.add(Keys::action, Actions::changePublicKeys);
        msg.add(Keys::publicKey, base64Encode(_publicKey));
        msg.add(Keys::nonce, base64Encode(generateNonce()));
        msg.add(Keys::clientID, _b64ClientID);
        serverMsg = transact(msg, false);
    }

    // receive responce from server and read the public key
    if (serverMsg.get<string>(Keys::success) != SuccessCodes::success) {
        _debug_cerr << "change public key failed\n";
        throw runtime_error{"change public key failed\n"};
    }
    _serverPublicKey = base64Decode(serverMsg.get<string>(Keys::publicKey));
}

void KeePassXCClient::associate() {
    // get database hash
    {
        _debug_cerr << "get database hash\n";
        ptree msg;
        msg.add(Keys::action, Actions::getDatabasehash);
        ptree resp = transact(msg, true);
        _b64DatabaseHash = resp.get<string>(Keys::hash);
    }

    // test associate
    {
        _debug_cerr << "test associate\n";
        ptree msg;
        msg.add(Keys::action, Actions::testAssociate);
        msg.add(Keys::id, _b64DatabaseHash);
        msg.add(Keys::key, _b64IdentificationKey);
        ptree resp = transact(msg, true);
        if (resp.get<string>(Keys::success) == SuccessCodes::success) {
            _debug_cerr << "already associated\n";
            return;
        }
    }

    // not associated, associate now
    {
        _debug_cerr << "associate\n";
        ptree msg;
        msg.add(Keys::action, Actions::associate);
        msg.add(Keys::publicKey, base64Encode(_publicKey));
        msg.add(Keys::idKey, _b64IdentificationKey);
        ptree resp = transact(msg, true);
        if (resp.get<string>(Keys::success) != SuccessCodes::success) {
            _debug_cerr << "associate failed\n";
            throw runtime_error{"associate failed\n"};
        }
    }
}

void KeePassXCClient::connectSocket() {
    constexpr char socket_name[]{"kpxc_server"};
#ifdef _WIN32
    decltype(auto) user_name = getenv("USERNAME");
    if (!user_name) {
        _debug_cerr << "cannot find environment variable USERNAME\n";
        throw runtime_error{"cannot find environment variable USERNAME"};
    }
    string path =
        string{"\\\\.\\pipe\\keepassxc\\"} + user_name + '\\' + socket_name;
    _npipe = CreateFileA(path.c_str(), GENERIC_ALL, 0, nullptr, OPEN_EXISTING,
                         FILE_FLAG_OVERLAPPED, nullptr);
    if (_npipe == INVALID_HANDLE_VALUE) {
        _debug_cerr << "cannot open named pipe\n";
        throw runtime_error{"cannot open named pipe"};
    }
    _socket.assign(_npipe);
#else
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    if (xdg)
        _socket.connect(string{xdg} + '/' + socket_name);
    else
        _socket.connect(string{"/tmp/"} + socket_name);
#endif
}
} // namespace KeePassPinentry
