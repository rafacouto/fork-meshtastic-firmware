// create second module for satellites?

// The central node will generate a 256 or 128 bit value as its seed. This is the value other nodes subscribe to, and serves as
// the root of the chain

//

// Basic design:
// This module watches a channel for text messages.
// each message gets sha256 summed, and then appended to a git-style blockchain. Probably need a counter, too
// then the message, metadata, hash, and git hash information are saved. sqlite?

// nodes/sub-controllers can subscribe to a database

// A node can DM the controller, querying if a single message is on the chain, or asking for the last message hash

// if the message is not on the chain, the node can resend the message

// if the node lacks messages, it can request them

// will need the concept of sub-controllers, that subscribe to the central controller, can help push updates

// catch-up messages only go out when the mesh is low use %

// Normal firmware will only attempt to sync the chain a few times, then just ask for the latest few messages. A phone app can try
// harder

// host will periodically advertise its presence

// at least initially, there can only be one authoritative host

// first draft is just to save channel 0 in a git-style database

// message objects get a hash value
// the message chain gets a commit hash
//

#include "StoreForwardPlusPlus.h"
#include "MeshService.h"
#include "RTC.h"
#include "SHA256.h"
#include "meshUtils.h"

StoreForwardPlusPlusModule::StoreForwardPlusPlusModule()
    : ProtobufModule("StoreForward++", meshtastic_PortNum_STORE_FORWARD_PLUSPLUS_APP, &meshtastic_StoreForwardPlusPlus_msg),
      concurrency::OSThread("StoreForward++")
{
    LOG_WARN("StoreForwardPlusPlusModule init");
    int res = sqlite3_open("test.db", &ppDb);
    LOG_WARN("Result1 %u", res);
    char *err = nullptr;
    res = sqlite3_exec(ppDb, "         \
        CREATE TABLE channel_messages( \
        destination INT NOT NULL,      \
        sender INT NOT NULL,           \
        packet_id INT NOT NULL,        \
        want_ack BOOL NOT NULL,        \
        channel_hash INT NOT NULL,      \
        encrypted_bytes BLOB NOT NULL, \
        message_hash BLOB NOT NULL,    \
        rx_time INT NOT NULL,          \
        commit_hash BLOB NOT NULL,     \
        payload TEXT,                  \
        PRIMARY KEY (message_hash)     \
        );",
                       NULL, NULL, &err);
    LOG_WARN("Result2 %u", res);
    if (err != nullptr)
        ;
    LOG_ERROR("%s", err);
    sqlite3_free(err);

    // create table DMs
    res = sqlite3_exec(ppDb, "         \
        CREATE TABLE direct_messages( \
        destination INT NOT NULL,      \
        sender INT NOT NULL,           \
        packet_id INT NOT NULL,        \
        want_ack BOOL NOT NULL,        \
        channel_hash INT NOT NULL,      \
        commit_hash BLOB NOT NULL,     \
        encrypted_bytes BLOB NOT NULL, \
        message_hash BLOB NOT NULL,    \
        payload TEXT,                  \
        rx_time INT NOT NULL,          \
        PRIMARY KEY (message_hash)     \
        );",
                       NULL, NULL, &err);
    LOG_WARN("Result2 %u", res);
    if (err != nullptr)
        ;
    LOG_ERROR("%s", err);
    sqlite3_free(err);

    // create table mappings
    // create table DMs
    res = sqlite3_exec(ppDb, "         \
        CREATE TABLE mappings( \
        chain_type INT NOT NULL,      \
        identifier INT NOT NULL,           \
        root_hash BLOB NOT NULL,     \
        PRIMARY KEY (identifier)     \
        );",
                       NULL, NULL, &err);
    LOG_WARN("Result2 %u", res);
    if (err != nullptr)
        ;
    LOG_ERROR("%s", err);
    sqlite3_free(err);
    // type
    // sha256hash
    // channelhash or 64 bit combination

    // store schema version somewhere

    std::string insert_statement = "INSERT INTO channel_messages (destination, sender, packet_id, want_ack, channel_hash, \
        encrypted_bytes, message_hash, rx_time, commit_hash, payload) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_prepare(ppDb, insert_statement.c_str(), insert_statement.length(), &stmt, NULL);

    encryptedOk = true;

    this->setInterval(60 * 1000);
}

int32_t StoreForwardPlusPlusModule::runOnce()
{
    LOG_WARN("StoreForward++ runONce");
    if (getRTCQuality() < RTCQualityNTP) {
        LOG_WARN("StoreForward++ deferred due to time quality %u", getRTCQuality());
        return 60 * 60 * 1000;
    }
    // look up channel 0 hash
    // look up root hash
    int hash = channels.getHash(0);
    // get tip of chain for this channel
    // long term probably keep this in memory
    std::string getEntry_string =
        "select commit_hash, message_hash from channel_messages where channel_hash=? order by rowid desc LIMIT 1;";
    sqlite3_stmt *getEntry;
    int rc = sqlite3_prepare(ppDb, getEntry_string.c_str(), getEntry_string.size(), &getEntry, NULL);
    sqlite3_bind_int(getEntry, 1, hash);
    sqlite3_step(getEntry);
    uint8_t *last_message_chain_hash = (uint8_t *)sqlite3_column_blob(getEntry, 0);
    uint8_t *last_message_hash = (uint8_t *)sqlite3_column_blob(getEntry, 0);

    if (last_message_chain_hash == nullptr || last_message_hash == nullptr) {
        LOG_WARN("Store and Forward++ database lookup returned null");
        return 60 * 60 * 1000;
    }

    meshtastic_StoreForwardPlusPlus storeforward = meshtastic_StoreForwardPlusPlus_init_zero;
    storeforward.sfpp_message_type = meshtastic_StoreForwardPlusPlus_SFPP_message_type_CANON_ANNOUNCE;
    // set root hash

    // set message hash
    storeforward.message_hash.size = 32;
    memcpy(storeforward.message_hash.bytes, last_message_hash, 32);

    // set chain hash
    storeforward.chain_hash.size = 32;
    memcpy(storeforward.chain_hash.bytes, last_message_chain_hash, 32);

    // done with the sqlite3 allocated memory
    sqlite3_finalize(getEntry);
    // storeforward.
    meshtastic_MeshPacket *p = allocDataProtobuf(storeforward);
    p->to = NODENUM_BROADCAST;
    p->decoded.want_response = false;
    p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    p->channel = 0;
    LOG_INFO("Send packet to mesh");
    service->sendToMesh(p, RX_SRC_LOCAL, true);

    return 60 * 60 * 1000;
}

bool StoreForwardPlusPlusModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_StoreForwardPlusPlus *t)
{
    LOG_WARN("in handleReceivedProtobuf");
}

ProcessMessage StoreForwardPlusPlusModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    // To avoid terrible time problems, require NTP or GPS time
    if (getRTCQuality() < RTCQualityNTP) {
        return ProcessMessage::CONTINUE; // Let others look at this message also if they want
    }

    // the sender+destination pair is an interesting unique id (though ordering) (smaller one goes first?)
    // so messages with a unique pair become a chain
    // These get a table

    // message to broadcast get a chain per channel hash
    // second table
    // for now, channel messages are limited to decryptable
    // limited to text messages

    // create a unique-from-nodenums() class that returns a 64-bit value

    SHA256 message_hash, chain_hash;
    uint8_t message_hash_bytes[32] = {0};
    uint8_t chain_hash_bytes[32] = {0};

    // For the moment, this is strictly LoRa
    if (mp.transport_mechanism != meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA) {
        return ProcessMessage::CONTINUE; // Let others look at this message also if they want
    }

    // will eventually host DMs and other undecodable messages
    if (mp.which_payload_variant != meshtastic_MeshPacket_decoded_tag) {
        return ProcessMessage::CONTINUE; // Let others look at this message also if they want
    }
    // refuse without valid time?
    LOG_WARN("in handleReceived");
    if (mp.decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP && mp.decoded.dest == NODENUM_BROADCAST) {
        // todo drop anything other than to broadcast
        std::string getEntry_string =
            "select commit_hash from channel_messages where channel_hash=? order by rowid desc LIMIT 1;";
        sqlite3_stmt *getEntry;
        int rc = sqlite3_prepare(ppDb, getEntry_string.c_str(), getEntry_string.size(), &getEntry, NULL);
        sqlite3_bind_int(getEntry, 1, router->p_encrypted->channel);
        sqlite3_step(getEntry);

        // this is allocated by sqlite3 and will be deleted when finalize is called
        uint8_t *last_message_hash = (uint8_t *)sqlite3_column_blob(getEntry, 0);
        if (last_message_hash) {
            printBytes("last message: 0x", last_message_hash, 32);
        } else {
            // generate root hash and populate lookup table
        }

        // do not include rxtime in the message hash. We want these to match when more then one node receives and compares notes.
        // feel free to include it in the commit hash

        message_hash.reset();
        message_hash.update(router->p_encrypted->encrypted.bytes, router->p_encrypted->encrypted.size);
        message_hash.update(&mp.to, sizeof(mp.to));
        message_hash.update(&mp.from, sizeof(mp.from));
        message_hash.update(&mp.id, sizeof(mp.id));
        message_hash.finalize(message_hash_bytes, 32);

        chain_hash.reset();
        if (last_message_hash) {
            chain_hash.update(last_message_hash, 32);
        }
        chain_hash.update(message_hash_bytes, 32);
        // message_hash.update(&mp.rx_time, sizeof(mp.rx_time));
        chain_hash.finalize(chain_hash_bytes, 32);

        sqlite3_finalize(getEntry);

        // select HEX(commit_hash),HEX(channel_hash), payload, destination from channel_messages order by rowid desc;

        // push a message into the local chain DB
        // destination
        sqlite3_bind_int(stmt, 1, mp.to);
        // sender
        sqlite3_bind_int(stmt, 2, mp.from);
        // packet_id
        sqlite3_bind_int(stmt, 3, mp.id);
        // want_ack
        sqlite3_bind_int(stmt, 4, mp.want_ack);
        // channel_hash
        sqlite3_bind_int(stmt, 5, router->p_encrypted->channel);
        // encrypted_bytes
        sqlite3_bind_blob(stmt, 6, router->p_encrypted->encrypted.bytes, router->p_encrypted->encrypted.size, NULL);

        // message_hash
        sqlite3_bind_blob(stmt, 7, message_hash_bytes, 32, NULL);
        // rx_time
        sqlite3_bind_int(stmt, 8, mp.rx_time);

        // commit_hash
        sqlite3_bind_blob(stmt, 9, chain_hash_bytes, 32, NULL);
        // payload
        sqlite3_bind_text(stmt, 10, (char *)mp.decoded.payload.bytes, mp.decoded.payload.size, NULL);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);

        return ProcessMessage::CONTINUE; // Let others look at this message also if they want

        // one of the command messages
    } else if (mp.decoded.portnum == meshtastic_PortNum_STORE_FORWARD_PLUSPLUS_APP) {
        // when we get an update this way, if the message isn't on the chain, this node hasn't seen it, and can rebroadcast.
    }
}

// announce latest hash
// chain_end_announce

// check if hash is known
// hash_query

// request next message
// link_request

// send encapsulated message
// link_provide_whole
// link_provide_half1
// link_provide_half2

// onboard request message?

// get x from top?

// messages
// Given this chain root, do you have a packet that matches this message hash?
// responds with chain hash etc

// given this chain root, what is your last chain and message hash?
// given this chain root, what is your next message after this chain hash? (do we have an overhead problem here?) (blegh,
// fragmentation) (but also, trunking)

// broadcast on this chain root, here is my last chain hash

// consider third-order nodes

// I can't talk directly to strata, I can talk to a satellite. Inform sat of a message. Sat stores it as if had seen it locally,
// and pushes it to central

// message Eventually works out through chain

// sat can capture time of receipt

// terms:
// CANON
// stratum
// chain
// links on the chain