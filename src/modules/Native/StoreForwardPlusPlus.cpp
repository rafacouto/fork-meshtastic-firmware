// I've done a lot of this in SQLite for now, but honestly it needs to happen in memory, and get saved to sqlite during downtime

// TODO: Put some channel usage limits on this: Should be limited to 25% utilization, for instance

// TODO: custom hops. 1 maybe 0

// TODO: non-stratum0 nodes need to be pointed at their upstream source? Maybe

// TODO: Work without sending some of the hashes/ short hashes

// things may get weird if there are multiple stratum-0 nodes on a single mesh. Come up with mitigations

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

// message objects get a hash value
// the message chain gets a commit hash
//

#include "StoreForwardPlusPlus.h"
#include "MeshService.h"
#include "RTC.h"
#include "SHA256.h"
#include "meshUtils.h"
#include "modules/RoutingModule.h"

StoreForwardPlusPlusModule::StoreForwardPlusPlusModule()
    : ProtobufModule("StoreForwardpp", meshtastic_PortNum_STORE_FORWARD_PLUSPLUS_APP, &meshtastic_StoreForwardPlusPlus_msg),
      concurrency::OSThread("StoreForwardpp")
{
    LOG_WARN("StoreForwardPlusPlusModule init");

    if (portduino_config.sfpp_stratum0)
        LOG_WARN("SF++ stratum0");

    int res = sqlite3_open("test.db", &ppDb);
    LOG_WARN("Result1 %u", res);

    char *err = nullptr;

    res = sqlite3_exec(ppDb, "         \
        CREATE TABLE channel_messages( \
        destination INT NOT NULL,      \
        sender INT NOT NULL,           \
        packet_id INT NOT NULL,        \
        rx_time INT NOT NULL,          \
        root_hash BLOB NOT NULL,      \
        encrypted_bytes BLOB NOT NULL, \
        message_hash BLOB NOT NULL,    \
        commit_hash BLOB NOT NULL,     \
        payload TEXT,                  \
        PRIMARY KEY (message_hash)     \
        );",
                       NULL, NULL, &err);
    LOG_WARN("Result2 %u", res);
    if (err != nullptr)
        LOG_ERROR("%s", err);
    sqlite3_free(err);

    res = sqlite3_exec(ppDb, "         \
        CREATE TABLE local_messages( \
        destination INT NOT NULL,      \
        sender INT NOT NULL,           \
        packet_id INT NOT NULL,        \
        rx_time INT NOT NULL,          \
        channel_hash INT NOT NULL,      \
        encrypted_bytes BLOB NOT NULL, \
        message_hash BLOB NOT NULL,    \
        payload TEXT,                  \
        PRIMARY KEY (message_hash)     \
        );",
                       NULL, NULL, &err);
    LOG_WARN("Result2 %u", res);
    if (err != nullptr)
        LOG_ERROR("%s", err);
    sqlite3_free(err);

    // create table DMs
    res = sqlite3_exec(ppDb, "         \
        CREATE TABLE direct_messages( \
        destination INT NOT NULL,      \
        sender INT NOT NULL,           \
        packet_id INT NOT NULL,        \
        rx_time INT NOT NULL,          \
        channel_hash INT NOT NULL,     \
        commit_hash BLOB NOT NULL,     \
        encrypted_bytes BLOB NOT NULL, \
        message_hash BLOB NOT NULL,    \
        payload TEXT,                  \
        PRIMARY KEY (message_hash)     \
        );",
                       NULL, NULL, &err);
    LOG_WARN("Result2 %u", res);
    if (err != nullptr)
        LOG_ERROR("%s", err);
    sqlite3_free(err);

    // mappings table -- connects the root hashes to channel hashes and DM identifiers
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
        LOG_ERROR("%s", err);
    sqlite3_free(err);

    // store schema version somewhere

    // prepared statements *should* make this faster.
    sqlite3_prepare_v2(ppDb, "INSERT INTO channel_messages (destination, sender, packet_id, root_hash, \
        encrypted_bytes, message_hash, rx_time, commit_hash, payload) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);",
                       -1, &chain_insert_stmt, NULL);

    sqlite3_prepare_v2(ppDb, "INSERT INTO local_messages (destination, sender, packet_id, channel_hash, \
        encrypted_bytes, message_hash, rx_time, payload) VALUES(?, ?, ?, ?, ?, ?, ?, ?);",
                       -1, &scratch_insert_stmt, NULL);

    sqlite3_prepare_v2(ppDb, "select destination, sender, packet_id, encrypted_bytes, message_hash, rx_time, channel_hash \
        from local_messages where channel_hash=? order by rx_time asc LIMIT 1;", // earliest first
                       -1, &fromScratchStmt, NULL);

    sqlite3_prepare_v2(ppDb,
                       "select destination, sender, packet_id, encrypted_bytes, message_hash, rx_time, channel_hash, payload \
        from local_messages where message_hash=? order by rx_time asc LIMIT 1;", // earliest first
                       -1, &fromScratchByHashStmt, NULL);

    sqlite3_prepare_v2(ppDb, "SELECT COUNT(*) from channel_messages where message_hash=?", -1, &checkDup, NULL);

    sqlite3_prepare_v2(ppDb, "SELECT COUNT(*) from local_messages where message_hash=?", -1, &checkScratch, NULL);

    sqlite3_prepare_v2(ppDb, "DELETE from local_messages where message_hash=?", -1, &removeScratch, NULL);

    sqlite3_prepare_v2(ppDb, "UPDATE channel_messages SET payload=? WHERE message_hash=?", -1, &updatePayloadStmt, NULL);

    encryptedOk = true;

    // wait about 15 seconds after boot for the first runOnce()
    this->setInterval(15 * 1000);
}

int32_t StoreForwardPlusPlusModule::runOnce()
{
    LOG_WARN("StoreForward++ runONce");
    if (getRTCQuality() < RTCQualityNTP) {
        LOG_WARN("StoreForward++ deferred due to time quality %u", getRTCQuality());
        return 60 * 60 * 1000;
    }
    uint8_t root_hash_bytes[32] = {0};
    ChannelHash hash = channels.getHash(0);
    getOrAddRootFromChannelHash(hash, root_hash_bytes);

    // get tip of chain for this channel
    uint8_t last_message_commit_hash[32] = {0};
    uint8_t last_message_hash[32] = {0};
    uint32_t chain_end_rx_time = getChainEnd(hash, last_message_commit_hash, last_message_hash);
    if (chain_end_rx_time == 0) {
        LOG_WARN("Store and Forward++ database lookup returned null");
        return 60 * 60 * 1000;
    }

    // if we have something in scratch, maybe send it rather then announce?
    // TODO: include timestamp?
    // thought being that it would be nice to have an accurate timestamp on messages.
    // if we don't include the timestamp in the CANON announcements, the only way to get it is to receive the full message.
    canonAnnounce(last_message_hash, last_message_commit_hash, root_hash_bytes, chain_end_rx_time);

    return 60 * 60 * 1000;
}

bool StoreForwardPlusPlusModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_StoreForwardPlusPlus *t)
{
    SHA256 commit_hash;
    uint8_t last_message_hash[32] = {0};
    uint8_t last_commit_hash[32] = {0};
    uint8_t commit_hash_bytes[32] = {0};

    LOG_WARN("in handleReceivedProtobuf");
    LOG_WARN("Sfp++ node %u sent us sf++ packet", mp.from);
    printBytes("commit_hash ", t->commit_hash.bytes, t->commit_hash.size);
    printBytes("root_hash ", t->root_hash.bytes, t->root_hash.size);
    if (t->sfpp_message_type == meshtastic_StoreForwardPlusPlus_SFPP_message_type_CANON_ANNOUNCE) {
        // check commit_hash.size

        if (portduino_config.sfpp_stratum0) {
            LOG_WARN("Received a CANON_ANNOUNCE while stratum 0");
            uint8_t next_commit_hash[32] = {0};

            if (getNextHash(t->root_hash.bytes, t->commit_hash.bytes, next_commit_hash)) {
                printBytes("next chain hash: ", next_commit_hash, 32);

                broadcastLink(next_commit_hash, t->root_hash.bytes);
            }
        } else {
            uint8_t tmp_root_hash_bytes[32] = {0};

            LOG_WARN("Received a CANON_ANNOUNCE");
            if (getRootFromChannelHash(router->p_encrypted->channel, tmp_root_hash_bytes)) {
                // we found the hash, check if it's the right one
                if (memcmp(tmp_root_hash_bytes, t->root_hash.bytes, 32) != 0) {
                    LOG_WARN("Found root hash, and it doesn't match!");
                    return true;
                }
            } else {

                addRootToMappings(router->p_encrypted->channel, t->root_hash.bytes);
                LOG_WARN("Adding root hash to mappings");
            }

            // get tip of chain for this channel
            uint8_t last_message_commit_hash[32] = {0};
            uint8_t last_message_hash[32] = {0};

            // get chain tip
            if (getChainEnd(router->p_encrypted->channel, last_message_commit_hash, last_message_hash)) {
                if (memcmp(last_message_commit_hash, t->commit_hash.bytes, 32) == 0) {
                    LOG_WARN("End of chain matches!");
                    sendFromScratch(router->p_encrypted->channel);
                    // TODO: Send a message from the local queue
                } else {
                    ("End of chain does not match!");
                    if (isInScratch(t->message_hash.bytes)) {

                        commit_hash.reset();

                        if (getChainEnd(router->p_encrypted->channel, last_commit_hash, last_message_hash)) {
                            printBytes("last message: 0x", last_commit_hash, 32);
                            commit_hash.update(last_commit_hash, 32);
                        } else {
                            printBytes("new chain root: 0x", t->root_hash.bytes, 32);
                            commit_hash.update(t->root_hash.bytes, 32);
                        }

                        commit_hash.update(t->message_hash.bytes, 32);
                        // message_hash.update(&mp.rx_time, sizeof(mp.rx_time));
                        commit_hash.finalize(commit_hash_bytes, 32);

                        // if this matches, we don't need to request the message
                        // we know exactly what it is
                        if (memcmp(commit_hash_bytes, t->commit_hash.bytes, 32) == 0) {
                            link_object scratch_object = getFromScratch(t->message_hash.bytes, 32);

                            // most of this we need to fetch from scratch
                            addToChain(scratch_object.to, scratch_object.from, scratch_object.id, scratch_object.channel_hash,
                                       scratch_object.encrypted_bytes, scratch_object.encrypted_len, scratch_object.message_hash,
                                       commit_hash_bytes, t->root_hash.bytes, scratch_object.rx_time, "", 0);
                            // TODO: Copy payload from scratch into chain
                            if (scratch_object.payload != "") {
                                updatePayload(t->message_hash.bytes, scratch_object.payload.c_str(),
                                              scratch_object.payload.size());
                            }
                            removeFromScratch(t->message_hash.bytes);
                            // short circuit and return
                            return true;
                        }
                    }
                    requestNextMessage(t->root_hash.bytes, last_message_commit_hash);
                }
            } else {
                LOG_WARN("No Messages on this chain, request!");
                requestNextMessage(t->root_hash.bytes, t->root_hash.bytes);
            }
        }
    } else if (t->sfpp_message_type == meshtastic_StoreForwardPlusPlus_SFPP_message_type_LINK_REQUEST) {
        uint8_t next_commit_hash[32] = {0};

        LOG_WARN("Received link request");
        if (getNextHash(t->root_hash.bytes, t->commit_hash.bytes, next_commit_hash)) {
            printBytes("next chain hash: ", next_commit_hash, 32);

            broadcastLink(next_commit_hash, t->root_hash.bytes);
        }

        // if root and chain hashes are the same, grab the first message on the chain
        // if different, get the message directly after.
        // check if the root

    } else if (t->sfpp_message_type == meshtastic_StoreForwardPlusPlus_SFPP_message_type_LINK_PROVIDE) {
        LOG_WARN("Link Provide received!");
        ChannelHash _channel_hash = getChannelHashFromRoot(t->root_hash.bytes);

        //
        if (portduino_config.sfpp_stratum0) {
            if (isInDB(t->message_hash.bytes)) {
                LOG_WARN("Received link already in chain");
                // TODO: respond with last link?
            }
            uint8_t root_hash_bytes[32] = {0};

            if (!getRootFromChannelHash(router->p_encrypted->channel, root_hash_bytes)) {
                LOG_WARN("Hash bytes not found for incoming link");
                return true;
            }

            if (t->root_hash.size != 32 || memcmp(root_hash_bytes, t->root_hash.bytes, 32) != 0) {
                LOG_WARN("Hash bytes mismatch for incoming link");
                return true;
            }

            commit_hash.reset();

            if (getChainEnd(router->p_encrypted->channel, last_commit_hash, last_message_hash)) {
                printBytes("last message: 0x", last_commit_hash, 32);
                commit_hash.update(last_commit_hash, 32);
            } else {
                printBytes("new chain root: 0x", root_hash_bytes, 32);
                commit_hash.update(root_hash_bytes, 32);
            }

            commit_hash.update(t->message_hash.bytes, 32);
            // message_hash.update(&mp.rx_time, sizeof(mp.rx_time));
            commit_hash.finalize(commit_hash_bytes, 32);

            // calculate the commit_hash
            addToChain(t->encapsulated_to, t->encapsulated_from, t->encapsulated_id, _channel_hash, t->message.bytes,
                       t->message.size, t->message_hash.bytes, commit_hash_bytes, root_hash_bytes, t->encapsulated_rxtime, "", 0);

            canonAnnounce(t->message_hash.bytes, commit_hash_bytes, root_hash_bytes, t->encapsulated_rxtime);

            LOG_WARN("Attempting to Rebroadcast1");
            meshtastic_MeshPacket *p = router->allocForSending();
            p->to = t->encapsulated_to;
            p->from = t->encapsulated_from;
            p->id = t->encapsulated_id;
            p->channel = _channel_hash;
            p->which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
            p->encrypted.size = t->message.size;
            memcpy(p->encrypted.bytes, t->message.bytes, t->message.size);
            p->transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA; // only a tiny white lie
            service->sendToMesh(p, RX_SRC_RADIO, true);                                       // Send to mesh, cc to phone
            // router->sendLocal(p);

        } else {
            addToChain(t->encapsulated_to, t->encapsulated_from, t->encapsulated_id, _channel_hash, t->message.bytes,
                       t->message.size, t->message_hash.bytes, t->commit_hash.bytes, t->root_hash.bytes, t->encapsulated_rxtime,
                       "", 0);
            if (isInScratch(t->message_hash.bytes)) {
                // TODO: Copy payload from scratch into chain
                link_object scratch_object = getFromScratch(t->message_hash.bytes, 32);
                if (scratch_object.payload != "") {
                    updatePayload(t->message_hash.bytes, scratch_object.payload.c_str(), scratch_object.payload.size());
                }
                removeFromScratch(t->message_hash.bytes);
            } else {
                // TODO: compare the time, and don't rebroadcast really old messages
                // if this packet is new to us, we rebroadcast it
                LOG_WARN("Attempting to Rebroadcast2");
                meshtastic_MeshPacket *p = router->allocForSending();
                p->to = t->encapsulated_to;
                p->from = t->encapsulated_from;
                p->id = t->encapsulated_id;
                p->channel = _channel_hash;
                p->which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
                p->encrypted.size = t->message.size;
                memcpy(p->encrypted.bytes, t->message.bytes, t->message.size);
                p->transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA; // only a tiny white lie
                service->sendToMesh(p, RX_SRC_RADIO, true);                                       // Send to mesh, cc to phone

                // router->sendLocal(p);
            }
            requestNextMessage(t->root_hash.bytes, t->commit_hash.bytes);

            // check for message hash in scratch
        }

        // turn around and request the next message
    }

    return true;
}

ProcessMessage StoreForwardPlusPlusModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    // To avoid terrible time problems, require NTP or GPS time
    if (getRTCQuality() < RTCQualityNTP) {
        return ProcessMessage::CONTINUE;
    }

    // the sender+destination pair is an interesting unique id (though ordering) (smaller one goes first?)
    // so messages with a unique pair become a chain
    // These get a table

    // message to broadcast get a chain per channel hash
    // second table
    // for now, channel messages are limited to decryptable
    // limited to text messages

    // create a unique-from-nodenums() class that returns a 64-bit value

    SHA256 message_hash, commit_hash;
    uint8_t message_hash_bytes[32] = {0};
    uint8_t commit_hash_bytes[32] = {0};
    uint8_t root_hash_bytes[32] = {0};

    // For the moment, this is strictly LoRa
    if (mp.transport_mechanism != meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA) {
        return ProcessMessage::CONTINUE; // Let others look at this message also if they want
    }

    // will eventually host DMs and other undecodable messages
    if (mp.which_payload_variant != meshtastic_MeshPacket_decoded_tag) {
        return ProcessMessage::CONTINUE; // Let others look at this message also if they want
    }
    LOG_WARN("in handleReceived");
    if (mp.decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP && mp.to == NODENUM_BROADCAST) {

        // do not include rxtime in the message hash. We want these to match when more then one node receives and compares notes.
        // maybe include it in the commit hash

        message_hash.reset();
        message_hash.update(router->p_encrypted->encrypted.bytes, router->p_encrypted->encrypted.size);
        message_hash.update(&mp.to, sizeof(mp.to));
        message_hash.update(&mp.from, sizeof(mp.from));
        message_hash.update(&mp.id, sizeof(mp.id));
        message_hash.finalize(message_hash_bytes, 32);

        if (isInDB(message_hash_bytes)) {
            LOG_WARN("found message in db");
            updatePayload(message_hash_bytes, (char *)mp.decoded.payload.bytes, mp.decoded.payload.size);
            // TODO: For this iteration, we should check if the text payload is present in the db, and update it if not
            return ProcessMessage::CONTINUE;
        }

        if (!portduino_config.sfpp_stratum0) {
            if (!isInDB(message_hash_bytes)) {
                addToScratch(mp.to, mp.from, mp.id, router->p_encrypted->channel, router->p_encrypted->encrypted.bytes,
                             router->p_encrypted->encrypted.size, message_hash_bytes, root_hash_bytes, mp.rx_time,
                             (char *)mp.decoded.payload.bytes, mp.decoded.payload.size);
                LOG_WARN("added message to scratch");
                // send link to upstream?
            }
            return ProcessMessage::CONTINUE;
        }

        // need to resolve the channel hash to the root hash
        getRootFromChannelHash(router->p_encrypted->channel, root_hash_bytes);
        uint8_t last_message_hash[32] = {0};
        uint8_t last_commit_hash[32] = {0};

        commit_hash.reset();

        if (getChainEnd(router->p_encrypted->channel, last_commit_hash, last_message_hash)) {
            printBytes("last message: 0x", last_commit_hash, 32);
            commit_hash.update(last_commit_hash, 32);
        } else {
            printBytes("new chain root: 0x", root_hash_bytes, 32);
            commit_hash.update(root_hash_bytes, 32);
        }

        commit_hash.update(message_hash_bytes, 32);
        // message_hash.update(&mp.rx_time, sizeof(mp.rx_time));
        commit_hash.finalize(commit_hash_bytes, 32);

        // select HEX(commit_hash),HEX(channel_hash), payload, destination from channel_messages order by rowid desc;

        // push a message into the local chain DB

        // next, the stratum n+1 node needs to tuck messages away and attempt to update stratum 0

        addToChain(mp.to, mp.from, mp.id, router->p_encrypted->channel, router->p_encrypted->encrypted.bytes,
                   router->p_encrypted->encrypted.size, message_hash_bytes, commit_hash_bytes, root_hash_bytes, mp.rx_time,
                   (char *)mp.decoded.payload.bytes, mp.decoded.payload.size);

        // TODO: Limit to 25% bandwidth
        canonAnnounce(message_hash_bytes, commit_hash_bytes, root_hash_bytes, mp.rx_time);

        return ProcessMessage::CONTINUE; // Let others look at this message also if they want

        // one of the command messages
    } else if (mp.decoded.portnum == meshtastic_PortNum_STORE_FORWARD_PLUSPLUS_APP) {
        LOG_WARN("Got a STORE_FORWARD++ packet");
        meshtastic_StoreForwardPlusPlus scratch;
        pb_decode_from_bytes(mp.decoded.payload.bytes, mp.decoded.payload.size, meshtastic_StoreForwardPlusPlus_fields, &scratch);
        handleReceivedProtobuf(mp, &scratch);
        // when we get an update this way, if the message isn't on the chain, this node hasn't seen it, and can rebroadcast.
        return ProcessMessage::CONTINUE;
    }
    return ProcessMessage::CONTINUE;
}

bool StoreForwardPlusPlusModule::getRootFromChannelHash(ChannelHash _ch_hash, uint8_t *_root_hash)
{
    bool found = false;
    sqlite3_stmt *getHash;
    int rc = sqlite3_prepare_v2(ppDb, "select root_hash from mappings where identifier=?;", -1, &getHash, NULL);
    sqlite3_bind_int(getHash, 1, _ch_hash);
    sqlite3_step(getHash);
    uint8_t *tmp_root_hash = (uint8_t *)sqlite3_column_blob(getHash, 0);
    if (tmp_root_hash) {
        LOG_WARN("Found root hash!");
        memcpy(_root_hash, tmp_root_hash, 32);
        found = true;
    }
    sqlite3_finalize(getHash);
    return found;
}

ChannelHash StoreForwardPlusPlusModule::getChannelHashFromRoot(uint8_t *_root_hash)
{
    sqlite3_stmt *getHash;
    int rc = sqlite3_prepare_v2(ppDb, "select identifier from mappings where root_hash=?;", -1, &getHash, NULL);
    sqlite3_bind_blob(getHash, 1, _root_hash, 32, NULL);
    sqlite3_step(getHash);
    ChannelHash tmp_hash = (ChannelHash)sqlite3_column_int(getHash, 0);
    sqlite3_finalize(getHash);
    return tmp_hash;
}

// return code indicates newly created chain
bool StoreForwardPlusPlusModule::getOrAddRootFromChannelHash(ChannelHash _ch_hash, uint8_t *_root_hash)
{
    LOG_WARN("getOrAddRootFromChannelHash()");
    bool isNew = !getRootFromChannelHash(_ch_hash, _root_hash);

    if (isNew) {
        if (portduino_config.sfpp_stratum0) {
            LOG_WARN("Generating Root hash!");
            // generate root hash
            SHA256 commit_hash;
            commit_hash.update(&_ch_hash, sizeof(_ch_hash));
            NodeNum ourNode = nodeDB->getNodeNum();
            commit_hash.update(&ourNode, sizeof(ourNode));
            uint32_t rtc_sec = getValidTime(RTCQuality::RTCQualityDevice, true);
            commit_hash.update(&rtc_sec, sizeof(rtc_sec));
            commit_hash.finalize(_root_hash, 32);

            addRootToMappings(_ch_hash, _root_hash);
            LOG_WARN("here4");
        }
    }
    return isNew;
}

bool StoreForwardPlusPlusModule::addRootToMappings(ChannelHash _ch_hash, uint8_t *_root_hash)
{
    LOG_WARN("addRootToMappings()");
    printBytes("_root_hash", _root_hash, 32);
    sqlite3_stmt *getHash;

    // write to the table
    int rc =
        sqlite3_prepare_v2(ppDb, "INSERT INTO mappings (chain_type, identifier, root_hash) VALUES(?, ?, ?);", -1, &getHash, NULL);
    LOG_WARN("%d", rc);
    int type = chain_types::channel_chain;
    // note, must be an int variable

    sqlite3_bind_int(getHash, 1, type);
    sqlite3_bind_int(getHash, 2, _ch_hash);
    sqlite3_bind_blob(getHash, 3, _root_hash, 32, NULL);
    // sqlite3_bind_int(getHash, 4, nodeToAdd);
    rc = sqlite3_step(getHash);
    LOG_WARN("result %u, %s", rc, sqlite3_errmsg(ppDb));
    sqlite3_finalize(getHash);
    return true;
}

uint32_t StoreForwardPlusPlusModule::getChainEnd(ChannelHash _ch_hash, uint8_t *_commit_hash, uint8_t *_message_hash)
{
    LOG_WARN("getChainEnd");
    uint8_t _root_hash[32] = {0};
    if (!getRootFromChannelHash(_ch_hash, _root_hash)) {
        LOG_WARN("No root hash found for channel %u", _ch_hash);
        return 0;
    }

    std::string getEntry_string =
        "select commit_hash, message_hash, rx_time from channel_messages where root_hash=? order by rowid desc LIMIT 1;";
    sqlite3_stmt *getEntry;
    int rc = sqlite3_prepare_v2(ppDb, getEntry_string.c_str(), getEntry_string.size(), &getEntry, NULL);
    sqlite3_bind_blob(getEntry, 1, _root_hash, 32, NULL);
    sqlite3_step(getEntry);
    uint8_t *last_message_commit_hash = (uint8_t *)sqlite3_column_blob(getEntry, 0);
    uint8_t *last_message_hash = (uint8_t *)sqlite3_column_blob(getEntry, 1);
    uint32_t _rx_time = sqlite3_column_int(getEntry, 2);
    if (last_message_commit_hash != nullptr) {
        memcpy(_commit_hash, last_message_commit_hash, 32);
    }
    if (last_message_hash != nullptr) {
        memcpy(_message_hash, last_message_hash, 32);
    }
    if (last_message_commit_hash == nullptr || last_message_hash == nullptr) {
        LOG_WARN("Store and Forward++ database lookup returned null");
        sqlite3_finalize(getEntry);

        return 0;
    }
    sqlite3_finalize(getEntry);
    return _rx_time;
}

void StoreForwardPlusPlusModule::requestNextMessage(uint8_t *_root_hash, uint8_t *_commit_hash)
{

    meshtastic_StoreForwardPlusPlus storeforward = meshtastic_StoreForwardPlusPlus_init_zero;
    storeforward.sfpp_message_type = meshtastic_StoreForwardPlusPlus_SFPP_message_type_LINK_REQUEST;
    // set root hash

    // set chain hash
    storeforward.commit_hash.size = 32;
    memcpy(storeforward.commit_hash.bytes, _commit_hash, 32);

    // set root hash
    storeforward.root_hash.size = 32;
    memcpy(storeforward.root_hash.bytes, _root_hash, 32);

    // storeforward.
    meshtastic_MeshPacket *p = allocDataProtobuf(storeforward);
    p->to = NODENUM_BROADCAST;
    p->decoded.want_response = false;
    p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    p->channel = 0;
    LOG_INFO("Send packet to mesh");
    service->sendToMesh(p, RX_SRC_LOCAL, true);
}

bool StoreForwardPlusPlusModule::getNextHash(uint8_t *_root_hash, uint8_t *_commit_hash, uint8_t *next_commit_hash)
{
    LOG_WARN("getNextHash");

    ChannelHash _channel_hash = getChannelHashFromRoot(_root_hash);
    LOG_WARN("_channel_hash %u", _channel_hash);

    sqlite3_stmt *getHash;
    int rc = sqlite3_prepare_v2(ppDb, "select commit_hash from channel_messages where root_hash=? order by rowid ASC;", -1,
                                &getHash, NULL);

    LOG_WARN("%d", rc);
    if (rc != SQLITE_OK) {
        LOG_WARN("here2 %u, %s", rc, sqlite3_errmsg(ppDb));
    }
    sqlite3_bind_blob(getHash, 1, _root_hash, 32, NULL);

    bool next_hash = false;

    // asking for the first entry on the chain
    if (memcmp(_root_hash, _commit_hash, 32) == 0) {
        rc = sqlite3_step(getHash);
        if (rc != SQLITE_OK) {
            LOG_WARN("here2 %u, %s", rc, sqlite3_errmsg(ppDb));
        }
        uint8_t *tmp_commit_hash = (uint8_t *)sqlite3_column_blob(getHash, 0);
        printBytes("commit_hash", tmp_commit_hash, 32);
        memcpy(next_commit_hash, tmp_commit_hash, 32);
        next_hash = true;
    } else {
        bool found_hash = false;

        LOG_WARN("Looking for next hashes");
        uint8_t *tmp_commit_hash;
        while (sqlite3_step(getHash) != SQLITE_DONE) {
            tmp_commit_hash = (uint8_t *)sqlite3_column_blob(getHash, 0);

            if (found_hash) {
                LOG_WARN("Found hash");
                memcpy(next_commit_hash, tmp_commit_hash, 32);
                next_hash = true;
                break;
            }
            if (memcmp(tmp_commit_hash, _commit_hash, 32) == 0)
                found_hash = true;
        }
    }

    sqlite3_finalize(getHash);
    return next_hash;
}

bool StoreForwardPlusPlusModule::broadcastLink(uint8_t *_commit_hash, uint8_t *_root_hash)
{
    sqlite3_stmt *getHash;
    int rc = sqlite3_prepare_v2(ppDb, "select destination, sender, packet_id, encrypted_bytes, message_hash, rx_time \
        from channel_messages where commit_hash=?;",
                                -1, &getHash, NULL);

    LOG_WARN("%d", rc);
    if (rc != SQLITE_OK) {
        LOG_WARN("here2 %u, %s", rc, sqlite3_errmsg(ppDb));
    }
    sqlite3_bind_blob(getHash, 1, _commit_hash, 32, NULL);
    sqlite3_step(getHash);

    meshtastic_StoreForwardPlusPlus storeforward = meshtastic_StoreForwardPlusPlus_init_zero;
    storeforward.sfpp_message_type = meshtastic_StoreForwardPlusPlus_SFPP_message_type_LINK_PROVIDE;

    storeforward.encapsulated_to = sqlite3_column_int(getHash, 0);
    storeforward.encapsulated_from = sqlite3_column_int(getHash, 1);
    storeforward.encapsulated_id = sqlite3_column_int(getHash, 2);

    uint8_t *_payload = (uint8_t *)sqlite3_column_blob(getHash, 3);
    storeforward.message.size = sqlite3_column_bytes(getHash, 3);
    memcpy(storeforward.message.bytes, _payload, storeforward.message.size);

    uint8_t *_message_hash = (uint8_t *)sqlite3_column_blob(getHash, 4);
    storeforward.message_hash.size = 32;
    memcpy(storeforward.message_hash.bytes, _message_hash, storeforward.message_hash.size);

    storeforward.encapsulated_rxtime = sqlite3_column_int(getHash, 5);

    storeforward.commit_hash.size = 32;
    memcpy(storeforward.commit_hash.bytes, _commit_hash, 32);

    storeforward.root_hash.size = 32;
    memcpy(storeforward.root_hash.bytes, _root_hash, 32);

    sqlite3_finalize(getHash);

    meshtastic_MeshPacket *p = allocDataProtobuf(storeforward);
    p->to = NODENUM_BROADCAST;
    p->decoded.want_response = false;
    p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    p->channel = 0;
    LOG_INFO("Send link to mesh");
    service->sendToMesh(p, RX_SRC_LOCAL, true);
    return true;
}

bool StoreForwardPlusPlusModule::sendFromScratch(uint8_t _channel_hash)
{
    LOG_WARN("sendFromScratch");
    //    "select destination, sender, packet_id, channel_hash, encrypted_bytes, message_hash, rx_time \
    //    from local_messages order by rx_time desc LIMIT 1;"
    sqlite3_bind_int(fromScratchStmt, 1, _channel_hash);
    if (sqlite3_step(fromScratchStmt) == SQLITE_DONE) {
        LOG_WARN("No messages in scratch to forward");
        return false;
    }
    uint8_t _root_hash[32] = {0};
    if (!getRootFromChannelHash(_channel_hash, _root_hash)) {
        LOG_ERROR("Error getting root hash");
        return false;
    }

    meshtastic_StoreForwardPlusPlus storeforward = meshtastic_StoreForwardPlusPlus_init_zero;
    storeforward.sfpp_message_type = meshtastic_StoreForwardPlusPlus_SFPP_message_type_LINK_PROVIDE;

    storeforward.encapsulated_to = sqlite3_column_int(fromScratchStmt, 0);
    storeforward.encapsulated_from = sqlite3_column_int(fromScratchStmt, 1);
    storeforward.encapsulated_id = sqlite3_column_int(fromScratchStmt, 2);

    uint8_t *_encrypted = (uint8_t *)sqlite3_column_blob(fromScratchStmt, 3);
    storeforward.message.size = sqlite3_column_bytes(fromScratchStmt, 3);
    memcpy(storeforward.message.bytes, _encrypted, storeforward.message.size);

    uint8_t *_message_hash = (uint8_t *)sqlite3_column_blob(fromScratchStmt, 4);
    storeforward.message_hash.size = 32;
    memcpy(storeforward.message_hash.bytes, _message_hash, storeforward.message_hash.size);

    storeforward.encapsulated_rxtime = sqlite3_column_int(fromScratchStmt, 5);

    storeforward.root_hash.size = 32;
    memcpy(storeforward.root_hash.bytes, _root_hash, 32);

    sqlite3_reset(fromScratchStmt);

    meshtastic_MeshPacket *p = allocDataProtobuf(storeforward);
    p->to = NODENUM_BROADCAST;
    p->decoded.want_response = false;
    p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    p->channel = 0;
    LOG_INFO("Send link to mesh");
    service->sendToMesh(p, RX_SRC_LOCAL, true);
    return true;
}

bool StoreForwardPlusPlusModule::addToChain(uint32_t to, uint32_t from, uint32_t id, ChannelHash channel_hash,
                                            uint8_t *encrypted_bytes, size_t encrypted_len, uint8_t *_message_hash,
                                            uint8_t *_commit_hash, uint8_t *_root_hash, uint32_t _rx_time, char *payload_bytes,
                                            size_t payload_len)

{
    LOG_WARN("Add to chain");
    // TODO: Make a data structure for this data

    // push a message into the local chain DB
    // destination
    sqlite3_bind_int(chain_insert_stmt, 1, to);
    // sender
    sqlite3_bind_int(chain_insert_stmt, 2, from);
    // packet_id
    sqlite3_bind_int(chain_insert_stmt, 3, id);
    // root_hash
    sqlite3_bind_blob(chain_insert_stmt, 4, _root_hash, 32, NULL);
    // encrypted_bytes
    sqlite3_bind_blob(chain_insert_stmt, 5, encrypted_bytes, encrypted_len, NULL);

    // message_hash
    sqlite3_bind_blob(chain_insert_stmt, 6, _message_hash, 32, NULL);
    // rx_time
    sqlite3_bind_int(chain_insert_stmt, 7, _rx_time);

    // commit_hash
    sqlite3_bind_blob(chain_insert_stmt, 8, _commit_hash, 32, NULL);
    // payload
    sqlite3_bind_text(chain_insert_stmt, 9, payload_bytes, payload_len, NULL);

    sqlite3_step(chain_insert_stmt);
    sqlite3_reset(chain_insert_stmt);
    return true;
}

bool StoreForwardPlusPlusModule::addToScratch(uint32_t to, uint32_t from, uint32_t id, ChannelHash channel_hash,
                                              uint8_t *encrypted_bytes, size_t encrypted_len, uint8_t *_message_hash,
                                              uint8_t *_root_hash, uint32_t _rx_time, char *payload_bytes, size_t payload_len)

{
    // TODO: Make a data structure for this data

    // push a message into the local chain DB
    // destination
    sqlite3_bind_int(scratch_insert_stmt, 1, to);
    // sender
    sqlite3_bind_int(scratch_insert_stmt, 2, from);
    // packet_id
    sqlite3_bind_int(scratch_insert_stmt, 3, id);
    // root_hash
    sqlite3_bind_blob(scratch_insert_stmt, 4, _root_hash, 32, NULL);
    // encrypted_bytes
    sqlite3_bind_blob(scratch_insert_stmt, 5, encrypted_bytes, encrypted_len, NULL);

    // message_hash
    sqlite3_bind_blob(scratch_insert_stmt, 6, _message_hash, 32, NULL);
    // rx_time
    sqlite3_bind_int(scratch_insert_stmt, 7, _rx_time);

    // payload
    sqlite3_bind_text(scratch_insert_stmt, 8, payload_bytes, payload_len, NULL);
    const char *_error_mesg = sqlite3_errmsg(ppDb);

    LOG_WARN("step %u, %s", sqlite3_step(scratch_insert_stmt), _error_mesg);
    sqlite3_reset(scratch_insert_stmt);
    return true;
}

void StoreForwardPlusPlusModule::canonAnnounce(uint8_t *_message_hash, uint8_t *_commit_hash, uint8_t *_root_hash,
                                               uint32_t _rx_time)
{
    meshtastic_StoreForwardPlusPlus storeforward = meshtastic_StoreForwardPlusPlus_init_zero;
    storeforward.sfpp_message_type = meshtastic_StoreForwardPlusPlus_SFPP_message_type_CANON_ANNOUNCE;
    // set root hash

    // set message hash
    storeforward.message_hash.size = 32;
    memcpy(storeforward.message_hash.bytes, _message_hash, 32);

    // set chain hash
    storeforward.commit_hash.size = 32;
    memcpy(storeforward.commit_hash.bytes, _commit_hash, 32);

    // set root hash
    storeforward.root_hash.size = 32;
    memcpy(storeforward.root_hash.bytes, _root_hash, 32);

    storeforward.encapsulated_rxtime = _rx_time;
    // storeforward.
    meshtastic_MeshPacket *p = allocDataProtobuf(storeforward);
    p->to = NODENUM_BROADCAST;
    p->decoded.want_response = false;
    p->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    p->channel = 0;
    LOG_INFO("Send packet to mesh");
    service->sendToMesh(p, RX_SRC_LOCAL, true);
}

bool StoreForwardPlusPlusModule::isInDB(uint8_t *message_hash_bytes)
{
    sqlite3_bind_blob(checkDup, 1, message_hash_bytes, 32, NULL);
    sqlite3_step(checkDup);
    int numberFound = sqlite3_column_int(checkDup, 0);
    sqlite3_reset(checkDup);
    if (numberFound > 0)
        return true;
    return false;
}

bool StoreForwardPlusPlusModule::isInScratch(uint8_t *message_hash_bytes)
{
    LOG_WARN("isInScratch");
    sqlite3_bind_blob(checkScratch, 1, message_hash_bytes, 32, NULL);
    sqlite3_step(checkScratch);
    int numberFound = sqlite3_column_int(checkScratch, 0);
    sqlite3_reset(checkScratch);
    if (numberFound > 0)
        return true;
    return false;
}

void StoreForwardPlusPlusModule::removeFromScratch(uint8_t *message_hash_bytes)
{
    LOG_WARN("removeFromScratch");
    sqlite3_bind_blob(removeScratch, 1, message_hash_bytes, 32, NULL);
    sqlite3_step(removeScratch);
    int numberFound = sqlite3_column_int(removeScratch, 0);
    sqlite3_reset(removeScratch);
}

void StoreForwardPlusPlusModule::updatePayload(uint8_t *message_hash_bytes, const char *payload_bytes, size_t payload_len)
{
    LOG_WARN("updatePayload");
    sqlite3_bind_text(updatePayloadStmt, 1, payload_bytes, payload_len, NULL);
    sqlite3_bind_blob(updatePayloadStmt, 2, message_hash_bytes, 32, NULL);
    auto res = sqlite3_step(updatePayloadStmt);
    const char *_error_mesg = sqlite3_errmsg(ppDb);
    LOG_WARN("step %u, %s", res, _error_mesg);
    sqlite3_reset(updatePayloadStmt);
}

StoreForwardPlusPlusModule::link_object StoreForwardPlusPlusModule::getFromScratch(uint8_t *message_hash_bytes, size_t hash_len)
{

    // vscode wrote this
    LOG_WARN("getFromScratch");
    link_object lo;

    sqlite3_bind_blob(fromScratchByHashStmt, 1, message_hash_bytes, hash_len, NULL);
    auto res = sqlite3_step(fromScratchByHashStmt);
    const char *_error_mesg = sqlite3_errmsg(ppDb);
    LOG_WARN("step %u, %s", res, _error_mesg);
    lo.to = sqlite3_column_int(fromScratchByHashStmt, 0);
    lo.from = sqlite3_column_int(fromScratchByHashStmt, 1);
    lo.id = sqlite3_column_int(fromScratchByHashStmt, 2);

    uint8_t *encrypted_bytes = (uint8_t *)sqlite3_column_blob(fromScratchByHashStmt, 3);
    lo.encrypted_len = sqlite3_column_bytes(fromScratchByHashStmt, 3);
    memcpy(lo.encrypted_bytes, encrypted_bytes, lo.encrypted_len);
    uint8_t *message_hash = (uint8_t *)sqlite3_column_blob(fromScratchByHashStmt, 4);
    memcpy(lo.message_hash, message_hash, 32);
    lo.rx_time = sqlite3_column_int(fromScratchByHashStmt, 5);
    lo.channel_hash - sqlite3_column_int(fromScratchByHashStmt, 6);
    lo.payload =
        std::string((char *)sqlite3_column_text(fromScratchByHashStmt, 7), sqlite3_column_bytes(fromScratchByHashStmt, 7));
    sqlite3_reset(fromScratchByHashStmt);
    return lo;
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