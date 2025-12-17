#pragma once
#include "Channels.h"
#include "ProtobufModule.h"
#include "Router.h"
#include "SinglePortModule.h"
#include "sqlite3.h"

/**
 * A simple example module that just replies with "Message received" to any message it receives.
 */
class StoreForwardPlusPlusModule : public ProtobufModule<meshtastic_StoreForwardPlusPlus>, private concurrency::OSThread
{
    struct link_object {
        uint32_t to;
        uint32_t from;
        uint32_t id;
        uint32_t rx_time;
        ChannelHash channel_hash;
        uint8_t encrypted_bytes[256] = {0};
        size_t encrypted_len;
        uint8_t message_hash[32] = {0};
        uint8_t root_hash[32] = {0};
        uint8_t commit_hash[32] = {0};
        // TODO: Make these sizes instead?
        bool has_commit_hash = false;
        std::string payload;
    };

  public:
    /** Constructor
     * name is for debugging output
     */
    StoreForwardPlusPlusModule();

    /*
      -Override the wantPacket method.
    */
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override
    {
        // if encrypted but not too FFFF
        // want
        switch (p->decoded.portnum) {
        case meshtastic_PortNum_TEXT_MESSAGE_APP:
        case 35:
            return true;
        default:
            return false;
        }
    }

  protected:
    /** Called to handle a particular incoming message
    @return ProcessMessage::STOP if you've guaranteed you've handled this message and no other handlers should be considered for
    it
    */
    virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_StoreForwardPlusPlus *t) override;

    virtual int32_t runOnce() override;

  private:
    sqlite3 *ppDb;
    sqlite3_stmt *chain_insert_stmt;
    sqlite3_stmt *scratch_insert_stmt;
    sqlite3_stmt *checkDup;
    sqlite3_stmt *checkScratch;
    sqlite3_stmt *removeScratch;
    sqlite3_stmt *updatePayloadStmt;
    sqlite3_stmt *getPayloadFromScratchStmt;
    sqlite3_stmt *fromScratchStmt;
    sqlite3_stmt *fromScratchByHashStmt;

    // returns wasfound
    bool getRootFromChannelHash(ChannelHash, uint8_t *);

    ChannelHash getChannelHashFromRoot(uint8_t *_root_hash);

    bool getNextHash(uint8_t *_root_hash, uint8_t *, uint8_t *);

    // returns isnew
    bool getOrAddRootFromChannelHash(ChannelHash, uint8_t *);

    bool addRootToMappings(ChannelHash, uint8_t *);

    // return indicates message found
    uint32_t getChainEnd(ChannelHash, uint8_t *, uint8_t *);

    void requestNextMessage(uint8_t *, uint8_t *);

    bool broadcastLink(uint8_t *, uint8_t *);

    bool sendFromScratch(uint8_t);

    bool addToChain(link_object &);

    bool addToScratch(link_object &);

    void canonAnnounce(uint8_t *, uint8_t *, uint8_t *, uint32_t);

    bool isInDB(uint8_t *);

    bool isInScratch(uint8_t *);

    link_object getFromScratch(uint8_t *, size_t);

    void removeFromScratch(uint8_t *);

    void updatePayload(uint8_t *, std::string);

    // does not set the root hash
    link_object ingestTextPacket(const meshtastic_MeshPacket &, const meshtastic_MeshPacket *);

    link_object ingestLinkMessage(meshtastic_StoreForwardPlusPlus *);

    void rebroadcastLinkObject(link_object &);

    bool checkCommitHash(link_object &lo, uint8_t *commit_hash_bytes, size_t hash_len);

    enum chain_types {
        channel_chain = 0,
    };
};
