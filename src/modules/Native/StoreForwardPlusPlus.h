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

    // returns wasfound
    bool getRootFromChannelHash(ChannelHash, uint8_t *);

    ChannelHash getChannelHashFromRoot(uint8_t *_root_hash);

    bool getNextHash(uint8_t *_root_hash, uint8_t *_chain_hash, uint8_t *next_chain_hash);

    // returns isnew
    bool getOrAddRootFromChannelHash(ChannelHash, uint8_t *);

    bool addRootToMappings(ChannelHash, uint8_t *);

    // return indicates message found
    bool getChainEnd(ChannelHash, uint8_t *, uint8_t *);

    void requestNextMessage(uint8_t *, uint8_t *);

    bool broadcastLink(uint8_t *, uint8_t *);

    bool sendFromScratch(uint8_t);

    bool addToChain(uint32_t, uint32_t, uint32_t, bool, ChannelHash, uint8_t *, size_t, uint8_t *, uint8_t *, uint8_t *, uint32_t,
                    char *, size_t);
    bool addToScratch(uint32_t, uint32_t, uint32_t, bool, ChannelHash, uint8_t *, size_t, uint8_t *, uint8_t *, uint32_t, char *,
                      size_t);
    void canonAnnounce(uint8_t *, uint8_t *, uint8_t *);

    bool isInDB(uint8_t *);

    bool isInScratch(uint8_t *);

    void removeFromScratch(uint8_t *);

    void updatePayload(uint8_t *, const char *, size_t);

    std::string getPayloadFromScratch(uint8_t *);

    enum chain_types {
        channel_chain = 0,
    };
};
