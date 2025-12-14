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
    sqlite3_stmt *stmt;

    // returns wasfound
    bool getRootFromChannelHash(ChannelHash, uint8_t *);

    // returns isnew
    bool getOrAddRootFromChannelHash(ChannelHash, uint8_t *);

    bool addRootToMappings(ChannelHash, uint8_t *);

    // return indicates message found
    bool getChainEnd(ChannelHash, uint8_t *, uint8_t *);

    enum chain_types {
        channel_chain = 0,
    };
};
