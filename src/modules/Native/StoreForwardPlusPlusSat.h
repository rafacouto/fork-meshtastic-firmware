#pragma once
#include "Router.h"
#include "SinglePortModule.h"
#include "sqlite3.h"

/**
 * A simple example module that just replies with "Message received" to any message it receives.
 */
class StoreForwardPlusPlusSatModule : public SinglePortModule // should probably derive this from the main class
{
  public:
    /** Constructor
     * name is for debugging output
     */
    StoreForwardPlusPlusSatModule();

    /*
      -Override the wantPacket method.
    */
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override
    {
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

  private:
    sqlite3 *ppDb;
    sqlite3_stmt *stmt;
};
