/**
 * This file is part of TelepathyQt
 *
 * @copyright Copyright (C) 2012 Collabora Ltd. <http://www.collabora.co.uk/>
 * @copyright Copyright (C) 2012 Nokia Corporation
 * @license LGPL 2.1
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "TelepathyQt/_gen/svc-connection.h"

#include <TelepathyQt/Global>
#include <TelepathyQt/MethodInvocationContext>
#include <TelepathyQt/Types>
#include "TelepathyQt/debug-internal.h"

namespace Tp
{

class TP_QT_NO_EXPORT BaseConnection::Adaptee : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QStringList interfaces READ interfaces)
    Q_PROPERTY(uint selfHandle READ selfHandle)
    Q_PROPERTY(uint status READ status)
    Q_PROPERTY(bool hasImmortalHandles READ hasImmortalHandles)
public:
    Adaptee(const QDBusConnection &dbusConnection, BaseConnection *cm);
    ~Adaptee();

    QStringList interfaces() const;
    uint status() const {
        return mConnection->status();
    }
    uint selfHandle() const;
    bool hasImmortalHandles() const {
        return true;
    }

private Q_SLOTS:
    void getSelfHandle(const Tp::Service::ConnectionAdaptor::GetSelfHandleContextPtr &context);
    void getStatus(const Tp::Service::ConnectionAdaptor::GetStatusContextPtr &context);
    void connect(const Tp::Service::ConnectionAdaptor::ConnectContextPtr &context);
    void getInterfaces(const Tp::Service::ConnectionAdaptor::GetInterfacesContextPtr &context) {
        context->setFinished(interfaces());
    }

    void getProtocol(const Tp::Service::ConnectionAdaptor::GetProtocolContextPtr &context) {
        context->setFinished(mConnection->protocolName());
    }

    void holdHandles(uint handleType, const Tp::UIntList &handles, const Tp::Service::ConnectionAdaptor::HoldHandlesContextPtr &context) {
        context->setFinished();
    }

    void inspectHandles(uint handleType, const Tp::UIntList &handles, const Tp::Service::ConnectionAdaptor::InspectHandlesContextPtr &context);

    void listChannels(const Tp::Service::ConnectionAdaptor::ListChannelsContextPtr &context) {
        context->setFinished(mConnection->channelsInfo());
    }

    void disconnect(const Tp::Service::ConnectionAdaptor::DisconnectContextPtr &context);

    //void releaseHandles(uint handleType, const Tp::UIntList &handles, const Tp::Service::ConnectionAdaptor::ReleaseHandlesContextPtr &context);
    void requestChannel(const QString &type, uint handleType, uint handle, bool suppressHandler, const Tp::Service::ConnectionAdaptor::RequestChannelContextPtr &context);
    void requestHandles(uint handleType, const QStringList &identifiers, const Tp::Service::ConnectionAdaptor::RequestHandlesContextPtr &context);
    //void addClientInterest(const QStringList &tokens, const Tp::Service::ConnectionAdaptor::AddClientInterestContextPtr &context);
    //void removeClientInterest(const QStringList &tokens, const Tp::Service::ConnectionAdaptor::RemoveClientInterestContextPtr &context);

public:
    BaseConnection *mConnection;
    Service::ConnectionAdaptor *mAdaptor;

Q_SIGNALS:
    void selfHandleChanged(uint selfHandle);
    void newChannel(const QDBusObjectPath &objectPath, const QString &channelType, uint handleType, uint handle, bool suppressHandler);
    void connectionError(const QString &error, const QVariantMap &details);
    void statusChanged(uint status, uint reason);
};

class TP_QT_NO_EXPORT BaseConnectionRequestsInterface::Adaptee : public QObject
{
    Q_OBJECT
    Q_PROPERTY(Tp::ChannelDetailsList channels READ channels)
    Q_PROPERTY(Tp::RequestableChannelClassList requestableChannelClasses READ requestableChannelClasses)

public:
    Adaptee(BaseConnectionRequestsInterface *interface);
    ~Adaptee();
    Tp::ChannelDetailsList channels() const;
    Tp::RequestableChannelClassList requestableChannelClasses() const {
        debug() << "BaseConnectionRequestsInterface::requestableChannelClasses";
        return mInterface->requestableChannelClasses;
    }

private Q_SLOTS:
    void createChannel(const QVariantMap &request, const Tp::Service::ConnectionInterfaceRequestsAdaptor::CreateChannelContextPtr &context);
    void ensureChannel(const QVariantMap &request, const Tp::Service::ConnectionInterfaceRequestsAdaptor::EnsureChannelContextPtr &context);
Q_SIGNALS:
    void newChannels(const Tp::ChannelDetailsList &channels);
    void channelClosed(const QDBusObjectPath &removed);

public:
    BaseConnectionRequestsInterface *mInterface;
};

class TP_QT_NO_EXPORT BaseConnectionContactsInterface::Adaptee : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QStringList contactAttributeInterfaces READ contactAttributeInterfaces)
public:
    Adaptee(BaseConnectionContactsInterface *interface);
    ~Adaptee();
    QStringList contactAttributeInterfaces() const;

private Q_SLOTS:
    void getContactAttributes(const Tp::UIntList &handles, const QStringList &interfaces, bool hold,
                              const Tp::Service::ConnectionInterfaceContactsAdaptor::GetContactAttributesContextPtr &context);
public:
    BaseConnectionContactsInterface *mInterface;
};

class TP_QT_NO_EXPORT BaseConnectionSimplePresenceInterface::Adaptee : public QObject
{
    Q_OBJECT

    Q_PROPERTY(Tp::SimpleStatusSpecMap statuses READ statuses)
    Q_PROPERTY(uint maximumStatusMessageLength READ maximumStatusMessageLength)
public:
    Adaptee(BaseConnectionSimplePresenceInterface *interface);
    ~Adaptee();
    Tp::SimpleStatusSpecMap statuses() const;
    int maximumStatusMessageLength() const;

private Q_SLOTS:
    void setPresence(const QString &status, const QString &statusMessage,
                     const Tp::Service::ConnectionInterfaceSimplePresenceAdaptor::SetPresenceContextPtr &context);
    void getPresences(const Tp::UIntList &contacts,
                      const Tp::Service::ConnectionInterfaceSimplePresenceAdaptor::GetPresencesContextPtr &context);
Q_SIGNALS:
    void presencesChanged(const Tp::SimpleContactPresences &presence);

public:
    BaseConnectionSimplePresenceInterface *mInterface;
};

class TP_QT_NO_EXPORT BaseConnectionContactListInterface::Adaptee : public QObject
{
    Q_OBJECT
    Q_PROPERTY(uint contactListState READ contactListState)
    Q_PROPERTY(bool contactListPersists READ contactListPersists)
    Q_PROPERTY(bool canChangeContactList READ canChangeContactList)
    Q_PROPERTY(bool requestUsesMessage READ requestUsesMessage)
    Q_PROPERTY(bool downloadAtConnection READ downloadAtConnection)
public:
    Adaptee(BaseConnectionContactListInterface *interface);
    ~Adaptee();

    uint contactListState() const;
    bool contactListPersists() const;
    bool canChangeContactList() const;
    bool requestUsesMessage() const;
    bool downloadAtConnection() const;
private Q_SLOTS:
    void getContactListAttributes(const QStringList &interfaces, bool hold, const Tp::Service::ConnectionInterfaceContactListAdaptor::GetContactListAttributesContextPtr &context);
    void requestSubscription(const Tp::UIntList &contacts, const QString &message, const Tp::Service::ConnectionInterfaceContactListAdaptor::RequestSubscriptionContextPtr &context);
    //void authorizePublication(const Tp::UIntList &contacts, const Tp::Service::ConnectionInterfaceContactListAdaptor::AuthorizePublicationContextPtr &context);
    //void removeContacts(const Tp::UIntList &contacts, const Tp::Service::ConnectionInterfaceContactListAdaptor::RemoveContactsContextPtr &context);
    //void unsubscribe(const Tp::UIntList &contacts, const Tp::Service::ConnectionInterfaceContactListAdaptor::UnsubscribeContextPtr &context);
    //void unpublish(const Tp::UIntList &contacts, const Tp::Service::ConnectionInterfaceContactListAdaptor::UnpublishContextPtr &context);
    //void download(const Tp::Service::ConnectionInterfaceContactListAdaptor::DownloadContextPtr &context);
Q_SIGNALS:
    void contactListStateChanged(uint contactListState);
    void contactsChangedWithID(const Tp::ContactSubscriptionMap &changes, const Tp::HandleIdentifierMap &identifiers, const Tp::HandleIdentifierMap &removals);
    void contactsChanged(const Tp::ContactSubscriptionMap &changes, const Tp::UIntList &removals);

public:
    BaseConnectionContactListInterface *mInterface;
};

class TP_QT_NO_EXPORT BaseConnectionAddressingInterface::Adaptee : public QObject
{
    Q_OBJECT

public:
    Adaptee(BaseConnectionAddressingInterface *interface);
    ~Adaptee();


private Q_SLOTS:
    void getContactsByVCardField(const QString &field, const QStringList &addresses, const QStringList &interfaces, const Tp::Service::ConnectionInterfaceAddressingAdaptor::GetContactsByVCardFieldContextPtr &context);
    void getContactsByURI(const QStringList &URIs, const QStringList &interfaces, const Tp::Service::ConnectionInterfaceAddressingAdaptor::GetContactsByURIContextPtr &context);
Q_SIGNALS:

public:
    BaseConnectionAddressingInterface *mInterface;
};

}
