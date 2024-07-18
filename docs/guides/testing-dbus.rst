Testing D-Bus Services
======================

Infopipe
********

Access to the Infopipe services is achieved through the
:class:`sssd_test_framework.roles.client.Client` class. It provides the
:meth:`sssd_test_framework.roles.client.Client.infopipe()` method that
returns a pre-instantiated object of class
:class:`sssd_test_framework.utils.sbus.DBUSDestination`, which gives you
direct access to the `Infopipe` destination.

With the destination, it is possible to get the different objects it provides.
Each object has its own ``object path``. These objects are obtained by calling
the destination's :meth:`sssd_test_framework.utils.sbus.DBUSDestination.getObject()`
method. The object path must be passed as argument. A list containing all the
available object paths can be retrieved with the method
:meth:`sssd_test_framework.utils.sbus.DBUSDestination.getObjectPaths()`.

.. note::
    Passing an ``object path`` that doesn't exist will not generate an error nor
    raise an exception. It will, instead, create a valid object with no attributes.
    This is a strange behavior of ``Introspection``.

Once you have one of these objects, you can access other D-BUS sub-objects
provided by that destination by simply treating them as attributes of the
parent object. **Methods** and **properties** are accessed in the same way.

.. note::
    Accessing an attribute that can't be mapped to a subobject, attribute or
    method, will raise an :class:`AttributeError` exception.

In the following example, there is an LDAP domain called `test`.

.. code-block:: python
    :caption: Infopipe Example

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_infopipe__GetUserProperties(client: Client, provider: GenericProvider):
        provider.user("user-1").add(uid=10001, gid=20001)

        client.sssd.start()

        users = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users");
        user_path = users.FindByName("user-1")
        assert "/org/freedesktop/sssd/infopipe/Users/test/10001" == user_path

        user = client.ifp.getObject(user_path)
        uid = user.Get("org.freedesktop.sssd.infopipe.Users.User", "uidNumber")
        assert uid == 10001

        gid = user.gidNumber
        assert gid == 20001

        props = user.GetAll("org.freedesktop.sssd.infopipe.Users.User")
        assert props["uidNumber"] == 10001
        assert props["gidNumber"] == 20001
        assert props["name"] == "user-1"
        assert props["homeDirectory"] == "/home/user-1"

Internals
---------
Although :class:`sssd_test_framework.roles.client.Client` provides the
:meth:`sssd_test_framework.roles.client.Client.infopipe()` method, the framework
allows you to access any D-Bus destination. To achieve that you need to
instantiate the :class:`sssd_test_framework.utils.sbus.DBUSDestination` class,
providing the MultihostHost where the D-Bus services are running, the destination
(the application) to contact and the bus to connect to.

The bus can be the bus' path as a string, or one of the predefined buses:

* :attr:`sssd_test_framework.utils.sbus.DBUSKnownBus.SYSTEM`
* :attr:`sssd_test_framework.utils.sbus.DBUSKnownBus.SESSION`
* :attr:`sssd_test_framework.utils.sbus.DBUSKnownBus.MONITOR`

.. code-block:: python
    :caption: Accessing the monitor

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_example__monitor(client: Client):
        client.sssd.start()

        monitor = DBUSDestination(client.host, dest="sssd.monitor", bus=DBUSKnownBus.MONITOR)

        sssd = monitor.getObject(objpath="/sssd")

        res = sssd.debug_level
        assert res == 0xFFF0

        sssd.debug_level = 0x0070


A Note On Type Conversion
~~~~~~~~~~~~~~~~~~~~~~~~~
All methods and properties accept and return Python types. Internally they are
converted to some specific classes helping to treat them and map them to D-Bus
types.

Objects of these types represent values that are passed to/from the methods and
properties. Their type is given by the class. For instance, DBUSTypeString is a
D-Bus string.

These classes are all subclasses of the abstract class
:class:`sssd_test_framework.utils.dbus.types.DBUSType` and they provide the
following methods:

* :attr:`sssd_test_framework.utils.dbus.types.DBUSType.value`: A property to read
  and set the (Python) value.
* :meth:`sssd_test_framework.utils.dbus.types.DBUSType.mimic()`: a method to copy
  itself without copying the value while maintaining the structure (subtypes).
* :meth:`sssd_test_framework.utils.dbus.types.DBUSType.param()`: The string
  representation of the value in a format suitable to be used as a parameter for
  ``dbus-send``.
* :meth:`sssd_test_framework.utils.dbus.types.DBUSType.parse()`: Parses the
  string resulting from an execution of ``dbus-send`` and set the value to the
  object.

Basic types (integers, strings, booleans, etc.) are subclasses of the
:class:`sssd_test_framework.utils.dbus.types.DBUSTypeBasic` abstract class.

Container types -- that is, the subclasses of the abstract class
:class:`sssd_test_framework.utils.dbus.types.DBUSTypeContainer` -- accept a
parameter for their constructors, another
:class:`sssd_test_framework.utils.dbus.types.DBUSType` object of the expected type.

.. code-block:: python
    :caption: Declaring an array of unit32

    s = "array [ uint32 1 uint32 2 uint32 3 ]"
    a = DBUSTypeArray(DBUSTypeUInt32())
    a.parse(DBUSResult(s))
    print(a.value)
    [1, 2, 3]

In some cases it may not be possible to know in advance the type of the elements
of a container type. In that case, no object is passed to the constructor. The
type will be guessed while parsing the result from ``dbus-send``.

.. note::
    ``dbus-send`` doesn't explain very well how container types are combined as
    parameters, and so far we didn't use them. So we might have to adapt the
    results of param() if they are ever used.

.. note::
    Using instrospection it is possible to get the methods and properties
    signatures. Nevertheless, the signature for ``variant`` types does not include
    the type of the contained type, as it does for the arrays and dictionaries.
    Because of this, it is not possible to know in advance which type to expect
    and will have to be guessed while parsing.

Implemented Types
~~~~~~~~~~~~~~~~~
The following classes are already implemented.

* :class:`sssd_test_framework.utils.dbus.types.DBUSType`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeBoolean`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeString`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeObjectPath`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeInteger`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeByte`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeInt16`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeInt32`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeInt64`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeUInt16`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeUInt32`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeUInt64`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeDouble`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeContainer`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeArray`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeDict`
* :class:`sssd_test_framework.utils.dbus.types.DBUSTypeVariant`

.. note::
    Although the `D-Bus specification`_ considers ``dict entry`` a separate type,
    we didn't implement it as such because there is no use case for it outside
    of an array, in which case the array becomes a dictionary.

.. _D-Bus specification: https://dbus.freedesktop.org/doc/dbus-specification.html#type-system

Not Implemented Types
~~~~~~~~~~~~~~~~~~~~~
Some other classes were not implemented because they are not accepted by
``dbus-send``:

* signature
* UNIX FD
* struct

Helper Classes
~~~~~~~~~~~~~~
Class :class:`sssd_test_framework.utils.dbus.types.DBUSSignatureReader` provides
a single class method
:meth:`sssd_test_framework.utils.dbus.types.DBUSSignatureReader.read()`
used to read a method or property signature from a string and generate the
corresponding :class:`sssd_test_framework.utils.dbus.types.DBUSType` objects
required for the method or property.
