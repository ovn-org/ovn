..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in OVN documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

==================
VIF Plug Providers
==================

Traditionally it has been the CMSes responsibility to create VIFs as part of
instance life cycle, and subsequently manage plug/unplug operations on the
integration bridge following the conventions described in the
`Open vSwitch Integration Guide`_ for mapping of VIFs to OVN logical port.

With the advent of NICs connected to multiple distinct CPUs we can have a
topology where the instance runs on one host and Open vSwitch and OVN runs on
a different host, the smartnic control plane CPU.  The host facing interfaces
will be visible to Open vSwitch and OVN as representor ports.

The actions necessary for plugging and unplugging the representor port in
Open vSwitch running on the smartnic control plane CPU would be the same for
every CMS.

Instead of every CMS having to develop their own version of an agent to do
the plugging, we provide a pluggable infrastructure in OVN that allows the
`ovn-controller` to perform the plugging on CMS direction.

Hardware or platform specific details for initialization and lookup of
representor ports is provided by an plugging provider library hosted inside or
outside the core OVN repository, and linked at OVN build time.

Life Cycle of an OVN plugged VIF
--------------------------------

1. CMS creates a record in the OVN Northbound Logical_Switch_Port table with
   the options column containing the `vif-plug-type` key with a value
   corresponding to the `const char *type` provided by the VIF plug provider
   implementation as well as a `requested-chassis` key with a value pointing at
   the name or hostname of the chassis it wants the VIF plugged on.  Additional
   VIF plug provider specific key/value pairs must be provided for successful
   lookup.

2. `ovn-northd` looks up the name or hostname provided in the
   `requested-chassis` option and fills the OVN Southbound Port_Binding
   requested_chassis column, it also copies relevant options over to the
   Port_Binding record.

3. `ovn-controller` monitors Southbound Port_Binding entries with a
   requested_chassis column pointing at its chassis UUID.  When it encounters
   an entry with option `vif-plug-type` and it has registered a VIF plug
   provider matching that type, it will act on it even if no local binding
   exists yet.

4. It will fill the `struct vif_plug_port_ctx_in` as defined in
   `lib/vif-plug.h` with `op_type` set to 'PLUG_OP_CREATE' and make a call to
   the VIF plug providers `vif_plug_port_prepare` callback function.  VIF plug
   provider performs lookup and fills the `struct vif_plug_port_ctx_out` as
   defined in `lib/vif-plug.h`.

5. `ovn-controller` creates a port and interface record in the local OVSDB
   using the details provided by the VIF plug provider and also adds
   `external-ids:iface-id` with value matching the logical port name and
   `external-ids:ovn-plugged` with value matching the logical port
   `vif-plug-type`.  When the port creation is done a call will first be made
   to the VIF plug providers `vif_plug_port_finish` function and then to the
   `vif_plug_port_ctx_destroy` function to free any memory allocated by the VIF
   plug implementation.

6. The Open vSwitch vswitchd will assign a ofport to the newly created
   interface and on the next `ovn-controller` main loop iteration flows will be
   installed.

7. On each main loop iteration the `ovn-controller` will in addition to normal
   flow processing make a call to the VIF plug provider again similar to the
   first creation in case anything needs updating for the interface record.

8. The port will be unplugged when an event occurs which would make the
   `ovn-controller` release a logical port, for example the Logical_Switch_Port
   and Port_Binding entry disappearing from the database or its
   `requested_chassis` column being pointed to a different chassis.


The VIF plug provider interface
-------------------------------

The interface between internals of OVN and a VIF plug provider is a set of
callbacks as defined by the `struct vif_plug_class` in
`lib/vif-plug-provider.h`.

It is important to note that these callbacks will be called in the critical
path of the `ovn-controller` processing loop, so care must be taken to make the
implementation as efficient as possible, and under no circumstance can any of
the callback functions make calls that block.

On `ovn-controller` startup, VIF plug providers made available at build time
will be registered by the identifier provided in the `const char *type`
pointer, at this time the `init` function pointer will be called if it is
non-NULL.

> **Note**: apart from the `const char *type` pointer, no attempt will be made
            to access VIF plug provider data or functions before the call to
            the `init` has been made.

On `ovn-controller` exit, the VIF plug providers registered in the above
mentioned procedure will have their `destroy` function pointer called if it is
non-NULL.

If the VIF plug provider has internal lookup tables that need to be maintained
they can define a `run` function which will be called as part of the
`ovn-controller` main loop.  If there are any changes encountered the function
should return 'true' to signal that further processing is necessary, 'false'
otherwise.

On update of Interface records the `ovn-controller` will pass on a `sset`
to the `ovsport_update_iface` function containing options the plug
implementation finds pertinent to maintain for successful operation.  This
`sset` is retrieved by making a call to the plug implementation
`vif_plug_get_maintained_iface_options` function pointer if it is non-NULL.
This allows presence of other users of the OVSDB maintaining a different set of
options on the same set of Interface records without wiping out their changes.

Before creating or updating an existing interface record the VIF plug provider
`vif_plug_port_prepare` function pointer will be called with valid pointers to
`struct vif_plug_port_ctx_in` and `struct vif_plug_port_ctx_out` data
structures.  If the VIF plug provider implementation is able to perform lookup
it should fill the `struct vif_plug_port_ctx_out` data structure and return
'true'.  The `ovn-controller` will then create or update the port/interface
records and then call `vif_plug_port_finish` when the transactions commits and
`vif_plug_port_ctx_destroy` to free any allocated memory.  If the VIF plug
provider implementation is unable to perform lookup or prepare the desired
resource at this time, it should return 'false' which will tell the
`ovn-controller` to not plug the port, in this case it will not call
`vif_plug_port_finish` nor `vif_plug_port_ctx_destroy`.

> **Note**: The VIF plug provider implementation should exhaust all
            non-blocking options to succeed with lookup from within the
            `vif_plug_port_prepare` handler, including refreshing lookup
            tables if necessary.

Before removing port and interface records previously plugged by the
`ovn-controller` as identified by presence of the Interface
`external-ids:ovn-plugged` key, the `ovn-controller` will look up the
`vif-plug-type` from `external-ids:ovn-plugged`, fill
`struct vif_plug_port_ctx_in` with `op_type` set to 'PLUG_OP_REMOVE' and make a
call to `vif_plug_port_prepare`.  After the port and interface has been removed
a call will be made to `vif_plug_port_finish`.  Both calls will be made with
the pointer to `vif_plug_port_ctx_out` set to 'NULL', and no call will be made
to `vif_plug_port_ctx_destroy`.

Building with in-tree VIF plug providers
----------------------------------------

VIF plug providers hosted in the OVN repository live under
`lib/vif-plug-providers`:

To enable them, provide the `--enable-vif-plug-providers` command line option
to the configure script when building OVN.

Building with an externally provided VIF plug provider
------------------------------------------------------

There is also infrastructure in place to support linking OVN with an externally
built VIF plug provider.

This external VIF plug provider must define a NULL-terminated array of pointers
to `struct vif_plug_class` data structures named `vif_plug_provider_classes`.
Example:

.. code-block:: none

   const struct vif_plug_class *vif_plug_provider_classes[] = {
       &vif_plug_foo,
       NULL,
   };

The name of the repository for the external VIF plug provider should be the
same as the name of the library it produces, and the built library artifact
should be placed in lib/.libs.  Example:

.. code-block:: none

   ovn-vif-foo/
   ovn-vif-foo/lib/.libs/libovn-vif-foo.la

To enable such a VIF plug provider provide the
`--with-vif-plug-provider=/path/to/ovn-vif-foo` command line option to the
configure script when building OVN.

.. LINKS
.. _Open vSwitch Integration Guide:
   https://docs.openvswitch.org/en/latest/topics/integration/
