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

===========================================================
Adding a new OVN feature to the DDlog version of ovn-northd
===========================================================

This document describes the usual steps an OVN developer should go
through when adding a new feature to ``ovn-northd-ddlog``. In order to
make things less abstract we will use the IP Multicast
``ovn-northd-ddlog`` implementation as an example. Even though the
document is structured as a tutorial there might still exist
feature-specific aspects that are not covered here.

Overview
--------

DDlog is a dataflow system: it receives data from a data source (a set
of "input relations"), processes it through "intermediate relations"
according to the rules specified in the DDlog program, and sends the
processed "output relations" to a data sink.  In OVN, the input
relations primarily come from the OVN Northbound database and the
output relations primarily go to the OVN Southbound database.  The
process looks like this::

    from NBDB  +----------+   +-----------------+   +-----------+  to SBDB
    ---------->|Input rels|-->|Intermediate rels|-->|Output rels|---------->
               +----------+   +-----------------+   +-----------+

Adding a new feature to ``ovn-northd-ddlog`` usually involves the
following steps:

1. Update northbound and/or southbound OVSDB schemas.

2. Configure DDlog/OVSDB bindings.

3. Define intermediate DDlog relations and rules to compute them.

4. Write rules to update output relations.

5. Generate ``Logical_Flow``s and/or other forwarding records (e.g.,
   ``Multicast_Group``) that will control the dataplane operations.

Update NB and/or SB OVSDB schemas
---------------------------------

This step is no different from the normal development flow in C.

Most of the times a developer chooses between two ways of configuring
a new feature:

1. Adding a set of columns to tables in the NB and/or SB database (or
   adding key-value pairs to existing columns).

2. Adding new tables to the NB and/or SB database.

Looking at IP Multicast, there are two ``OVN Northbound`` tables where
configuration information is stored:

- ``Logical_Switch``, column ``other_config``, keys ``mcast_*``.

- ``Logical_Router``, column ``options``, keys ``mcast_*``.

These tables become inputs to the DDlog pipeline.

In addition we add a new table ``IP_Multicast`` to the SB database.
DDlog will update this table, that is, ``IP_Multicast`` receives
output from the above pipeline.

Configuring DDlog/OVSDB bindings
--------------------------------

Configuring ``northd/automake.mk``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The OVN build process uses DDlog's ``ovsdb2ddlog`` utility to parse
``ovn-nb.ovsschema`` and ``ovn-sb.ovsschema`` and then automatically
populate ``OVN_Northbound.dl`` and ``OVN_Southbound.dl``.  For each
OVN Northbound and Southbound table, it generates one or more
corresponding DDlog relations.

We need to supply ``ovsdb2ddlog`` with some information that it can't
infer from the OVSDB schemas.  This information must be specified as
``ovsdb2ddlog`` arguments, which are read from
``northd/ovn-nb.dlopts`` and ``northd/ovn-sb.dlopts``.

The main choice for each new table is whether it is used for output.
Output tables can also be used for input, but the converse is not
true.  If the table is used for output at all, we add ``-o <table>``
to the option file.  Our new table ``IP_Multicast`` is an output
table, so we add ``-o IP_Multicast`` to ``ovn-sb.dlopts``.

For input-only tables, ``ovsdb2ddlog`` generates a DDlog input
relation with the same name.  For output tables, it generates this
table plus an output relation named ``Out_<table>``.  Thus,
``OVN_Southbound.dl`` has two relations for ``IP_Multicast``::

    input relation IP_Multicast (
        _uuid: uuid,
        datapath: string,
        enabled: Set<bool>,
        querier: Set<bool>
    )
    output relation Out_IP_Multicast (
        _uuid: uuid,
        datapath: string,
        enabled: Set<bool>,
        querier: Set<bool>
    )

For an output table, consider whether only some of the columns are
used for output, that is, some of the columns are effectively
input-only.  This is common in OVN for OVSDB columns that are managed
externally (e.g. by a CMS).  For each input-only column, we add ``--ro
<table>.<column>``.  Alternatively, if most of the columns are
input-only but a few are output columns, add ``--rw <table>.<column>``
for each of the output columns.  In our case, all of the columns are
used for output, so we do not need to add anything.

Finally, in some cases ``ovn-northd-ddlog`` shouldn't change values in
. One such case is the ``seq_no`` column in the
``IP_Multicast`` table. To do that we need to instruct ``ovsdb2ddlog``
to treat the column as read-only by using the ``--ro`` switch.

``ovsdb2ddlog`` generates a number of additional DDlog relations, for
use by auto-generated OVSDB adapter logic.  These are irrelevant to
most DDLog developers, although sometimes they can be handy for
debugging.  See the appendix_ for details.

Define intermediate DDlog relations and rules to compute them.
--------------------------------------------------------------

Obviously there will be a one-to-one relationship between logical
switches/routers and IP multicast configuration. One way to represent
this relationship is to create multicast configuration DDlog relations
to be referenced by ``&Switch`` and ``&Router`` DDlog records::

    /* IP Multicast per switch configuration. */
    relation &McastSwitchCfg(
        datapath      : uuid,
        enabled       : bool,
        querier       : bool
    }

    &McastSwitchCfg(
            .datapath = ls_uuid,
            .enabled  = map_get_bool_def(other_config, "mcast_snoop", false),
            .querier  = map_get_bool_def(other_config, "mcast_querier", true)) :-
        nb.Logical_Switch(._uuid        = ls_uuid,
                          .other_config = other_config).

Then reference these relations in ``&Switch`` and ``&Router``. For
example, in ``lswitch.dl``, the ``&Switch`` relation definition now
contains::

    relation &Switch(
        ls:                nb.Logical_Switch,
        [...]
        mcast_cfg:         Ref<McastSwitchCfg>
    )

And is populated by the following rule which references the correct
``McastSwitchCfg`` based on the logical switch uuid::

    &Switch(.ls        = ls,
            [...]
            .mcast_cfg = mcast_cfg) :-
        nb.Logical_Switch[ls],
        [...]
        mcast_cfg in &McastSwitchCfg(.datapath = ls._uuid).

Build state based on information dynamically updated by ``ovn-controller``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some OVN features rely on information learned by ``ovn-controller`` to
generate ``Logical_Flow`` or other records that control the dataplane.
In case of IP Multicast, ``ovn-controller`` uses IGMP to learn
multicast groups that are joined by hosts.

Each ``ovn-controller`` maintains its own set of records to avoid
ownership and concurrency with other controllers. If two hosts that
are connected to the same logical switch but reside on different
hypervisors (different ``ovn-controller`` processes) join the same
multicast group G, each of the controllers will create an
``IGMP_Group`` record in the ``OVN Southbound`` database which will
contain a set of ports to which the interested hosts are connected.

At this point ``ovn-northd-ddlog`` needs to aggregate the per-chassis
IGMP records to generate a single ``Logical_Flow`` for group G.
Moreover, the ports on which the hosts are connected are represented
as references to ``Port_Binding`` records in the database.  These also
need to be translated to ``&SwitchPort`` DDlog relations.  The
corresponding DDlog operations that need to be performed are:

- Flatten the ``<IGMP group, ports>`` mapping in order to be able to
  do the translation from ``Port_Binding`` to ``&SwitchPort``. For
  each ``IGMP_Group`` record in the ``OVN Southbound`` database
  generate an individual record of type ``IgmpSwitchGroupPort`` for
  each ``Port_Binding`` in the set of ports that joined the
  group. Also, translate the ``Port_Binding`` uuid to the
  corresponding ``Logical_Switch_Port`` uuid::

    relation IgmpSwitchGroupPort(
        address: string,
        switch : Ref<Switch>,
        port   : uuid
    )

    IgmpSwitchGroupPort(address, switch, lsp_uuid) :-
        sb::IGMP_Group(.address = address, .datapath = igmp_dp_set,
                        .ports = pb_ports),
        var pb_port_uuid = FlatMap(pb_ports),
        sb::Port_Binding(._uuid = pb_port_uuid, .logical_port = lsp_name),
        &SwitchPort(
            .lsp = nb.Logical_Switch_Port{._uuid = lsp_uuid, .name = lsp_name},
            .sw = switch).

- Aggregate the flattened IgmpSwitchGroupPort (implicitly from all
  ``ovn-controller`` instances) grouping by adress and logical
  switch::

    relation IgmpSwitchMulticastGroup(
        address: string,
        switch : Ref<Switch>,
        ports  : Set<uuid>
    )

    IgmpSwitchMulticastGroup(address, switch, ports) :-
        IgmpSwitchGroupPort(address, switch, port),
        var ports = port.group_by((address, switch)).to_set().

At this point we have all the feature configuration relevant
information stored in DDlog relations in ``ovn-northd-ddlog`` memory.

Write rules to update output relations
--------------------------------------

The developer updates output tables by writing rules that generate
``Out_*`` relations.  For IP Multicast this means::

    /* IP_Multicast table (only applicable for Switches). */
    sb::Out_IP_Multicast(._uuid = hash128(cfg.datapath),
                         .datapath = cfg.datapath,
                         .enabled = set_singleton(cfg.enabled),
                         .querier = set_singleton(cfg.querier)) :-
        &McastSwitchCfg[cfg].

.. note:: ``OVN_Southbound.dl`` also contains an ``IP_Multicast``
   relation with ``input`` qualifier.  This relation stores the
   current snapshot of the OVSDB table and cannot be written to.

Generate ``Logical_Flow`` and/or other forwarding records
---------------------------------------------------------

At this point we have defined all DDlog relations required to generate
``Logical_Flow``s.  All we have to do is write the rules to do so.
For each ``IgmpSwitchMulticastGroup`` we generate a ``Flow`` that has
as action ``"outport = <Multicast_Group>; output;"``::

    /* Ingress table 17: Add IP multicast flows learnt from IGMP (priority 90). */
    for (IgmpSwitchMulticastGroup(.address = address, .switch = &sw)) {
        Flow(.logical_datapath = sw.dpname,
             .stage            = switch_stage(IN, L2_LKUP),
             .priority         = 90,
             .__match          = "eth.mcast && ip4 && ip4.dst == ${address}",
             .actions          = "outport = \"${address}\"; output;",
             .external_ids     = map_empty())
    }

In some cases generating a logical flow is not enough. For IGMP we
also need to maintain OVN southbound ``Multicast_Group`` records,
one per IGMP group storing the corresponding ``Port_Binding`` uuids of
ports where multicast traffic should be sent.  This is also relatively
straightforward::

    /* Create a multicast group for each IGMP group learned by a Switch.
     * 'tunnel_key' == 0 triggers an ID allocation later.
     */
    sb::Out_Multicast_Group (.datapath   = switch.dpname,
                             .name       = address,
                             .tunnel_key = 0,
                             .ports      = set_map_uuid2name(port_ids)) :-
        IgmpSwitchMulticastGroup(address, &switch, port_ids).

We must also define DDlog relations that will allocate ``tunnel_key``
values.  There are two cases: tunnel keys for records that already
existed in the database are preserved to implement stable id
allocation; new multicast groups need new keys.  This kind of
allocation can be tricky, especially to new users of DDlog.  OVN
contains multiple instances of allocation, so it's probably worth
reading through the existing cases and following their pattern, and,
if it's still tricky, asking for assistance.

Appendix A. Additional relations generated by ``ovsdb2ddlog``
-------------------------------------------------------------

.. _appendix:

ovsdb2ddlog generates some extra relations to manage communication
with the OVSDB server.  It generates records in the following
relations when rows in OVSDB output tables need to be added or deleted
or updated.

In the steady state, when everything is working well, a given record
stays in any one of these relations only briefly: just long enough for
``ovn-northd-ddlog`` to send a transaction to the OVSDB server.  When
the OVSDB server applies the update and sends an acknowledgement, this
ordinarily means that these relations become empty, because there are
no longer any further changes to send.

Thus, records that persist in one of these relations is a sign of a
problem.  One example of such a problem is the database server
rejecting the transactions sent by ``ovn-northd-ddlog``, which might
happen if, for example, a bug in a ``.dl`` file would cause some OVSDB
constraint or relational integrity rule to be violated.  (Such a
problem can often be diagnosed by looking in the OVSDB server's log.)

- ``DeltaPlus_IP_Multicast`` used by the DDlog program to track new
  records that are not yet added to the database::

    output relation DeltaPlus_IP_Multicast (
        datapath: uuid_or_string_t,
        enabled: Set<bool>,
        querier: Set<bool>
    )

- ``DeltaMinus_IP_Multicast`` used by the DDlog program to track
  records that are no longer needed in the database and need to be
  removed::

    output relation DeltaMinus_IP_Multicast (
        _uuid: uuid
    )

- ``Update_IP_Multicast`` used by the DDlog program to track records
  whose fields need to be updated in the database::

   output relation Update_IP_Multicast (
       _uuid: uuid,
       enabled: Set<bool>,
       querier: Set<bool>
   )
