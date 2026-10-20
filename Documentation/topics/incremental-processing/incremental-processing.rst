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

==================================
OVN Incremental Processing Engine
==================================

The OVN Incremental Processing Engine is a framework designed to efficiently
handle changes in input data (e.g., Southbound DB tables, local OVSDB
interfaces) and update the desired state (e.g., OpenFlow rules) accordingly.
Instead of performing a full recomputation whenever an input changes, which can
be inefficient for large datasets, the engine tracks changes and processes them
incrementally.

Concepts
--------

The engine is composed of a Directed Acyclic Graph (DAG) of **engine nodes**.

- **Engine Node:** Represents a unit of data processing. Each node maintains
  its own data, which persists across main loop iterations.
- **Inputs:** Nodes can have inputs (dependencies) from other nodes.
- **Change Handlers:** For each input, a user-defined change handler function
  can be implemented. This function processes the changes from the input and
  updates the node's data.
- **Run Function:** If no change handler is defined for an input, or if the
  change handler returns `EN_UNHANDLED`, the node's `run` method is called to
  perform a full recomputation based on all inputs.

The engine facilitates:

- **Correctness:** By making dependencies explicit.
- **Maintainability:** By providing a structured way to implement complex
  logic.
- **Scalability:** By enabling fine-grained, incremental updates.

Engine Node State
~~~~~~~~~~~~~~~~~

The whole graph is processed by a single top-level `engine_run(bool
recompute_allowed)` call, typically made once per main loop iteration; this
is distinct from the per-node `run` method described above. The state of an
engine node (`enum engine_node_state`) describes the validity of its data
after such an `engine_run()` call:

- `EN_STALE`: The data in the node is not up to date with the DB or its inputs.
  This is the initial state before the engine runs.
- `EN_UPDATED`: The node's data is valid and was updated during the last engine
  run. This indicates that downstream nodes may need to process these changes.
- `EN_UNCHANGED`: The node's data is valid and did not change during the last
  engine run. Downstream nodes can skip processing if they only depend on
  changed inputs.
- `EN_CANCELED`: Processing for this node was canceled during the last run.
  This usually triggers a full recomputation in the next iteration.

Engine Invocation per Binary
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The `recompute_allowed` argument to that call is what determines whether
cancellation can happen: a node is canceled when it is marked as writing to
the Southbound DB (`sb_write`) and needs a full recompute while the caller
passed `recompute_allowed = false`. Cancellation stops that engine run
immediately; the whole graph is retried once `recompute_allowed` is `true`
again on some later iteration, which need not be the very next one.

`ovn-northd` calls `engine_run()` only once it holds the Southbound DB lock
and has valid Northbound and Southbound transactions in hand. `ovn-ic`
similarly checks that all four of its NB/SB/IC-NB/IC-SB transactions are
non-NULL. Otherwise, they skip running the engine for that iteration
entirely. Because of this, they always pass `recompute_allowed = true` and
their nodes are never canceled.

`ovn-br-controller`'s nodes are never canceled either: it connects to two
databases -- the local `Open_vSwitch` database and the separate OVN Bridge
database -- but only reads from them. Unlike `ovn-northd` and `ovn-ic`
though, this isn't an enforced guarantee: its precondition for calling
`engine_run()` doesn't actually check for a valid transaction, it simply
happens that no node needs one today.

`ovn-controller` takes a different approach: it calls `engine_run()` on
every main loop iteration regardless of whether a full recompute is
currently possible, so that purely incremental changes can still be
processed even when a full recompute isn't. It passes
`recompute_allowed = true` only when it has a Southbound DB transaction
and no backlog of unsent OpenFlow messages; otherwise it passes
`recompute_allowed = false`, for two reasons:

- It has no Southbound DB transaction yet this iteration. If, during that
  run, a node marked `sb_write` has an input that changed and needs a full
  recompute (no change handler for it, or its change handler returned
  `EN_UNHANDLED` -- see "Run Function" above), the engine cancels that node
  instead of calling its `run` method. A recompute would have been unsafe
  anyway: a write attempted with no transaction can't be caught by the
  engine's write-protection check.
- `ovs-vswitchd` isn't necessarily unresponsive, but `ovn-controller` still
  has OpenFlow messages from a previous round that it hasn't managed to hand
  off to the socket connecting to it yet. Rather than wait for any
  acknowledgment, it simply defers adding more work on top of what's already
  queued. This is a deliberate optimization, not a hard requirement.

Input Handler Result
~~~~~~~~~~~~~~~~~~~~

Change handlers return a result (`enum engine_input_handler_result`) indicating
the outcome of processing an input change:

- `EN_UNHANDLED`: The change handler could not handle the input change.
  This forces the engine to fall back to a full recomputation of the node using
  its `run` method.
- `EN_HANDLED_UPDATED`: The change was successfully handled, and the node's
  data was updated as a result.
- `EN_HANDLED_UNCHANGED`: The change was successfully handled, but the node's
  data remained unchanged.

Usage of these return values allows the engine to optimize the flow of updates
through the graph.

Graph Visualization
-------------------

Understanding the dependencies between engine nodes is crucial for debugging
and optimization. OVN provides a mechanism to dump the engine graph in Graphviz
DOT format.

Dumping the Graph
~~~~~~~~~~~~~~~~~

`ovn-northd`, `ovn-controller` and `ovn-ic` all support the
`--dump-inc-proc-graph` command-line option.

.. note::
    `ovn-br-controller` also builds its desired state (bridge flows) using
    the incremental processing engine, but it does not currently implement
    `--dump-inc-proc-graph`.

Full Graph Dump
+++++++++++++++

To dump the entire engine graph, simply pass the option without arguments:

.. code-block:: bash

   ovn-northd --dump-inc-proc-graph
   # or
   ovn-controller --dump-inc-proc-graph
   # or
   ovn-ic --dump-inc-proc-graph

This will output the full DAG definition to stdout.

Partial Graph Dump
++++++++++++++++++

For complex graphs, it can be useful to view only a subset of the nodes. One
can provide a specific node name as an argument to dump the graph leading up
to that node (including the node itself and its transitive dependencies).

.. code-block:: bash

   # Dump the graph for 'datapath_sync' node in ovn-northd
   ovn-northd --dump-inc-proc-graph=datapath_sync

   # Dump the graph for 'runtime_data' node in ovn-controller
   ovn-controller --dump-inc-proc-graph=runtime_data

   # Dump the graph for 'ic' node in ovn-ic
   ovn-ic --dump-inc-proc-graph=ic

This allows for focused analysis of specific parts of the processing pipeline.

Example Output
~~~~~~~~~~~~~~

The output is in DOT format and can be visualized using tools like `dot` from
the Graphviz suite.

.. code-block:: none

   digraph "Incremental-Processing-Engine" {
       rankdir=LR;
       NB_nb_global [style=filled, shape=box, fillcolor=white, label="NB_nb_global"];
       global_config [style=filled, shape=box, fillcolor=white, label="global_config"];
       northd [style=filled, shape=box, fillcolor=white, label="northd"];
       NB_nb_global -> global_config [label="global_config_nb_global_handler"];
       global_config -> northd [label="northd_global_config_handler"];
   }

Edges are labeled with the name of the change handler function if one is
registered for that dependency.

The DOT output can be converted to an image (e.g., PNG) using the `dot` utility
from Graphviz:

.. code-block:: bash

   ovn-northd --dump-inc-proc-graph | dot -Tpng -o engine_graph.png
   ovn-controller --dump-inc-proc-graph | dot -Tpng -o engine_graph.png
   ovn-ic --dump-inc-proc-graph | dot -Tpng -o engine_graph.png


As an example, here is each binary's graph rendered up to one representative
node:

`ovn-northd`, up to the `datapath_sync` node:

.. code-block:: bash

   ovn-northd --dump-inc-proc-graph=datapath_sync | dot -Tpng -o datapath-sync-graph.png

.. figure:: datapath-sync-graph.png
   :alt: OVN Incremental Processing Graph (datapath_sync node)
   :width: 80%
   :align: center

`ovn-controller`, up to the `evpn_arp` node:

.. code-block:: bash

   ovn-controller --dump-inc-proc-graph=evpn_arp | dot -Tpng -o evpn-arp-graph.png

.. figure:: evpn-arp-graph.png
   :alt: OVN Incremental Processing Graph (evpn_arp node)
   :width: 80%
   :align: center

`ovn-ic`, up to the `ic` node:

.. code-block:: bash

   ovn-ic --dump-inc-proc-graph=ic | dot -Tpng -o ic-graph.png

.. figure:: ic-graph.png
   :alt: OVN Incremental Processing Graph (ic node)
   :width: 25%
   :align: center

Runtime Introspection
---------------------

`ovn-northd`, `ovn-controller`, `ovn-ic` and `ovn-br-controller` all register
the same set of `ovn-appctl`/`ovs-appctl` commands for inspecting and
controlling the engine at runtime:

- `inc-engine/show-stats [node] [counter]`: Display the per-node
  `recompute`, `compute` and `cancel` counters. If `node` is given, only
  that node's counters are shown; `counter` further restricts the output to
  one of `recompute`, `compute` or `cancel`.
- `inc-engine/clear-stats`: Reset all engine counters to zero.
- `inc-engine/recompute`: Force a full recompute of the engine on the next
  iteration, bypassing incremental change handlers.
- `inc-engine/compute-log-timeout <msecs>`: Set the threshold, in
  milliseconds, above which a node's compute/recompute time is logged as
  slow (default 500ms).
- `inc-engine/list-stopwatches [node]`: List engine nodes and, for each,
  the change handlers that can be timed. If `node` is given, only that
  node's handlers are listed.
- `inc-engine/enable-stopwatch [node]`: Start timing recompute and change
  handler invocations for `node`, or for every node if omitted. Results are
  viewed with the `stopwatch/show` command. Stopwatches are disabled by
  default, as they add measurable CPU overhead.
- `inc-engine/disable-stopwatch [node]`: Stop timing for `node`, or for
  every node if omitted. This is the default state.

Implementation Details
----------------------

The engine core is implemented in `lib/inc-proc-eng.c` and
`lib/inc-proc-eng.h`.

Key Structures
~~~~~~~~~~~~~~

- `struct engine_node`: The base structure for a node. Contains inputs, data,
  state, callback functions (`run`, `init`, `cleanup`, `is_valid`,
  `clear_tracked_data`, `get_compute_failure_info`), the per-node `stats`
  counters exposed by `inc-engine/show-stats`, and the `stopwatch_enabled`
  flag toggled by `inc-engine/enable-stopwatch` and
  `inc-engine/disable-stopwatch`.
- `struct engine_node_input`: Describes a dependency on another node and the
  associated change handler.
- `struct engine_context`: Carries the OVSDB transaction handles for the
  current iteration, plus an opaque `client_ctx` pointer that each binary
  uses to pass its own private state (e.g. `ovn-controller`'s
  `controller_engine_ctx`) through to `run()` methods and change handlers.
  Accessed with `engine_get_context()`.

Usage Guidelines
----------------

When working with the incremental processing engine:

1. **Focus on Data:** Design nodes based on the data they maintain.
2. **Explicit Dependencies:** Avoid using global variables. All inputs should
   be explicitly defined in the graph.
3. **Handle All Changes:** Ensure that for every input, either a change handler
   updates the node correctly, or the `run` method recomputes it entirely.
   Returning `EN_UNHANDLED` from a handler triggers recomputation.
