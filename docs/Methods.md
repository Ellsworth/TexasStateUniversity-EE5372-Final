# Methods

## Network Traversal

* Dijkstra's algorithm
  * Classical algorithm with excellent performance.
  * Due to the nature of the algorithm, we must know the network topology to use this algorithm. This is not feasible for low power IoT devices, as we would need to maintain a map of the network at all times.
* Time-to-live
  * Used in networking.
  * We could use the same method as Bob Bruninga's Automatic Packet Reporting System (APRS).
  * Maintain a counter of the number of hops left and subtract one per hop.
NamedTuple
### Experiment 1

All nodes share a common master key.

* Pros:
  * Very simple to implement and use. Low storage cost and performance overhead to manage keys.
* Cons:
  * A single compromised node is able to read every message on the network.


### Experiment 2

All nodes have a unique key. The keys are stored on a server that runs the network. 

This configuration is well suited for smart power meters, industrial Internet of Things (IIoT).

* Pros:
    * It is harder to get access to the entire network if one of the node's key is hacked
* Cons:
    * Requires storing all the keys.
    * Difficult to handle node-to-node communication, as each connection pair requires a key.

NOTES: We are just centralizing the risk. Additional security of the master node is needed to ensure the safety of the network.
       Aggrigators have the keys. If you get an aggrigator you only get access to a certain number of devices and not the entire network
       Could propose that as an alternative approach to one master.

       Adding latency to the system because server runs the whole thing