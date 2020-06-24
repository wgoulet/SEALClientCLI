# SEALClientCLI
Basic CLI application for working with SEAL server

This very basic application demonstrates working with a remote service providing fully homomorphic encryption capabilities. This client uses the Microsoft SEAL library 
(https://www.microsoft.com/en-us/research/project/microsoft-seal/). It currently is little more than a 'Hello World' example.

The client demonstrates basic Add operations on simple integer values. The client also demonstrates a way to send/receive data from a webservice that provides FHE services by serializing SEAL objects for transmission over the wire.
