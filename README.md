Intrusive cryptography interface is designed to minimize overhead by avoiding
buffer copies, dynamic allocations and aiming for a desired asymptotic
complexity. This ensures high speed and resource efficiency. Dynamic
allocation allows handling integers of any size but comes at the expense of
performance and may introduce side-channel vulnerabilities.
