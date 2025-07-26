# Bitwarden Collections

Defines the data model for collections both encrypted and decrypted. It also handles conversions
between those two states by implementing `Encryptable`. It also provides `Tree` struct which allows
all structs implementing `TreeItem` to be represented in a tree structure along with functions to
access each node.
