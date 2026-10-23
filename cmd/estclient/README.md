# estclient

Application estclient is an EST client.

On Unix, `serverkeygen -keyout` removes group and other read and write
permissions from an existing regular output file before writing the private
key. This also removes intentionally configured group access. Windows file
access remains controlled by its existing ACLs.
