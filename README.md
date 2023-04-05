
# Kerberos provider demo

This project demonstrates how to create a JAAS provider for Kerberos JGSS. It does not implement Kerberos itself,
instead delegates to the JVM's stock builtin provider.

This project was made with the purpose of showcasing the shortcomings of the JVM's API for this purpose - particularly
that several interfaces required for making such implementation, as well as classes useful for this purpose are
internal and inaccessible with the introduction of the module system in Java 9. It also showcases issues with the
code using the provider, which necessitate further workarounds (even for the JVM's own native JGSS provider), also
demonstrated here.

The project was not made with the purpose to be used and wasn't tested, so may or may not work in practice. Comments
are added in the source code to explain the purpose of each component and differences from a real implementation vs.
this demo delegating to the stock provider. The `example.Demo` class contains a `main` method, that may serve as an
ideal starting point for reading the code.

The project has no dependencies so it can be added to any existing project without further requirements. It can be
compiled on Java 8.

