# SVSM OCP protocol

The SVSM Observability and Configuration Protocol (OCP) is a
new sub-protocol of the SVSM specification.

The guest, running at lower VMPL, can use it to interact with
SVSM sources by listing, reading or writing them.

## Object and Sources
Sources are organized around the objects to which they belong,
which are classified by specific categories.

The SVSM maintains a list of these objects on an ordered map
that is accessible through a primary index, and sources
within the objects are available through a secondary index.

Indexes are stable during runtime, as they are not reused for new sources.

### Objects
Objects contains basic information on the category of the object
and a variable number of sources. The details that userspace can
obtain from the objects are:

  * **primary index**: Represents the object
  * **category**: Represent the kind of object, that group sources together
  * **count**: Contains the number of sources that the object

The data structures used for returning the details is the following:
```rust
#[repr(C)]
pub struct OcpObjectDetails {
    sup_index: u32,
    category: OcpObjectType,
    count: u32,
}
```

### Sources
Sources have the following layout:

  * **primary index**: Represents the object in which the source is located
	* **secundary index**: Represents the index at which the source is   available through the object
  * **type**: kind of data returned from this source. Such as string or integer values.
  * **flags**: contains sources information.  For now, it only indicates whether or not a source is writable.
  * **name**: human readable source name.

The data structure used for returning the details is the following:
```rust
#[repr(C)]
pub struct OcpSourceDetails {
    sup_index: u32,
    sub_index: u32,
    kind: OcpSourceType,
    flags: OcpSourceFlags,
    name: [u8; OCP_SOURCE_NAME_LEN],
}
```

Each source has a basic unit type and can be seen as a slice of that unit type. For now, there are two kind of sources:
* **string**: contains a variable number of bytes, that can grow at runtime. The unit type is a single byte.
*  **static string**: contains a fixed number of bytes. The unit type is a single byte.

Read and write operations can operate at a source `offset`. The latter is source dependant and is based on the basic unit type of the source.
SVSM checks at runtime that the value is correctly a multiple of the
base type.

## Protocol number
```
pub const SVSM_OBSERVABILITY_CONFIGURATION_PROTOCOL: u32 = 5;
```

## Protocol requests

### List objects
Request SVSM to provide a (sub)list of available objects
with basic information and the number of sources each object
has.

#### Call ID

```
const SVSM_OCP_LIST_OBJECTS: u32 = 0;
```

#### Parameters
* **RDX**: buffer address (guest physical).
* **RCX**: IN/OUT register
  * index of the first object to return (IN)
  * number of bytes returned (OUT)
* **R8**: number of bytes to return.
  It must be a multiple of 12 bytes (object details size) and represent the number of objects required multiplied for the size.

**note**: For now, buffer size is limited to 4096 bytes.

### List object sources
Request SVSM to provide a (sub)list of available sources
for a specific object.

#### Call ID
```
const SVSM_OCP_LIST_OBJECT_SOURCES: u32 = 1;
```

#### Parameters
* **RDX**: buffer address (guest physical).
* **RCX**: IN/OUT registers:
    - Primary index representing an object (IN up 32 bits)
    - Secundary index representing a source in the object (IN low 32 bits)
    - number of bytes returned (OUT)
* **R8**: number of bytes to return.
  It must be a multiple of 128 (source details size) and represents the number of sources of the specific objects required multiplied for the size.

**note**: For now, buffer size is limited to 4096 bytes.

### Read source
Request SVSM to provide data from a specific source.

#### Call ID
```
const SVSM_OCP_READ: u32 = 2;
```
#### Parameters
* **RDX**: buffer address (guest physical).
* **RCX**: contains both:
  - Primary index representing an object
  - Secundary index representing a source in the object
* **R8**: IN/OUT parameter:
	- Number of bytes of a source to read (IN)
	-  Number of bytes read (OUT)
* **R9**: offset of the source where to start read from

**note**: For now, buffer size is limited to 4096 bytes.

### Write source
Request SVSM to update a specific source with the data
provided.

#### Call ID
```
const SVSM_OCP_WRITE: u32 = 3;
```
#### Parameters
* **RDX**: buffer address (guest physical).
* **RCX**: contains both:
  - Primary index representing an object
  - Secundary index representing a source in the object
* **R8**: IN/OUT parameter:
	- Number of bytes of a source to write (IN)
	- Number of bytes written (OUT)
* **R9**: offset of the source where to start write to

**note**: For now, buffer size is limited to 4096 bytes.

## Available sources

### Version

This is a simple source that can only be read. It provides
information on the current SVSM version.

### Log Buffer

This source allows the user to read the information logged
by SVSM during its runtime.
