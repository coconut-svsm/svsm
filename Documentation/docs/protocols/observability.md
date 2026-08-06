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

Indexes are stable during runtime.

### Objects
Objects contains basic information on the category of the object
and a variable number of sources

### Sources
Sources have the following layout:

  * **primary index**: Represents the object in which the source is located
  * **secundary index**: Represents the index at which the source is   available through the object
  * **type**: kind of data returned from this source. Such as string or integer values.
  * **flags**: contains sources information.  For now, it only indicates whether or not a source is writable.
  * **name**: human readable source name.

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
* **RCX**: index of the first object to return
* **R8**: number of objects to return

### List object sources
Request SVSM to provide a (sub)list of available sources
for a specific object.

#### Call ID
```
const SVSM_OCP_LIST_OBJECT_SOURCES: u32 = 1;
```

#### Parameters
* **RDX**: buffer address (guest physical).
* **RCX**: contains both:
    - Primary index representing an object
    - Secundary index representing a source in the object
* **R8**: number of sources of an object to return

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
* **R8**: number of bytes of a source to read
* **R9**: number of bytes read

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
* **R8**: number of bytes of a source to write
* **R9**: number of bytes written

## Available sources

### Version

This is a simple source that can only be read. It provides
information on the current SVSM version.

### Log Buffer

This source allows the user to read the information logged
by SVSM during its runtime.
