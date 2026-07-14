# SVSM OCP protocol

The SVSM Observability and Configuration Protocol (OCP) is a
new sub-protocol of the SVSM specification.

The guest, running at lower VMPL, can use it to interact with
SVSM sources by listing, reading or writing them.

## Object and Sources
Sources are organized around the objects to which they belong,
which are classified by specific categories. The SVSM maintains
an ordered list of these objects

### Sources info
Sources have the following layout:

  * **flags**: contains sources information.  For now, it only indicates whether or not a source is writable.
  * **type**: kind of data returned from this source. `0x00` is reserved for Objects.
  * **name**: human readable source name.

Each source has a basic unit type and can be seen as a slice of that unit type. For now, there are two kind of sources:
* **Single Bytes**: contains a variable number of bytes, that can grow at runtime. The unit type is a single byte.
*  **X-bit Signed Integer**: contains a variable length array of X-bit signed integer . The unit type is X-bit.

Read and write operations can operate at a source `offset`. The latter is source dependant and is based on the basic unit type of the source.
SVSM checks at runtime that the value is correctly a multiple of the
base type.

## Protocol number
```
pub const SVSM_OBSERVABILITY_CONFIGURATION_PROTOCOL: u32 = 5;
```

## Protocol requests

### List objects & sources
Request SVSM to provide a (sub)list of available objects
with basic information.

#### Call ID

```
const SVSM_OCP_LIST_OBJECTS: u32 = 0;
```

#### Parameters
* **RDX**: buffer address (guest physical).
* **RCX**: Optional GPA of object name
* **R8**: IN/OUT register
  * number of bytes requested (IN)
  * number of bytes returned (OUT)
* **R9**: number of bytes necessary to return all objects/sources.

**note**: For now, buffer size is limited to 4096 bytes.

If **RCX** is 0, this call returns the list of objects, otherwise
it returns the list of sources for the specific object.

### Read source
Request SVSM to provide data from a specific source.

#### Call ID
```
const SVSM_OCP_READ: u32 = 2;
```
#### Parameters
* **RDX**: buffer address (guest physical).
* **RCX**: GPA with source identifier (OBJ name/source name)
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
* **RCX**: GPA with source identifier (OBJ name/source name)
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
