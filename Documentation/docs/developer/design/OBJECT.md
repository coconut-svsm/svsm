# Background

The syscalls design philosophy is to provide a unified interface for the user to
access system resources, which are represented by object handles. This makes
objects a fundamental concept in the COCONUT-SVSM kernel

This document describes the object and object handle from both the user mode's
and the COCONUT-SVSM kernel's point of view.

# Key Data Structures

## Object

An object represents the type of resource like file, VM, vCPU in the
COCONUT-SVSM kernel, that can be accessible by the user mode. A trait named Obj
is defined for such type of resource, which defines the common functionalities
of the object. The Obj trait is defined with the trait bounds of Send and Sync,
which means the object implementing Obj trait could be sent to another thread
and shared between threads safely.

```Rust
trait Obj: Send + Sync {
    /// Convert to a virtual machine object if is supported.
    fn as_vm(&self) -> Option<&VmObj> {
        None
    }

    /// Convert to a virtual cpu object if is supported.
    fn as_vcpu(&self) -> Option<&VcpuObj> {
        None
    }

    /// Get a mappable file handle if the object is mappable.
    fn mappable(&self) -> Option<&FileHandle> {
        None
    }

    /// Convert to an object which implements EventObj trait.
    fn as_event(&self) -> Option<&dyn EventObj> {
        None
    }
    ...
}
```

In order for the user mode to access the resources in the COCONUT-SVSM kernel,
the kernel needs to implement the `Obj` trait to represent the resources as
objects. Some objects may need to implement multiple methods in the Obj trait
for multiple purposes. For example, a vcpu object needs to implement `as_vcpu()`
to represent it as a vcpu object, `mappable()` to provide a file handle for its
user-mode-mappable backing 4k page, and `as_event()` to represent it as an event
object which can be used by the WAIT_FOR_EVENT syscall.

```Rust
struct VcpuObj {
    id: VmId,
    ...
}

/// The trait for the object which can be used as an event.
trait EventObj {
    ...
}

impl EventObj for VcpuObj {
    ...
}

impl Obj for VcpuObj {
    fn as_vcpu(&self) -> Option<&VcpuObj> {
        Some(self)
    }

    fn mappable(&self) -> Option<&FileHandle> {
        Some(&self.run_page_file_handle)
    }

    fn as_event(&self) -> Option<&dyn EventObj> {
        Some(self)
    }
    ...
}

```

Objects without special requirements can fall back to the default implementation
in the Obj trait, which returns None.

## Object Handle

When the user mode is trying to open a particular kernel resource via the
syscalls, the COCONUT-SVSM kernel creates a corresponding object which
implements Obj trait, and allocates an object handle with a unique id for that
object. The object handle is defined as below:

```Rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjHandle(u32);

impl ObjHandle {
    /// Create a new object handle with the allocated id
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl From<u32> for ObjHandle {
    #[inline]
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<ObjHandle> for u32 {
    #[inline]
    fn from(obj_handle: ObjHandle) -> Self {
        obj_handle.0
    }
}
```

An `ObjHandle` can be converted to a `u32` id which is returned to the user
mode, and the subsequent syscalls use this id to access this object. The passed
id from the syscalls can be converted to an `ObjHandle`, which is used to access
the object in the COCONUT-SVSM kernel.

### User Mode Object Handle

The object is exposed to the user mode via the object-opening related syscalls,
which returns the id of the object created by the COCONUT-SVSM kernel. The user
mode can make use this id to access the corresponding object via other syscalls.
From the user mode's point of view, the object handle is defined as below:

```Rust
/// User mode object handle received from syscalls.
pub struct ObjHandle(u32);

impl ObjHandle {
    /// Create a new object handle with the id returned from a syscall.
    pub(crate) fn new(id: u32) -> Self {
        Self(id)
    }
}

impl From<&ObjHandle> for u32 {
    #[inline]
    fn from(obj_handle: &ObjHandle) -> Self {
        obj_handle.0
    }
}

impl Drop for ObjHandle {
    fn drop(&mut self) {
        // Close the object when drop the ObjHandle.
        unsafe { syscall1(SYS_CLOSE, self.0.into()) };
    }
}

```

The user mode `ObjHandle` doesn't implement Copy/Clone trait, and dropping
`ObjHandle` will automatically close the underlying object via the syscall.

For a syscall class which is associated with a particular object handle type,
e.g. VM object handles for VMM subsystem syscalls, VCPU object handles for VCPU
subsystem syscalls, can be defined as:

```Rust
pub struct VmObjHandle(ObjHandle);
```

```Rust
pub struct VcpuObjHandle(ObjHandle);
```

# Object Management in COCONUT-SVSM Kernel

To facilitate the user mode using the object, the COCONUT-SVSM kernel should:

- Manage the object's lifecycle properly. The underlying object should be
  dropped when the user mode closes the object handle via syscalls, or the user
  mode is terminated without closing.

- Prevent one user mode process from misusing the object handle opened by
  another. But the object handles are shared among the threads within the same
  process.

To achieve the above goals, the opened object should be associated with the
process which creates it. The task structure is extended to hold the created
objects.

```Rust
pub struct Task {
    ...

    /// Objects shared among threads within the same process
    objs: Arc<RWLock<BTreeMap<ObjHandle, Arc<dyn Obj>>>>,
}
```

The objs is a BTreeMap with the object handle id as the key and the Arc<dyn Obj>
as the value. It is wrapped by an Arc and protected by a RWLock, to make it
shared among the threads within the same process.

The task structure will provide 3 new functions:

- `add_obj(&self, obj: Arc<dyn Obj>) -> Result<ObjHandle, SvsmError>;` It
  allocates a unique ObjHandle which is local to the process for the object. The
  object is added to the BTreeMap with the `ObjHandle` as the key. This method
  will be used by the syscalls which open an object.

- `remove_obj(&self, id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError>;` It
  removes the object from the BTreeMap. This method will be used by the CLOSE
  syscall to remove the corresponding object from process and drop it.

- `get_obj(&self, id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError>;` It gets
  the object from the BTreeMap, which increases the reference counter. This
  method will be used by the syscalls which access an object.

When a task is terminated while it still has opened objects, these objects will
be dropped automatically when the `objs` is dropped, if `objs` held the last
reference to the objects.

# Opening an Object in User Mode

The user mode can open a particular object via syscalls. For example, VM_OPEN
syscall is used to open a virtual machine object. The COCONUT-SVSM kernel
provides `obj_add()` function to facilitate opening an object in user mode.

```Rust
pub fn sys_vm_open(idx: u32) -> Result<u64, i32> {
    // Get the VmObj
    let vm_obj = get_vm_obj(idx)?;

    // Add the VmObj to the current process and return the
    // object handle id to the user mode.
    obj_add(vm_obj).map_or(Err(EINVAL), |id| Ok(u32::from(id).into()))
}

```

```Rust
/// Add an object to the current process and assigns it an `ObjHandle`.
///
/// # Arguments
///
/// * `obj` - An Arc<dyn Obj> representing the object to be added.
///
/// # Returns
///
/// * `Result<ObjHandle, SvsmError>` - Returns the object handle of the
///   added object if successful, or an `SvsmError` on failure.
///
/// # Errors
///
/// This function will return an error if adding the object to the
/// current task fails.
pub fn obj_add(obj: Arc<dyn Obj>) -> Result<ObjHandle, SvsmError> {
    current_task().add_obj(obj)
}
```

```Rust
impl Task {
    ...

    /// Adds an object to the current task.
    ///
    /// # Arguments
    ///
    /// * `obj` - The object to be added.
    ///
    /// # Returns
    ///
    /// * `Result<ObjHandle, SvsmError>` - Returns the object handle for the object
    ///   to be added if successful, or an `SvsmError` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if allocating the object handle fails.
    pub fn add_obj(&self, obj: Arc<dyn Obj>) -> Result<ObjHandle, SvsmError> {
        let mut objs = self.objs.lock_write();
        let last_key = objs
            .keys()
            .last()
            .map_or(Some(0), |k| u32::from(*k).checked_add(1))
            .ok_or(SvsmError::from(ObjError::InvalidHandle))?;
        let id = ObjHandle::new(if last_key != objs.len() as u32 {
            objs.keys()
                .enumerate()
                .find(|(i, &key)| *i as u32 != u32::from(key))
                .unwrap()
                .0 as u32
        } else {
            last_key
        });

        objs.insert(id, obj);

        Ok(id)
    }
}
```

The `obj_add()` takes the `Arc<dyn Obj>` as an input, which represents the
particular object to be added, and stores the object in the current task via the
`add_obj()` method. An `ObjHandle` is allocated by the `add_obj()` which is
local to the process, and returned to the syscall. It is converted to a `u32`
and returned to the user mode as the user mode `ObjHandle`.

# Closing an Object in User Mode

The CLOSE syscall can close an object, taking the object handle id as the input
parameter. The COCONUT-SVSM kernel provides `obj_close()` function to facilitate
closing an object in the syscall.

```Rust
pub fn sys_close(obj_id: u32) -> Result<u64, i32> {
    // Close the object by the object handle id.
    let _ = obj_close(obj_id.into());
    Ok(0)
}
```

```Rust
/// Closes an object identified by its unique identifier.
///
/// # Arguments
///
/// * `id` - The ObjHandle for the object to be closed.
///
/// # Returns
///
/// * `Result<Arc<dyn Obj>, SvsmError>` - Returns the object pointer
///   on success, or an `SvsmError` on failure.
///
/// # Errors
///
/// This function will return an error if removing the object from the
/// current task fails.
pub fn obj_close(id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
    current_task().remove_obj(id)
}

```

```Rust
impl Task {
    ...

    /// Removes an object from the current task.
    ///
    /// # Arguments
    ///
    /// * `id` - The ObjHandle for the object to be removed.
    ///
    /// # Returns
    ///
    /// * `Result<Arc<dyn Obj>, SvsmError>` - Returns the removed object
    ///   pointer on success, or an `SvsmError` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if the object handle id does not
    /// exist in the current task.
    pub fn remove_obj(&self, id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
        self.objs
            .lock_write()
            .remove(&id)
            .ok_or(ObjError::NotFound.into())
    }
}

```

After removing the `Arc<dyn Obj>` from the current task, the object will be
dropped by the CLOSE syscall if this is the last reference to the object.

# Accessing an Object in User Mode

Certain syscalls can access the objects by taking the object handle id as an
input. For example, VM_CAPABILITIES syscall takes an object handle id as input,
and returns the corresponding capability of the virtual machine object. The
COCONUT-SVSM kernel provides `obj_get()` function to facilitate accessing an
object in a syscall.

```Rust
pub fn sys_vm_capabilities(obj_id: u32, idx: u32) -> Result<u64, i32> {
   // Get the object according to the id
   if let Ok(obj) = obj_get(obj_id.into()) {
        // Try to convert to the VmObj if it is.
        if let Some(vm) = obj.as_vm() {
            ...
        }
    }
}
```

```Rust
/// Retrieves the Arc<dyn Obj> by its unique identifier.
///
/// # Arguments
///
/// * `id` - The ObjHandle for the object to be retrieved.
///
/// # Returns
///
/// * `Result<Arc<dyn Obj>, SvsmError>` - Returns the Arc<dyn Obj> on
///   success, or an `SvsmError` on failure.
///
/// # Errors
///
/// This function will return an error if retrieving the object from the
/// current task fails.
pub fn obj_get(id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
    current_task().get_obj(id)
}
```

```Rust
impl Task {
    ...

    /// Retrieves an object from the current task.
    ///
    /// # Arguments
    ///
    /// * `id` - The ObjHandle for the object to be retrieved.
    ///
    /// # Returns
    ///
    /// * `Result<Arc<dyn Obj>, SvsmError>` - Returns the Arc<dyn Obj> on
    ///   success, or an `SvsmError` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if the object handle id does not exist
    /// in the current task.
    pub fn get_obj(&self, id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
        self.objs
            .lock_read()
            .get(&id)
            .cloned()
            .ok_or(ObjError::NotFound.into())
        )
    }
}
```

The `obj_get()` gets a cloned `Arc<dyn Obj>` in the current task through the
`ObjHandle`, which increases the reference count. Once the syscall completes the
operation, the `Arc<dyn Obj>` will be dropped and the reference count will be
decreased.
