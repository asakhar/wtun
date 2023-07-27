use winapi::shared::{
  devpropdef::{DEVPROPCOMPKEY, DEVPROPERTY},
  minwindef::ULONG,
  ntdef::{HRESULT, PCWSTR, PVOID},
};

#[allow(dead_code)]
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum DEVPROP_OPERATOR {
  MODIFIER_NOT = 65536,
  MODIFIER_IGNORE_CASE = 131072,
  NONE = 0,
  EXISTS = 1,
  NOT_EXISTS = 65537,
  EQUALS = 2,
  NOT_EQUALS = 65538,
  GREATER_THAN = 3,
  LESS_THAN = 4,
  GREATER_THAN_EQUALS = 5,
  LESS_THAN_EQUALS = 6,
  EQUALS_IGNORE_CASE = 131074,
  NOT_EQUALS_IGNORE_CASE = 196610,
  BITWISE_AND = 7,
  BITWISE_OR = 8,
  BEGINS_WITH = 9,
  ENDS_WITH = 10,
  CONTAINS = 11,
  BEGINS_WITH_IGNORE_CASE = 131081,
  ENDS_WITH_IGNORE_CASE = 131082,
  CONTAINS_IGNORE_CASE = 131083,
  LIST_CONTAINS = 4096,
  LIST_ELEMENT_BEGINS_WITH = 8192,
  LIST_ELEMENT_ENDS_WITH = 12288,
  LIST_ELEMENT_CONTAINS = 16384,
  LIST_CONTAINS_IGNORE_CASE = 135168,
  LIST_ELEMENT_BEGINS_WITH_IGNORE_CASE = 139264,
  LIST_ELEMENT_ENDS_WITH_IGNORE_CASE = 143360,
  LIST_ELEMENT_CONTAINS_IGNORE_CASE = 147456,
  AND_OPEN = 1048576,
  AND_CLOSE = 2097152,
  OR_OPEN = 3145728,
  OR_CLOSE = 4194304,
  NOT_OPEN = 5242880,
  NOT_CLOSE = 6291456,
  ARRAY_CONTAINS = 268435456,
  MASK_EVAL = 4095,
  MASK_LIST = 61440,
  MASK_MODIFIER = 983040,
  MASK_NOT_LOGICAL = -267386881,
  MASK_LOGICAL = 267386880,
  MASK_ARRAY = -268435456,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct DEVPROP_FILTER_EXPRESSION {
  pub(crate) Operator: DEVPROP_OPERATOR,
  pub(crate) Property: DEVPROPERTY,
}

#[allow(dead_code)]
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum DEV_OBJECT_TYPE {
  Unknown = 0,
  DeviceInterface = 1,
  DeviceContainer = 2,
  Device = 3,
  DeviceInterfaceClass = 4,
  AEP = 5,
  AEPContainer = 6,
  DeviceInstallerClass = 7,
  DeviceInterfaceDisplay = 8,
  DeviceContainerDisplay = 9,
  AEPService = 10,
  DevicePanel = 11,
}
#[allow(dead_code)]
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum DEV_QUERY_FLAGS {
  None = 0,
  UpdateResults = 1,
  AllProperties = 2,
  Localize = 4,
  AsyncClose = 8,
}

#[allow(dead_code)]
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum DEV_QUERY_STATE {
  Initialized = 0,
  EnumCompleted = 1,
  Aborted = 2,
  Closed = 3,
}

#[allow(dead_code)]
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum DEV_QUERY_RESULT_ACTION {
  StateChange = 0,
  Add = 1,
  Update = 2,
  Remove = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct DEV_OBJECT {
  pub(crate) ObjectType: DEV_OBJECT_TYPE,
  pub(crate) pszObjectId: PCWSTR,
  pub(crate) cPropertyCount: ULONG,
  pub(crate) pProperties: *const DEVPROPERTY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct DEV_QUERY_RESULT_ACTION_DATA {
  pub(crate) Action: DEV_QUERY_RESULT_ACTION,
  pub(crate) Data: _DEV_QUERY_RESULT_ACTION_DATA__DEV_QUERY_RESULT_UPDATE_PAYLOAD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) union _DEV_QUERY_RESULT_ACTION_DATA__DEV_QUERY_RESULT_UPDATE_PAYLOAD {
  pub(crate) State: DEV_QUERY_STATE,
  pub(crate) DeviceObject: DEV_OBJECT,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct HDEVQUERY__ {
  pub(crate) unused: ::std::os::raw::c_int,
}

pub(crate) type HDEVQUERY = *mut HDEVQUERY__;
pub(crate) type PHDEVQUERY = *mut HDEVQUERY;

pub(crate) type PDEV_QUERY_RESULT_CALLBACK = ::std::option::Option<
  unsafe extern "system" fn(
    hDevQuery: HDEVQUERY,
    pContext: PVOID,
    pActionData: *const DEV_QUERY_RESULT_ACTION_DATA,
  ),
>;

extern "system" {
  pub(crate) fn DevCreateObjectQuery(
    ObjectType: DEV_OBJECT_TYPE,
    QueryFlags: ULONG,
    cRequestedProperties: ULONG,
    pRequestedProperties: *const DEVPROPCOMPKEY,
    cFilterExpressionCount: ULONG,
    pFilter: *const DEVPROP_FILTER_EXPRESSION,
    pCallback: PDEV_QUERY_RESULT_CALLBACK,
    pContext: PVOID,
    phDevQuery: PHDEVQUERY,
  ) -> HRESULT;
}
extern "system" {
  pub(crate) fn DevCloseObjectQuery(hDevQuery: HDEVQUERY);
}
